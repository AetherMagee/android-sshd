package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// keyOpts are the per-key options in authorized_keys, written OpenSSH-style
// before the key: user="shell",approve="never",max-age="10m" ssh-ed25519 AAAA...
type keyOpts struct {
	user         string        // root, shell or a numeric uid
	approve      string        // window, always or never
	maxAge       time.Duration // connections are closed after this long
	fromNode     string        // only accept from this tailnet node name, if set
	noForwarding bool          // no-port-forwarding
}

const (
	approveWindow = "window" // prompt, then remember for the chosen duration
	approveAlways = "always" // prompt on every connection
	approveNever  = "never"

	defaultMaxAge = 8 * time.Hour
)

// keyLine is one non-comment line of authorized_keys.
type keyLine struct {
	n       int // line number
	key     ssh.PublicKey
	comment string
	opts    *keyOpts
	err     error // unparseable line or invalid options
}

func readKeys(path string) ([]keyLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []keyLine
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k := keyLine{n: i + 1}
		var options []string
		k.key, k.comment, options, _, k.err = ssh.ParseAuthorizedKey([]byte(line))
		if k.err == nil {
			k.opts, k.err = parseOpts(options)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// findKey returns the options of key in the authorized_keys file at path.
// A matching key with an unknown option is an error rather than accepted
// without the restriction the option was meant to add (e.g. command=).
func findKey(path string, key ssh.PublicKey) (*keyOpts, string, error) {
	keys, err := readKeys(path)
	if err != nil {
		return nil, "", err
	}
	want := key.Marshal()
	for _, k := range keys {
		if k.key == nil || !bytes.Equal(k.key.Marshal(), want) {
			continue
		}
		if k.err != nil {
			return nil, "", fmt.Errorf("%s:%d: key %q: %w", path, k.n, k.comment, k.err)
		}
		return k.opts, k.comment, nil
	}
	return nil, "", nil
}

var nodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

func parseOpts(options []string) (*keyOpts, error) {
	o := &keyOpts{user: "root", approve: approveWindow, maxAge: defaultMaxAge}
	for _, opt := range options {
		name, val, _ := strings.Cut(opt, "=")
		val = strings.Trim(val, `"`)
		switch name {
		case "user":
			if _, err := strconv.ParseUint(val, 10, 32); err != nil && val != "root" && val != "shell" {
				return nil, fmt.Errorf("user=%q: want root, shell or a uid", val)
			}
			o.user = val
		case "approve":
			if val != approveWindow && val != approveAlways && val != approveNever {
				return nil, fmt.Errorf("approve=%q: want window, always or never", val)
			}
			o.approve = val
		case "max-age":
			d, err := time.ParseDuration(val)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("max-age=%q: want a duration like 30m or 8h", val)
			}
			o.maxAge = d
		case "from-node":
			if !nodeName.MatchString(val) {
				return nil, fmt.Errorf("from-node=%q: want a device name", val)
			}
			o.fromNode = val
		case "no-port-forwarding":
			o.noForwarding = true
		default:
			return nil, fmt.Errorf("unsupported option %q", name)
		}
	}
	return o, nil
}

// format renders the options that differ from the defaults.
func (o *keyOpts) format() string {
	var s []string
	if o.user != "root" {
		s = append(s, `user="`+o.user+`"`)
	}
	if o.approve != approveWindow {
		s = append(s, `approve="`+o.approve+`"`)
	}
	if o.maxAge != defaultMaxAge {
		s = append(s, `max-age="`+shortDuration(o.maxAge)+`"`)
	}
	if o.fromNode != "" {
		s = append(s, `from-node="`+o.fromNode+`"`)
	}
	if o.noForwarding {
		s = append(s, "no-port-forwarding")
	}
	return strings.Join(s, ",")
}

// shortDuration formats 8h0m0s as 8h and 1h30m0s as 1h30m.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
