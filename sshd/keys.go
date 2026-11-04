package main

import (
	"bytes"
	"fmt"
	"os"
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
	comment      string
}

const (
	approveWindow = "window" // prompt, then remember for the chosen duration
	approveAlways = "always" // prompt on every connection
	approveNever  = "never"
)

// findKey returns the options of key in the authorized_keys file at path.
// A matching key with an unknown option is an error rather than accepted
// without the restriction the option was meant to add (e.g. command=).
func findKey(path string, key ssh.PublicKey) (*keyOpts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	want := key.Marshal()
	for len(bytes.TrimSpace(data)) > 0 {
		pk, comment, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			// No more keys (the parser skips comments and malformed lines).
			return nil, nil
		}
		data = rest
		if !bytes.Equal(pk.Marshal(), want) {
			continue
		}
		o, err := parseOpts(options)
		if err != nil {
			return nil, fmt.Errorf("%s: key %q: %w", path, comment, err)
		}
		o.comment = comment
		return o, nil
	}
	return nil, nil
}

func parseOpts(options []string) (*keyOpts, error) {
	o := &keyOpts{user: "root", approve: approveWindow, maxAge: 8 * time.Hour}
	for _, opt := range options {
		name, val, _ := strings.Cut(opt, "=")
		val = strings.Trim(val, `"`)
		switch name {
		case "user":
			if val != "root" && val != "shell" && !isUint(val) {
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
			o.fromNode = val
		case "no-port-forwarding":
			o.noForwarding = true
		default:
			return nil, fmt.Errorf("unsupported option %q", name)
		}
	}
	return o, nil
}

func isUint(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
