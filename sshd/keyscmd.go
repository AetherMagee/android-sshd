package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// runKeys is `android-sshd keys`, the WebUI's way to read and edit
// authorized_keys without parsing it in JavaScript:
//
//	keys list                       JSON: host key + every key line
//	keys put [options] <public key> add the key, or replace its options
//	keys rm <fingerprint>
func runKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	dir := fs.String("dir", "/data/adb/sshd", "state dir")
	user := fs.String("user", "root", "root, shell or a uid")
	approve := fs.String("approve", approveWindow, "window, always or never")
	maxAge := fs.String("max-age", shortDuration(defaultMaxAge), "connection age limit")
	fromNode := fs.String("from-node", "", "only from this tailnet device")
	noFwd := fs.Bool("no-port-forwarding", false, "refuse ssh -L")
	if len(args) == 0 {
		return errors.New("usage: android-sshd keys list|put|rm [-dir D] [options] [<public key> | <fingerprint>]")
	}
	cmd := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	path := filepath.Join(*dir, "authorized_keys")

	switch cmd {
	case "list":
		return listKeys(*dir, path)
	case "put":
		if fs.NArg() != 1 {
			return errors.New("put: want one public key")
		}
		opts := []string{`user="` + *user + `"`, `approve="` + *approve + `"`, `max-age="` + *maxAge + `"`}
		if *fromNode != "" {
			opts = append(opts, `from-node="`+*fromNode+`"`)
		}
		if *noFwd {
			opts = append(opts, "no-port-forwarding")
		}
		o, err := parseOpts(opts)
		if err != nil {
			return err
		}
		key, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(fs.Arg(0)))
		if err != nil {
			return errors.New("put: not an OpenSSH public key")
		}
		if len(options) > 0 {
			return errors.New("put: pass options as flags, not in the key")
		}
		line := strings.TrimSpace(o.format() + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + comment)
		return editKeys(path, ssh.FingerprintSHA256(key), line)
	case "rm":
		if fs.NArg() != 1 {
			return errors.New("rm: want a fingerprint")
		}
		return editKeys(path, fs.Arg(0), "")
	}
	return fmt.Errorf("unknown keys command %q", cmd)
}

type keyJSON struct {
	Line             int    `json:"line"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	PublicKey        string `json:"publicKey,omitempty"` // type, base64 and comment, without options
	Comment          string `json:"comment,omitempty"`
	User             string `json:"user,omitempty"`
	Approve          string `json:"approve,omitempty"`
	MaxAge           string `json:"maxAge,omitempty"`
	FromNode         string `json:"fromNode,omitempty"`
	NoPortForwarding bool   `json:"noPortForwarding,omitempty"`
	Error            string `json:"error,omitempty"`
}

func listKeys(dir, path string) error {
	out := struct {
		HostKey string    `json:"hostKey,omitempty"`
		Keys    []keyJSON `json:"keys"`
	}{Keys: []keyJSON{}}
	if data, err := os.ReadFile(filepath.Join(dir, "ssh_host_ed25519_key")); err == nil {
		if s, err := ssh.ParsePrivateKey(data); err == nil {
			out.HostKey = ssh.FingerprintSHA256(s.PublicKey())
		}
	}
	keys, err := readKeys(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, k := range keys {
		j := keyJSON{Line: k.n, Comment: k.comment}
		if k.key != nil {
			j.Fingerprint = ssh.FingerprintSHA256(k.key)
			j.PublicKey = strings.TrimSpace(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.key))) + " " + k.comment)
		}
		if k.opts != nil {
			j.User, j.Approve, j.MaxAge = k.opts.user, k.opts.approve, shortDuration(k.opts.maxAge)
			j.FromNode, j.NoPortForwarding = k.opts.fromNode, k.opts.noForwarding
		}
		if k.err != nil {
			j.Error = k.err.Error()
		}
		out.Keys = append(out.Keys, j)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// editKeys replaces the line holding the key with fingerprint fp by line
// (removing it if line is empty), or appends line if the key isn't there.
// Comments and other lines are kept as they are.
func editKeys(path, fp, line string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(data) == 0 {
		lines = nil
	}
	found := false
	var out []string
	for _, l := range lines {
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil && ssh.FingerprintSHA256(k) == fp {
			if !found && line != "" {
				out = append(out, line)
			}
			found = true
			continue
		}
		out = append(out, l)
	}
	if !found {
		if line == "" {
			return fmt.Errorf("no key %s", fp)
		}
		out = append(out, line)
	}

	var buf bytes.Buffer
	for _, l := range out {
		buf.WriteString(l + "\n")
	}
	return writeFileAtomic(path, buf.Bytes())
}
