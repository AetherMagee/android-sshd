package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKeysEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	os.WriteFile(path, []byte("# header comment\n"), 0o600)
	pub := func() (string, string) {
		p, _, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := ssh.NewPublicKey(p)
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " me@laptop", ssh.FingerprintSHA256(k)
	}
	a, fpA := pub()
	b, fpB := pub()

	if err := runKeys([]string{"put", "-dir", dir, a}); err != nil {
		t.Fatal(err)
	}
	if err := runKeys([]string{"put", "-dir", dir, "-user", "shell", "-max-age", "30m", "-from-node", "laptop", b}); err != nil {
		t.Fatal(err)
	}
	// Editing replaces the line in place.
	if err := runKeys([]string{"put", "-dir", dir, "-approve", "never", "-max-age", "90m", a}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	want := "# header comment\n" +
		`approve="never",max-age="1h30m" ` + a + "\n" +
		`user="shell",max-age="30m",from-node="laptop" ` + b + "\n"
	if string(data) != want {
		t.Fatalf("got\n%s\nwant\n%s", data, want)
	}

	if err := runKeys([]string{"rm", "-dir", dir, fpA}); err != nil {
		t.Fatal(err)
	}
	keys, _ := readKeys(path)
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0].key) != fpB || keys[0].opts.user != "shell" {
		t.Fatalf("after rm: %+v", keys)
	}

	for _, bad := range [][]string{
		{"put", "-dir", dir, "-user", "nobody", a},
		{"put", "-dir", dir, "-from-node", `x",command="sh`, a},
		{"put", "-dir", dir, `command="sh" ` + a},
		{"put", "-dir", dir, "not a key"},
		{"rm", "-dir", dir, fpA},
	} {
		if err := runKeys(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
