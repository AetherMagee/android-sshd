package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	// The server re-executes itself (here: the test binary) as the sftp server.
	if len(os.Args) > 1 && os.Args[1] == "sftp" {
		runSFTP()
		return
	}
	os.Exit(m.Run())
}

type fakePhone struct {
	prompts atomic.Int32
	answer  func(window bool) (time.Duration, error)
}

func (f *fakePhone) prompt(ctx context.Context, title, text string, window bool) (time.Duration, error) {
	f.prompts.Add(1)
	return f.answer(window)
}

type env struct {
	t     *testing.T
	addr  string
	phone *fakePhone
	keys  string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	hk, err := loadHostKey(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	phone := &fakePhone{answer: func(bool) (time.Duration, error) { return 15 * time.Minute, nil }}
	s := &server{
		keysPath: filepath.Join(dir, "authorized_keys"),
		shell:    "/bin/sh",
		rootHome: dir,
		self:     self,
		hostKey:  hk,
		approver: newApprover(phone.prompt, 5*time.Second),
		whois:    func(string) (peer, error) { return peer{}, errors.New("no tailscale") },
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serve(ln)
	return &env{t: t, addr: ln.Addr().String(), phone: phone, keys: s.keysPath}
}

// key adds a fresh key with the given options and returns its signer.
// user= defaults to the current uid so no privilege change is needed.
func (e *env) key(opts string) ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	if !strings.Contains(opts, "user=") {
		opts = strings.TrimPrefix(opts+`,user="`+strconv.Itoa(os.Getuid())+`"`, ",")
	}
	line := strings.TrimSpace(opts+" "+string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " test\n"
	f, err := os.OpenFile(e.keys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	f.WriteString(line)
	f.Close()
	return signer
}

func (e *env) dial(k ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User:            "whoever",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(k)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

func (e *env) run(k ssh.Signer, cmd string) (string, error) {
	c, err := e.dial(k)
	if err != nil {
		return "", err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	out, err := s.CombinedOutput(cmd)
	return string(out), err
}

func TestExec(t *testing.T) {
	e := newEnv(t)
	k := e.key(`approve="never"`)
	c, err := e.dial(k)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	var stdout, stderr bytes.Buffer
	s.Stdout, s.Stderr = &stdout, &stderr
	if err := s.Run("echo hi; echo err >&2"); err != nil || stdout.String() != "hi\n" || stderr.String() != "err\n" {
		t.Fatalf("got %q / %q, %v", stdout.String(), stderr.String(), err)
	}
	c.Close()
	_, err = e.run(k, "exit 3")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("want exit 3, got %v", err)
	}
	if n := e.phone.prompts.Load(); n != 0 {
		t.Fatalf("approve=never prompted %d times", n)
	}
}

// A command that exits without reading stdin must end the session even
// though the client keeps stdin open (sftp clients do).
func TestExecStdinOpen(t *testing.T) {
	e := newEnv(t)
	c, err := e.dial(e.key(`approve="never"`))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	s.StdinPipe()
	done := make(chan error, 1)
	go func() { done <- s.Run("exit 7") }()
	select {
	case err := <-done:
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 7 {
			t.Fatalf("want exit 7, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session hung with stdin open")
	}
}

func TestUnknownKeyAndOption(t *testing.T) {
	e := newEnv(t)
	bad := e.key(`command="true"`)
	if _, err := e.run(bad, "true"); err == nil {
		t.Fatal("key with unsupported option was accepted")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := ssh.NewSignerFromKey(priv)
	if _, err := e.run(stranger, "true"); err == nil {
		t.Fatal("unknown key was accepted")
	}
}

func TestApprovalWindow(t *testing.T) {
	e := newEnv(t)
	k := e.key("")
	for i := 0; i < 3; i++ {
		if out, err := e.run(k, "echo ok"); err != nil || out != "ok\n" {
			t.Fatalf("run %d: %q, %v", i, out, err)
		}
	}
	if n := e.phone.prompts.Load(); n != 1 {
		t.Fatalf("want 1 prompt for 3 logins within the window, got %d", n)
	}
}

func TestApprovalConcurrentCoalesced(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.phone.answer = func(bool) (time.Duration, error) { <-release; return time.Minute, nil }
	k := e.key("")
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() { _, err := e.run(k, "true"); errs <- err }()
	}
	time.Sleep(300 * time.Millisecond)
	close(release)
	for i := 0; i < 3; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := e.phone.prompts.Load(); n != 1 {
		t.Fatalf("want 1 prompt for concurrent logins, got %d", n)
	}
}

func TestApprovalAlwaysAndDeny(t *testing.T) {
	e := newEnv(t)
	k := e.key(`approve="always"`)
	e.phone.answer = func(window bool) (time.Duration, error) {
		if window {
			t.Error("approve=always offered a window")
		}
		return 0, nil
	}
	e.run(k, "true")
	e.run(k, "true")
	if n := e.phone.prompts.Load(); n != 2 {
		t.Fatalf("approve=always: want 2 prompts, got %d", n)
	}
	e.phone.answer = func(bool) (time.Duration, error) { return 0, errDenied }
	if _, err := e.run(k, "true"); err == nil {
		t.Fatal("denied login succeeded")
	}
}

func TestPty(t *testing.T) {
	e := newEnv(t)
	c, err := e.dial(e.key(`approve="never"`))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out, err := s.Output("tty; echo $TERM; stty size")
	if err != nil || !strings.HasPrefix(string(out), "/dev/pts/") || !strings.Contains(string(out), "xterm\r\n24 80") {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestMaxAge(t *testing.T) {
	e := newEnv(t)
	c, err := e.dial(e.key(`approve="never",max-age="1s"`))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s, _ := c.NewSession()
	s.Run("sleep 30")
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("connection lived %s past max-age 1s", d)
	}
}

func TestSFTP(t *testing.T) {
	e := newEnv(t)
	c, err := e.dial(e.key(`approve="never"`))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fc, err := sftp.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	path := filepath.Join(t.TempDir(), "f")
	f, err := fc.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("data"))
	f.Close()
	if got, _ := os.ReadFile(path); string(got) != "data" {
		t.Fatalf("got %q", got)
	}
}

func TestForwarding(t *testing.T) {
	e := newEnv(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.Copy(c, c)
			c.Close()
		}
	}()

	c, err := e.dial(e.key(`approve="never"`))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc, err := c.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(tc, "ping")
	buf := make([]byte, 4)
	io.ReadFull(tc, buf)
	if !bytes.Equal(buf, []byte("ping")) {
		t.Fatalf("got %q", buf)
	}

	c2, _ := e.dial(e.key(`approve="never",no-port-forwarding`))
	defer c2.Close()
	if _, err := c2.Dial("tcp", ln.Addr().String()); err == nil {
		t.Fatal("no-port-forwarding key could forward")
	}
}

func TestTailnetOnly(t *testing.T) {
	s := &server{tailnetOnly: true, whois: func(ip string) (peer, error) { return peer{id: "n1", name: "laptop", ip: ip}, nil }}
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"100.101.102.103:5000", true},
		{"[fd7a:115c:a1e0::1]:5000", true},
		{"192.168.1.5:5000", false},
		{"[::ffff:100.64.0.1]:5000", true},
	} {
		_, err := s.identify(fakeConn{addr: tc.addr})
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v, err=%v", tc.addr, tc.ok, err)
		}
	}
}

type fakeConn struct {
	net.Conn
	addr string
}

func (f fakeConn) RemoteAddr() net.Addr { a, _ := net.ResolveTCPAddr("tcp", f.addr); return a }
