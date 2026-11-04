// android-sshd: a small SSH server for rooted Android. Public-key auth only,
// per-key privilege (root/shell/uid), optional approval on the phone through
// the companion app, and a hard cap on connection age.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type server struct {
	keysPath    string
	tailnetOnly bool
	shell       string
	rootHome    string
	self        string // this binary, re-executed as the sftp server
	hostKey     ssh.Signer
	approver    *approver
	whois       func(ip string) (peer, error)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "sftp":
			runSFTP()
			return
		case "keys":
			if err := runKeys(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	dir := flag.String("dir", "/data/adb/sshd", "state dir: authorized_keys, host key, root's home")
	addr := flag.String("listen", ":22", "listen address")
	tailnetOnly := flag.Bool("tailnet-only", true, "accept only connections from tailnet peers (identified with tailscale whois)")
	timeout := flag.Duration("prompt-timeout", time.Minute, "how long to wait for an answer on the phone")
	shell := flag.String("shell", "/system/bin/sh", "login shell")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	hostKey, err := loadHostKey(*dir + "/ssh_host_ed25519_key")
	if err != nil {
		log.Fatal(err)
	}
	// Non-root sessions can't reach the module dir (/data/adb is 0700); use
	// the copy the root manager mounts into /system/bin, present after a reboot.
	self := "/system/bin/android-sshd"
	if _, err := os.Stat(self); err != nil {
		if self, err = os.Executable(); err != nil {
			log.Fatal(err)
		}
	}
	s := &server{
		keysPath:    *dir + "/authorized_keys",
		tailnetOnly: *tailnetOnly,
		shell:       *shell,
		rootHome:    *dir + "/home",
		self:        self,
		hostKey:     hostKey,
		approver:    newApprover(appPrompt, *timeout),
		whois:       tailscaleWhois,
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (tailnet-only=%v), host key %s", ln.Addr(), s.tailnetOnly, ssh.FingerprintSHA256(hostKey.PublicKey()))
	s.serve(ln)
}

func (s *server) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Print(err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

var tailnetRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

func isTailnet(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range tailnetRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// identify resolves the remote end. In tailnet-only mode the address must be
// a tailnet peer known to tailscaled; a LAN host can't complete a TCP
// handshake with a spoofed 100.x source, since replies route via tailscale0.
func (s *server) identify(c net.Conn) (peer, error) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return peer{}, err
	}
	ip := ap.Addr().Unmap()
	if isTailnet(ip) {
		p, err := s.whois(ip.String())
		if err == nil || s.tailnetOnly {
			return p, err
		}
	} else if s.tailnetOnly {
		return peer{}, fmt.Errorf("%s is not a tailnet address", ip)
	}
	return peer{id: ip.String(), name: ip.String(), ip: ip.String()}, nil
}

func (s *server) handle(c net.Conn) {
	defer c.Close()
	from, err := s.identify(c)
	if err != nil {
		log.Printf("%s: rejected: %v", c.RemoteAddr(), err)
		return
	}

	type offered struct {
		opts    *keyOpts
		comment string
	}
	keys := map[string]offered{} // by fingerprint, for keys offered on this connection
	var preAuth ssh.ServerPreAuthConn
	cfg := &ssh.ServerConfig{
		ServerVersion:       "SSH-2.0-android-sshd",
		PreAuthConnCallback: func(c ssh.ServerPreAuthConn) { preAuth = c },
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			o, comment, err := findKey(s.keysPath, key)
			if err != nil {
				log.Printf("%s: %v", from, err)
				return nil, err
			}
			if o == nil {
				return nil, errors.New("unknown key")
			}
			if o.fromNode != "" && !strings.EqualFold(o.fromNode, from.name) {
				return nil, fmt.Errorf("key %q only allowed from %s", comment, o.fromNode)
			}
			keys[fp] = offered{o, comment}
			return &ssh.Permissions{Extensions: map[string]string{"fp": fp}}, nil
		},
		// Runs only after the client proved it holds the key, so a stranger
		// who knows a public key can't trigger prompts.
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			fp := perms.Extensions["fp"]
			k := keys[fp]
			o := k.opts
			title := fmt.Sprintf("SSH login as %s", o.user)
			text := fmt.Sprintf("From %s\nKey %s %s", from, k.comment, fp)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			err := s.approver.approve(o.approve, fp+"|"+from.id, title, text, func() {
				preAuth.SendAuthBanner(fmt.Sprintf("android-sshd: approve this login on the phone (%s)...\n", s.approver.timeout))
				wg.Go(func() { authKeepalive(preAuth, stop) })
			})
			close(stop)
			wg.Wait() // no banners after auth completes
			if err != nil {
				log.Printf("%s: key %q: %v", from, k.comment, err)
				return nil, err
			}
			return perms, nil
		},
	}
	cfg.AddHostKey(s.hostKey)

	// Bounds the handshake, including the wait for an answer on the phone.
	c.SetDeadline(time.Now().Add(s.approver.timeout + 30*time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		log.Printf("%s: %v", from, err)
		return
	}
	c.SetDeadline(time.Time{})
	k := keys[sc.Permissions.Extensions["fp"]]
	o := k.opts
	acct, err := account(o.user, s.rootHome)
	if err != nil {
		log.Printf("%s: %v", from, err)
		sc.Close()
		return
	}
	log.Printf("%s: logged in as %s with key %q (max-age %s)", from, o.user, k.comment, o.maxAge)
	s.serveConn(sc, chans, reqs, o, acct)
	log.Printf("%s: disconnected", from)
}

// authKeepalive sends empty banners while auth waits on the phone. OpenSSH
// prints nothing for them, but they keep clients with a short
// ServerAliveInterval (which also bounds auth) from timing out.
func authKeepalive(c ssh.ServerPreAuthConn, stop <-chan struct{}) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.SendAuthBanner("")
		}
	}
}

func loadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(block)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}
