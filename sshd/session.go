package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// acct is the identity commands run as.
type acct struct {
	name    string
	uid     uint32
	groups  []uint32
	home    string
	selinux string // context to switch to via runcon, if any
}

// Supplementary groups of `adb shell` (input log adb sdcard_rw sdcard_r
// ext_data_rw ext_obb_rw net_bt_admin net_bt inet net_bw_stats readproc uhid readtracefs).
var shellGroups = []uint32{1004, 1007, 1011, 1015, 1028, 1078, 1079, 3001, 3002, 3003, 3006, 3009, 3011, 3012}

func account(user, rootHome string) (acct, error) {
	switch user {
	case "root":
		if err := os.MkdirAll(rootHome, 0o700); err != nil {
			return acct{}, err
		}
		return acct{name: "root", uid: 0, home: rootHome}, nil
	case "shell":
		return acct{name: "shell", uid: 2000, groups: shellGroups, home: "/data/local/tmp", selinux: "u:r:shell:s0"}, nil
	}
	uid, err := strconv.ParseUint(user, 10, 32)
	if err != nil {
		return acct{}, fmt.Errorf("bad user %q", user)
	}
	return acct{name: user, uid: uint32(uid), home: "/"}, nil
}

// conn tracks one authenticated connection: its child processes (killed on
// disconnect) and session channels (told about the coming max-age cutoff).
type conn struct {
	*server
	sc   *ssh.ServerConn
	opts *keyOpts
	acct acct
	ctx  context.Context

	mu       sync.Mutex
	sessions map[ssh.Channel]bool
}

const maxAgeWarning = time.Minute

func (s *server) serveConn(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, o *keyOpts, a acct) {
	ctx, cancel := context.WithCancel(s.stopping)
	defer cancel()
	// On shutdown also close the connection, so no new sessions start.
	defer context.AfterFunc(ctx, func() { sc.Close() })()
	c := &conn{server: s, sc: sc, opts: o, acct: a, ctx: ctx, sessions: map[ssh.Channel]bool{}}

	if o.maxAge > maxAgeWarning {
		warn := time.AfterFunc(o.maxAge-maxAgeWarning, func() {
			c.notify(fmt.Sprintf("\r\nandroid-sshd: this connection closes in %s (max-age %s)\r\n", maxAgeWarning, o.maxAge))
		})
		defer warn.Stop()
	}
	cut := time.AfterFunc(o.maxAge, func() {
		log.Printf("%s: closing, max-age %s reached", sc.RemoteAddr(), o.maxAge)
		sc.Close()
	})
	defer cut.Stop()

	go ssh.DiscardRequests(reqs) // keepalives; remote forwarding (-R) is not supported
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go c.session(ch, creqs)
		case "direct-tcpip":
			if o.noForwarding {
				nc.Reject(ssh.Prohibited, "port forwarding is disabled for this key")
				continue
			}
			go c.forward(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (c *conn) notify(msg string) {
	c.mu.Lock()
	chans := make([]ssh.Channel, 0, len(c.sessions))
	for ch := range c.sessions {
		chans = append(chans, ch)
	}
	c.mu.Unlock()
	// Outside the lock and in parallel: a client that stopped reading mustn't
	// hold up the others.
	for _, ch := range chans {
		go io.WriteString(ch.Stderr(), msg)
	}
}

type ptyReq struct {
	Term       string
	Cols, Rows uint32
	W, H       uint32
	Modes      string
}

type winReq struct{ Cols, Rows, W, H uint32 }

func (c *conn) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	c.mu.Lock()
	c.sessions[ch] = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.sessions, ch)
		c.mu.Unlock()
		ch.Close()
	}()

	var pt *ptyReq
	var tty *os.File
	var hangup func()
	done := make(chan uint32, 1)
	started := false
	for {
		var req *ssh.Request
		select {
		case req = <-reqs:
		case status := <-done:
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			return
		}
		if req == nil { // channel closed by the client, e.g. a ControlMaster client exited
			if !started {
				return
			}
			hangup()
			if tty != nil {
				tty.Close() // ends the output copy even if background jobs hold the pty
			}
			reqs = nil
			continue
		}
		ok := false
		switch req.Type {
		case "pty-req":
			var p ptyReq
			if !started && ssh.Unmarshal(req.Payload, &p) == nil {
				pt, ok = &p, true
			}
		case "window-change":
			var w winReq
			if tty != nil && ssh.Unmarshal(req.Payload, &w) == nil {
				setSize(tty, w.Cols, w.Rows)
			}
		case "shell", "exec", "subsystem":
			if started {
				break
			}
			argv, err := c.command(req)
			if err != nil {
				io.WriteString(ch.Stderr(), err.Error()+"\r\n")
				break
			}
			tty, hangup, err = c.start(ch, argv, pt, done)
			if err != nil {
				log.Printf("%s: start %q: %v", c.sc.RemoteAddr(), argv, err)
				io.WriteString(ch.Stderr(), "android-sshd: "+err.Error()+"\r\n")
				break
			}
			started, ok = true, true
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
		if !started && (req.Type == "shell" || req.Type == "exec" || req.Type == "subsystem") {
			return
		}
	}
}

func (c *conn) command(req *ssh.Request) ([]string, error) {
	var argv []string
	switch req.Type {
	case "shell":
		argv = []string{c.shell, "-l"}
	case "exec":
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		argv = []string{c.shell, "-c", p.Command}
	case "subsystem":
		var p struct{ Name string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		if p.Name != "sftp" {
			return nil, fmt.Errorf("unsupported subsystem %q", p.Name)
		}
		argv = []string{c.self, "sftp"}
	}
	if c.acct.selinux != "" {
		// Domains like shell can only be entered through /system/bin/sh
		// (shell_exec), so transition there and exec the real command.
		argv = append([]string{"/system/bin/runcon", c.acct.selinux, "/system/bin/sh", "-c", `exec "$@"`, "sh"}, argv...)
	}
	return argv, nil
}

// start runs argv for the session and sends its exit status to done.
// It returns the pty master (if one was requested) and a func that ends the
// session's processes; disconnecting calls it too.
func (c *conn) start(ch ssh.Channel, argv []string, pt *ptyReq, done chan<- uint32) (*os.File, func(), error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = c.acct.home
	cmd.Env = c.env(pt)
	attr := &syscall.SysProcAttr{Setsid: true}
	if c.acct.uid != uint32(os.Getuid()) {
		attr.Credential = &syscall.Credential{Uid: c.acct.uid, Gid: c.acct.uid, Groups: c.acct.groups}
	}

	var tty *os.File
	exited := make(chan struct{})
	if pt != nil {
		master, err := c.startPty(cmd, attr, pt)
		if err != nil {
			return nil, nil, err
		}
		tty = master
		go io.Copy(master, ch)
		output := make(chan struct{})
		go func() { drain(ch, master, exited); close(output) }()
		go func() {
			status := exitStatus(cmd.Wait())
			close(exited)
			<-output // EIO once nothing holds the terminal, or quiet for a second (background jobs)
			master.Close()
			done <- status
		}()
	} else {
		cmd.SysProcAttr = attr
		// Our own pipes rather than cmd.Stdout = ch: exec's copier would be cut off
		// (dropping output) by WaitDelay, or hang without it on background jobs.
		outR, outW, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		errR, errW, err := os.Pipe()
		if err != nil {
			outR.Close()
			outW.Close()
			return nil, nil, err
		}
		cmd.Stdout, cmd.Stderr = outW, errW
		// Not cmd.Stdin = ch: Wait would block until the client closes stdin.
		stdin, err := cmd.StdinPipe()
		if err == nil {
			err = cmd.Start()
		}
		outW.Close()
		errW.Close()
		if err != nil {
			outR.Close()
			errR.Close()
			return nil, nil, err
		}
		go func() { io.Copy(stdin, ch); stdin.Close() }()
		var copies sync.WaitGroup
		copies.Go(func() { drain(ch, outR, exited) })
		copies.Go(func() { drain(ch.Stderr(), errR, exited) })
		go func() {
			status := exitStatus(cmd.Wait())
			close(exited)
			copies.Wait() // all output is sent before the exit status
			outR.Close()
			errR.Close()
			done <- status
		}()
	}

	c.procs.Add(1)
	go func() { <-exited; c.procs.Add(-1) }()

	// Signal the whole session (pgid = pid thanks to Setsid), but never after
	// it exited: the pid could belong to someone else by then.
	pid := cmd.Process.Pid
	hangup := func() {
		select {
		case <-exited:
			return
		default:
		}
		syscall.Kill(-pid, syscall.SIGHUP)
		go func() {
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				syscall.Kill(-pid, syscall.SIGKILL)
			}
		}()
	}
	stop := context.AfterFunc(c.ctx, hangup)
	go func() { <-exited; stop() }()
	return tty, hangup, nil
}

// startPty runs cmd on a new terminal owned by the session's user and returns
// the master, non-blocking so that closing it interrupts a pending read.
func (c *conn) startPty(cmd *exec.Cmd, attr *syscall.SysProcAttr, pt *ptyReq) (*os.File, error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	if err := os.Chown(tty.Name(), int(c.acct.uid), int(c.acct.uid)); err != nil && c.acct.uid != uint32(os.Getuid()) {
		ptmx.Close()
		return nil, err
	}
	// creack/pty leaves the master in blocking mode; swap in a pollable duplicate.
	fd, err := unix.Dup(int(ptmx.Fd()))
	ptmx.Close()
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	master := os.NewFile(uintptr(fd), "ptmx")
	setSize(master, pt.Cols, pt.Rows)
	attr.Setctty, attr.Ctty = true, 0
	cmd.SysProcAttr = attr
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, err
	}
	return master, nil
}

func setSize(master *os.File, cols, rows uint32) {
	if rc, err := master.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
		})
	}
}

func exitStatus(err error) uint32 {
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + uint32(ws.Signal())
		}
		return uint32(ee.ExitCode())
	}
	if err != nil {
		return 255
	}
	return 0
}

// drain copies a session's output pipe to the client, however slowly it reads.
// Once the process has exited, a pipe that stays silent for a second is given
// up on: a background job may hold it open forever.
func drain(w io.Writer, r *os.File, exited <-chan struct{}) {
	idle := func() { r.SetReadDeadline(time.Now().Add(time.Second)) }
	go func() { <-exited; idle() }()
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			select {
			case <-exited:
				idle()
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *conn) env(pt *ptyReq) []string {
	var env []string
	for _, kv := range c.baseEnv {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "HOME", k == "USER", k == "LOGNAME", k == "SHELL", k == "TERM", strings.HasPrefix(k, "SSH_"):
		default:
			env = append(env, kv)
		}
	}
	rh, rp, _ := net.SplitHostPort(c.sc.RemoteAddr().String())
	lh, lp, _ := net.SplitHostPort(c.sc.LocalAddr().String())
	env = append(env,
		"HOME="+c.acct.home, "USER="+c.acct.name, "LOGNAME="+c.acct.name, "SHELL="+c.shell,
		"SSH_CONNECTION="+strings.Join([]string{rh, rp, lh, lp}, " "),
		"SSH_CLIENT="+strings.Join([]string{rh, rp, lp}, " "),
	)
	if pt != nil {
		env = append(env, "TERM="+pt.Term)
	}
	return env
}

// forward handles `ssh -L`: connect from the phone to host:port.
func (c *conn) forward(nc ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	tc, err := d.DialContext(c.ctx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		tc.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	defer context.AfterFunc(c.ctx, func() { tc.Close(); ch.Close() })()
	// Each direction ends on its own (half-close); the forward ends when both have.
	var both sync.WaitGroup
	both.Go(func() { io.Copy(tc, ch); tc.(*net.TCPConn).CloseWrite() })
	both.Go(func() { io.Copy(ch, tc); ch.CloseWrite() })
	both.Wait()
	ch.Close()
	tc.Close()
}

// runSFTP is `android-sshd sftp`: an sftp server on stdio, started as the
// session's user so file access follows that user's permissions.
func runSFTP() {
	s, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{os.Stdin, os.Stdout})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Serve(); err != nil && err != io.EOF {
		log.Fatal(err)
	}
}
