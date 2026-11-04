package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// promptFunc asks the phone's owner to approve a login. window offers
// time-limited approvals; it returns how long the approval lasts (0 = this
// connection only) or an error if denied or unanswered before ctx ends.
type promptFunc func(ctx context.Context, title, text string, window bool) (time.Duration, error)

var errDenied = errors.New("denied on the phone")

// approver remembers approval windows per (key, peer) and coalesces
// concurrent prompts for the same pair into one notification.
type approver struct {
	prompt  promptFunc
	timeout time.Duration

	mu      sync.Mutex
	until   map[string]time.Time
	pending map[string]*pendingPrompt
}

type pendingPrompt struct {
	done chan struct{}
	err  error
}

func newApprover(p promptFunc, timeout time.Duration) *approver {
	return &approver{prompt: p, timeout: timeout, until: map[string]time.Time{}, pending: map[string]*pendingPrompt{}}
}

// approve returns nil once the login identified by id (key fingerprint +
// peer) is approved under mode. wait is called right before blocking on a
// prompt, so the client can be told to look at the phone.
func (a *approver) approve(mode, id, title, text string, wait func()) error {
	if mode == approveNever {
		return nil
	}
	if mode == approveAlways {
		wait()
		_, err := a.ask(title, text, false)
		return err
	}

	a.mu.Lock()
	if time.Now().Before(a.until[id]) {
		a.mu.Unlock()
		return nil
	}
	p, ok := a.pending[id]
	if !ok {
		p = &pendingPrompt{done: make(chan struct{})}
		a.pending[id] = p
	}
	a.mu.Unlock()

	wait()
	if ok {
		<-p.done
		return p.err
	}
	d, err := a.ask(title, text, true)
	a.mu.Lock()
	if err == nil && d > 0 {
		a.until[id] = time.Now().Add(d)
	}
	delete(a.pending, id)
	a.mu.Unlock()
	p.err = err
	close(p.done)
	return err
}

func (a *approver) ask(title, text string, window bool) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	d, err := a.prompt(ctx, title, text, window)
	if errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("no answer on the phone within %s", a.timeout)
	}
	return d, err
}

// The companion app (app/) shows the notification and writes the answer to
// its private files dir, which only it and root can write.
const (
	appPkg      = "io.github.aethermagee.sshd"
	appAnswers  = "/data/user/0/" + appPkg + "/files"
	includeStop = "32" // FLAG_INCLUDE_STOPPED_PACKAGES: deliver even if the app never ran
)

func appPrompt(ctx context.Context, title, text string, window bool) (time.Duration, error) {
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	secs := 60
	if dl, ok := ctx.Deadline(); ok {
		secs = int(time.Until(dl).Seconds())
	}
	if err := broadcast(ctx, "PROMPT", id, "--es", "title", title, "--es", "text", text,
		"--ei", "timeout", strconv.Itoa(secs), "--ez", "window", strconv.FormatBool(window)); err != nil {
		return 0, err
	}
	defer func() {
		// Dismiss the notification if we stopped waiting first; a no-op otherwise.
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		broadcast(cctx, "CANCEL", id)
	}()

	path := filepath.Join(appAnswers, id)
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-t.C:
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		os.Remove(path)
		// "allow <seconds>" or "deny"
		verb, arg, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
		if verb != "allow" {
			return 0, errDenied
		}
		n, _ := strconv.Atoi(arg)
		return time.Duration(n) * time.Second, nil
	}
}

func broadcast(ctx context.Context, action, id string, extras ...string) error {
	args := append([]string{"broadcast", "--user", "0", "-f", includeStop,
		"-n", appPkg + "/.PromptReceiver", "-a", appPkg + "." + action, "--es", "id", id}, extras...)
	out, err := exec.CommandContext(ctx, "am", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("am broadcast %s: %v: %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// peer describes the other end of a connection.
type peer struct {
	id   string // stable identity used for approval windows
	name string // shown in prompts and matched by from-node
	user string // tailnet login, if known
	ip   string
}

func (p peer) String() string {
	if p.user != "" {
		return fmt.Sprintf("%s (%s, %s)", p.name, p.user, p.ip)
	}
	if p.name != p.ip {
		return fmt.Sprintf("%s (%s)", p.name, p.ip)
	}
	return p.ip
}

// tailscaleWhois identifies a tailnet IP via the tailscale CLI.
func tailscaleWhois(ip string) (peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tailscale", "whois", "--json", ip).Output()
	if err != nil {
		return peer{}, fmt.Errorf("tailscale whois %s: %w", ip, err)
	}
	var w struct {
		Node struct {
			StableID     string
			ComputedName string
		}
		UserProfile struct{ LoginName string }
	}
	if err := json.Unmarshal(out, &w); err != nil || w.Node.StableID == "" {
		return peer{}, fmt.Errorf("tailscale whois %s: unexpected output", ip)
	}
	return peer{id: w.Node.StableID, name: w.Node.ComputedName, user: w.UserProfile.LoginName, ip: ip}, nil
}
