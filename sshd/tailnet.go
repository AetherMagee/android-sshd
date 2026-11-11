package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

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

// tailscaleBin finds the tailscale CLI: on PATH, or in android-tailscaled's
// module dir when the root manager doesn't mount modules into /system
// (KernelSU without a metamodule, or before the first reboot).
func tailscaleBin() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	for _, p := range []string{
		"/data/adb/modules_update/android-tailscaled/system/bin/tailscale",
		"/data/adb/modules/android-tailscaled/system/bin/tailscale",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "tailscale"
}

// tailscaleWhois identifies a tailnet IP via the tailscale CLI.
func tailscaleWhois(ip string) (peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tailscaleBin(), "whois", "--json", ip).Output()
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
