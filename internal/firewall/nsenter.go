package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// NetNSDetector detects whether the current process is in a containerized network namespace.
type NetNSDetector struct {
	override string // "auto", "true", "false"
}

// NewNetNSDetector creates a new NetNSDetector.
func NewNetNSDetector(override string) *NetNSDetector {
	return &NetNSDetector{override: strings.ToLower(override)}
}

// ShouldUseNsenter determines whether commands targeting the host network namespace need nsenter.
func (d *NetNSDetector) ShouldUseNsenter() bool {
	if d.override == "true" {
		return true
	}
	if d.override == "false" {
		return false
	}

	// Auto-detection
	selfStat, err1 := os.Stat("/proc/self/ns/net")
	initStat, err2 := os.Stat("/proc/1/ns/net")
	if err1 != nil || err2 != nil {
		return false
	}

	selfSys, ok1 := selfStat.Sys().(*syscall.Stat_t)
	initSys, ok2 := initStat.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return false
	}

	// If inodes differ, we are in a container network namespace (e.g. docker bridge)
	if selfSys.Ino != initSys.Ino {
		return true
	}

	return false
}

// WrapCommand prepends nsenter --net=/proc/1/ns/net if nsenter is needed.
func (d *NetNSDetector) WrapCommand(ctx context.Context, cmd string, args ...string) *exec.Cmd {
	if d.ShouldUseNsenter() {
		newArgs := append([]string{"--net=/proc/1/ns/net", cmd}, args...)
		return exec.CommandContext(ctx, "nsenter", newArgs...)
	}
	return exec.CommandContext(ctx, cmd, args...)
}

// RunCommand executes a command with nsenter wrapping if applicable.
func (d *NetNSDetector) RunCommand(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	c := d.WrapCommand(ctx, cmd, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("command '%s %s' failed: %w (output: %s)", cmd, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
