package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

// IptablesAdapter manages host firewall rules using iptables / ip6tables.
type IptablesAdapter struct {
	mu       sync.Mutex
	detector *NetNSDetector
}

func NewIptablesAdapter(detector *NetNSDetector) *IptablesAdapter {
	return &IptablesAdapter{detector: detector}
}

func (a *IptablesAdapter) Name() string {
	return "iptables"
}

func (a *IptablesAdapter) Detect(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("iptables")
	return err == nil, nil
}

func (a *IptablesAdapter) Validate(ctx context.Context) error {
	detected, _ := a.Detect(ctx)
	if !detected {
		return fmt.Errorf("iptables not found in path")
	}
	return a.initChains(ctx)
}

func (a *IptablesAdapter) initChains(ctx context.Context) error {
	for _, bin := range []string{"iptables", "ip6tables"} {
		// Check if binary exists
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		// Create FUNNEL_INPUT chain if it doesn't exist
		_, _ = a.detector.RunCommand(ctx, bin, "-N", "FUNNEL_INPUT")
		// Ensure jump from INPUT exists
		if _, err := a.detector.RunCommand(ctx, bin, "-C", "INPUT", "-j", "FUNNEL_INPUT"); err != nil {
			if out, err := a.detector.RunCommand(ctx, bin, "-I", "INPUT", "1", "-j", "FUNNEL_INPUT"); err != nil {
				return fmt.Errorf("failed to configure %s jump rule: %w (output: %s)", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (a *IptablesAdapter) ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	bin := "iptables"
	if ip.Is6() {
		bin = "ip6tables"
	}

	for _, p := range ports {
		args := []string{
			"-A", "FUNNEL_INPUT",
			"-s", ip.String(),
			"-p", strings.ToLower(p.Protocol),
			"--dport", strconv.Itoa(p.Port),
			"-m", "comment", "--comment", fmt.Sprintf("grant_%d", grantID),
			"-j", "ACCEPT",
		}
		if _, err := a.detector.RunCommand(ctx, bin, args...); err != nil {
			return err
		}
	}
	return nil
}

func (a *IptablesAdapter) RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	bin := "iptables"
	if ip.Is6() {
		bin = "ip6tables"
	}

	for _, p := range ports {
		argsWithComment := []string{
			"-D", "FUNNEL_INPUT",
			"-s", ip.String(),
			"-p", strings.ToLower(p.Protocol),
			"--dport", strconv.Itoa(p.Port),
			"-m", "comment", "--comment", fmt.Sprintf("grant_%d", grantID),
			"-j", "ACCEPT",
		}
		if _, err := a.detector.RunCommand(ctx, bin, argsWithComment...); err != nil {
			argsPlain := []string{
				"-D", "FUNNEL_INPUT",
				"-s", ip.String(),
				"-p", strings.ToLower(p.Protocol),
				"--dport", strconv.Itoa(p.Port),
				"-j", "ACCEPT",
			}
			a.detector.RunCommand(ctx, bin, argsPlain...)
		}
	}
	return nil
}

func (a *IptablesAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.initChains(ctx); err != nil {
		return err
	}

	for _, bin := range []string{"iptables", "ip6tables"} {
		a.detector.RunCommand(ctx, bin, "-F", "FUNNEL_INPUT")
	}

	for _, g := range activeGrants {
		bin := "iptables"
		if g.IP.Is6() {
			bin = "ip6tables"
		}
		for _, p := range g.Ports {
			args := []string{
				"-A", "FUNNEL_INPUT",
				"-s", g.IP.String(),
				"-p", strings.ToLower(p.Protocol),
				"--dport", strconv.Itoa(p.Port),
				"-m", "comment", "--comment", "funnel_active",
				"-j", "ACCEPT",
			}
			a.detector.RunCommand(ctx, bin, args...)
		}
	}
	return nil
}

func (a *IptablesAdapter) ListActiveRules(ctx context.Context) ([]ActiveRule, error) {
	var rules []ActiveRule
	for _, bin := range []string{"iptables", "ip6tables"} {
		out, err := a.detector.RunCommand(ctx, bin, "-S", "FUNNEL_INPUT")
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "-A FUNNEL_INPUT") {
				continue
			}
			var r ActiveRule
			r.Backend = bin
			tokens := strings.Fields(line)
			for i, tok := range tokens {
				if tok == "-s" && i+1 < len(tokens) {
					r.IP = strings.TrimSuffix(strings.TrimSuffix(tokens[i+1], "/32"), "/128")
				}
				if tok == "-p" && i+1 < len(tokens) {
					r.Protocol = tok
				}
				if tok == "--dport" && i+1 < len(tokens) {
					p, _ := strconv.Atoi(tokens[i+1])
					r.Port = p
				}
			}
			if r.IP != "" && r.Port > 0 {
				rules = append(rules, r)
			}
		}
	}
	return rules, nil
}
