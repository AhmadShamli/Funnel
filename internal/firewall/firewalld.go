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

// FirewalldAdapter manages rules using firewalld (firewall-cmd).
type FirewalldAdapter struct {
	mu       sync.Mutex
	detector *NetNSDetector
}

func NewFirewalldAdapter(detector *NetNSDetector) *FirewalldAdapter {
	return &FirewalldAdapter{detector: detector}
}

func (f *FirewalldAdapter) Name() string {
	return "firewalld"
}

func (f *FirewalldAdapter) Detect(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("firewall-cmd")
	if err != nil {
		return false, nil
	}
	out, err := f.detector.RunCommand(ctx, "firewall-cmd", "--state")
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(out)) == "running", nil
}

func (f *FirewalldAdapter) Validate(ctx context.Context) error {
	detected, err := f.Detect(ctx)
	if err != nil || !detected {
		return fmt.Errorf("firewalld is not active or running")
	}
	return nil
}

func (f *FirewalldAdapter) buildRichRule(ip netip.Addr, proto string, port int) string {
	family := "ipv4"
	if ip.Is6() {
		family = "ipv6"
	}
	return fmt.Sprintf("rule family=\"%s\" source address=\"%s\" port port=\"%d\" protocol=\"%s\" accept",
		family, ip.String(), port, strings.ToLower(proto))
}

func (f *FirewalldAdapter) ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, p := range ports {
		richRule := f.buildRichRule(ip, p.Protocol, p.Port)
		args := []string{"--add-rich-rule", richRule}
		if duration > 0 {
			args = append(args, fmt.Sprintf("--timeout=%ds", int(duration.Seconds())))
		}
		if _, err := f.detector.RunCommand(ctx, "firewall-cmd", args...); err != nil {
			return err
		}
	}
	return nil
}

func (f *FirewalldAdapter) RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, p := range ports {
		richRule := f.buildRichRule(ip, p.Protocol, p.Port)
		f.detector.RunCommand(ctx, "firewall-cmd", "--remove-rich-rule", richRule)
	}
	return nil
}

func (f *FirewalldAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// In firewalld, reload zone or clear existing rich rules
	rules, _ := f.ListActiveRules(ctx)
	for _, r := range rules {
		addr, err := netip.ParseAddr(r.IP)
		if err == nil {
			richRule := f.buildRichRule(addr, r.Protocol, r.Port)
			f.detector.RunCommand(ctx, "firewall-cmd", "--remove-rich-rule", richRule)
		}
	}

	for _, g := range activeGrants {
		for _, p := range g.Ports {
			richRule := f.buildRichRule(g.IP, p.Protocol, p.Port)
			f.detector.RunCommand(ctx, "firewall-cmd", "--add-rich-rule", richRule)
		}
	}
	return nil
}

func (f *FirewalldAdapter) ListActiveRules(ctx context.Context) ([]ActiveRule, error) {
	out, err := f.detector.RunCommand(ctx, "firewall-cmd", "--list-rich-rules")
	if err != nil {
		return nil, err
	}

	var rules []ActiveRule
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "accept") {
			continue
		}
		// rule family="..." source address="..." port port="..." protocol="..." accept
		var r ActiveRule
		r.Backend = "firewalld"
		fields := strings.Fields(line)
		for _, field := range fields {
			if strings.HasPrefix(field, "source address=") {
				r.IP = strings.Trim(strings.TrimPrefix(field, "source address="), "\"")
			}
			if strings.HasPrefix(field, "port=") {
				p, _ := strconv.Atoi(strings.Trim(strings.TrimPrefix(field, "port="), "\""))
				r.Port = p
			}
			if strings.HasPrefix(field, "protocol=") {
				r.Protocol = strings.Trim(strings.TrimPrefix(field, "protocol="), "\"")
			}
		}
		if r.IP != "" && r.Port > 0 {
			rules = append(rules, r)
		}
	}
	return rules, nil
}
