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

// UfwAdapter manages firewall rules using UFW.
type UfwAdapter struct {
	mu       sync.Mutex
	detector *NetNSDetector
}

func NewUfwAdapter(detector *NetNSDetector) *UfwAdapter {
	return &UfwAdapter{detector: detector}
}

func (u *UfwAdapter) Name() string {
	return "ufw"
}

func (u *UfwAdapter) Detect(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("ufw")
	if err != nil {
		return false, nil
	}
	out, err := u.detector.RunCommand(ctx, "ufw", "status")
	if err != nil {
		return false, nil
	}
	return strings.Contains(strings.ToLower(string(out)), "status:"), nil
}

func (u *UfwAdapter) Validate(ctx context.Context) error {
	detected, err := u.Detect(ctx)
	if err != nil || !detected {
		return fmt.Errorf("ufw is not active or installed")
	}
	return nil
}

func (u *UfwAdapter) ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, p := range ports {
		// ufw allow proto <proto> from <ip> to any port <port> comment "grant_<grantID>"
		args := []string{"allow", "proto", strings.ToLower(p.Protocol), "from", ip.String(), "to", "any", "port", strconv.Itoa(p.Port), "comment", fmt.Sprintf("grant_%d", grantID)}
		if _, err := u.detector.RunCommand(ctx, "ufw", args...); err != nil {
			return err
		}
	}
	return nil
}

func (u *UfwAdapter) RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, p := range ports {
		args := []string{"delete", "allow", "proto", strings.ToLower(p.Protocol), "from", ip.String(), "to", "any", "port", strconv.Itoa(p.Port)}
		u.detector.RunCommand(ctx, "ufw", args...)
	}
	return nil
}

func (u *UfwAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// In UFW, only delete existing funnel-managed rules (with comment grant_ or funnel_)
	rules, _ := u.ListActiveRules(ctx)
	for _, r := range rules {
		if strings.HasPrefix(r.Comment, "grant_") || strings.HasPrefix(r.Comment, "funnel") {
			args := []string{"delete", "allow", "proto", strings.ToLower(r.Protocol), "from", r.IP, "to", "any", "port", strconv.Itoa(r.Port)}
			u.detector.RunCommand(ctx, "ufw", args...)
		}
	}

	for _, g := range activeGrants {
		for _, p := range g.Ports {
			args := []string{"allow", "proto", strings.ToLower(p.Protocol), "from", g.IP.String(), "to", "any", "port", strconv.Itoa(p.Port), "comment", "funnel_active"}
			u.detector.RunCommand(ctx, "ufw", args...)
		}
	}
	return nil
}

func (u *UfwAdapter) ListActiveRules(ctx context.Context) ([]ActiveRule, error) {
	out, err := u.detector.RunCommand(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseUfwStatusLines(string(out)), nil
}

func parseUfwStatusLines(out string) []ActiveRule {
	var rules []ActiveRule
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "ALLOW IN") {
			continue
		}
		// Strip the "[ 1]" or "[10]" prefix
		idx := strings.Index(line, "]")
		if idx == -1 {
			continue
		}
		rest := strings.TrimSpace(line[idx+1:])
		parts := strings.Fields(rest)
		// Expected format: <target> ALLOW IN <fromIP> [# <comment>]
		if len(parts) < 4 {
			continue
		}
		target := parts[0] // e.g. 22/tcp or 19132/udp
		fromIP := parts[3] // IP or Anywhere

		comment := ""
		if hashIdx := strings.Index(rest, "#"); hashIdx != -1 {
			comment = strings.TrimSpace(rest[hashIdx+1:])
		}

		targetParts := strings.Split(target, "/")
		if len(targetParts) == 2 {
			port, _ := strconv.Atoi(targetParts[0])
			if port > 0 {
				rules = append(rules, ActiveRule{
					Backend:  "ufw",
					IP:       fromIP,
					Protocol: targetParts[1],
					Port:     port,
					Comment:  comment,
				})
			}
		}
	}
	return rules
}
