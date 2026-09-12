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
		// ufw allow from <ip> to any port <port> proto <proto> comment "grant_<grantID>"
		args := []string{"allow", "from", ip.String(), "to", "any", "port", strconv.Itoa(p.Port), "proto", strings.ToLower(p.Protocol), "comment", fmt.Sprintf("grant_%d", grantID)}
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
		args := []string{"delete", "allow", "from", ip.String(), "to", "any", "port", strconv.Itoa(p.Port), "proto", strings.ToLower(p.Protocol)}
		u.detector.RunCommand(ctx, "ufw", args...)
	}
	return nil
}

func (u *UfwAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	// In UFW, delete existing funnel rules and re-apply
	rules, _ := u.ListActiveRules(ctx)
	for _, r := range rules {
		args := []string{"delete", "allow", "from", r.IP, "to", "any", "port", strconv.Itoa(r.Port), "proto", strings.ToLower(r.Protocol)}
		u.detector.RunCommand(ctx, "ufw", args...)
	}

	for _, g := range activeGrants {
		for _, p := range g.Ports {
			args := []string{"allow", "from", g.IP.String(), "to", "any", "port", strconv.Itoa(p.Port), "proto", strings.ToLower(p.Protocol), "comment", "funnel_active"}
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

	var rules []ActiveRule
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "ALLOW IN") {
			continue
		}
		// Parsing basic UFW numbered rule line
		// e.g. [ 1] 22/tcp ALLOW IN 203.0.113.1 # grant_1
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		target := parts[1] // e.g. 22/tcp
		fromIP := parts[4] // IP

		targetParts := strings.Split(target, "/")
		if len(targetParts) == 2 {
			port, _ := strconv.Atoi(targetParts[0])
			if port > 0 {
				rules = append(rules, ActiveRule{
					Backend:  "ufw",
					IP:       fromIP,
					Protocol: targetParts[1],
					Port:     port,
				})
			}
		}
	}
	return rules, nil
}
