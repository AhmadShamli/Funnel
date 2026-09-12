package firewall

import (
	"bytes"
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

// NftablesAdapter manages host firewall rules using the modern nftables engine.
type NftablesAdapter struct {
	mu       sync.Mutex
	detector *NetNSDetector
}

// NewNftablesAdapter creates an nftables adapter.
func NewNftablesAdapter(detector *NetNSDetector) *NftablesAdapter {
	return &NftablesAdapter{
		detector: detector,
	}
}

func (n *NftablesAdapter) Name() string {
	return "nftables"
}

func (n *NftablesAdapter) Detect(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("nft")
	if err != nil {
		return false, nil
	}
	out, err := n.detector.RunCommand(ctx, "nft", "--version")
	if err != nil {
		return false, nil
	}
	return strings.Contains(strings.ToLower(string(out)), "nftables"), nil
}

func (n *NftablesAdapter) Validate(ctx context.Context) error {
	detected, err := n.Detect(ctx)
	if err != nil {
		return err
	}
	if !detected {
		return fmt.Errorf("nft command not found in system path")
	}

	// Ensure base table and chain exist
	return n.initTable(ctx)
}

func (n *NftablesAdapter) initTable(ctx context.Context) error {
	script := `
table inet funnel {
    chain input {
        type filter hook input priority -10; policy accept;
    }
}
`
	cmd := n.detector.WrapCommand(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize table inet funnel: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *NftablesAdapter) ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.initTable(ctx); err != nil {
		return err
	}

	for _, p := range ports {
		var saddrField string
		if ip.Is6() {
			saddrField = "ip6 saddr"
		} else {
			saddrField = "ip saddr"
		}

		proto := strings.ToLower(p.Protocol)
		comment := fmt.Sprintf("grant_%d", grantID)
		rule := fmt.Sprintf("table inet funnel { chain input { %s %s %s dport %d accept comment \"%s\"; } }",
			saddrField, ip.String(), proto, p.Port, comment)

		cmd := n.detector.WrapCommand(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(rule)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to apply nft rule: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (n *NftablesAdapter) RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// In nftables, revoking specific rules can be done by parsing handles or via SyncGrants.
	// We list rules and delete by handle matching the IP and port.
	rules, err := n.ListActiveRules(ctx)
	if err != nil {
		return err
	}

	for _, p := range ports {
		for _, r := range rules {
			if r.IP == ip.String() && strings.EqualFold(r.Protocol, p.Protocol) && r.Port == p.Port {
				if r.Handle != "" {
					_, _ = n.detector.RunCommand(ctx, "nft", "delete", "rule", "inet", "funnel", "input", "handle", r.Handle)
				}
			}
		}
	}
	return nil
}

func (n *NftablesAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var buf bytes.Buffer
	buf.WriteString("table inet funnel {\n")
	buf.WriteString("    chain input {\n")
	buf.WriteString("        type filter hook input priority -10; policy accept;\n")
	buf.WriteString("    }\n")
	buf.WriteString("}\n")
	buf.WriteString("flush chain inet funnel input\n")

	for _, g := range activeGrants {
		saddrField := "ip saddr"
		if g.IP.Is6() {
			saddrField = "ip6 saddr"
		}
		for _, p := range g.Ports {
			proto := strings.ToLower(p.Protocol)
			buf.WriteString(fmt.Sprintf("add rule inet funnel input %s %s %s dport %d accept comment \"funnel_active\"\n",
				saddrField, g.IP.String(), proto, p.Port))
		}
	}

	cmd := n.detector.WrapCommand(ctx, "nft", "-f", "-")
	cmd.Stdin = &buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft sync failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *NftablesAdapter) ListActiveRules(ctx context.Context) ([]ActiveRule, error) {
	out, err := n.detector.RunCommand(ctx, "nft", "-a", "list", "chain", "inet", "funnel", "input")
	if err != nil {
		// If table doesn't exist yet, return empty
		return nil, nil
	}

	var rules []ActiveRule
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "dport") || !strings.Contains(line, "accept") {
			continue
		}

		var rule ActiveRule
		rule.Backend = "nftables"
		tokens := strings.Fields(line)
		for i, tok := range tokens {
			if (tok == "saddr") && i+1 < len(tokens) {
				rule.IP = tokens[i+1]
			}
			if (tok == "tcp" || tok == "udp") && i+2 < len(tokens) && tokens[i+1] == "dport" {
				rule.Protocol = tok
				p, _ := strconv.Atoi(tokens[i+2])
				rule.Port = p
			}
			if tok == "comment" && i+1 < len(tokens) {
				rule.Comment = strings.Trim(tokens[i+1], "\";")
			}
			if tok == "handle" && i+1 < len(tokens) {
				rule.Handle = strings.Trim(tokens[i+1], "\";")
			}
		}

		if rule.IP != "" && rule.Port > 0 {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}
