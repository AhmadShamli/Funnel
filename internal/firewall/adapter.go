package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

// ActiveGrantRules represents a source IP and the aggregate set of active ports to allow.
type ActiveGrantRules struct {
	IP    netip.Addr
	Ports []models.PortRule
}

// ActiveRule represents a currently observed firewall rule.
type ActiveRule struct {
	Backend  string            `json:"backend"`
	IP       string            `json:"ip"`
	Protocol string            `json:"protocol"`
	Port     int               `json:"port"`
	Comment  string            `json:"comment,omitempty"`
	Handle   string            `json:"handle,omitempty"`
}

// FirewallAdapter abstracts Linux firewall subsystems.
type FirewallAdapter interface {
	Name() string
	Detect(ctx context.Context) (bool, error)
	Validate(ctx context.Context) error
	ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error
	RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error
	SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error
	ListActiveRules(ctx context.Context) ([]ActiveRule, error)
}

// BackendInfo describes firewall engine status.
type BackendInfo struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	Error     string `json:"error,omitempty"`
}

func RuleKey(ip netip.Addr, proto string, port int) string {
	return fmt.Sprintf("%s_%s_%d", ip.String(), proto, port)
}
