package firewall

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

// MockFirewallAdapter provides an in-memory firewall adapter for non-root testing and CI/CD.
type MockFirewallAdapter struct {
	mu          sync.RWMutex
	name        string
	rules       map[string]ActiveRule // key: RuleKey
	applyCalls  int
	revokeCalls int
	syncCalls   int
	failNext    error
}

// NewMockFirewallAdapter initializes a new mock firewall adapter.
func NewMockFirewallAdapter() *MockFirewallAdapter {
	return &MockFirewallAdapter{
		name:  "mock",
		rules: make(map[string]ActiveRule),
	}
}

func (m *MockFirewallAdapter) Name() string {
	return m.name
}

func (m *MockFirewallAdapter) Detect(ctx context.Context) (bool, error) {
	return true, nil
}

func (m *MockFirewallAdapter) Validate(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.failNext
}

func (m *MockFirewallAdapter) SetFailNext(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext = err
}

func (m *MockFirewallAdapter) ApplyGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil
		return err
	}

	m.applyCalls++
	for _, p := range ports {
		k := RuleKey(ip, p.Protocol, p.Port)
		m.rules[k] = ActiveRule{
			Backend:  "mock",
			IP:       ip.String(),
			Protocol: p.Protocol,
			Port:     p.Port,
		}
	}
	return nil
}

func (m *MockFirewallAdapter) RevokeGrant(ctx context.Context, grantID int64, ip netip.Addr, ports []models.PortRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil
		return err
	}

	m.revokeCalls++
	for _, p := range ports {
		k := RuleKey(ip, p.Protocol, p.Port)
		delete(m.rules, k)
	}
	return nil
}

func (m *MockFirewallAdapter) SyncGrants(ctx context.Context, activeGrants []ActiveGrantRules) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil
		return err
	}

	m.syncCalls++
	m.rules = make(map[string]ActiveRule)
	for _, g := range activeGrants {
		for _, p := range g.Ports {
			k := RuleKey(g.IP, p.Protocol, p.Port)
			m.rules[k] = ActiveRule{
				Backend:  "mock",
				IP:       g.IP.String(),
				Protocol: p.Protocol,
				Port:     p.Port,
			}
		}
	}
	return nil
}

func (m *MockFirewallAdapter) ListActiveRules(ctx context.Context) ([]ActiveRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []ActiveRule
	for _, r := range m.rules {
		result = append(result, r)
	}
	return result, nil
}

func (m *MockFirewallAdapter) HasRule(ip netip.Addr, proto string, port int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := RuleKey(ip, proto, port)
	_, exists := m.rules[k]
	return exists
}

func (m *MockFirewallAdapter) TotalRules() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}
