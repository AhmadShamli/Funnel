package firewall

import (
	"context"
	"strings"
)

// Factory holds all initialized firewall adapters and selects the active one.
type Factory struct {
	detector *NetNSDetector
	adapters map[string]FirewallAdapter
	order    []string
}

// NewFactory initializes the adapter factory.
func NewFactory(useNsenter string) *Factory {
	detector := NewNetNSDetector(useNsenter)
	adapters := map[string]FirewallAdapter{
		"mock":      NewMockFirewallAdapter(),
		"nftables":  NewNftablesAdapter(detector),
		"firewalld": NewFirewalldAdapter(detector),
		"ufw":       NewUfwAdapter(detector),
		"iptables":  NewIptablesAdapter(detector),
	}
	return &Factory{
		detector: detector,
		adapters: adapters,
		order:    []string{"nftables", "firewalld", "ufw", "iptables", "mock"},
	}
}

// SelectBackend picks the active firewall adapter based on configuration preference or auto-probing.
func (f *Factory) SelectBackend(ctx context.Context, preference string) FirewallAdapter {
	pref := strings.ToLower(preference)
	if adapter, ok := f.adapters[pref]; ok {
		return adapter
	}

	// Auto-detection
	for _, name := range f.order {
		adapter := f.adapters[name]
		if name == "mock" {
			// Fallback to mock if nothing else detected
			return adapter
		}
		if detected, _ := adapter.Detect(ctx); detected {
			return adapter
		}
	}

	return f.adapters["mock"]
}

// DetectAll queries all adapters and returns their detection/health status.
func (f *Factory) DetectAll(ctx context.Context) []BackendInfo {
	var results []BackendInfo
	for _, name := range f.order {
		adapter := f.adapters[name]
		info := BackendInfo{Name: name}

		detected, err := adapter.Detect(ctx)
		info.Installed = detected
		if err != nil {
			info.Error = err.Error()
		}

		if detected {
			if valErr := adapter.Validate(ctx); valErr == nil {
				info.Active = true
			} else {
				info.Error = valErr.Error()
			}
		}

		results = append(results, info)
	}
	return results
}

// GetAdapter retrieves an adapter by name.
func (f *Factory) GetAdapter(name string) FirewallAdapter {
	return f.adapters[strings.ToLower(name)]
}
