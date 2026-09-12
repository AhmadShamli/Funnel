package firewall

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

func TestMockFirewallAdapter(t *testing.T) {
	ctx := context.Background()
	mock := NewMockFirewallAdapter()

	ip := netip.MustParseAddr("203.0.113.50")
	ports := []models.PortRule{
		{Protocol: "tcp", Port: 22},
		{Protocol: "tcp", Port: 80},
	}

	// 1. Apply grant
	if err := mock.ApplyGrant(ctx, 1, ip, ports, 1*time.Hour); err != nil {
		t.Fatalf("ApplyGrant failed: %v", err)
	}

	if !mock.HasRule(ip, "tcp", 22) || !mock.HasRule(ip, "tcp", 80) {
		t.Fatalf("expected rules for 22 and 80 to exist")
	}

	// 2. Revoke one port
	revokePorts := []models.PortRule{{Protocol: "tcp", Port: 80}}
	if err := mock.RevokeGrant(ctx, 1, ip, revokePorts); err != nil {
		t.Fatalf("RevokeGrant failed: %v", err)
	}

	if mock.HasRule(ip, "tcp", 80) {
		t.Fatalf("port 80 should have been revoked")
	}
	if !mock.HasRule(ip, "tcp", 22) {
		t.Fatalf("port 22 should still exist")
	}

	// 3. SyncGrants
	syncRules := []ActiveGrantRules{
		{
			IP: netip.MustParseAddr("198.51.100.1"),
			Ports: []models.PortRule{
				{Protocol: "tcp", Port: 443},
			},
		},
	}
	if err := mock.SyncGrants(ctx, syncRules); err != nil {
		t.Fatalf("SyncGrants failed: %v", err)
	}

	if mock.HasRule(ip, "tcp", 22) {
		t.Fatalf("old rule should be purged by sync")
	}
	if !mock.HasRule(netip.MustParseAddr("198.51.100.1"), "tcp", 443) {
		t.Fatalf("synced rule should be present")
	}
}

func TestFactoryAndHelperClientInternal(t *testing.T) {
	ctx := context.Background()
	factory := NewFactory("false")

	client := NewHelperClient("internal", "", "mock", factory)

	// Detect backends
	resp, err := client.Execute(ctx, HelperRequest{Action: "detect"})
	if err != nil || !resp.Success {
		t.Fatalf("helper detect failed: %v, resp: %+v", err, resp)
	}

	// Apply grant via helper
	applyResp, err := client.Execute(ctx, HelperRequest{
		Action:  "apply_grant",
		Backend: "mock",
		GrantID: 10,
		IP:      "192.0.2.1",
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 8080},
		},
	})
	if err != nil || !applyResp.Success {
		t.Fatalf("helper apply_grant failed: %v, resp: %+v", err, applyResp)
	}

	// List rules
	listResp, err := client.Execute(ctx, HelperRequest{
		Action:  "list_rules",
		Backend: "mock",
	})
	if err != nil || !listResp.Success {
		t.Fatalf("helper list_rules failed: %v, resp: %+v", err, listResp)
	}
	if len(listResp.Rules) != 1 || listResp.Rules[0].Port != 8080 {
		t.Fatalf("unexpected rules list: %+v", listResp.Rules)
	}
}

func TestHelperUnixSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_helper.sock")

	factory := NewFactory("false")
	server := NewHelperServer(factory)

	go func() {
		_ = server.RunSocketDaemon(ctx, sockPath)
	}()

	// Wait for socket to appear
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := NewHelperClient("socket", sockPath, "mock", factory)

	resp, err := client.Execute(ctx, HelperRequest{
		Action:  "apply_grant",
		Backend: "mock",
		GrantID: 42,
		IP:      "192.0.2.42",
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 9000},
		},
	})
	if err != nil || !resp.Success {
		t.Fatalf("socket apply_grant failed: %v, resp: %+v", err, resp)
	}
}

func TestParseUfwStatusLines(t *testing.T) {
	sampleOutput := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                  
[ 2] 80/tcp                     ALLOW IN    Anywhere                  
[ 3] 19132/udp                  ALLOW IN    161.142.150.107            # grant_3
[10] 19133/udp                  ALLOW IN    161.142.150.107            # funnel_active
`

	rules := parseUfwStatusLines(sampleOutput)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d: %+v", len(rules), rules)
	}

	// Verify single digit parsing
	if rules[0].Port != 22 || rules[0].Protocol != "tcp" || rules[0].IP != "Anywhere" {
		t.Errorf("unexpected rule 0: %+v", rules[0])
	}

	// Verify grant comment
	if rules[2].Port != 19132 || rules[2].Protocol != "udp" || rules[2].IP != "161.142.150.107" || rules[2].Comment != "grant_3" {
		t.Errorf("unexpected rule 2: %+v", rules[2])
	}

	// Verify double digit parsing
	if rules[3].Port != 19133 || rules[3].Protocol != "udp" || rules[3].IP != "161.142.150.107" || rules[3].Comment != "funnel_active" {
		t.Errorf("unexpected rule 3: %+v", rules[3])
	}
}
