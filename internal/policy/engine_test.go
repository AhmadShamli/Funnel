package policy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/models"
)

func setupTestEngine(t *testing.T) (*Engine, *database.DB, *firewall.MockFirewallAdapter) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	factory := firewall.NewFactory("false")
	mockFW := factory.GetAdapter("mock").(*firewall.MockFirewallAdapter)
	helperClient := firewall.NewHelperClient("internal", "", "mock", factory)
	rateLimiter := auth.NewRateLimiter(5, 60*time.Second, 5, 5*time.Minute, 15*time.Minute)
	pepper := "test-pepper-123"

	engine := NewEngine(db, helperClient, rateLimiter, pepper)
	return engine, db, mockFW
}

func TestAuthenticateAndSharedNATPortDelta(t *testing.T) {
	ctx := context.Background()
	engine, db, mockFW := setupTestEngine(t)
	defer db.Close()

	now := time.Now().UTC()
	sharedIP := netip.MustParseAddr("203.0.113.100")

	// 1. Create Port Group 1 (ports 22 and 80)
	pg1 := &models.PortGroup{
		Name:                 "SSH and Web",
		AvailabilityMode:     "key_only",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		MaxDurationSeconds:   7200,
		IsActive:             true,
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 22},
			{Protocol: "tcp", Port: 80},
		},
	}
	_ = db.CreatePortGroup(ctx, pg1)

	// Create Port Group 2 (ports 80 and 443)
	pg2 := &models.PortGroup{
		Name:                 "Web and HTTPS",
		AvailabilityMode:     "key_only",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		MaxDurationSeconds:   7200,
		IsActive:             true,
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 80},
			{Protocol: "tcp", Port: 443},
		},
	}
	_ = db.CreatePortGroup(ctx, pg2)

	// Create Access Key 1
	key1Hash := auth.HashAccessKey(engine.pepper, "secret1")
	key1 := &models.AccessKey{
		Name:         "Key One",
		PasswordHash: key1Hash,
		IsActive:     true,
		AllowExtend:  true,
		PortGroupIDs: []int64{pg1.ID},
	}
	_ = db.CreateAccessKey(ctx, key1)

	// Create Access Key 2
	key2Hash := auth.HashAccessKey(engine.pepper, "secret2")
	key2 := &models.AccessKey{
		Name:         "Key Two",
		PasswordHash: key2Hash,
		IsActive:     true,
		AllowExtend:  true,
		PortGroupIDs: []int64{pg2.ID},
	}
	_ = db.CreateAccessKey(ctx, key2)

	// 2. Authenticate User 1 behind shared NAT
	grant1, token1, err := engine.AuthenticateVisitor(ctx, sharedIP, "secret1", now)
	if err != nil {
		t.Fatalf("auth user 1 failed: %v", err)
	}
	if len(grant1.Ports) != 2 {
		t.Fatalf("expected 2 ports for grant 1, got %d", len(grant1.Ports))
	}
	if !mockFW.HasRule(sharedIP, "tcp", 22) || !mockFW.HasRule(sharedIP, "tcp", 80) {
		t.Fatalf("firewall rules for user 1 missing")
	}

	// Verify visitor status for User 1 using their cookie token
	evalUser1, err := engine.EvaluateVisitor(ctx, sharedIP, token1, now)
	if err != nil || !evalUser1.HasActiveGrant {
		t.Fatalf("eval user 1 failed: %+v", evalUser1)
	}
	if len(evalUser1.AllowedPorts) != 2 {
		t.Fatalf("eval user 1 expected 2 ports, got %d", len(evalUser1.AllowedPorts))
	}

	// 3. Authenticate User 2 behind SAME shared NAT IP
	grant2, token2, err := engine.AuthenticateVisitor(ctx, sharedIP, "secret2", now)
	if err != nil {
		t.Fatalf("auth user 2 failed: %v", err)
	}
	_ = token2

	// Now firewall has 22, 80, 443
	if !mockFW.HasRule(sharedIP, "tcp", 22) || !mockFW.HasRule(sharedIP, "tcp", 80) || !mockFW.HasRule(sharedIP, "tcp", 443) {
		t.Fatalf("firewall should have union of ports 22, 80, 443")
	}

	// 4. Test Strict Privacy: An unauthenticated visitor from this same IP sees NO peer ports
	evalAnon, err := engine.EvaluateVisitor(ctx, sharedIP, "", now)
	if err != nil {
		t.Fatalf("eval anon failed: %v", err)
	}
	if evalAnon.HasActiveGrant {
		t.Fatalf("anonymous visitor without token must NOT see active grant of peers")
	}

	// 5. Test Immediate Port Delta Sync on Revoke:
	// Revoke grant 1 (had 22 and 80).
	// Port 22 should be removed from firewall because only grant 1 had it.
	// Port 80 must REMAIN because grant 2 still has it!
	err = engine.RevokeGrant(ctx, grant1.ID, sharedIP, now)
	if err != nil {
		t.Fatalf("revoke grant 1 failed: %v", err)
	}

	if mockFW.HasRule(sharedIP, "tcp", 22) {
		t.Fatalf("port 22 should have been removed from firewall")
	}
	if !mockFW.HasRule(sharedIP, "tcp", 80) {
		t.Fatalf("port 80 should still be open because grant 2 is active!")
	}
	if !mockFW.HasRule(sharedIP, "tcp", 443) {
		t.Fatalf("port 443 should still be open for grant 2")
	}

	// 6. Test Extension on Grant 2
	extendedGrant, err := engine.ExtendGrant(ctx, grant2.ID, sharedIP, "secret2", false, nil, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("extend grant 2 failed: %v", err)
	}
	if extendedGrant.ExtensionCount != 1 {
		t.Fatalf("expected extension count 1, got %d", extendedGrant.ExtensionCount)
	}

	// 7. Test Extension Password Challenge Failure
	_, err = engine.ExtendGrant(ctx, grant2.ID, sharedIP, "wrong-password", false, nil, now.Add(15*time.Minute))
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestStartupReconciliation(t *testing.T) {
	ctx := context.Background()
	engine, db, mockFW := setupTestEngine(t)
	defer db.Close()

	now := time.Now().UTC()
	ip1 := "192.0.2.1"
	ip2 := "192.0.2.2"

	// Create an expired grant
	pastGrant := &models.AccessGrant{
		GrantSource:      "password",
		SourceIP:         ip1,
		Status:           "active",
		VisitorTokenHash: "token_past",
		GrantedAt:        now.Add(-2 * time.Hour),
		ExpiresAt:        now.Add(-1 * time.Hour),
		Ports:            []models.PortRule{{Protocol: "tcp", Port: 8080}},
	}
	_ = db.CreateAccessGrant(ctx, pastGrant)

	// Create an active grant
	activeGrant := &models.AccessGrant{
		GrantSource:      "password",
		SourceIP:         ip2,
		Status:           "active",
		VisitorTokenHash: "token_active",
		GrantedAt:        now,
		ExpiresAt:        now.Add(1 * time.Hour),
		Ports:            []models.PortRule{{Protocol: "tcp", Port: 9000}},
	}
	_ = db.CreateAccessGrant(ctx, activeGrant)

	expiredCount, restoredCount, err := engine.ReconcileStartup(ctx, now)
	if err != nil {
		t.Fatalf("ReconcileStartup failed: %v", err)
	}

	if expiredCount != 1 {
		t.Errorf("expected 1 expired grant, got %d", expiredCount)
	}
	if restoredCount != 1 {
		t.Errorf("expected 1 restored grant, got %d", restoredCount)
	}

	// Check firewall rules after sync
	if mockFW.HasRule(netip.MustParseAddr(ip1), "tcp", 8080) {
		t.Errorf("expired grant port should not be on firewall")
	}
	if !mockFW.HasRule(netip.MustParseAddr(ip2), "tcp", 9000) {
		t.Errorf("active grant port 9000 should be on firewall")
	}
}
