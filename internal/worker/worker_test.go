package worker

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/policy"
)

func TestWorkerExpirationAndCleanup(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	factory := firewall.NewFactory("false")
	mockFW := factory.GetAdapter("mock").(*firewall.MockFirewallAdapter)
	helperClient := firewall.NewHelperClient("internal", "", "mock", factory)
	rateLimiter := auth.NewRateLimiter(5, 60*time.Second, 5, 5*time.Minute, 15*time.Minute)
	engine := policy.NewEngine(db, helperClient, rateLimiter, "pepper")

	now := time.Now().UTC()
	ip := "192.0.2.77"

	// Create grant that expires in the past
	pastGrant := &models.AccessGrant{
		GrantSource:      "password",
		SourceIP:         ip,
		Status:           "active",
		VisitorTokenHash: "past_token",
		GrantedAt:        now.Add(-2 * time.Hour),
		ExpiresAt:        now.Add(-10 * time.Minute),
		Ports:            []models.PortRule{{Protocol: "tcp", Port: 8080}},
	}
	_ = db.CreateAccessGrant(ctx, pastGrant)
	_ = mockFW.ApplyGrant(ctx, pastGrant.ID, netip.MustParseAddr(ip), pastGrant.Ports, 1*time.Hour)

	// Create an old audit event
	_ = db.RecordAuditEvent(ctx, &models.AuditEvent{
		EventType:       "TEST_EVENT",
		ActorType:       "system",
		ActorIdentifier: "test",
		CreatedAt:       now.AddDate(0, 0, -100),
	})

	worker := NewWorker(db, engine, 90)

	// Test runExpiration
	worker.runExpiration(ctx, now)

	activeGrants, _ := db.ListActiveGrantsByIP(ctx, ip, now)
	if len(activeGrants) != 0 {
		t.Errorf("expected 0 active grants after expiration, got %d", len(activeGrants))
	}

	if mockFW.HasRule(netip.MustParseAddr(ip), "tcp", 8080) {
		t.Errorf("expired port should have been removed from firewall by worker")
	}

	// Test runCleanup
	worker.runCleanup(ctx, now)

	testEvents, _ := db.ListAuditEvents(ctx, "TEST_EVENT", 10, 0)
	if len(testEvents) != 0 {
		t.Errorf("expected 0 TEST_EVENT audit events after pruning 100-day-old event with 90-day retention, got %d", len(testEvents))
	}
}
