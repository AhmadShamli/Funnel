package database

import (
	"context"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

func TestDatabaseCRUD(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// 1. Admin Users
	count, err := db.CountAdminUsers(ctx)
	if err != nil {
		t.Fatalf("CountAdminUsers failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 admin users, got %d", count)
	}

	admin := &models.AdminUser{
		Username:     "admin",
		PasswordHash: "hashedpw",
		Role:         "admin",
		IsActive:     true,
		AllowExtend:  true,
	}
	if err := db.CreateAdminUser(ctx, admin); err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}

	fetchedAdmin, err := db.GetAdminUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("GetAdminUserByUsername failed: %v", err)
	}
	if fetchedAdmin.ID != admin.ID || fetchedAdmin.Username != "admin" {
		t.Errorf("admin mismatch: %+v vs %+v", admin, fetchedAdmin)
	}

	// 2. Port Groups & Ports
	pg := &models.PortGroup{
		Name:                 "SSH & Web",
		Description:          "Standard ports",
		CustomText:           "[b]Welcome to SSH & Web[/b]\nConnect via [url=https://example.com]Example[/url]",
		AvailabilityMode:     "key_only",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		MaxDurationSeconds:   7200,
		IsActive:             true,
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 22},
			{Protocol: "tcp", Port: 80},
			{Protocol: "tcp", Port: 443},
		},
	}
	if err := db.CreatePortGroup(ctx, pg); err != nil {
		t.Fatalf("CreatePortGroup failed: %v", err)
	}
	if pg.ID == 0 {
		t.Fatalf("expected non-zero port group ID")
	}

	fetchedPG, err := db.GetPortGroupByID(ctx, pg.ID)
	if err != nil {
		t.Fatalf("GetPortGroupByID failed: %v", err)
	}
	if len(fetchedPG.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(fetchedPG.Ports))
	}
	if fetchedPG.CustomText != pg.CustomText {
		t.Fatalf("expected CustomText %q, got %q", pg.CustomText, fetchedPG.CustomText)
	}

	// Test updating PortGroup with new custom text
	pg.CustomText = "Updated custom text [code]ssh root@host[/code]"
	if err := db.UpdatePortGroup(ctx, pg); err != nil {
		t.Fatalf("UpdatePortGroup failed: %v", err)
	}
	updatedPG, err := db.GetPortGroupByID(ctx, pg.ID)
	if err != nil {
		t.Fatalf("GetPortGroupByID failed after update: %v", err)
	}
	if updatedPG.CustomText != pg.CustomText {
		t.Fatalf("expected updated CustomText %q, got %q", pg.CustomText, updatedPG.CustomText)
	}

	// 3. Access Keys
	key := &models.AccessKey{
		Name:             "Dev Key",
		PasswordHash:     "keyhash123",
		IsActive:         true,
		AllowExtend:      true,
		CreatedByAdminID: &admin.ID,
		PortGroupIDs:     []int64{pg.ID},
	}
	if err := db.CreateAccessKey(ctx, key); err != nil {
		t.Fatalf("CreateAccessKey failed: %v", err)
	}

	fetchedKey, err := db.GetAccessKeyByPasswordHash(ctx, "keyhash123")
	if err != nil {
		t.Fatalf("GetAccessKeyByPasswordHash failed: %v", err)
	}
	if fetchedKey.Name != "Dev Key" || len(fetchedKey.PortGroups) != 1 {
		t.Fatalf("unexpected fetched key: %+v", fetchedKey)
	}

	// 4. Access Grants & Expiration
	now := time.Now().UTC()
	grant := &models.AccessGrant{
		AccessKeyID:      &key.ID,
		GrantSource:      "password",
		SourceIP:         "203.0.113.10",
		Status:           "active",
		VisitorTokenHash: "visittoken123",
		GrantedAt:        now,
		ExpiresAt:        now.Add(1 * time.Hour),
		Ports:            pg.Ports,
	}
	if err := db.CreateAccessGrant(ctx, grant); err != nil {
		t.Fatalf("CreateAccessGrant failed: %v", err)
	}

	activeGrants, err := db.ListActiveGrantsByIP(ctx, "203.0.113.10", now)
	if err != nil {
		t.Fatalf("ListActiveGrantsByIP failed: %v", err)
	}
	if len(activeGrants) != 1 {
		t.Fatalf("expected 1 active grant, got %d", len(activeGrants))
	}

	// Check grant by token
	fetchedGrant, err := db.GetAccessGrantByTokenHash(ctx, "visittoken123")
	if err != nil {
		t.Fatalf("GetAccessGrantByTokenHash failed: %v", err)
	}
	if fetchedGrant.SourceIP != "203.0.113.10" || len(fetchedGrant.Ports) != 3 {
		t.Fatalf("unexpected fetched grant: %+v", fetchedGrant)
	}

	// 5. Expire grants
	future := now.Add(2 * time.Hour)
	expired, err := db.ExpireOldGrants(ctx, future)
	if err != nil {
		t.Fatalf("ExpireOldGrants failed: %v", err)
	}
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired grant, got %d", len(expired))
	}

	// 6. Audit Events
	event := &models.AuditEvent{
		EventType:       "GRANT_CREATED",
		ActorType:       "visitor",
		ActorIdentifier: "Dev Key",
		TargetIP:        "203.0.113.10",
		DetailsJSON:     `{"ports":[22,80,443]}`,
	}
	if err := db.RecordAuditEvent(ctx, event); err != nil {
		t.Fatalf("RecordAuditEvent failed: %v", err)
	}

	events, err := db.ListAuditEvents(ctx, "", 10, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
}
