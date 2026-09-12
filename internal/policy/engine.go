package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/models"
)

var (
	ErrInvalidCredentials       = errors.New("invalid access password")
	ErrKeyInactive              = errors.New("access key is currently inactive or expired")
	ErrConcurrentLimitReached   = errors.New("maximum concurrent IP limit reached for this access key")
	ErrKeyUsageExhausted        = errors.New("access key maximum usage count exhausted")
	ErrGrantNotFound            = errors.New("active grant not found")
	ErrExtensionNotAllowed      = errors.New("session extensions are not permitted for this grant")
	ErrMaxExtensionsReached     = errors.New("maximum number of extensions reached")
	ErrCeilingReached           = errors.New("maximum session lifetime ceiling reached")
	ErrIPMismatch               = errors.New("client IP does not match the active grant")
)

// Engine orchestrates visitor evaluation, password authentication, port delta sync, and extensions.
type Engine struct {
	db          *database.DB
	helper      *firewall.HelperClient
	rateLimiter *auth.RateLimiter
	pepper      string
}

// NewEngine creates a new policy engine.
func NewEngine(db *database.DB, helper *firewall.HelperClient, rateLimiter *auth.RateLimiter, pepper string) *Engine {
	return &Engine{
		db:          db,
		helper:      helper,
		rateLimiter: rateLimiter,
		pepper:      pepper,
	}
}

// VisitorStatusResult represents the evaluation result for an incoming visitor IP.
type VisitorStatusResult struct {
	ClientIP          netip.Addr
	IsAlwaysAllowed   bool
	HasActiveGrant    bool
	Grant             *models.AccessGrant
	AllowedPorts      []models.PortRule
	RemainingSeconds  int
	CanExtend         bool
	RateLimitStatus   auth.RateLimitResult
}

// EvaluateVisitor determines the access state of a visitor IP and optional grant cookie.
func (e *Engine) EvaluateVisitor(ctx context.Context, clientIP netip.Addr, tokenCookie string, now time.Time) (*VisitorStatusResult, error) {
	result := &VisitorStatusResult{
		ClientIP: clientIP,
	}

	// Check rate limit state
	result.RateLimitStatus = e.rateLimiter.CheckVisitor(clientIP.String(), now)

	// 1. Check if an active grant already exists matching the cookie token
	if tokenCookie != "" {
		tokenHash := auth.HashToken(tokenCookie)
		grant, err := e.db.GetAccessGrantByTokenHash(ctx, tokenHash)
		if err == nil && grant != nil && grant.IsActiveAt(now) {
			// Verify client IP matches the grant IP
			if grant.SourceIP == clientIP.String() {
				result.HasActiveGrant = true
				result.Grant = grant
				result.AllowedPorts = grant.Ports
				rem := int(grant.ExpiresAt.Sub(now).Seconds())
				if rem < 0 {
					rem = 0
				}
				result.RemainingSeconds = rem
				result.CanExtend = e.checkCanExtend(ctx, grant, now)
				return result, nil
			}
		}
	}

	// 2. Check always-allowed CIDR policies
	networks, err := e.db.ListAllowedNetworks(ctx)
	if err == nil {
		for _, net := range networks {
			if net.Mode == "always_allowed" && net.IsValidAt(now) && net.MatchesIP(clientIP) {
				// Matched an always-allowed rule!
				result.IsAlwaysAllowed = true

				// Find or create active grant for this always-allowed rule
				existingGrants, _ := e.db.ListActiveGrantsByIP(ctx, clientIP.String(), now)
				for _, g := range existingGrants {
					if g.GrantSource == "always_allowed" {
						result.HasActiveGrant = true
						result.Grant = &g
						result.AllowedPorts = g.Ports
						rem := int(g.ExpiresAt.Sub(now).Seconds())
						if rem < 0 {
							rem = 0
						}
						result.RemainingSeconds = rem
						return result, nil
					}
				}

				// Create an automated grant for always-allowed
				grant, token, err := e.createAlwaysAllowedGrant(ctx, clientIP, net, now)
				if err == nil {
					result.HasActiveGrant = true
					result.Grant = grant
					result.AllowedPorts = grant.Ports
					result.RemainingSeconds = net.GrantDurationSeconds
					_ = token
				}
				return result, nil
			}
		}
	}

	// Check if IP has active grants from other sessions (shared NAT)
	// We do not disclose peer sessions to this anonymous visitor!
	return result, nil
}

// AuthenticateVisitor authenticates a visitor password and creates an active port grant.
func (e *Engine) AuthenticateVisitor(ctx context.Context, clientIP netip.Addr, password string, now time.Time) (*models.AccessGrant, string, error) {
	ipStr := clientIP.String()

	// Rate limit check
	rlResult := e.rateLimiter.CheckVisitor(ipStr, now)
	if rlResult.Blocked {
		return nil, "", fmt.Errorf("rate limit exceeded (try again in %d seconds): %s", rlResult.RetryAfterSeconds, rlResult.Reason)
	}

	// Keyed HMAC verification with indexed DB point lookup
	passHash := auth.HashAccessKey(e.pepper, password)
	key, err := e.db.GetAccessKeyByPasswordHash(ctx, passHash)
	if err != nil || key == nil || !key.IsValidAt(now) {
		tripped := e.rateLimiter.RecordVisitorFailure(ipStr, now)
		details, _ := json.Marshal(map[string]interface{}{"ip": ipStr, "circuit_breaker_tripped": tripped})
		_ = e.db.RecordAuditEvent(ctx, &models.AuditEvent{
			EventType:       "VISITOR_LOGIN_FAILED",
			ActorType:       "visitor",
			ActorIdentifier: ipStr,
			TargetIP:        ipStr,
			DetailsJSON:     string(details),
		})
		return nil, "", ErrInvalidCredentials
	}

	// Check concurrent IP cap
	if key.MaxConcurrentIPs != nil {
		activeIPs, err := e.db.CountActiveGrantsByAccessKeyID(ctx, key.ID, now)
		if err == nil && activeIPs >= *key.MaxConcurrentIPs {
			return nil, "", ErrConcurrentLimitReached
		}
	}

	// Collect approved ports
	portsMap := make(map[string]models.PortRule)
	duration := 3600 * time.Second
	if key.MaxDurationSeconds != nil && *key.MaxDurationSeconds > 0 {
		duration = time.Duration(*key.MaxDurationSeconds) * time.Second
	}

	for _, pg := range key.PortGroups {
		if pg.IsValidAt(now) {
			if pg.GrantDurationSeconds > 0 && (key.MaxDurationSeconds == nil || *key.MaxDurationSeconds == 0) {
				duration = time.Duration(pg.GrantDurationSeconds) * time.Second
			}
			for _, p := range pg.Ports {
				portsMap[firewall.RuleKey(clientIP, p.Protocol, p.Port)] = p
			}
		}
	}

	// If key has no port groups, check global default port groups
	if len(portsMap) == 0 {
		allPGs, _ := e.db.ListPortGroups(ctx)
		for _, pg := range allPGs {
			if pg.AvailabilityMode == "global" && pg.IsValidAt(now) {
				for _, p := range pg.Ports {
					portsMap[firewall.RuleKey(clientIP, p.Protocol, p.Port)] = p
				}
			}
		}
	}

	var ports []models.PortRule
	for _, p := range portsMap {
		ports = append(ports, p)
	}

	// Calculate expiration, respecting key.ValidUntil
	expiresAt := now.Add(duration)
	if key.ValidUntil != nil && key.ValidUntil.Before(expiresAt) {
		expiresAt = *key.ValidUntil
	}

	// Create grant
	rawToken, err := auth.GenerateRandomToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate grant token: %w", err)
	}

	grant := &models.AccessGrant{
		AccessKeyID:      &key.ID,
		GrantSource:      "password",
		SourceIP:         ipStr,
		ExtensionCount:   0,
		Status:           "active",
		VisitorTokenHash: auth.HashToken(rawToken),
		GrantedAt:        now,
		ExpiresAt:        expiresAt,
		Ports:            ports,
		AccessKeyName:    key.Name,
	}

	if err := e.db.CreateAccessGrant(ctx, grant); err != nil {
		return nil, "", fmt.Errorf("failed to record access grant: %w", err)
	}

	// Update key usage counters
	_ = e.db.IncrementAccessKeyUse(ctx, key.ID, now)

	// Apply grant via firewall helper
	_, err = e.helper.Execute(ctx, firewall.HelperRequest{
		Action:          "apply_grant",
		GrantID:         grant.ID,
		IP:              ipStr,
		Ports:           ports,
		DurationSeconds: int(duration.Seconds()),
	})
	if err != nil {
		// Log error but proceed if DB grant succeeded
	}

	// Record success in rate limiter
	e.rateLimiter.RecordVisitorSuccess(ipStr)

	// Audit log
	details, _ := json.Marshal(map[string]interface{}{
		"key_id":    key.ID,
		"key_name":  key.Name,
		"ports":     ports,
		"duration":  duration.String(),
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
	_ = e.db.RecordAuditEvent(ctx, &models.AuditEvent{
		EventType:       "VISITOR_GRANT_CREATED",
		ActorType:       "visitor",
		ActorIdentifier: key.Name,
		TargetIP:        ipStr,
		DetailsJSON:     string(details),
	})

	return grant, rawToken, nil
}

// RevokeGrant revokes an active grant, calculates port delta sync, and updates the firewall.
func (e *Engine) RevokeGrant(ctx context.Context, grantID int64, clientIP netip.Addr, now time.Time) error {
	grant, err := e.db.GetAccessGrantByID(ctx, grantID)
	if err != nil || grant == nil {
		return ErrGrantNotFound
	}

	if clientIP.IsValid() && grant.SourceIP != clientIP.String() {
		return ErrIPMismatch
	}

	if err := e.db.RevokeGrant(ctx, grant.ID, now); err != nil {
		return fmt.Errorf("failed to revoke grant in database: %w", err)
	}

	// Immediate port delta sync
	if err := e.SyncPortDeltaForIP(ctx, grant.SourceIP, grant.Ports, now); err != nil {
		// Log error
	}

	details, _ := json.Marshal(map[string]interface{}{
		"grant_id": grant.ID,
		"source":   grant.GrantSource,
		"ports":    grant.Ports,
	})
	_ = e.db.RecordAuditEvent(ctx, &models.AuditEvent{
		EventType:       "GRANT_REVOKED",
		ActorType:       "visitor",
		ActorIdentifier: grant.SourceIP,
		TargetIP:        grant.SourceIP,
		DetailsJSON:     string(details),
	})

	return nil
}

// ExtendGrant extends an active grant duration adhering to all administrative constraints.
func (e *Engine) ExtendGrant(ctx context.Context, grantID int64, clientIP netip.Addr, candidatePassword string, isAdmin bool, adminUser *models.AdminUser, now time.Time) (*models.AccessGrant, error) {
	grant, err := e.db.GetAccessGrantByID(ctx, grantID)
	if err != nil || grant == nil || !grant.IsActiveAt(now) {
		return nil, ErrGrantNotFound
	}

	if clientIP.IsValid() && grant.SourceIP != clientIP.String() {
		return nil, ErrIPMismatch
	}

	// 1. Password challenge for visitors
	if !isAdmin {
		if candidatePassword == "" {
			return nil, errors.New("password required to extend session")
		}
		if grant.AccessKeyID == nil {
			return nil, ErrExtensionNotAllowed
		}
		key, err := e.db.GetAccessKeyByID(ctx, *grant.AccessKeyID)
		if err != nil || key == nil {
			return nil, ErrInvalidCredentials
		}
		if !auth.VerifyAccessKey(e.pepper, candidatePassword, key.PasswordHash) {
			return nil, ErrInvalidCredentials
		}
		if !key.IsValidAt(now) || !key.AllowExtend {
			return nil, ErrExtensionNotAllowed
		}
	} else if adminUser != nil {
		if !adminUser.AllowExtend {
			return nil, ErrExtensionNotAllowed
		}
	}

	// 2. Check allow_extend across governing entities
	if !e.checkCanExtend(ctx, grant, now) {
		return nil, ErrExtensionNotAllowed
	}

	// 3. Check max_extensions cap
	maxExt := e.getMaxExtensions(ctx, grant, adminUser)
	if maxExt != nil && grant.ExtensionCount >= *maxExt {
		return nil, ErrMaxExtensionsReached
	}

	// 4. Calculate bounded extension duration
	initialDuration := grant.ExpiresAt.Sub(grant.GrantedAt)
	if initialDuration <= 0 {
		initialDuration = 3600 * time.Second
	}

	// Extended expiration cannot stack beyond initial duration from now
	newExpiresAt := now.Add(initialDuration)

	// Cumulative cap: total lifetime cannot exceed granted_at + 2 * initialDuration
	cumulativeCeiling := grant.GrantedAt.Add(2 * initialDuration)
	if newExpiresAt.After(cumulativeCeiling) {
		newExpiresAt = cumulativeCeiling
	}

	// Clamp to any calendar valid_until cutoff
	if grant.AccessKeyID != nil {
		key, _ := e.db.GetAccessKeyByID(ctx, *grant.AccessKeyID)
		if key != nil && key.ValidUntil != nil && key.ValidUntil.Before(newExpiresAt) {
			newExpiresAt = *key.ValidUntil
		}
	}

	if !newExpiresAt.After(now) {
		return nil, ErrCeilingReached
	}

	// 5. Update DB
	if err := e.db.ExtendGrant(ctx, grant.ID, newExpiresAt); err != nil {
		return nil, fmt.Errorf("failed to extend grant: %w", err)
	}

	grant.ExtensionCount++
	grant.ExpiresAt = newExpiresAt

	// 6. Refresh firewall timeout
	parsedIP, err := netip.ParseAddr(grant.SourceIP)
	if err == nil {
		durationSecs := int(newExpiresAt.Sub(now).Seconds())
		_, _ = e.helper.Execute(ctx, firewall.HelperRequest{
			Action:          "apply_grant",
			GrantID:         grant.ID,
			IP:              parsedIP.String(),
			Ports:           grant.Ports,
			DurationSeconds: durationSecs,
		})
	}

	details, _ := json.Marshal(map[string]interface{}{
		"grant_id":        grant.ID,
		"extension_count": grant.ExtensionCount,
		"new_expires_at":  newExpiresAt.Format(time.RFC3339),
	})
	_ = e.db.RecordAuditEvent(ctx, &models.AuditEvent{
		EventType:       "GRANT_EXTENDED",
		ActorType:       "visitor",
		ActorIdentifier: grant.SourceIP,
		TargetIP:        grant.SourceIP,
		DetailsJSON:     string(details),
	})

	return grant, nil
}

// SyncPortDeltaForIP calculates port differences and removes ports that have zero remaining claims.
func (e *Engine) SyncPortDeltaForIP(ctx context.Context, ip string, revokedPorts []models.PortRule, now time.Time) error {
	activeGrants, err := e.db.ListActiveGrantsByIP(ctx, ip, now)
	if err != nil {
		return err
	}

	// Build map of remaining active ports for this IP
	activePortMap := make(map[string]bool)
	for _, g := range activeGrants {
		for _, p := range g.Ports {
			k := fmt.Sprintf("%s_%d", strings.ToLower(p.Protocol), p.Port)
			activePortMap[k] = true
		}
	}

	// Find delta ports that no other grant claims
	var portsToRemove []models.PortRule
	for _, p := range revokedPorts {
		k := fmt.Sprintf("%s_%d", strings.ToLower(p.Protocol), p.Port)
		if !activePortMap[k] {
			portsToRemove = append(portsToRemove, p)
		}
	}

	if len(portsToRemove) > 0 {
		parsedIP, err := netip.ParseAddr(ip)
		if err == nil {
			_, err = e.helper.Execute(ctx, firewall.HelperRequest{
				Action: "revoke_grant",
				IP:     parsedIP.String(),
				Ports:  portsToRemove,
			})
			return err
		}
	}

	return nil
}

// ReconcileStartup performs a full audit scan, expires offline grants, and re-syncs firewall rules.
func (e *Engine) ReconcileStartup(ctx context.Context, now time.Time) (expiredCount int, restoredGrants int, err error) {
	// 1. Mark offline-expired grants
	expired, err := e.db.ExpireOldGrants(ctx, now)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to expire old grants: %w", err)
	}
	expiredCount = len(expired)

	// 2. Fetch all currently active grants
	activeGrants, err := e.db.ListActiveGrantsAll(ctx, now)
	if err != nil {
		return expiredCount, 0, fmt.Errorf("failed to fetch active grants: %w", err)
	}
	restoredGrants = len(activeGrants)

	// 3. Group by IP and compute union of ports
	ipPortGroups := make(map[string]map[string]models.PortRule)
	for _, g := range activeGrants {
		if _, exists := ipPortGroups[g.SourceIP]; !exists {
			ipPortGroups[g.SourceIP] = make(map[string]models.PortRule)
		}
		for _, p := range g.Ports {
			k := fmt.Sprintf("%s_%d", strings.ToLower(p.Protocol), p.Port)
			ipPortGroups[g.SourceIP][k] = p
		}
	}

	var syncList []firewall.ActiveGrantRules
	for ipStr, pMap := range ipPortGroups {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		var ports []models.PortRule
		for _, p := range pMap {
			ports = append(ports, p)
		}
		syncList = append(syncList, firewall.ActiveGrantRules{
			IP:    addr,
			Ports: ports,
		})
	}

	// 4. Atomically sync firewall
	_, err = e.helper.Execute(ctx, firewall.HelperRequest{
		Action:       "sync_grants",
		ActiveGrants: syncList,
	})
	if err != nil {
		return expiredCount, restoredGrants, fmt.Errorf("firewall sync failed: %w", err)
	}

	// 5. Log audit event
	details, _ := json.Marshal(map[string]interface{}{
		"expired_offline_grants": expiredCount,
		"active_grants_restored": restoredGrants,
		"distinct_ips_synced":    len(syncList),
	})
	_ = e.db.RecordAuditEvent(ctx, &models.AuditEvent{
		EventType:       "STARTUP_RECONCILIATION_COMPLETED",
		ActorType:       "system",
		ActorIdentifier: "funnel_startup",
		TargetIP:        "",
		DetailsJSON:     string(details),
	})

	return expiredCount, restoredGrants, nil
}

func (e *Engine) createAlwaysAllowedGrant(ctx context.Context, ip netip.Addr, net models.AllowedNetwork, now time.Time) (*models.AccessGrant, string, error) {
	duration := time.Duration(net.GrantDurationSeconds) * time.Second
	expiresAt := now.Add(duration)

	var ports []models.PortRule
	for _, pg := range net.PortGroups {
		ports = append(ports, pg.Ports...)
	}

	rawToken, _ := auth.GenerateRandomToken(32)
	grant := &models.AccessGrant{
		AllowedNetworkID:   &net.ID,
		GrantSource:        "always_allowed",
		SourceIP:           ip.String(),
		ExtensionCount:     0,
		Status:             "active",
		VisitorTokenHash:   auth.HashToken(rawToken),
		GrantedAt:          now,
		ExpiresAt:          expiresAt,
		Ports:              ports,
		AllowedNetworkName: net.Name,
	}

	if err := e.db.CreateAccessGrant(ctx, grant); err != nil {
		return nil, "", err
	}

	_, _ = e.helper.Execute(ctx, firewall.HelperRequest{
		Action:          "apply_grant",
		GrantID:         grant.ID,
		IP:              ip.String(),
		Ports:           ports,
		DurationSeconds: int(duration.Seconds()),
	})

	return grant, rawToken, nil
}

func (e *Engine) checkCanExtend(ctx context.Context, grant *models.AccessGrant, now time.Time) bool {
	// Check Access Key if set
	if grant.AccessKeyID != nil {
		key, err := e.db.GetAccessKeyByID(ctx, *grant.AccessKeyID)
		if err != nil || key == nil || !key.AllowExtend || !key.IsValidAt(now) {
			return false
		}
		// Check all key's port groups
		for _, pg := range key.PortGroups {
			if !pg.AllowExtend {
				return false
			}
		}
	}

	// Check Allowed Network if set
	if grant.AllowedNetworkID != nil {
		net, err := e.db.GetAllowedNetworkByID(ctx, *grant.AllowedNetworkID)
		if err != nil || net == nil || !net.AllowExtend || !net.IsValidAt(now) {
			return false
		}
		for _, pg := range net.PortGroups {
			if !pg.AllowExtend {
				return false
			}
		}
	}

	// Check max extensions
	maxExt := e.getMaxExtensions(ctx, grant, nil)
	if maxExt != nil && grant.ExtensionCount >= *maxExt {
		return false
	}

	return true
}

func (e *Engine) getMaxExtensions(ctx context.Context, grant *models.AccessGrant, admin *models.AdminUser) *int {
	var minLimit *int

	updateMin := func(limit *int) {
		if limit == nil {
			return
		}
		if minLimit == nil || *limit < *minLimit {
			minLimit = limit
		}
	}

	if admin != nil {
		updateMin(admin.MaxExtensions)
	}

	if grant.AccessKeyID != nil {
		key, _ := e.db.GetAccessKeyByID(ctx, *grant.AccessKeyID)
		if key != nil {
			updateMin(key.MaxExtensions)
			for _, pg := range key.PortGroups {
				updateMin(pg.MaxExtensions)
			}
		}
	}

	if grant.AllowedNetworkID != nil {
		net, _ := e.db.GetAllowedNetworkByID(ctx, *grant.AllowedNetworkID)
		if net != nil {
			updateMin(net.MaxExtensions)
			for _, pg := range net.PortGroups {
				updateMin(pg.MaxExtensions)
			}
		}
	}

	return minLimit
}
