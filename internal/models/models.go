package models

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// AdminUser represents an administrator account.
type AdminUser struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	PasswordHash       string     `json:"-"`
	Role               string     `json:"role"`
	IsActive           bool       `json:"is_active"`
	AllowExtend        bool       `json:"allow_extend"`
	MaxExtensions      *int       `json:"max_extensions"`
	ValidFrom          *time.Time `json:"valid_from"`
	ValidUntil         *time.Time `json:"valid_until"`
	MustChangePassword bool       `json:"must_change_password"`
	FailedLoginCount   int        `json:"failed_login_count"`
	LockedUntil        *time.Time `json:"locked_until"`
	CreatedAt          time.Time  `json:"created_at"`
}

// IsLocked checks if the account is currently locked out.
func (u *AdminUser) IsLocked(now time.Time) bool {
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		return true
	}
	return false
}

// IsValidAt checks if the account is valid at the given time.
func (u *AdminUser) IsValidAt(now time.Time) bool {
	if !u.IsActive {
		return false
	}
	if u.ValidFrom != nil && u.ValidFrom.After(now) {
		return false
	}
	if u.ValidUntil != nil && u.ValidUntil.Before(now) {
		return false
	}
	return true
}

// AdminSession represents an authenticated admin session.
type AdminSession struct {
	ID               int64     `json:"id"`
	AdminUserID      int64     `json:"admin_user_id"`
	SessionTokenHash string    `json:"-"`
	UserAgent        string    `json:"user_agent"`
	ClientIP         string    `json:"client_ip"`
	CreatedAt        time.Time `json:"created_at"`
	LastActivityAt   time.Time `json:"last_activity_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// IsExpired checks if the session is expired based on idle or absolute timeout.
func (s *AdminSession) IsExpired(now time.Time, idleTimeout time.Duration) bool {
	if now.After(s.ExpiresAt) {
		return true
	}
	if idleTimeout > 0 && now.Sub(s.LastActivityAt) > idleTimeout {
		return true
	}
	return false
}

// PortRule represents a single transport protocol and port number.
type PortRule struct {
	ID          int64  `json:"id,omitempty"`
	PortGroupID int64  `json:"port_group_id,omitempty"`
	Protocol    string `json:"protocol"` // "tcp" or "udp"
	Port        int    `json:"port"`     // 1 - 65535
}

func (p PortRule) String() string {
	return fmt.Sprintf("%d/%s", p.Port, strings.ToLower(p.Protocol))
}

// PortGroup represents a collection of ports with availability and duration rules.
type PortGroup struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	Description          string     `json:"description"`
	AvailabilityMode     string     `json:"availability_mode"` // "global", "key_only", "always_allowed", "login_required"
	AllowExtend          bool       `json:"allow_extend"`
	MaxExtensions        *int       `json:"max_extensions"`
	GrantDurationSeconds int        `json:"grant_duration_seconds"`
	MaxDurationSeconds   int        `json:"max_duration_seconds"`
	ValidFrom            *time.Time `json:"valid_from"`
	ValidUntil           *time.Time `json:"valid_until"`
	NetworkMatchMode     string     `json:"network_match_mode"` // "any", "all"
	IsActive             bool       `json:"is_active"`
	Ports                []PortRule `json:"ports"`
}

// IsValidAt checks if the port group is valid at the given time.
func (pg *PortGroup) IsValidAt(now time.Time) bool {
	if !pg.IsActive {
		return false
	}
	if pg.ValidFrom != nil && pg.ValidFrom.After(now) {
		return false
	}
	if pg.ValidUntil != nil && pg.ValidUntil.Before(now) {
		return false
	}
	return true
}

// AccessKey represents an anonymous password-based authorization key.
type AccessKey struct {
	ID                 int64       `json:"id"`
	Name               string      `json:"name"`
	PasswordHash       string      `json:"-"`
	IsActive           bool        `json:"is_active"`
	AllowExtend        bool        `json:"allow_extend"`
	MaxExtensions      *int        `json:"max_extensions"`
	MaxConcurrentIPs   *int        `json:"max_concurrent_ips"`
	MaxTotalUses       *int        `json:"max_total_uses"`
	UseCount           int         `json:"use_count"`
	MaxDurationSeconds *int        `json:"max_duration_seconds"`
	ValidFrom          *time.Time  `json:"valid_from"`
	ValidUntil         *time.Time  `json:"valid_until"`
	LastUsedAt         *time.Time  `json:"last_used_at"`
	CreatedByAdminID   *int64      `json:"created_by_admin_id"`
	PortGroupIDs       []int64     `json:"port_group_ids,omitempty"`
	PortGroups         []PortGroup `json:"port_groups,omitempty"`
}

// IsValidAt checks if the access key is active and within its validity window.
func (k *AccessKey) IsValidAt(now time.Time) bool {
	if !k.IsActive {
		return false
	}
	if k.ValidFrom != nil && k.ValidFrom.After(now) {
		return false
	}
	if k.ValidUntil != nil && k.ValidUntil.Before(now) {
		return false
	}
	if k.MaxTotalUses != nil && k.UseCount >= *k.MaxTotalUses {
		return false
	}
	return true
}

// AllowedNetwork represents an IP/CIDR policy rule.
type AllowedNetwork struct {
	ID                   int64       `json:"id"`
	Name                 string      `json:"name"`
	NetworkCIDR          string      `json:"network_cidr"`
	Mode                 string      `json:"mode"`  // "always_allowed" or "login_required"
	Scope                string      `json:"scope"` // "global" or "key_only"
	AllowExtend          bool        `json:"allow_extend"`
	MaxExtensions        *int        `json:"max_extensions"`
	ValidFrom            *time.Time  `json:"valid_from"`
	ValidUntil           *time.Time  `json:"valid_until"`
	AccessKeyID          *int64      `json:"access_key_id"`
	GrantDurationSeconds int         `json:"grant_duration_seconds"`
	IsActive             bool        `json:"is_active"`
	PortGroupIDs         []int64     `json:"port_group_ids,omitempty"`
	PortGroups           []PortGroup `json:"port_groups,omitempty"`
}

// MatchesIP checks if the given IP address falls inside the AllowedNetwork CIDR.
func (an *AllowedNetwork) MatchesIP(ip netip.Addr) bool {
	prefix, err := netip.ParsePrefix(an.NetworkCIDR)
	if err != nil {
		// Try as single IP
		addr, err2 := netip.ParseAddr(an.NetworkCIDR)
		if err2 != nil {
			return false
		}
		return addr == ip
	}
	return prefix.Contains(ip)
}

// IsValidAt checks if the network rule is active and within its time window.
func (an *AllowedNetwork) IsValidAt(now time.Time) bool {
	if !an.IsActive {
		return false
	}
	if an.ValidFrom != nil && an.ValidFrom.After(now) {
		return false
	}
	if an.ValidUntil != nil && an.ValidUntil.Before(now) {
		return false
	}
	return true
}

// AccessGrant represents a granted port authorization session for a source IP.
type AccessGrant struct {
	ID                 int64      `json:"id"`
	AccessKeyID        *int64     `json:"access_key_id"`
	AllowedNetworkID   *int64     `json:"allowed_network_id"`
	GrantSource        string     `json:"grant_source"` // "password", "always_allowed", "admin"
	SourceIP           string     `json:"source_ip"`
	IPv6PrefixLength   *int       `json:"ipv6_prefix_length"`
	ExtensionCount     int        `json:"extension_count"`
	Status             string     `json:"status"` // "active", "expired", "revoked"
	VisitorTokenHash   string     `json:"-"`
	GrantedAt          time.Time  `json:"granted_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
	Ports              []PortRule `json:"ports"`
	AccessKeyName      string     `json:"access_key_name,omitempty"`
	AllowedNetworkName string     `json:"allowed_network_name,omitempty"`
}

// IsActiveAt checks if grant is active and not expired at the given time.
func (g *AccessGrant) IsActiveAt(now time.Time) bool {
	return g.Status == "active" && g.ExpiresAt.After(now)
}

// AuditEvent represents a logged operational or security event.
type AuditEvent struct {
	ID              int64     `json:"id"`
	EventType       string    `json:"event_type"`
	ActorType       string    `json:"actor_type"`       // "visitor", "admin", "system"
	ActorIdentifier string    `json:"actor_identifier"` // username, key name, or IP
	TargetIP        string    `json:"target_ip"`
	DetailsJSON     string    `json:"details_json"`
	CreatedAt       time.Time `json:"created_at"`
}
