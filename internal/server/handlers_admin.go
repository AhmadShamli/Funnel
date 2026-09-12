package server

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/ipresolver"
	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/policy"
	"github.com/AhmadShamli/Funnel/internal/web"
	"github.com/go-chi/chi/v5"
)

type AdminHandlers struct {
	cfg         *config.Config
	db          *database.DB
	engine      *policy.Engine
	rateLimiter *auth.RateLimiter
	resolver    *ipresolver.Resolver
	helper      *firewall.HelperClient
	factory     *firewall.Factory
	tm          *web.TemplateManager
}

func NewAdminHandlers(
	cfg *config.Config,
	db *database.DB,
	engine *policy.Engine,
	rl *auth.RateLimiter,
	resolver *ipresolver.Resolver,
	helper *firewall.HelperClient,
	factory *firewall.Factory,
	tm *web.TemplateManager,
) *AdminHandlers {
	return &AdminHandlers{
		cfg:         cfg,
		db:          db,
		engine:      engine,
		rateLimiter: rl,
		resolver:    resolver,
		helper:      helper,
		factory:     factory,
		tm:          tm,
	}
}

// --- Auth Handlers ---

func (h *AdminHandlers) HandleLoginGet(w http.ResponseWriter, r *http.Request) {
	// If zero admins, redirect to setup wizard
	count, _ := h.db.CountAdminUsers(r.Context())
	if count == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"CSRFToken": GetCSRFToken(r),
		"Error":     r.URL.Query().Get("error"),
	}
	_ = h.tm.Render(w, "admin_login", data)
}

func (h *AdminHandlers) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Rate limit check
	rlResult := h.rateLimiter.CheckAdminLogin(clientIP.String(), now)
	if rlResult.Blocked {
		http.Redirect(w, r, fmt.Sprintf("/admin/login?error=Rate+limit+exceeded.+Retry+in+%d+seconds", rlResult.RetryAfterSeconds), http.StatusSeeOther)
		return
	}

	user, err := h.db.GetAdminUserByUsername(r.Context(), username)
	if err != nil || user == nil || !user.IsValidAt(now) || user.IsLocked(now) {
		_, lockUser := h.rateLimiter.RecordAdminFailure(clientIP.String(), username, now)
		if user != nil {
			var lockUntil *time.Time
			if lockUser || user.FailedLoginCount >= 4 {
				t := now.Add(15 * time.Minute)
				lockUntil = &t
			}
			_ = h.db.IncrementAdminFailedLogin(r.Context(), user.ID, lockUntil)
		}

		_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
			EventType:       "ADMIN_LOGIN_FAILED",
			ActorType:       "admin",
			ActorIdentifier: username,
			TargetIP:        clientIP.String(),
			DetailsJSON:     `{"reason":"invalid credentials or account locked"}`,
		})
		http.Redirect(w, r, "/admin/login?error=Invalid+username+or+password", http.StatusSeeOther)
		return
	}

	if !auth.CheckAdminPassword(user.PasswordHash, password) {
		_, lockUser := h.rateLimiter.RecordAdminFailure(clientIP.String(), username, now)
		var lockUntil *time.Time
		if lockUser || user.FailedLoginCount >= 4 {
			t := now.Add(15 * time.Minute)
			lockUntil = &t
		}
		_ = h.db.IncrementAdminFailedLogin(r.Context(), user.ID, lockUntil)

		_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
			EventType:       "ADMIN_LOGIN_FAILED",
			ActorType:       "admin",
			ActorIdentifier: username,
			TargetIP:        clientIP.String(),
			DetailsJSON:     `{"reason":"incorrect password"}`,
		})
		http.Redirect(w, r, "/admin/login?error=Invalid+username+or+password", http.StatusSeeOther)
		return
	}

	// Successful login: reset failed login count
	_ = h.db.ResetAdminFailedLogin(r.Context(), user.ID)

	// Issue session token
	rawSessionToken, _ := auth.GenerateRandomToken(32)
	session := &models.AdminSession{
		AdminUserID:      user.ID,
		SessionTokenHash: auth.HashToken(rawSessionToken),
		UserAgent:        r.UserAgent(),
		ClientIP:         clientIP.String(),
		CreatedAt:        now,
		LastActivityAt:   now,
		ExpiresAt:        now.Add(h.cfg.SessionMaxLifetime),
	}

	if err := h.db.CreateAdminSession(r.Context(), session); err != nil {
		http.Redirect(w, r, "/admin/login?error=Failed+to+create+session", http.StatusSeeOther)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "funnel_admin_session",
		Value:    rawSessionToken,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
	})

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "ADMIN_LOGIN_SUCCESS",
		ActorType:       "admin",
		ActorIdentifier: user.Username,
		TargetIP:        clientIP.String(),
		DetailsJSON:     `{"status":"authenticated"}`,
	})

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("funnel_admin_session"); err == nil && cookie.Value != "" {
		tokenHash := auth.HashToken(cookie.Value)
		_ = h.db.DeleteAdminSession(r.Context(), tokenHash)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "funnel_admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// --- Dashboard ---

func (h *AdminHandlers) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	activeGrants, _ := h.db.ListActiveGrantsAll(r.Context(), now)
	keys, _ := h.db.ListAccessKeys(r.Context())
	groups, _ := h.db.ListPortGroups(r.Context())
	events, _ := h.db.ListAuditEvents(r.Context(), "", 10, 0)

	activeKeysCount := 0
	for _, k := range keys {
		if k.IsValidAt(now) {
			activeKeysCount++
		}
	}

	cbActive, _ := h.rateLimiter.IsCircuitBreakerActive(now)

	data := h.baseData(r, "dashboard")
	data["ActiveGrantsCount"] = len(activeGrants)
	data["ActiveKeysCount"] = activeKeysCount
	data["PortGroupsCount"] = len(groups)
	data["RecentEvents"] = events
	data["ActiveBackend"] = h.cfg.FirewallBackend
	data["CircuitBreakerActive"] = cbActive

	_ = h.tm.Render(w, "admin_dashboard", data)
}

// --- Access Keys ---

func (h *AdminHandlers) HandleAccessKeysGet(w http.ResponseWriter, r *http.Request) {
	keys, _ := h.db.ListAccessKeys(r.Context())
	groups, _ := h.db.ListPortGroups(r.Context())

	data := h.baseData(r, "keys")
	data["Keys"] = keys
	data["PortGroups"] = groups

	_ = h.tm.Render(w, "admin_keys", data)
}

func (h *AdminHandlers) HandleAccessKeysPost(w http.ResponseWriter, r *http.Request) {
	adminUser := GetAdminUser(r)
	name := strings.TrimSpace(r.FormValue("name"))
	password := strings.TrimSpace(r.FormValue("password"))

	if name == "" || password == "" {
		http.Redirect(w, r, "/admin/access-keys?error=Name+and+password+are+required", http.StatusSeeOther)
		return
	}

	var portGroupIDs []int64
	_ = r.ParseForm()
	for _, rawID := range r.Form["port_group_ids[]"] {
		if id, err := strconv.ParseInt(rawID, 10, 64); err == nil {
			portGroupIDs = append(portGroupIDs, id)
		}
	}

	var maxConcurrent, maxUses, maxDuration, maxExt *int
	if v := r.FormValue("max_concurrent_ips"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxConcurrent = &n
		}
	}
	if v := r.FormValue("max_total_uses"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxUses = &n
		}
	}
	if v := r.FormValue("max_duration_seconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxDuration = &n
		}
	}
	if v := r.FormValue("max_extensions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxExt = &n
		}
	}

	var validUntil *time.Time
	if v := r.FormValue("valid_until"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
			utc := t.UTC()
			validUntil = &utc
		}
	}

	allowExtend := r.FormValue("allow_extend") == "1"
	passHash := auth.HashAccessKey(h.cfg.SecretKey, password)

	key := &models.AccessKey{
		Name:               name,
		PasswordHash:       passHash,
		IsActive:           true,
		AllowExtend:        allowExtend,
		MaxExtensions:      maxExt,
		MaxConcurrentIPs:   maxConcurrent,
		MaxTotalUses:       maxUses,
		MaxDurationSeconds: maxDuration,
		ValidUntil:         validUntil,
		CreatedByAdminID:   &adminUser.ID,
		PortGroupIDs:       portGroupIDs,
	}

	if err := h.db.CreateAccessKey(r.Context(), key); err != nil {
		http.Redirect(w, r, "/admin/access-keys?error="+err.Error(), http.StatusSeeOther)
		return
	}

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "ACCESS_KEY_CREATED",
		ActorType:       "admin",
		ActorIdentifier: adminUser.Username,
		TargetIP:        "",
		DetailsJSON:     fmt.Sprintf(`{"key_name":"%s"}`, name),
	})

	http.Redirect(w, r, "/admin/access-keys?success=Access+key+created", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleAccessKeysToggle(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	key, err := h.db.GetAccessKeyByID(r.Context(), id)
	if err == nil && key != nil {
		key.IsActive = !key.IsActive
		_ = h.db.UpdateAccessKey(r.Context(), key)
	}

	http.Redirect(w, r, "/admin/access-keys", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleAccessKeysDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	_ = h.db.DeleteAccessKey(r.Context(), id)
	http.Redirect(w, r, "/admin/access-keys", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleAccessKeysUpdate(w http.ResponseWriter, r *http.Request) {
	adminUser := GetAdminUser(r)
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/access-keys?error=Invalid+access+key+ID", http.StatusSeeOther)
		return
	}

	key, err := h.db.GetAccessKeyByID(r.Context(), id)
	if err != nil || key == nil {
		http.Redirect(w, r, "/admin/access-keys?error=Access+key+not+found", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/admin/access-keys?error=Key+name+is+required", http.StatusSeeOther)
		return
	}
	key.Name = name

	password := strings.TrimSpace(r.FormValue("password"))
	if password != "" {
		key.PasswordHash = auth.HashAccessKey(h.cfg.SecretKey, password)
	} else {
		key.PasswordHash = "" // Preserves existing password in db.UpdateAccessKey
	}

	var portGroupIDs []int64
	_ = r.ParseForm()
	for _, rawID := range r.Form["port_group_ids[]"] {
		if pgID, err := strconv.ParseInt(rawID, 10, 64); err == nil {
			portGroupIDs = append(portGroupIDs, pgID)
		}
	}
	key.PortGroupIDs = portGroupIDs

	var maxConcurrent, maxUses, maxDuration, maxExt *int
	if v := r.FormValue("max_concurrent_ips"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxConcurrent = &n
		}
	}
	key.MaxConcurrentIPs = maxConcurrent

	if v := r.FormValue("max_total_uses"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxUses = &n
		}
	}
	key.MaxTotalUses = maxUses

	if v := r.FormValue("max_duration_seconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxDuration = &n
		}
	}
	key.MaxDurationSeconds = maxDuration

	if v := r.FormValue("max_extensions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxExt = &n
		}
	}
	key.MaxExtensions = maxExt

	var validUntil *time.Time
	if v := r.FormValue("valid_until"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
			utc := t.UTC()
			validUntil = &utc
		}
	}
	key.ValidUntil = validUntil

	key.AllowExtend = r.FormValue("allow_extend") == "1"

	if err := h.db.UpdateAccessKey(r.Context(), key); err != nil {
		http.Redirect(w, r, "/admin/access-keys?error="+err.Error(), http.StatusSeeOther)
		return
	}

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "ACCESS_KEY_UPDATED",
		ActorType:       "admin",
		ActorIdentifier: adminUser.Username,
		TargetIP:        "",
		DetailsJSON:     fmt.Sprintf(`{"key_name":"%s"}`, name),
	})

	http.Redirect(w, r, "/admin/access-keys?success=Access+key+updated", http.StatusSeeOther)
}

// --- Port Groups ---

func (h *AdminHandlers) HandlePortGroupsGet(w http.ResponseWriter, r *http.Request) {
	groups, _ := h.db.ListPortGroups(r.Context())
	data := h.baseData(r, "port_groups")
	data["PortGroups"] = groups
	_ = h.tm.Render(w, "admin_port_groups", data)
}

func (h *AdminHandlers) HandlePortGroupsPost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	availMode := r.FormValue("availability_mode")
	duration, _ := strconv.Atoi(r.FormValue("grant_duration_seconds"))
	if duration <= 0 {
		duration = 3600
	}

	var maxExt *int
	if v := r.FormValue("max_extensions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxExt = &n
		}
	}
	allowExtend := r.FormValue("allow_extend") == "1"

	_ = r.ParseForm()
	protocols := r.Form["port_protocol[]"]
	ports := r.Form["port_number[]"]

	var portRules []models.PortRule
	for i := 0; i < len(ports); i++ {
		pNum, err := strconv.Atoi(ports[i])
		if err == nil && pNum >= 1 && pNum <= 65535 {
			proto := "tcp"
			if i < len(protocols) && strings.ToLower(protocols[i]) == "udp" {
				proto = "udp"
			}
			portRules = append(portRules, models.PortRule{Protocol: proto, Port: pNum})
		}
	}

	pg := &models.PortGroup{
		Name:                 name,
		Description:          desc,
		AvailabilityMode:     availMode,
		AllowExtend:          allowExtend,
		MaxExtensions:        maxExt,
		GrantDurationSeconds: duration,
		MaxDurationSeconds:   duration * 4,
		IsActive:             true,
		Ports:                portRules,
	}

	if err := h.db.CreatePortGroup(r.Context(), pg); err != nil {
		http.Redirect(w, r, "/admin/port-groups?error="+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/port-groups?success=Port+group+created", http.StatusSeeOther)
}

func (h *AdminHandlers) HandlePortGroupsDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	_ = h.db.DeletePortGroup(r.Context(), id)
	http.Redirect(w, r, "/admin/port-groups", http.StatusSeeOther)
}

func (h *AdminHandlers) HandlePortGroupsUpdate(w http.ResponseWriter, r *http.Request) {
	adminUser := GetAdminUser(r)
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/port-groups?error=Invalid+port+group+ID", http.StatusSeeOther)
		return
	}

	pg, err := h.db.GetPortGroupByID(r.Context(), id)
	if err != nil || pg == nil {
		http.Redirect(w, r, "/admin/port-groups?error=Port+group+not+found", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/admin/port-groups?error=Group+name+is+required", http.StatusSeeOther)
		return
	}
	pg.Name = name
	pg.Description = strings.TrimSpace(r.FormValue("description"))
	pg.AvailabilityMode = r.FormValue("availability_mode")

	duration, _ := strconv.Atoi(r.FormValue("grant_duration_seconds"))
	if duration <= 0 {
		duration = 3600
	}
	pg.GrantDurationSeconds = duration
	pg.MaxDurationSeconds = duration * 4

	var maxExt *int
	if v := r.FormValue("max_extensions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxExt = &n
		}
	}
	pg.MaxExtensions = maxExt
	pg.AllowExtend = r.FormValue("allow_extend") == "1"

	_ = r.ParseForm()
	protocols := r.Form["port_protocol[]"]
	ports := r.Form["port_number[]"]

	var portRules []models.PortRule
	for i := 0; i < len(ports); i++ {
		pNum, err := strconv.Atoi(ports[i])
		if err == nil && pNum >= 1 && pNum <= 65535 {
			proto := "tcp"
			if i < len(protocols) && strings.ToLower(protocols[i]) == "udp" {
				proto = "udp"
			}
			portRules = append(portRules, models.PortRule{Protocol: proto, Port: pNum})
		}
	}
	pg.Ports = portRules

	if err := h.db.UpdatePortGroup(r.Context(), pg); err != nil {
		http.Redirect(w, r, "/admin/port-groups?error="+err.Error(), http.StatusSeeOther)
		return
	}

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "PORT_GROUP_UPDATED",
		ActorType:       "admin",
		ActorIdentifier: adminUser.Username,
		TargetIP:        "",
		DetailsJSON:     fmt.Sprintf(`{"group_name":"%s"}`, name),
	})

	http.Redirect(w, r, "/admin/port-groups?success=Port+group+updated", http.StatusSeeOther)
}

// --- Allowed Networks ---

func (h *AdminHandlers) HandleAllowedNetworksGet(w http.ResponseWriter, r *http.Request) {
	networks, _ := h.db.ListAllowedNetworks(r.Context())
	groups, _ := h.db.ListPortGroups(r.Context())

	data := h.baseData(r, "networks")
	data["Networks"] = networks
	data["PortGroups"] = groups

	_ = h.tm.Render(w, "admin_networks", data)
}

func (h *AdminHandlers) HandleAllowedNetworksPost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("network_cidr"))
	mode := r.FormValue("mode")
	duration, _ := strconv.Atoi(r.FormValue("grant_duration_seconds"))
	if duration <= 0 {
		duration = 3600
	}

	var portGroupIDs []int64
	_ = r.ParseForm()
	for _, rawID := range r.Form["port_group_ids[]"] {
		if id, err := strconv.ParseInt(rawID, 10, 64); err == nil {
			portGroupIDs = append(portGroupIDs, id)
		}
	}

	an := &models.AllowedNetwork{
		Name:                 name,
		NetworkCIDR:          cidr,
		Mode:                 mode,
		Scope:                "global",
		AllowExtend:          true,
		GrantDurationSeconds: duration,
		IsActive:             true,
		PortGroupIDs:         portGroupIDs,
	}

	if err := h.db.CreateAllowedNetwork(r.Context(), an); err != nil {
		http.Redirect(w, r, "/admin/allowed-networks?error="+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/allowed-networks?success=Network+rule+created", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleAllowedNetworksDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	_ = h.db.DeleteAllowedNetwork(r.Context(), id)
	http.Redirect(w, r, "/admin/allowed-networks", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleAllowedNetworksUpdate(w http.ResponseWriter, r *http.Request) {
	adminUser := GetAdminUser(r)
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/allowed-networks?error=Invalid+network+rule+ID", http.StatusSeeOther)
		return
	}

	an, err := h.db.GetAllowedNetworkByID(r.Context(), id)
	if err != nil || an == nil {
		http.Redirect(w, r, "/admin/allowed-networks?error=Network+rule+not+found", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("network_cidr"))
	if name == "" || cidr == "" {
		http.Redirect(w, r, "/admin/allowed-networks?error=Name+and+CIDR+are+required", http.StatusSeeOther)
		return
	}
	an.Name = name
	an.NetworkCIDR = cidr
	an.Mode = r.FormValue("mode")

	duration, _ := strconv.Atoi(r.FormValue("grant_duration_seconds"))
	if duration <= 0 {
		duration = 3600
	}
	an.GrantDurationSeconds = duration

	var portGroupIDs []int64
	_ = r.ParseForm()
	for _, rawID := range r.Form["port_group_ids[]"] {
		if pgID, err := strconv.ParseInt(rawID, 10, 64); err == nil {
			portGroupIDs = append(portGroupIDs, pgID)
		}
	}
	an.PortGroupIDs = portGroupIDs

	if err := h.db.UpdateAllowedNetwork(r.Context(), an); err != nil {
		http.Redirect(w, r, "/admin/allowed-networks?error="+err.Error(), http.StatusSeeOther)
		return
	}

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "ALLOWED_NETWORK_UPDATED",
		ActorType:       "admin",
		ActorIdentifier: adminUser.Username,
		TargetIP:        "",
		DetailsJSON:     fmt.Sprintf(`{"network_name":"%s","cidr":"%s"}`, name, cidr),
	})

	http.Redirect(w, r, "/admin/allowed-networks?success=Network+rule+updated", http.StatusSeeOther)
}

// --- Active Grants ---

func (h *AdminHandlers) HandleGrantsGet(w http.ResponseWriter, r *http.Request) {
	grants, _ := h.db.ListGrants(r.Context(), "", 100, 0)
	data := h.baseData(r, "grants")
	data["Grants"] = grants
	_ = h.tm.Render(w, "admin_grants", data)
}

func (h *AdminHandlers) HandleGrantsRevoke(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	now := time.Now().UTC()

	_ = h.engine.RevokeGrant(r.Context(), id, netip.Addr{}, now)
	http.Redirect(w, r, "/admin/grants?success=Grant+revoked", http.StatusSeeOther)
}

// --- Firewalls ---

func (h *AdminHandlers) HandleFirewallsGet(w http.ResponseWriter, r *http.Request) {
	var backends []firewall.BackendInfo
	resp, err := h.helper.Execute(r.Context(), firewall.HelperRequest{Action: "detect"})
	if err == nil && resp != nil && len(resp.Backends) > 0 {
		backends = resp.Backends
	} else {
		backends = h.factory.DetectAll(r.Context())
	}

	rulesResp, _ := h.helper.Execute(r.Context(), firewall.HelperRequest{Action: "list_rules"})
	var activeRules []firewall.ActiveRule
	if rulesResp != nil {
		activeRules = rulesResp.Rules
	}

	data := h.baseData(r, "firewalls")
	data["Backends"] = backends
	data["ActiveRules"] = activeRules
	data["ActiveBackend"] = h.helper.Backend()

	_ = h.tm.Render(w, "admin_firewalls", data)
}

func (h *AdminHandlers) HandleFirewallsValidate(w http.ResponseWriter, r *http.Request) {
	resp, err := h.helper.Execute(r.Context(), firewall.HelperRequest{Action: "validate"})
	if err != nil || (resp != nil && !resp.Success) {
		msg := "Validation failed"
		if resp != nil && resp.Error != "" {
			msg += ": " + resp.Error
		}
		http.Redirect(w, r, "/admin/firewalls?error="+msg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/firewalls?success=Firewall+driver+validated+successfully", http.StatusSeeOther)
}

// --- Audit ---

func (h *AdminHandlers) HandleAuditGet(w http.ResponseWriter, r *http.Request) {
	events, _ := h.db.ListAuditEvents(r.Context(), "", 100, 0)
	data := h.baseData(r, "audit")
	data["Events"] = events
	_ = h.tm.Render(w, "admin_audit", data)
}

// --- Settings & Ingress ---

func (h *AdminHandlers) HandleSettingsGet(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	cbActive, _ := h.rateLimiter.IsCircuitBreakerActive(now)
	failedCount, thresh, _, _ := h.rateLimiter.GetCircuitBreakerStats(now)

	var trustedStrs []string
	for _, p := range h.resolver.GetTrustedProxies() {
		trustedStrs = append(trustedStrs, p.String())
	}

	data := h.baseData(r, "settings")
	data["ProxyMode"] = h.resolver.GetProxyMode()
	data["TrustedProxiesStr"] = strings.Join(trustedStrs, ", ")
	data["CircuitBreakerActive"] = cbActive
	data["FailedIPsCount"] = failedCount
	data["FailedIPsThreshold"] = thresh

	_ = h.tm.Render(w, "admin_settings", data)
}

func (h *AdminHandlers) HandleSettingsProxyPost(w http.ResponseWriter, r *http.Request) {
	mode := r.FormValue("proxy_mode")
	proxiesStr := r.FormValue("trusted_proxies")

	prefixes, err := config.ParseCIDRList(proxiesStr)
	if err != nil {
		http.Redirect(w, r, "/admin/settings?error=Invalid+CIDR+list", http.StatusSeeOther)
		return
	}

	h.resolver.SetProxyMode(mode)
	h.resolver.SetTrustedProxies(prefixes)

	http.Redirect(w, r, "/admin/settings?success=Proxy+settings+updated", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleSettingsSyncCloudflare(w http.ResponseWriter, r *http.Request) {
	prefixes, err := h.resolver.FetchCloudflareCIDRs(r.Context())
	if err != nil {
		http.Redirect(w, r, "/admin/settings?error="+err.Error(), http.StatusSeeOther)
		return
	}

	h.resolver.AddTrustedProxies(prefixes)
	http.Redirect(w, r, fmt.Sprintf("/admin/settings?success=Synced+%d+Cloudflare+CIDR+ranges", len(prefixes)), http.StatusSeeOther)
}

func (h *AdminHandlers) HandleCircuitBreakerReset(w http.ResponseWriter, r *http.Request) {
	h.rateLimiter.ResetCircuitBreaker()
	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "CIRCUIT_BREAKER_RESET",
		ActorType:       "admin",
		ActorIdentifier: GetAdminUser(r).Username,
		TargetIP:        "",
		DetailsJSON:     `{"action":"manual_reset"}`,
	})
	http.Redirect(w, r, "/admin?success=Circuit+breaker+reset+successfully", http.StatusSeeOther)
}

// --- Admin Users ---

func (h *AdminHandlers) HandleUsersGet(w http.ResponseWriter, r *http.Request) {
	users, _ := h.db.ListAdminUsers(r.Context())
	data := h.baseData(r, "users")
	data["Users"] = users
	_ = h.tm.Render(w, "admin_users", data)
}

func (h *AdminHandlers) HandleUsersPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	allowExtend := r.FormValue("allow_extend") == "1"

	var maxExt *int
	if v := r.FormValue("max_extensions"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxExt = &n
		}
	}

	hash, err := auth.HashAdminPassword(password, h.cfg.AdminMinPasswordLen)
	if err != nil {
		http.Redirect(w, r, "/admin/users?error="+err.Error(), http.StatusSeeOther)
		return
	}

	u := &models.AdminUser{
		Username:      username,
		PasswordHash:  hash,
		Role:          role,
		IsActive:      true,
		AllowExtend:   allowExtend,
		MaxExtensions: maxExt,
	}

	if err := h.db.CreateAdminUser(r.Context(), u); err != nil {
		http.Redirect(w, r, "/admin/users?error="+err.Error(), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/users?success=User+created", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleUsersToggle(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)

	u, err := h.db.GetAdminUserByID(r.Context(), id)
	if err == nil && u != nil {
		u.IsActive = !u.IsActive
		_ = h.db.UpdateAdminUser(r.Context(), u)
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *AdminHandlers) HandleUsersUnlock(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	_ = h.db.UnlockAdminUser(r.Context(), id)
	http.Redirect(w, r, "/admin/users?success=User+unlocked", http.StatusSeeOther)
}

// baseData prepares common template context variables.
func (h *AdminHandlers) baseData(r *http.Request, activeNav string) map[string]interface{} {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()
	cbActive, _ := h.rateLimiter.IsCircuitBreakerActive(now)

	return map[string]interface{}{
		"AdminUser":            GetAdminUser(r),
		"ClientIP":             clientIP.String(),
		"CSRFToken":            GetCSRFToken(r),
		"ActiveNav":            activeNav,
		"CircuitBreakerActive": cbActive,
		"FlashSuccess":         r.URL.Query().Get("success"),
		"FlashError":           r.URL.Query().Get("error"),
	}
}
