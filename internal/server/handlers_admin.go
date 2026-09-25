package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
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
	customText := strings.TrimSpace(r.FormValue("custom_text"))
	if customText == "" {
		customText = strings.TrimSpace(r.FormValue("bbcode"))
	}
	if customText == "" {
		customText = strings.TrimSpace(r.FormValue("text"))
	}
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

	portRules, err := parsePortRulesFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/admin/port-groups?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	pg := &models.PortGroup{
		Name:                 name,
		Description:          desc,
		CustomText:           customText,
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

	customText := strings.TrimSpace(r.FormValue("custom_text"))
	if customText == "" {
		customText = strings.TrimSpace(r.FormValue("bbcode"))
	}
	if customText == "" {
		customText = strings.TrimSpace(r.FormValue("text"))
	}
	pg.CustomText = customText

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

	portRules, err := parsePortRulesFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/admin/port-groups?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
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

// parsePortRulesFromRequest extracts and expands both single ports and port ranges from submitted form data.
func parsePortRulesFromRequest(r *http.Request) ([]models.PortRule, error) {
	_ = r.ParseForm()
	protocols := r.Form["port_protocol[]"]
	ports := r.Form["port_number[]"]

	rangeProtocols := r.Form["port_range_protocol[]"]
	rangeStarts := r.Form["port_range_start[]"]
	rangeEnds := r.Form["port_range_end[]"]

	seen := make(map[string]bool)
	var portRules []models.PortRule

	addRule := func(proto string, port int) {
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto != "udp" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%s/%d", proto, port)
		if !seen[key] && port >= 1 && port <= 65535 {
			seen[key] = true
			portRules = append(portRules, models.PortRule{Protocol: proto, Port: port})
		}
	}

	// 1. Process port_number[] entries (supports single "80", ranges "8000-8010", "8000:8010", or comma-separated)
	for i := 0; i < len(ports); i++ {
		raw := strings.TrimSpace(ports[i])
		if raw == "" {
			continue
		}
		proto := "tcp"
		if i < len(protocols) && strings.ToLower(strings.TrimSpace(protocols[i])) == "udp" {
			proto = "udp"
		}

		for _, token := range strings.Split(raw, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}

			// Check if token contains a range separator (- or :)
			if strings.Contains(token, "-") || strings.Contains(token, ":") {
				parts := strings.FieldsFunc(token, func(r rune) bool {
					return r == '-' || r == ':'
				})
				if len(parts) == 2 {
					start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
					end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
					if err1 != nil || err2 != nil || start < 1 || start > 65535 || end < 1 || end > 65535 {
						return nil, fmt.Errorf("invalid port range %q: ports must be between 1 and 65535", token)
					}
					if start > end {
						start, end = end, start
					}
					if end-start+1 > 1000 {
						return nil, fmt.Errorf("port range %q exceeds maximum allowed span of 1000 ports", token)
					}
					for p := start; p <= end; p++ {
						addRule(proto, p)
					}
				} else {
					return nil, fmt.Errorf("invalid port range format %q", token)
				}
			} else {
				pNum, err := strconv.Atoi(token)
				if err != nil || pNum < 1 || pNum > 65535 {
					return nil, fmt.Errorf("invalid port number %q: must be between 1 and 65535", token)
				}
				addRule(proto, pNum)
			}
		}
	}

	// 2. Process dedicated port range inputs (port_range_start[] and port_range_end[])
	for i := 0; i < len(rangeStarts); i++ {
		startStr := strings.TrimSpace(rangeStarts[i])
		var endStr string
		if i < len(rangeEnds) {
			endStr = strings.TrimSpace(rangeEnds[i])
		}
		if startStr == "" && endStr == "" {
			continue
		}
		if startStr == "" {
			startStr = endStr
		}
		if endStr == "" {
			endStr = startStr
		}

		proto := "tcp"
		if i < len(rangeProtocols) && strings.ToLower(strings.TrimSpace(rangeProtocols[i])) == "udp" {
			proto = "udp"
		}

		start, err1 := strconv.Atoi(startStr)
		end, err2 := strconv.Atoi(endStr)
		if err1 != nil || err2 != nil || start < 1 || start > 65535 || end < 1 || end > 65535 {
			return nil, fmt.Errorf("invalid port range %s-%s: ports must be between 1 and 65535", startStr, endStr)
		}
		if start > end {
			start, end = end, start
		}
		if end-start+1 > 1000 {
			return nil, fmt.Errorf("port range %d-%d exceeds maximum allowed span of 1000 ports", start, end)
		}
		for p := start; p <= end; p++ {
			addRule(proto, p)
		}
	}

	// Deterministic sort: protocol ("tcp" then "udp"), then port ASC
	sort.Slice(portRules, func(i, j int) bool {
		if portRules[i].Protocol != portRules[j].Protocol {
			return portRules[i].Protocol < portRules[j].Protocol
		}
		return portRules[i].Port < portRules[j].Port
	})

	return portRules, nil
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

// --- Open Ports ---

func (h *AdminHandlers) HandleOpenPortsGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()

	// 1. Fetch all active grants
	grants, err := h.db.ListActiveGrantsAll(ctx, now)
	if err != nil {
		grants = []models.AccessGrant{}
	}

	// 2. Fetch all configured port groups
	portGroups, err := h.db.ListPortGroups(ctx)
	if err != nil {
		portGroups = []models.PortGroup{}
	}

	pgNameMap := make(map[string]string)
	pgFullMap := make(map[string][]string)
	for _, pg := range portGroups {
		for _, p := range pg.Ports {
			key := fmt.Sprintf("%d/%s", p.Port, strings.ToLower(p.Protocol))
			if _, exists := pgNameMap[key]; !exists {
				pgNameMap[key] = pg.Name
			}
			pgFullMap[key] = append(pgFullMap[key], pg.Name)
		}
	}

	// 3. Fetch active firewall rules from kernel/backend
	rulesResp, _ := h.helper.Execute(ctx, firewall.HelperRequest{Action: "list_rules"})
	kernelRulesMap := make(map[string]bool)
	if rulesResp != nil {
		for _, rule := range rulesResp.Rules {
			key := fmt.Sprintf("%d/%s", rule.Port, strings.ToLower(rule.Protocol))
			kernelRulesMap[key] = true
		}
	}

	// 4. Fetch system listening sockets
	rawSockets := GetSystemListeningSockets()
	listeningPortsMap := make(map[string]bool)
	for _, s := range rawSockets {
		key := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		listeningPortsMap[key] = true
	}

	// 5. Aggregate active open firewall ports
	openPortsMap := make(map[string]*OpenPortSummary)
	for _, g := range grants {
		label := g.GrantSource
		if g.AccessKeyName != "" {
			label = g.AccessKeyName
		} else if g.AllowedNetworkName != "" {
			label = g.AllowedNetworkName
		}

		remSec := int(g.ExpiresAt.Sub(now).Seconds())
		if remSec < 0 {
			remSec = 0
		}

		for _, p := range g.Ports {
			proto := strings.ToLower(p.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			ruleKey := fmt.Sprintf("%d/%s", p.Port, proto)

			summary, exists := openPortsMap[ruleKey]
			if !exists {
				summary = &OpenPortSummary{
					Port:             p.Port,
					Protocol:         proto,
					RuleKey:          ruleKey,
					PortGroupName:    pgNameMap[ruleKey],
					KernelRuleActive: kernelRulesMap[ruleKey],
					Listening:        listeningPortsMap[ruleKey],
				}
				openPortsMap[ruleKey] = summary
			}

			summary.ActiveGrantsCount++
			summary.ClientIPs = append(summary.ClientIPs, g.SourceIP)
			summary.Grants = append(summary.Grants, OpenPortGrantRef{
				GrantID:          g.ID,
				SourceIP:         g.SourceIP,
				GrantSource:      g.GrantSource,
				SourceLabel:      label,
				GrantedAt:        g.GrantedAt,
				ExpiresAt:        g.ExpiresAt,
				RemainingSeconds: remSec,
			})
		}
	}

	// Deduplicate client IPs and create sorted open ports slice
	var openPortsList []OpenPortSummary
	for _, summary := range openPortsMap {
		seenIPs := make(map[string]bool)
		var uniqueIPs []string
		for _, ip := range summary.ClientIPs {
			if !seenIPs[ip] {
				seenIPs[ip] = true
				uniqueIPs = append(uniqueIPs, ip)
			}
		}
		summary.ClientIPs = uniqueIPs
		openPortsList = append(openPortsList, *summary)
	}

	sort.Slice(openPortsList, func(i, j int) bool {
		if openPortsList[i].Port != openPortsList[j].Port {
			return openPortsList[i].Port < openPortsList[j].Port
		}
		return openPortsList[i].Protocol < openPortsList[j].Protocol
	})

	// Enrich system listening sockets with Funnel context
	var systemSockets []SystemListeningSocket
	for _, s := range rawSockets {
		ruleKey := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		s.MatchedPortGroups = pgFullMap[ruleKey]

		if summary, hasGrant := openPortsMap[ruleKey]; hasGrant {
			s.FunnelStatus = "active_grant"
			s.ActiveGrantsCount = summary.ActiveGrantsCount
		} else if len(s.MatchedPortGroups) > 0 {
			s.FunnelStatus = "configured"
		} else if s.Scope == "localhost" {
			s.FunnelStatus = "localhost"
		} else {
			s.FunnelStatus = "exposed"
		}
		systemSockets = append(systemSockets, s)
	}

	data := h.baseData(r, "open_ports")
	data["OpenPorts"] = openPortsList
	data["ListeningSockets"] = systemSockets
	data["PortGroups"] = portGroups
	data["TotalOpenPortsCount"] = len(openPortsList)
	data["ActiveGrantsCount"] = len(grants)
	data["ListeningSocketsCount"] = len(systemSockets)
	data["ConfiguredPortGroupsCount"] = len(portGroups)
	data["ActiveBackend"] = h.helper.Backend()

	_ = h.tm.Render(w, "admin_open_ports", data)
}

func (h *AdminHandlers) HandleOpenPortsCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var portsToCheck []models.PortRule
	seen := make(map[string]bool)

	addPort := func(port int, proto string) {
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%d/%s", port, proto)
		if seen[key] || port <= 0 || port > 65535 {
			return
		}
		seen[key] = true
		portsToCheck = append(portsToCheck, models.PortRule{Port: port, Protocol: proto})
	}

	// 1. Check if specific ports requested in query param
	portsParam := strings.TrimSpace(r.URL.Query().Get("ports"))
	if portsParam != "" {
		for _, part := range strings.Split(portsParam, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			var proto string = "tcp"
			portPart := part
			if strings.Contains(part, "/") {
				sub := strings.SplitN(part, "/", 2)
				portPart = sub[0]
				proto = sub[1]
			}
			if strings.Contains(portPart, "-") || strings.Contains(portPart, ":") {
				rangeTokens := strings.FieldsFunc(portPart, func(r rune) bool {
					return r == '-' || r == ':'
				})
				if len(rangeTokens) == 2 {
					s, err1 := strconv.Atoi(strings.TrimSpace(rangeTokens[0]))
					e, err2 := strconv.Atoi(strings.TrimSpace(rangeTokens[1]))
					if err1 == nil && err2 == nil && s >= 1 && s <= 65535 && e >= 1 && e <= 65535 {
						if s > e {
							s, e = e, s
						}
						if e-s+1 <= 1000 {
							for p := s; p <= e; p++ {
								addPort(p, proto)
							}
						}
					}
				}
			} else {
				p, err := strconv.Atoi(portPart)
				if err == nil && p > 0 {
					addPort(p, proto)
				}
			}
		}
	}

	// 2. If no ports specified, check all open firewall ports and listening sockets
	if len(portsToCheck) == 0 {
		now := time.Now().UTC()
		grants, _ := h.db.ListActiveGrantsAll(ctx, now)
		for _, g := range grants {
			for _, p := range g.Ports {
				addPort(p.Port, p.Protocol)
			}
		}

		listening := GetSystemListeningSockets()
		for _, s := range listening {
			addPort(s.Port, s.Protocol)
		}
	}

	candidates := GetProbeCandidates(r.Host, h.cfg)
	results := CheckPortsConcurrently(ctx, portsToCheck, candidates, 500*time.Millisecond)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"count":      len(results),
		"ports":      results,
	})
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
	target := "/admin/grants?success=Grant+revoked"
	if r.URL.Query().Get("from") == "open-ports" || strings.Contains(r.Header.Get("Referer"), "open-ports") {
		target = "/admin/open-ports?success=Grant+revoked"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
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
