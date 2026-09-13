package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/policy"
	"github.com/AhmadShamli/Funnel/internal/web"
)

type VisitorHandlers struct {
	cfg         *config.Config
	db          *database.DB
	engine      *policy.Engine
	rateLimiter *auth.RateLimiter
	tm          *web.TemplateManager
}

func NewVisitorHandlers(cfg *config.Config, db *database.DB, engine *policy.Engine, rl *auth.RateLimiter, tm *web.TemplateManager) *VisitorHandlers {
	return &VisitorHandlers{
		cfg:         cfg,
		db:          db,
		engine:      engine,
		rateLimiter: rl,
		tm:          tm,
	}
}

func (h *VisitorHandlers) HandleIndex(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()

	var tokenCookie string
	if c, err := r.Cookie("funnel_grant"); err == nil {
		tokenCookie = c.Value
	}

	result, err := h.engine.EvaluateVisitor(r.Context(), clientIP, tokenCookie, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If visitor already has an active grant, redirect them to /access/current
	if result.HasActiveGrant {
		http.Redirect(w, r, "/access/current", http.StatusSeeOther)
		return
	}

	// Set HTTP status code for rate limiting
	if result.RateLimitStatus.Blocked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", result.RateLimitStatus.RetryAfterSeconds))
		if result.RateLimitStatus.Level == 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
		} else {
			w.WriteHeader(http.StatusTooManyRequests) // 429
		}
	}

	data := map[string]interface{}{
		"ClientIP":        clientIP.String(),
		"CSRFToken":       GetCSRFToken(r),
		"RateLimitStatus": result.RateLimitStatus,
		"IsAlwaysAllowed": result.IsAlwaysAllowed,
		"Error":           r.URL.Query().Get("error"),
	}

	_ = h.tm.Render(w, "visitor_index", data)
}

func (h *VisitorHandlers) HandleAccess(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	password := r.FormValue("password")
	now := time.Now().UTC()

	if password == "" {
		http.Redirect(w, r, "/?error=Password+is+required", http.StatusSeeOther)
		return
	}

	grant, rawToken, err := h.engine.AuthenticateVisitor(r.Context(), clientIP, password, now)
	if err != nil {
		http.Redirect(w, r, "/?error="+err.Error(), http.StatusSeeOther)
		return
	}

	// Set secure visitor cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "funnel_grant",
		Value:    rawToken,
		Path:     "/",
		Expires:  grant.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
	})

	http.Redirect(w, r, "/access/current", http.StatusSeeOther)
}

func (h *VisitorHandlers) HandleStatus(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()

	var tokenCookie string
	if c, err := r.Cookie("funnel_grant"); err == nil {
		tokenCookie = c.Value
	}

	result, err := h.engine.EvaluateVisitor(r.Context(), clientIP, tokenCookie, now)
	if err != nil || !result.HasActiveGrant {
		// If no active grant, redirect to index
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"ClientIP":         clientIP.String(),
		"CSRFToken":        GetCSRFToken(r),
		"Grant":            result.Grant,
		"AllowedPorts":     result.AllowedPorts,
		"PortGroups":       result.PortGroups,
		"RemainingSeconds": result.RemainingSeconds,
		"CanExtend":        result.CanExtend,
		"FlashSuccess":     r.URL.Query().Get("success"),
		"FlashError":       r.URL.Query().Get("error"),
	}

	_ = h.tm.Render(w, "visitor_status", data)
}

func (h *VisitorHandlers) HandleCheckPorts(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()

	var tokenCookie string
	if c, err := r.Cookie("funnel_grant"); err == nil {
		tokenCookie = c.Value
	}

	result, err := h.engine.EvaluateVisitor(r.Context(), clientIP, tokenCookie, now)
	if err != nil || !result.HasActiveGrant {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "No active access grant found",
			"active":    false,
			"client_ip": clientIP.String(),
			"ports":     []PortCheckStatus{},
		})
		return
	}

	candidates := GetProbeCandidates(r.Host, h.cfg)

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	portStatuses := CheckPortsConcurrently(ctx, result.AllowedPorts, candidates, 500*time.Millisecond)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"active":            true,
		"client_ip":         clientIP.String(),
		"remaining_seconds": result.RemainingSeconds,
		"checked_at":        now.Format(time.RFC3339),
		"ports":             portStatuses,
	})
}

func (h *VisitorHandlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()

	cookie, err := r.Cookie("funnel_grant")
	if err == nil && cookie.Value != "" {
		tokenHash := auth.HashToken(cookie.Value)
		grant, err := h.db.GetAccessGrantByTokenHash(r.Context(), tokenHash)
		if err == nil && grant != nil && grant.IsActiveAt(now) {
			_ = h.engine.RevokeGrant(r.Context(), grant.ID, clientIP, now)
		}
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "funnel_grant",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *VisitorHandlers) HandleExtend(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)
	now := time.Now().UTC()
	candidatePassword := r.FormValue("password")

	cookie, err := r.Cookie("funnel_grant")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tokenHash := auth.HashToken(cookie.Value)
	grant, err := h.db.GetAccessGrantByTokenHash(r.Context(), tokenHash)
	if err != nil || grant == nil || !grant.IsActiveAt(now) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Extend via policy engine
	extended, err := h.engine.ExtendGrant(r.Context(), grant.ID, clientIP, candidatePassword, false, nil, now)
	if err != nil {
		http.Redirect(w, r, "/access/current?error="+err.Error(), http.StatusSeeOther)
		return
	}

	// Update cookie expiration
	http.SetCookie(w, &http.Cookie{
		Name:     "funnel_grant",
		Value:    cookie.Value,
		Path:     "/",
		Expires:  extended.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.cfg.CookieSecure,
	})

	http.Redirect(w, r, "/access/current?success=Session+duration+successfully+extended", http.StatusSeeOther)
}
