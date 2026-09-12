package server

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/ipresolver"
	"github.com/AhmadShamli/Funnel/internal/models"
)

type contextKey string

const (
	clientIPContextKey     contextKey = "client_ip"
	csrfTokenContextKey    contextKey = "csrf_token"
	adminUserContextKey    contextKey = "admin_user"
	adminSessionContextKey contextKey = "admin_session"
)

// ClientIPMiddleware extracts the real client IP using the IP resolver.
func ClientIPMiddleware(resolver *ipresolver.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolver.ResolveClientIP(r)
			ctx := context.WithValue(r.Context(), clientIPContextKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClientIP retrieves client IP from request context.
func GetClientIP(r *http.Request) netip.Addr {
	if ip, ok := r.Context().Value(clientIPContextKey).(netip.Addr); ok {
		return ip
	}
	return netip.Addr{}
}

// CSRFMiddleware manages CSRF cookie issuance and validation.
func CSRFMiddleware(secureCookie bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string
			cookie, err := r.Cookie("funnel_csrf")
			if err == nil && cookie.Value != "" {
				token = cookie.Value
			} else {
				token, _ = auth.GenerateRandomToken(16)
				http.SetCookie(w, &http.Cookie{
					Name:     "funnel_csrf",
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Secure:   secureCookie,
				})
			}

			// Validate token on state-changing requests
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				formToken := r.FormValue("csrf_token")
				if formToken == "" {
					formToken = r.Header.Get("X-CSRF-Token")
				}
				if formToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(formToken)) != 1 {
					http.Error(w, "CSRF token validation failed", http.StatusForbidden)
					return
				}
			}

			ctx := context.WithValue(r.Context(), csrfTokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetCSRFToken retrieves CSRF token from request context.
func GetCSRFToken(r *http.Request) string {
	if token, ok := r.Context().Value(csrfTokenContextKey).(string); ok {
		return token
	}
	return ""
}

// AdminAuthMiddleware validates admin session and injects user and session into context.
func AdminAuthMiddleware(db *database.DB, idleTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("funnel_admin_session")
			if err != nil || cookie.Value == "" {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}

			now := time.Now().UTC()
			tokenHash := auth.HashToken(cookie.Value)
			session, err := db.GetAdminSessionByTokenHash(r.Context(), tokenHash)
			if err != nil || session == nil || session.IsExpired(now, idleTimeout) {
				// Clear invalid session cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "funnel_admin_session",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
				})
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}

			// Check admin user state
			user, err := db.GetAdminUserByID(r.Context(), session.AdminUserID)
			if err != nil || user == nil || !user.IsValidAt(now) || user.IsLocked(now) {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}

			// Touch session activity timestamp
			_ = db.TouchAdminSession(r.Context(), session.ID, now)

			ctx := context.WithValue(r.Context(), adminUserContextKey, user)
			ctx = context.WithValue(ctx, adminSessionContextKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAdminUser retrieves active admin user from request context.
func GetAdminUser(r *http.Request) *models.AdminUser {
	if u, ok := r.Context().Value(adminUserContextKey).(*models.AdminUser); ok {
		return u
	}
	return nil
}
