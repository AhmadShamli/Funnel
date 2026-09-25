package server

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/web"
)

type SetupHandlers struct {
	cfg               *config.Config
	db                *database.DB
	tm                *web.TemplateManager
	bootstrapToken    *string
	adminPathProvider func() string
}

func NewSetupHandlers(cfg *config.Config, db *database.DB, tm *web.TemplateManager, bootstrapToken *string, adminPathProvider func() string) *SetupHandlers {
	return &SetupHandlers{
		cfg:               cfg,
		db:                db,
		tm:                tm,
		bootstrapToken:    bootstrapToken,
		adminPathProvider: adminPathProvider,
	}
}

func (h *SetupHandlers) adminLoginURL(query string) string {
	prefix := "/admin"
	if h.adminPathProvider != nil {
		prefix = h.adminPathProvider()
	}
	url := prefix + "/login"
	if query != "" {
		if !strings.HasPrefix(query, "?") {
			query = "?" + query
		}
		url += query
	}
	return url
}

func (h *SetupHandlers) HandleSetupGet(w http.ResponseWriter, r *http.Request) {
	count, err := h.db.CountAdminUsers(r.Context())
	if err != nil || count > 0 {
		http.Redirect(w, r, h.adminLoginURL(""), http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"CSRFToken": GetCSRFToken(r),
		"Error":     r.URL.Query().Get("error"),
	}

	_ = h.tm.Render(w, "setup", data)
}

func (h *SetupHandlers) HandleSetupPost(w http.ResponseWriter, r *http.Request) {
	count, err := h.db.CountAdminUsers(r.Context())
	if err != nil || count > 0 {
		http.Redirect(w, r, h.adminLoginURL(""), http.StatusSeeOther)
		return
	}

	token := strings.TrimSpace(r.FormValue("bootstrap_token"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	// Validate bootstrap token
	expectedToken := ""
	if h.bootstrapToken != nil {
		expectedToken = *h.bootstrapToken
	}

	if expectedToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
		http.Redirect(w, r, "/setup?error=Invalid+bootstrap+token", http.StatusSeeOther)
		return
	}

	if len(username) < 3 {
		http.Redirect(w, r, "/setup?error=Username+must+be+at+least+3+characters", http.StatusSeeOther)
		return
	}

	if password != confirm {
		http.Redirect(w, r, "/setup?error=Passwords+do+not+match", http.StatusSeeOther)
		return
	}

	hash, err := auth.HashAdminPassword(password, h.cfg.AdminMinPasswordLen)
	if err != nil {
		http.Redirect(w, r, "/setup?error="+err.Error(), http.StatusSeeOther)
		return
	}

	admin := &models.AdminUser{
		Username:     username,
		PasswordHash: hash,
		Role:         "admin",
		IsActive:     true,
		AllowExtend:  true,
	}

	if err := h.db.CreateAdminUser(r.Context(), admin); err != nil {
		http.Redirect(w, r, "/setup?error=Failed+to+create+admin+user:+"+err.Error(), http.StatusSeeOther)
		return
	}

	// Invalidate bootstrap token permanently
	*h.bootstrapToken = ""

	_ = h.db.RecordAuditEvent(r.Context(), &models.AuditEvent{
		EventType:       "ADMIN_SETUP_COMPLETED",
		ActorType:       "system",
		ActorIdentifier: username,
		TargetIP:        GetClientIP(r).String(),
		DetailsJSON:     `{"message":"initial admin account bootstrapped"}`,
	})

	http.Redirect(w, r, h.adminLoginURL("success=Setup+complete.+Please+sign+in."), http.StatusSeeOther)
}
