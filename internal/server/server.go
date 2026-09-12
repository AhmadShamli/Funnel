package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/ipresolver"
	"github.com/AhmadShamli/Funnel/internal/policy"
	"github.com/AhmadShamli/Funnel/internal/version"
	"github.com/AhmadShamli/Funnel/internal/web"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// Server encapsulates HTTP routing, middleware, and dependency wiring.
type Server struct {
	cfg            *config.Config
	db             *database.DB
	engine         *policy.Engine
	rateLimiter    *auth.RateLimiter
	resolver       *ipresolver.Resolver
	helper         *firewall.HelperClient
	factory        *firewall.Factory
	tm             *web.TemplateManager
	router         *chi.Mux
	bootstrapToken *string
}

// NewServer initializes the HTTP router and registers all routes.
func NewServer(
	cfg *config.Config,
	db *database.DB,
	engine *policy.Engine,
	rl *auth.RateLimiter,
	resolver *ipresolver.Resolver,
	helper *firewall.HelperClient,
	factory *firewall.Factory,
	tm *web.TemplateManager,
	bootstrapToken *string,
) (*Server, error) {
	s := &Server{
		cfg:            cfg,
		db:             db,
		engine:         engine,
		rateLimiter:    rl,
		resolver:       resolver,
		helper:         helper,
		factory:        factory,
		tm:             tm,
		router:         chi.NewRouter(),
		bootstrapToken: bootstrapToken,
	}

	s.setupRoutes()
	return s, nil
}

// Handler returns the HTTP handler for testing or serving.
func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) setupRoutes() {
	r := s.router

	// Core middlewares
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(ClientIPMiddleware(s.resolver))
	r.Use(CSRFMiddleware(s.cfg.CookieSecure))

	// Static files
	r.Handle("/static/*", web.StaticFileServer())

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()

		dbStatus := "connected"
		if err := s.db.PingContext(ctx); err != nil {
			dbStatus = "error: " + err.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"app":        version.AppName,
			"version":    version.Version,
			"repository": version.RepositoryURL,
			"database":   dbStatus,
			"backend":    s.cfg.FirewallBackend,
			"time":       time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Visitor Handlers
	visitorH := NewVisitorHandlers(s.cfg, s.db, s.engine, s.rateLimiter, s.tm)
	r.Get("/", visitorH.HandleIndex)
	r.Post("/access", visitorH.HandleAccess)
	r.Get("/access/current", visitorH.HandleStatus)
	r.Get("/access/ports/check", visitorH.HandleCheckPorts)
	r.Get("/access/check-ports", visitorH.HandleCheckPorts)
	r.Post("/access/revoke", visitorH.HandleRevoke)
	r.Post("/access/extend", visitorH.HandleExtend)

	// Setup Wizard Handlers
	setupH := NewSetupHandlers(s.cfg, s.db, s.tm, s.bootstrapToken)
	r.Get("/setup", setupH.HandleSetupGet)
	r.Post("/setup", setupH.HandleSetupPost)

	// Admin Handlers
	adminH := NewAdminHandlers(s.cfg, s.db, s.engine, s.rateLimiter, s.resolver, s.helper, s.factory, s.tm)
	r.Get("/admin/login", adminH.HandleLoginGet)
	r.Post("/admin/login", adminH.HandleLoginPost)
	r.Post("/admin/logout", adminH.HandleLogout)

	// Protected Admin Routes
	r.Route("/admin", func(admin chi.Router) {
		admin.Use(AdminAuthMiddleware(s.db, s.cfg.SessionIdleTimeout))

		admin.Get("/", adminH.HandleDashboard)

		// Access Keys
		admin.Get("/access-keys", adminH.HandleAccessKeysGet)
		admin.Post("/access-keys", adminH.HandleAccessKeysPost)
		admin.Post("/access-keys/{id}/toggle", adminH.HandleAccessKeysToggle)
		admin.Post("/access-keys/{id}/delete", adminH.HandleAccessKeysDelete)

		// Port Groups
		admin.Get("/port-groups", adminH.HandlePortGroupsGet)
		admin.Post("/port-groups", adminH.HandlePortGroupsPost)
		admin.Post("/port-groups/{id}/delete", adminH.HandlePortGroupsDelete)

		// Allowed Networks
		admin.Get("/allowed-networks", adminH.HandleAllowedNetworksGet)
		admin.Post("/allowed-networks", adminH.HandleAllowedNetworksPost)
		admin.Post("/allowed-networks/{id}/delete", adminH.HandleAllowedNetworksDelete)

		// Grants
		admin.Get("/grants", adminH.HandleGrantsGet)
		admin.Post("/grants/{id}/revoke", adminH.HandleGrantsRevoke)

		// Firewalls
		admin.Get("/firewalls", adminH.HandleFirewallsGet)
		admin.Post("/firewalls/validate", adminH.HandleFirewallsValidate)

		// Audit
		admin.Get("/audit", adminH.HandleAuditGet)

		// Settings & Circuit Breaker
		admin.Get("/settings", adminH.HandleSettingsGet)
		admin.Post("/settings/proxy", adminH.HandleSettingsProxyPost)
		admin.Post("/settings/sync-cloudflare", adminH.HandleSettingsSyncCloudflare)
		admin.Post("/circuit-breaker/reset", adminH.HandleCircuitBreakerReset)

		// Admin Users
		admin.Get("/users", adminH.HandleUsersGet)
		admin.Post("/users", adminH.HandleUsersPost)
		admin.Post("/users/{id}/toggle", adminH.HandleUsersToggle)
		admin.Post("/users/{id}/unlock", adminH.HandleUsersUnlock)
	})
}
