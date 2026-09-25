package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/ipresolver"
	"github.com/AhmadShamli/Funnel/internal/policy"
	"github.com/AhmadShamli/Funnel/internal/server"
	"github.com/AhmadShamli/Funnel/internal/version"
	"github.com/AhmadShamli/Funnel/internal/web"
	"github.com/AhmadShamli/Funnel/internal/worker"
)

func main() {
	// Automatically ensure .env.example exists if neither .env nor .env.example exists
	configDir := config.DetermineConfigDir()
	if created, path, err := config.EnsureEnvExample(configDir); err == nil && created {
		log.Printf("[CONFIG] Neither .env nor .env.example found. Created default template at %s", path)
	}

	args := os.Args[1:]

	subcmd := "serve"
	if len(args) > 0 && !stringsHasPrefix(args[0], "-") {
		subcmd = args[0]
		args = args[1:]
	}

	switch subcmd {
	case "serve":
		runServe(args)
	case "helper":
		runHelper(args)
	case "health":
		runHealth(args)
	case "version":
		fmt.Printf("%s v%s (Linux static) - %s\n", version.AppName, version.Version, version.RepositoryURL)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nUsage: funnel [serve|helper|health|version]\n", subcmd)
		os.Exit(1)
	}
}

func runServe(args []string) {
	log.Printf("[FUNNEL] Initializing %s v%s... (%s)", version.AppName, version.Version, version.RepositoryURL)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
	}

	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open database at %s: %v", cfg.DatabasePath, err)
	}
	defer db.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Check admin bootstrap
	adminCount, err := db.CountAdminUsers(ctx)
	if err != nil {
		log.Fatalf("[FATAL] Failed to query admin users count: %v", err)
	}

	var bootstrapToken string
	if adminCount == 0 {
		bootstrapToken, err = auth.GenerateBootstrapToken()
		if err != nil {
			log.Fatalf("[FATAL] Failed to generate bootstrap token: %v", err)
		}
		printBootstrapBanner(cfg, bootstrapToken)
	}

	// Firewall & Transport Setup
	factory := firewall.NewFactory(cfg.UseNsenter)
	activeAdapter := factory.SelectBackend(ctx, cfg.FirewallBackend)
	log.Printf("[FIREWALL] Selected backend: %s (transport: %s)", activeAdapter.Name(), cfg.HelperTransport)

	helperClient := firewall.NewHelperClient(cfg.HelperTransport, cfg.HelperSocket, activeAdapter.Name(), factory)
	rateLimiter := auth.NewRateLimiter(
		cfg.RateLimitPerIPAttempts,
		cfg.RateLimitPerIPWindow,
		cfg.DistributedFailedIPThresh,
		cfg.DistributedWindow,
		time.Duration(cfg.DistributedLockoutMinutes)*time.Minute,
	)

	resolver := ipresolver.NewResolver(cfg.ProxyMode, cfg.TrustedProxies)
	engine := policy.NewEngine(db, helperClient, rateLimiter, cfg.SecretKey)

	// Startup Reconciliation
	now := time.Now().UTC()
	expired, restored, err := engine.ReconcileStartup(ctx, now)
	if err != nil {
		log.Printf("[WARNING] Startup firewall reconciliation warning: %v", err)
	} else {
		log.Printf("[RECONCILE] Startup complete: %d expired grants pruned, %d active grants synchronized to firewall", expired, restored)
	}

	// Start Background Worker
	bgWorker := worker.NewWorker(db, engine, cfg.AuditRetentionDays)
	go bgWorker.Start(ctx)

	// HTML Template Manager
	tm, err := web.NewTemplateManager()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load HTML templates: %v", err)
	}

	srvInstance, err := server.NewServer(cfg, db, engine, rateLimiter, resolver, helperClient, factory, tm, &bootstrapToken)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize server: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srvInstance.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	activeAdminPath := srvInstance.GetAdminPath()
	displayHost := cfg.Host
	if displayHost == "0.0.0.0" || displayHost == "" {
		displayHost = "127.0.0.1"
	}
	log.Printf("[ADMIN] Active administrator portal path: %s (access at http://%s:%d%s)", activeAdminPath, displayHost, cfg.Port, activeAdminPath)

	go func() {
		log.Printf("[SERVER] Funnel HTTP server listening on http://%s (proxy_mode: %s)", addr, cfg.ProxyMode)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("[SERVER] Shutting down HTTP server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	log.Printf("[SERVER] Funnel terminated cleanly.")
}

func runHelper(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: funnel helper [exec|daemon] [options]\n")
		os.Exit(1)
	}

	factory := firewall.NewFactory("auto")
	server := firewall.NewHelperServer(factory)
	ctx := context.Background()

	switch args[0] {
	case "exec":
		var req firewall.HelperRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			resp := firewall.HelperResponse{Success: false, Error: fmt.Sprintf("failed to parse json: %v", err)}
			_ = json.NewEncoder(os.Stdout).Encode(resp)
			os.Exit(1)
		}
		resp := server.Handle(ctx, req)
		_ = json.NewEncoder(os.Stdout).Encode(resp)

	case "daemon":
		fs := flag.NewFlagSet("helper-daemon", flag.ExitOnError)
		socketPath := fs.String("socket", "/run/funnel/helper.sock", "Path to unix domain socket")
		_ = fs.Parse(args[1:])

		log.Printf("[HELPER] Starting root helper daemon on unix socket %s", *socketPath)
		if err := server.RunSocketDaemon(ctx, *socketPath); err != nil {
			log.Fatalf("[FATAL] Helper socket daemon failed: %v", err)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown helper command: %s\n", args[0])
		os.Exit(1)
	}
}

func runHealth(args []string) {
	port := os.Getenv("FUNNEL_PORT")
	if port == "" {
		port = "8000"
	}
	url := fmt.Sprintf("http://127.0.0.1:%s/health", port)

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Funnel health check failed for %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid health check response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Funnel Healthy: %s\n", result["status"])
}

func printBootstrapBanner(cfg *config.Config, token string) {
	banner := `
================================================================================
  [FUNNEL BOOTSTRAP] Initial Administrator Setup Required
--------------------------------------------------------------------------------
  Setup Token: %s
  
  Navigate to: http://%s:%d/setup
  Enter the token above to create the initial administrator account.
  This token is one-time use and will permanently expire after creation.
================================================================================
`
	fmt.Printf(banner, token, cfg.Host, cfg.Port)
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}
