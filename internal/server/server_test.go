package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/firewall"
	"github.com/AhmadShamli/Funnel/internal/ipresolver"
	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/policy"
	"github.com/AhmadShamli/Funnel/internal/web"
)

func setupTestServer(t *testing.T) (*Server, *database.DB, *string) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	cfg.SecretKey = "test-secret-pepper"
	cfg.FirewallBackend = "mock"

	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}

	factory := firewall.NewFactory("false")
	helperClient := firewall.NewHelperClient("internal", "", "mock", factory)
	rateLimiter := auth.NewRateLimiter(5, 60*time.Second, 5, 5*time.Minute, 15*time.Minute)
	resolver := ipresolver.NewResolver("direct", nil)
	engine := policy.NewEngine(db, helperClient, rateLimiter, cfg.SecretKey)

	tm, err := web.NewTemplateManager()
	if err != nil {
		t.Fatalf("NewTemplateManager failed: %v", err)
	}

	bootstrapToken := "0123456789abcdef0123456789abcdef"

	srv, err := NewServer(cfg, db, engine, rateLimiter, resolver, helperClient, factory, tm, &bootstrapToken)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	return srv, db, &bootstrapToken
}

func getCSRFTokenFromResponse(resp *http.Response) string {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "funnel_csrf" {
			return cookie.Value
		}
	}
	return ""
}

func TestHealthEndpoint(t *testing.T) {
	srv, db, _ := setupTestServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"status":"ok"`) || !strings.Contains(body, `"database":"connected"`) ||
		!strings.Contains(body, `"version":"0.1.0"`) || !strings.Contains(body, `"app":"Funnel by ExciteCreation"`) ||
		!strings.Contains(body, `"repository":"https://github.com/AhmadShamli/Funnel"`) {
		t.Fatalf("unexpected health response: %s", body)
	}
}

func TestSetupWizardAndAdminLifecycle(t *testing.T) {
	srv, db, bToken := setupTestServer(t)
	defer db.Close()

	handler := srv.Handler()

	// 1. Initial GET /setup should succeed (status 200)
	req1 := httptest.NewRequest("GET", "/setup", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 from /setup, got %d", rec1.Code)
	}
	csrfToken := getCSRFTokenFromResponse(rec1.Result())

	// 2. POST /setup with wrong bootstrap token
	formBad := url.Values{
		"csrf_token":       {csrfToken},
		"bootstrap_token":  {"wrong-token"},
		"username":         {"admin"},
		"password":         {"SuperSecretAdminPassword123!"},
		"confirm_password": {"SuperSecretAdminPassword123!"},
	}
	req2 := httptest.NewRequest("POST", "/setup", strings.NewReader(formBad.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if !strings.Contains(rec2.Header().Get("Location"), "error=") {
		t.Fatalf("expected error redirect on bad bootstrap token, got: %s", rec2.Header().Get("Location"))
	}

	// 3. POST /setup with valid token
	formGood := url.Values{
		"csrf_token":       {csrfToken},
		"bootstrap_token":  {*bToken},
		"username":         {"admin"},
		"password":         {"SuperSecretAdminPassword123!"},
		"confirm_password": {"SuperSecretAdminPassword123!"},
	}
	req3 := httptest.NewRequest("POST", "/setup", strings.NewReader(formGood.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusSeeOther || !strings.Contains(rec3.Header().Get("Location"), "/admin/login") {
		t.Fatalf("expected redirect to /admin/login after setup, got %d to %s", rec3.Code, rec3.Header().Get("Location"))
	}

	// 4. Verify /setup is now permanently locked
	req4 := httptest.NewRequest("GET", "/setup", nil)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusSeeOther || !strings.Contains(rec4.Header().Get("Location"), "/admin/login") {
		t.Fatalf("/setup should redirect to /admin/login once setup is complete")
	}

	// 5. Admin Login
	loginForm := url.Values{
		"csrf_token": {csrfToken},
		"username":   {"admin"},
		"password":   {"SuperSecretAdminPassword123!"},
	}
	reqLogin := httptest.NewRequest("POST", "/admin/login", strings.NewReader(loginForm.Encode()))
	reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqLogin.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusSeeOther || recLogin.Header().Get("Location") != "/admin" {
		t.Fatalf("expected redirect to /admin on valid login, got %d to %s", recLogin.Code, recLogin.Header().Get("Location"))
	}

	var sessionCookie *http.Cookie
	for _, c := range recLogin.Result().Cookies() {
		if c.Name == "funnel_admin_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("expected admin session cookie")
	}

	// 6. Access Dashboard with session cookie
	reqDash := httptest.NewRequest("GET", "/admin", nil)
	reqDash.AddCookie(sessionCookie)
	recDash := httptest.NewRecorder()
	handler.ServeHTTP(recDash, reqDash)
	if recDash.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated dashboard, got %d", recDash.Code)
	}
	if !strings.Contains(recDash.Body.String(), "Operational Overview") {
		t.Fatalf("dashboard missing expected header")
	}
}

func TestVisitorFullWorkflow(t *testing.T) {
	srv, db, _ := setupTestServer(t)
	defer db.Close()
	ctx := context.Background()

	// Pre-create port group and key directly in DB for testing
	pg := &models.PortGroup{
		Name:                 "SSH Access",
		AvailabilityMode:     "key_only",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		IsActive:             true,
		Ports:                []models.PortRule{{Protocol: "tcp", Port: 22}},
	}
	_ = db.CreatePortGroup(ctx, pg)

	keyHash := auth.HashAccessKey("test-secret-pepper", "visitorpass123")
	key := &models.AccessKey{
		Name:         "Visitor Key",
		PasswordHash: keyHash,
		IsActive:     true,
		AllowExtend:  true,
		PortGroupIDs: []int64{pg.ID},
	}
	_ = db.CreateAccessKey(ctx, key)

	handler := srv.Handler()

	// 1. Visitor GET /
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "198.51.100.25:34567"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 for visitor index, got %d", rec1.Code)
	}
	csrfToken := getCSRFTokenFromResponse(rec1.Result())

	// 2. Visitor POST /access
	accessForm := url.Values{
		"csrf_token": {csrfToken},
		"password":   {"visitorpass123"},
	}
	req2 := httptest.NewRequest("POST", "/access", strings.NewReader(accessForm.Encode()))
	req2.RemoteAddr = "198.51.100.25:34567"
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusSeeOther || rec2.Header().Get("Location") != "/access/current" {
		t.Fatalf("expected redirect to /access/current, got %d to %s", rec2.Code, rec2.Header().Get("Location"))
	}

	var grantCookie *http.Cookie
	for _, c := range rec2.Result().Cookies() {
		if c.Name == "funnel_grant" {
			grantCookie = c
			break
		}
	}
	if grantCookie == nil {
		t.Fatalf("expected funnel_grant cookie")
	}

	// 3. Visitor GET /access/current
	req3 := httptest.NewRequest("GET", "/access/current", nil)
	req3.RemoteAddr = "198.51.100.25:34567"
	req3.AddCookie(grantCookie)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 for /access/current, got %d", rec3.Code)
	}
	if !strings.Contains(rec3.Body.String(), "22/tcp") {
		t.Fatalf("expected port 22/tcp on status page")
	}

	// 4. Visitor POST /access/extend
	extendForm := url.Values{
		"csrf_token": {csrfToken},
		"password":   {"visitorpass123"},
	}
	req4 := httptest.NewRequest("POST", "/access/extend", strings.NewReader(extendForm.Encode()))
	req4.RemoteAddr = "198.51.100.25:34567"
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req4.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	req4.AddCookie(grantCookie)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusSeeOther || !strings.Contains(rec4.Header().Get("Location"), "success") {
		t.Fatalf("expected successful extension redirect, got %d to %s", rec4.Code, rec4.Header().Get("Location"))
	}

	// 5. Visitor POST /access/revoke
	revokeForm := url.Values{
		"csrf_token": {csrfToken},
	}
	req5 := httptest.NewRequest("POST", "/access/revoke", strings.NewReader(revokeForm.Encode()))
	req5.RemoteAddr = "198.51.100.25:34567"
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req5.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	req5.AddCookie(grantCookie)
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)

	if rec5.Code != http.StatusSeeOther || rec5.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to / after revoke, got %d to %s", rec5.Code, rec5.Header().Get("Location"))
	}
}
