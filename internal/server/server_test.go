package server

import (
	"context"
	"encoding/json"
	"fmt"
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
		!strings.Contains(body, `"version":"0.2.0"`) || !strings.Contains(body, `"app":"Funnel by ExciteCreation"`) ||
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

func TestAdminUpdateEntities(t *testing.T) {
	srv, db, _ := setupTestServer(t)
	defer db.Close()
	ctx := context.Background()

	// 1. Create an admin user and session
	passHash, _ := auth.HashAdminPassword("AdminPass123456!", 12)
	admin := &models.AdminUser{
		Username:     "admin",
		PasswordHash: passHash,
		Role:         "admin",
		IsActive:     true,
	}
	if err := db.CreateAdminUser(ctx, admin); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	sessionToken := "admin-session-test-token"
	sess := &models.AdminSession{
		AdminUserID:      admin.ID,
		SessionTokenHash: auth.HashToken(sessionToken),
		LastActivityAt:   time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(1 * time.Hour),
		UserAgent:        "test-agent",
		ClientIP:         "192.0.2.1",
	}
	if err := db.CreateAdminSession(ctx, sess); err != nil {
		t.Fatalf("failed to create admin session: %v", err)
	}
	sessionCookie := &http.Cookie{Name: "funnel_admin_session", Value: sessionToken}
	csrfToken := "test-csrf-token-12345"
	csrfCookie := &http.Cookie{Name: "funnel_csrf", Value: csrfToken}

	// 2. Pre-create a port group, access key, and allowed network
	pg := &models.PortGroup{
		Name:                 "Initial PG",
		AvailabilityMode:     "key_only",
		AllowExtend:          false,
		GrantDurationSeconds: 1800,
		IsActive:             true,
		Ports:                []models.PortRule{{Protocol: "tcp", Port: 80}},
	}
	if err := db.CreatePortGroup(ctx, pg); err != nil {
		t.Fatalf("failed to create port group: %v", err)
	}

	key := &models.AccessKey{
		Name:             "Initial Key",
		PasswordHash:     auth.HashAccessKey("test-secret-pepper", "oldpass"),
		IsActive:         true,
		AllowExtend:      false,
		PortGroupIDs:     []int64{pg.ID},
		CreatedByAdminID: &admin.ID,
	}
	if err := db.CreateAccessKey(ctx, key); err != nil {
		t.Fatalf("failed to create access key: %v", err)
	}

	netRule := &models.AllowedNetwork{
		Name:                 "Initial Net",
		NetworkCIDR:          "10.0.0.0/8",
		Mode:                 "login_required",
		Scope:                "global",
		GrantDurationSeconds: 1800,
		IsActive:             true,
		PortGroupIDs:         []int64{pg.ID},
	}
	if err := db.CreateAllowedNetwork(ctx, netRule); err != nil {
		t.Fatalf("failed to create network rule: %v", err)
	}

	handler := srv.Handler()

	// 3. Test Update Port Group
	pgForm := url.Values{
		"csrf_token":             {csrfToken},
		"name":                   {"Updated PG"},
		"description":            {"Updated Description"},
		"availability_mode":      {"global"},
		"grant_duration_seconds": {"7200"},
		"allow_extend":           {"1"},
		"max_extensions":         {"3"},
		"port_protocol[]":        {"tcp", "udp"},
		"port_number[]":          {"443", "53"},
	}
	reqPG := httptest.NewRequest("POST", fmt.Sprintf("/admin/port-groups/%d", pg.ID), strings.NewReader(pgForm.Encode()))
	reqPG.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPG.AddCookie(sessionCookie)
	reqPG.AddCookie(csrfCookie)
	recPG := httptest.NewRecorder()
	handler.ServeHTTP(recPG, reqPG)

	if recPG.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on port group update, got %d", recPG.Code)
	}

	updatedPG, err := db.GetPortGroupByID(ctx, pg.ID)
	if err != nil {
		t.Fatalf("failed to get updated port group: %v", err)
	}
	if updatedPG.Name != "Updated PG" || updatedPG.GrantDurationSeconds != 7200 || !updatedPG.AllowExtend {
		t.Errorf("port group fields not properly updated: %+v", updatedPG)
	}
	if len(updatedPG.Ports) != 2 {
		t.Errorf("expected 2 updated ports, got %d", len(updatedPG.Ports))
	}

	// 4. Test Update Access Key
	keyForm := url.Values{
		"csrf_token":           {csrfToken},
		"name":                 {"Updated Key Name"},
		"password":             {"newpassword123"},
		"max_concurrent_ips":   {"5"},
		"max_total_uses":       {"10"},
		"max_duration_seconds": {"3600"},
		"allow_extend":         {"1"},
		"port_group_ids[]":     {fmt.Sprintf("%d", pg.ID)},
	}
	reqKey := httptest.NewRequest("POST", fmt.Sprintf("/admin/access-keys/%d", key.ID), strings.NewReader(keyForm.Encode()))
	reqKey.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqKey.AddCookie(sessionCookie)
	reqKey.AddCookie(csrfCookie)
	recKey := httptest.NewRecorder()
	handler.ServeHTTP(recKey, reqKey)

	if recKey.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on access key update, got %d", recKey.Code)
	}

	updatedKey, err := db.GetAccessKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("failed to get updated access key: %v", err)
	}
	if updatedKey.Name != "Updated Key Name" || !updatedKey.AllowExtend {
		t.Errorf("access key fields not properly updated: %+v", updatedKey)
	}
	expectedHash := auth.HashAccessKey("test-secret-pepper", "newpassword123")
	if updatedKey.PasswordHash != expectedHash {
		t.Errorf("expected updated password hash %s, got %s", expectedHash, updatedKey.PasswordHash)
	}

	// 5. Test Update Allowed Network
	netForm := url.Values{
		"csrf_token":             {csrfToken},
		"name":                   {"Updated Office Network"},
		"network_cidr":           {"192.168.1.0/24"},
		"mode":                   {"always_allowed"},
		"grant_duration_seconds": {"3600"},
		"port_group_ids[]":       {fmt.Sprintf("%d", pg.ID)},
	}
	reqNet := httptest.NewRequest("POST", fmt.Sprintf("/admin/allowed-networks/%d", netRule.ID), strings.NewReader(netForm.Encode()))
	reqNet.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNet.AddCookie(sessionCookie)
	reqNet.AddCookie(csrfCookie)
	recNet := httptest.NewRecorder()
	handler.ServeHTTP(recNet, reqNet)

	if recNet.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on network update, got %d", recNet.Code)
	}

	updatedNet, err := db.GetAllowedNetworkByID(ctx, netRule.ID)
	if err != nil {
		t.Fatalf("failed to get updated network: %v", err)
	}
	if updatedNet.Name != "Updated Office Network" || updatedNet.NetworkCIDR != "192.168.1.0/24" || updatedNet.Mode != "always_allowed" {
		t.Errorf("network fields not properly updated: %+v", updatedNet)
	}
}

func TestAdminOpenPortsPageAndCheck(t *testing.T) {
	srv, db, _ := setupTestServer(t)
	defer db.Close()
	ctx := context.Background()

	// 1. Create admin user and session
	now := time.Now().UTC()
	hash, err := auth.HashAdminPassword("Secret123456!", 12)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	admin := &models.AdminUser{
		Username:     "openportadmin",
		PasswordHash: hash,
		Role:         "superadmin",
		IsActive:     true,
		CreatedAt:    now,
	}
	if err := db.CreateAdminUser(ctx, admin); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	sessionToken, _ := auth.GenerateRandomToken(32)
	session := &models.AdminSession{
		AdminUserID:      admin.ID,
		SessionTokenHash: auth.HashToken(sessionToken),
		UserAgent:        "Go-Test-Agent",
		ClientIP:         "127.0.0.1",
		CreatedAt:        now,
		LastActivityAt:   now,
		ExpiresAt:        now.Add(8 * time.Hour),
	}
	if err := db.CreateAdminSession(ctx, session); err != nil {
		t.Fatalf("failed to create admin session: %v", err)
	}
	sessionCookie := &http.Cookie{Name: "funnel_admin_session", Value: sessionToken}

	// 2. Create a Port Group
	pg := &models.PortGroup{
		Name:                 "Database Cluster",
		AvailabilityMode:     "global",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		IsActive:             true,
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 5432},
			{Protocol: "tcp", Port: 6379},
		},
	}
	if err := db.CreatePortGroup(ctx, pg); err != nil {
		t.Fatalf("failed to create port group: %v", err)
	}

	// 3. Create Access Key and an active Access Grant
	key := &models.AccessKey{
		Name:         "Dev DB Team",
		PasswordHash: auth.HashAccessKey("test-secret-pepper", "dbpass123"),
		IsActive:     true,
		PortGroupIDs: []int64{pg.ID},
	}
	if err := db.CreateAccessKey(ctx, key); err != nil {
		t.Fatalf("failed to create access key: %v", err)
	}

	grantToken, _ := auth.GenerateRandomToken(32)
	grant := &models.AccessGrant{
		AccessKeyID:      &key.ID,
		GrantSource:      "password",
		SourceIP:         "203.0.113.50",
		Status:           "active",
		VisitorTokenHash: auth.HashToken(grantToken),
		GrantedAt:        now,
		ExpiresAt:        now.Add(1 * time.Hour),
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: 5432},
		},
		AccessKeyName: "Dev DB Team",
	}
	if err := db.CreateAccessGrant(ctx, grant); err != nil {
		t.Fatalf("failed to create access grant: %v", err)
	}

	handler := srv.Handler()

	// 4. Test GET /admin/open-ports
	reqPage := httptest.NewRequest("GET", "/admin/open-ports", nil)
	reqPage.AddCookie(sessionCookie)
	recPage := httptest.NewRecorder()
	handler.ServeHTTP(recPage, reqPage)

	if recPage.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin/open-ports, got %d: %s", recPage.Code, recPage.Body.String())
	}
	body := recPage.Body.String()
	if !strings.Contains(body, "Current Open Ports") {
		t.Errorf("expected page title 'Current Open Ports'")
	}
	if !strings.Contains(body, "5432/tcp") {
		t.Errorf("expected 5432/tcp to be displayed in open ports page")
	}
	if !strings.Contains(body, "203.0.113.50") {
		t.Errorf("expected client IP 203.0.113.50 to be displayed")
	}
	if !strings.Contains(body, "Database Cluster") {
		t.Errorf("expected port group name 'Database Cluster' to be displayed")
	}
	if !strings.Contains(body, "Dev DB Team") {
		t.Errorf("expected key name 'Dev DB Team' to be displayed")
	}

	// 5. Test GET /admin/open-ports/check (JSON reachability probe)
	reqCheck := httptest.NewRequest("GET", "/admin/open-ports/check?ports=5432/tcp", nil)
	reqCheck.AddCookie(sessionCookie)
	recCheck := httptest.NewRecorder()
	handler.ServeHTTP(recCheck, reqCheck)

	if recCheck.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin/open-ports/check, got %d: %s", recCheck.Code, recCheck.Body.String())
	}
	if ct := recCheck.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %s", ct)
	}

	var checkResp struct {
		Status string            `json:"status"`
		Ports  []PortCheckStatus `json:"ports"`
	}
	if err := json.Unmarshal(recCheck.Body.Bytes(), &checkResp); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}
	if checkResp.Status != "ok" {
		t.Errorf("expected status 'ok', got %s", checkResp.Status)
	}
	if len(checkResp.Ports) != 1 || checkResp.Ports[0].Port != 5432 {
		t.Errorf("expected 1 port result for 5432, got %+v", checkResp.Ports)
	}

	// 6. Test Revoke from Open Ports page
	csrfCookie := &http.Cookie{Name: "funnel_csrf", Value: "test-csrf-token"}
	revokeForm := url.Values{"csrf_token": {"test-csrf-token"}}
	reqRevoke := httptest.NewRequest("POST", fmt.Sprintf("/admin/grants/%d/revoke?from=open-ports", grant.ID), strings.NewReader(revokeForm.Encode()))
	reqRevoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqRevoke.AddCookie(sessionCookie)
	reqRevoke.AddCookie(csrfCookie)
	recRevoke := httptest.NewRecorder()
	handler.ServeHTTP(recRevoke, reqRevoke)

	if recRevoke.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect on grant revoke, got %d", recRevoke.Code)
	}
	if loc := recRevoke.Header().Get("Location"); loc != "/admin/open-ports?success=Grant+revoked" {
		t.Errorf("expected redirect to /admin/open-ports?success=Grant+revoked, got %s", loc)
	}

	// Verify grant is now revoked
	revokedGrant, err := db.GetAccessGrantByID(ctx, grant.ID)
	if err != nil {
		t.Fatalf("failed to get grant: %v", err)
	}
	if revokedGrant.Status != "revoked" {
		t.Errorf("expected status revoked, got %s", revokedGrant.Status)
	}
}

