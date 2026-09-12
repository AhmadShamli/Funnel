package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AhmadShamli/Funnel/internal/auth"
	"github.com/AhmadShamli/Funnel/internal/models"
)

func TestPortAccessibilityCheckerUnit(t *testing.T) {
	// Start a local TCP listener to represent an open port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	openPort := ln.Addr().(*net.TCPAddr).Port

	// Find an unused closed port
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find closed port candidate: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	candidates := []string{"127.0.0.1"}
	ports := []models.PortRule{
		{Port: openPort, Protocol: "tcp"},
		{Port: closedPort, Protocol: "tcp"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results := CheckPortsConcurrently(ctx, ports, candidates, 500*time.Millisecond)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var foundOpen, foundClosed bool
	for _, r := range results {
		if r.Port == openPort {
			foundOpen = true
			if !r.Open || r.Status != "open" {
				t.Errorf("expected openPort %d to be open, got status=%s, open=%v", openPort, r.Status, r.Open)
			}
		}
		if r.Port == closedPort {
			foundClosed = true
			if r.Open || r.Status != "closed" {
				t.Errorf("expected closedPort %d to be closed, got status=%s, open=%v", closedPort, r.Status, r.Open)
			}
		}
	}

	if !foundOpen || !foundClosed {
		t.Fatalf("missing expected open or closed port in results: %+v", results)
	}
}

func TestPortAccessibilityEndpoint(t *testing.T) {
	srv, db, _ := setupTestServer(t)
	defer db.Close()
	ctx := context.Background()

	// Start a test listener for open port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Reserve a closed port
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind test listener: %v", err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	// Configure PortGroup with openPort and closedPort
	pg := &models.PortGroup{
		Name:                 "Service Stack",
		AvailabilityMode:     "key_only",
		AllowExtend:          true,
		GrantDurationSeconds: 3600,
		IsActive:             true,
		Ports: []models.PortRule{
			{Protocol: "tcp", Port: openPort},
			{Protocol: "tcp", Port: closedPort},
		},
	}
	_ = db.CreatePortGroup(ctx, pg)

	keyHash := auth.HashAccessKey("test-secret-pepper", "checkpass123")
	key := &models.AccessKey{
		Name:         "Port Check Key",
		PasswordHash: keyHash,
		IsActive:     true,
		AllowExtend:  true,
		PortGroupIDs: []int64{pg.ID},
	}
	_ = db.CreateAccessKey(ctx, key)

	handler := srv.Handler()

	// 1. Unauthenticated request to /access/ports/check should return 401
	unauthReq := httptest.NewRequest("GET", "/access/ports/check", nil)
	unauthReq.RemoteAddr = "198.51.100.33:12345"
	unauthRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthRec, unauthReq)

	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated port check, got %d", unauthRec.Code)
	}

	// 2. Authenticate visitor
	// GET / to get CSRF token
	reqIndex := httptest.NewRequest("GET", "/", nil)
	reqIndex.RemoteAddr = "198.51.100.33:12345"
	recIndex := httptest.NewRecorder()
	handler.ServeHTTP(recIndex, reqIndex)
	csrfToken := getCSRFTokenFromResponse(recIndex.Result())

	// POST /access with password
	form := url.Values{
		"csrf_token": {csrfToken},
		"password":   {"checkpass123"},
	}
	reqAuth := httptest.NewRequest("POST", "/access", strings.NewReader(form.Encode()))
	reqAuth.RemoteAddr = "198.51.100.33:12345"
	reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAuth.AddCookie(&http.Cookie{Name: "funnel_csrf", Value: csrfToken})
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after login, got %d", recAuth.Code)
	}

	var grantCookie *http.Cookie
	for _, c := range recAuth.Result().Cookies() {
		if c.Name == "funnel_grant" {
			grantCookie = c
			break
		}
	}
	if grantCookie == nil {
		t.Fatalf("expected funnel_grant cookie")
	}

	// 3. Verify /access/current template contains port check elements
	reqStatus := httptest.NewRequest("GET", "/access/current", nil)
	reqStatus.RemoteAddr = "198.51.100.33:12345"
	reqStatus.AddCookie(grantCookie)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)

	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 for status page, got %d", recStatus.Code)
	}
	body := recStatus.Body.String()
	if !strings.Contains(body, "visitor-ports-list") {
		t.Errorf("status page missing visitor-ports-list element")
	}
	if !strings.Contains(body, "recheck-ports-btn") {
		t.Errorf("status page missing recheck-ports-btn element")
	}
	if !strings.Contains(body, "port-status-badge") {
		t.Errorf("status page missing port-status-badge element")
	}

	// 4. Authorized GET /access/ports/check
	reqCheck := httptest.NewRequest("GET", "/access/ports/check", nil)
	reqCheck.RemoteAddr = "198.51.100.33:12345"
	reqCheck.AddCookie(grantCookie)
	recCheck := httptest.NewRecorder()
	handler.ServeHTTP(recCheck, reqCheck)

	if recCheck.Code != http.StatusOK {
		t.Fatalf("expected 200 for port check endpoint, got %d: %s", recCheck.Code, recCheck.Body.String())
	}

	var checkResp struct {
		Active           bool              `json:"active"`
		ClientIP         string            `json:"client_ip"`
		RemainingSeconds int               `json:"remaining_seconds"`
		Ports            []PortCheckStatus `json:"ports"`
	}

	if err := json.Unmarshal(recCheck.Body.Bytes(), &checkResp); err != nil {
		t.Fatalf("failed to parse port check json: %v", err)
	}

	if !checkResp.Active {
		t.Errorf("expected active=true")
	}
	if len(checkResp.Ports) != 2 {
		t.Fatalf("expected 2 checked ports, got %d", len(checkResp.Ports))
	}

	for _, p := range checkResp.Ports {
		if p.Port == openPort {
			if !p.Open || p.Status != "open" {
				t.Errorf("expected openPort %d to be open, got status=%s, open=%v, msg=%s", openPort, p.Status, p.Open, p.Message)
			}
		} else if p.Port == closedPort {
			if p.Open || p.Status != "closed" {
				t.Errorf("expected closedPort %d to be closed, got status=%s, open=%v, msg=%s", closedPort, p.Status, p.Open, p.Message)
			}
		}
	}
}
