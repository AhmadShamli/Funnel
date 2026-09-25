package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedTemplates(t *testing.T) {
	tm, err := NewTemplateManager()
	if err != nil {
		t.Fatalf("NewTemplateManager failed: %v", err)
	}

	for name := range tm.templates {
		rec := httptest.NewRecorder()
		data := map[string]interface{}{
			"ClientIP":        "203.0.113.1",
			"CSRFToken":       "dummy-csrf-token",
			"AdminUser":       map[string]interface{}{"Username": "admin"},
			"ActiveNav":       "dashboard",
			"RateLimitStatus": map[string]interface{}{"Level": 0},
		}
		if err := tm.Render(rec, name, data); err != nil {
			t.Errorf("failed to render template %s: %v", name, err)
		}
		if rec.Code != 200 {
			t.Errorf("template %s expected status 200, got %d", name, rec.Code)
		}
		body := rec.Body.String()
		if name == "visitor_index" || name == "admin_dashboard" {
			if !strings.Contains(body, "Funnel by ExciteCreation") {
				t.Errorf("template %s missing 'Funnel by ExciteCreation' branding", name)
			}
			if !strings.Contains(body, "https://github.com/AhmadShamli/Funnel") {
				t.Errorf("template %s missing github repository link", name)
			}
			if !strings.Contains(body, "v0.4.4") {
				t.Errorf("template %s missing version 'v0.4.4'", name)
			}
		}
		if name == "visitor_status" {
			if !strings.Contains(body, `class="ip-pill"`) {
				t.Errorf("visitor_status missing ip-pill")
			}
			if !strings.Contains(body, `class="ip-label"`) {
				t.Errorf("visitor_status missing ip-label")
			}
			if !strings.Contains(body, `class="ip-value"`) {
				t.Errorf("visitor_status missing ip-value")
			}
			if !strings.Contains(body, `class="countdown-box"`) {
				t.Errorf("visitor_status missing countdown-box")
			}
			if !strings.Contains(body, `class="countdown-digits"`) {
				t.Errorf("visitor_status missing countdown-digits")
			}
			if !strings.Contains(body, `class="ports-header"`) {
				t.Errorf("visitor_status missing ports-header")
			}
		}
		if name == "admin_keys" {
			if !strings.Contains(body, `action="/admin/access-keys" method="POST" autocomplete="off"`) {
				t.Errorf("admin_keys form missing autocomplete=\"off\"")
			}
			if !strings.Contains(body, `id="key_name" name="name" required placeholder="e.g. Contractors-SSH" autocomplete="off"`) {
				t.Errorf("admin_keys key_name input missing autocomplete=\"off\"")
			}
			if !strings.Contains(body, `id="key_password" name="password" required placeholder="Enter visitor password" autocomplete="new-password"`) {
				t.Errorf("admin_keys key_password input missing autocomplete=\"new-password\"")
			}
		}
		if name == "admin_port_groups" {
			if !strings.Contains(body, "+ Add Port Range") {
				t.Errorf("admin_port_groups missing '+ Add Port Range' button")
			}
			if !strings.Contains(body, "addPortRangeRow") {
				t.Errorf("admin_port_groups missing addPortRangeRow handler")
			}
		}
	}

	// Verify static JavaScript contains port range helper
	jsData, err := EmbeddedFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("failed to read embedded app.js: %v", err)
	}
	jsStr := string(jsData)
	if !strings.Contains(jsStr, "function addPortRangeRow") {
		t.Errorf("app.js missing addPortRangeRow function")
	}

	// Verify static CSS contains responsive rules for mobile view
	cssData, err := EmbeddedFS.ReadFile("static/style.css")
	if err != nil {
		t.Fatalf("failed to read embedded style.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, "@media (max-width: 640px)") {
		t.Errorf("style.css missing mobile @media (max-width: 640px)")
	}
	if !strings.Contains(cssStr, "flex-direction: column") {
		t.Errorf("style.css missing flex-direction: column for two-row mobile layout")
	}
	if !strings.Contains(cssStr, "clamp(") {
		t.Errorf("style.css missing clamp for fluid countdown digits sizing")
	}
}
