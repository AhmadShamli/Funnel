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
			if !strings.Contains(body, "v0.1.0") {
				t.Errorf("template %s missing version 'v0.1.0'", name)
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
	}
}
