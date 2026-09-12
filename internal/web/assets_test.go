package web

import (
	"net/http/httptest"
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
	}
}
