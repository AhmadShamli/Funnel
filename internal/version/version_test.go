package version

import (
	"strings"
	"testing"
)

func TestVersionDefaults(t *testing.T) {
	if Version != "0.3.1" {
		t.Errorf("expected default Version to be 0.3.1, got %s", Version)
	}
	if AppName != "Funnel by ExciteCreation" {
		t.Errorf("expected AppName to be 'Funnel by ExciteCreation', got %s", AppName)
	}
	if RepositoryURL != "https://github.com/AhmadShamli/Funnel" {
		t.Errorf("expected RepositoryURL to be 'https://github.com/AhmadShamli/Funnel', got %s", RepositoryURL)
	}
	full := FullVersionString()
	if !strings.Contains(full, "0.3.1") || !strings.Contains(full, "ExciteCreation") || !strings.Contains(full, "https://github.com/AhmadShamli/Funnel") {
		t.Errorf("unexpected full version string: %s", full)
	}
}
