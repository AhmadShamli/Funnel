package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCIDRList(t *testing.T) {
	input := "192.168.1.0/24, 10.0.0.1, 2001:db8::/32, ::1"
	prefixes, err := ParseCIDRList(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(prefixes) != 4 {
		t.Fatalf("expected 4 prefixes, got %d", len(prefixes))
	}

	if prefixes[0].String() != "192.168.1.0/24" {
		t.Errorf("expected 192.168.1.0/24, got %s", prefixes[0].String())
	}

	if prefixes[1].String() != "10.0.0.1/32" {
		t.Errorf("expected 10.0.0.1/32, got %s", prefixes[1].String())
	}

	if prefixes[2].String() != "2001:db8::/32" {
		t.Errorf("expected 2001:db8::/32, got %s", prefixes[2].String())
	}

	if prefixes[3].String() != "::1/128" {
		t.Errorf("expected ::1/128, got %s", prefixes[3].String())
	}
}

func TestLoadDefaults(t *testing.T) {
	os.Unsetenv("FUNNEL_PORT")
	os.Unsetenv("FUNNEL_HOST")
	os.Unsetenv("PROXY_MODE")
	os.Unsetenv("DATABASE_PATH")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Port != 8000 {
		t.Errorf("expected port 8000, got %d", cfg.Port)
	}
	if cfg.ProxyMode != "reverse_proxy" {
		t.Errorf("expected reverse_proxy, got %s", cfg.ProxyMode)
	}
	if cfg.AuditRetentionDays != 90 {
		t.Errorf("expected 90 audit days, got %d", cfg.AuditRetentionDays)
	}
}

func TestEnsureEnvExampleBothMissing(t *testing.T) {
	tmpDir := t.TempDir()

	created, path, err := EnsureEnvExample(tmpDir)
	if err != nil {
		t.Fatalf("EnsureEnvExample failed: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true when neither .env nor .env.example exists")
	}
	if path != filepath.Join(tmpDir, ".env.example") {
		t.Errorf("expected path %s, got %s", filepath.Join(tmpDir, ".env.example"), path)
	}

	// Verify file was written with DefaultEnvExample content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read created file: %v", err)
	}
	if !strings.Contains(string(content), "FUNNEL_PORT=8000") {
		t.Errorf("created file missing expected content: %s", string(content))
	}
}

func TestEnsureEnvExampleWhenEnvExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .env
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("FUNNEL_PORT=9000\n"), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	created, _, err := EnsureEnvExample(tmpDir)
	if err != nil {
		t.Fatalf("EnsureEnvExample failed: %v", err)
	}
	if created {
		t.Fatalf("expected created=false when .env already exists")
	}

	// Verify .env.example was NOT created
	if fileExists(filepath.Join(tmpDir, ".env.example")) {
		t.Errorf(".env.example should NOT have been created when .env exists")
	}
}

func TestEnsureEnvExampleWhenEnvExampleExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create existing .env.example
	examplePath := filepath.Join(tmpDir, ".env.example")
	customContent := "# Custom existing template\n"
	if err := os.WriteFile(examplePath, []byte(customContent), 0644); err != nil {
		t.Fatalf("failed to write .env.example: %v", err)
	}

	created, _, err := EnsureEnvExample(tmpDir)
	if err != nil {
		t.Fatalf("EnsureEnvExample failed: %v", err)
	}
	if created {
		t.Fatalf("expected created=false when .env.example already exists")
	}

	// Verify existing content was not overwritten
	content, _ := os.ReadFile(examplePath)
	if string(content) != customContent {
		t.Errorf("existing .env.example was overwritten")
	}
}

func TestDetermineConfigDir(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("CONFIG_DIR", tmpDir)
	defer os.Unsetenv("CONFIG_DIR")

	dir := DetermineConfigDir()
	if dir != tmpDir {
		t.Errorf("expected CONFIG_DIR %s, got %s", tmpDir, dir)
	}
}

func TestLoadDotEnv(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("CONFIG_DIR", tmpDir)
	defer os.Unsetenv("CONFIG_DIR")

	os.Unsetenv("FUNNEL_PORT")
	os.Unsetenv("SECRET_KEY")

	envContent := `
# Custom test env
FUNNEL_PORT=9999
SECRET_KEY="my-custom-test-secret"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.Port != 9999 {
		t.Errorf("expected port 9999 from .env, got %d", cfg.Port)
	}
	if cfg.SecretKey != "my-custom-test-secret" {
		t.Errorf("expected secret from .env, got %s", cfg.SecretKey)
	}
}
