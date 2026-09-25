package config

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultEnvExample contains the default template configuration for Funnel.
const DefaultEnvExample = `# Funnel Configuration Template

# Network & HTTP Server
FUNNEL_HOST=0.0.0.0
FUNNEL_PORT=8000

# Security Secret (Used as pepper for keyed HMAC-SHA256 and session signing)
# Replace with a cryptographically random 64-character secret in production
SECRET_KEY=change-this-to-a-secure-random-secret-key-in-production

# Cookie Security (Set to true when serving over HTTPS)
COOKIE_SECURE=false

# Ingress Proxy Settings
# Options: "reverse_proxy", "cloudflare", "direct"
PROXY_MODE=reverse_proxy

# Trusted Proxy Subnets (Comma-separated CIDRs)
# Only headers (X-Forwarded-For, Forwarded, CF-Connecting-IP) from these IPs are accepted
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7

# Linux Firewall Backend
# Options: "auto", "nftables", "firewalld", "ufw", "iptables", "mock"
FIREWALL_BACKEND=auto

# Privileged Helper Transport
# Options: "sudo", "socket", "internal"
FUNNEL_HELPER_TRANSPORT=sudo
FUNNEL_HELPER_SOCKET=/run/funnel/helper.sock

# Docker Network Namespace Bridging
# Options: "auto", "true", "false"
FUNNEL_USE_NSENTER=auto

# IPv6 Scoping Prefix (128 for single host, 64 for SLAAC prefix)
IPV6_GRANT_PREFIX=128

# Brute-force & Two-Tier Rate Limiting
# Level 2 Distributed Circuit Breaker Settings
DISTRIBUTED_FAILED_IPS_THRESHOLD=5
DISTRIBUTED_LOCKOUT_DURATION_MINUTES=15

# Audit Retention (Days to retain audit events; 0 = indefinite)
AUDIT_LOG_RETENTION_DAYS=90

# Database Storage Path (Docker: /data/funnel.db, Bare-Metal: /var/lib/funnel/funnel.db)
DATABASE_PATH=/data/funnel.db

# Logging
LOG_LEVEL=INFO

# Docker Compose Network Configuration (If running under Docker)
EXTERNAL_NETWORK_NAME=web_proxy
FUNNEL_VOLUME_NAME=funnel_data

# Optional: Set specific user/group ID for container (leave commented out to use system-allocated ID upon creation)
# FUNNEL_UID=1000
# FUNNEL_GID=1000
`

// Config holds all configuration parameters for the Funnel service.
type Config struct {
	// Server
	Host string
	Port int

	// Database
	DatabasePath string

	// Security
	SecretKey             string
	SessionIdleTimeout    time.Duration
	SessionMaxLifetime    time.Duration
	CookieSecure          bool
	AdminMinPasswordLen   int
	BootstrapToken        string
	AdminPath             string // default "/admin"

	// Ingress & Proxy
	ProxyMode      string // "direct", "reverse_proxy", "cloudflare"
	TrustedProxies []netip.Prefix

	// Firewall & Privilege
	FirewallBackend string // "auto", "nftables", "firewalld", "ufw", "iptables", "mock"
	HelperTransport string // "internal", "sudo", "socket"
	HelperSocket    string
	UseNsenter      string // "auto", "true", "false"
	IPv6GrantPrefix int    // 128 or 64

	// Brute-force & Circuit Breaker
	RateLimitPerIPAttempts    int           // default 5
	RateLimitPerIPWindow      time.Duration // default 60s
	DistributedFailedIPThresh int           // default 5
	DistributedWindow         time.Duration // default 5m
	DistributedLockoutMinutes int           // default 15m

	// Operational
	AuditRetentionDays int // default 90 (0 = indefinite)
	LogLevel           string

	// Environment Detection
	IsDocker  bool
	IsSystemd bool
}

// DetermineConfigDir resolves the proper directory for configuration files based on the active runtime environment.
func DetermineConfigDir() string {
	if dir := os.Getenv("CONFIG_DIR"); dir != "" {
		return dir
	}
	if cfgPath := os.Getenv("CONFIG_PATH"); cfgPath != "" {
		return filepath.Dir(cfgPath)
	}
	if fileExists("/.dockerenv") && dirExists("/app") {
		return "/app"
	}
	if fileExists("/etc/funnel/funnel.env") || (dirExists("/etc/funnel") && os.Geteuid() == 0) {
		return "/etc/funnel"
	}
	return "."
}

// EnsureEnvExample checks if .env and .env.example exist in dir.
// If neither exists, it automatically creates .env.example in the proper directory.
func EnsureEnvExample(dir string) (bool, string, error) {
	if dir == "" {
		dir = "."
	}

	envPath := filepath.Join(dir, ".env")
	envExamplePath := filepath.Join(dir, ".env.example")
	funnelEnvPath := filepath.Join(dir, "funnel.env")
	funnelEnvExamplePath := filepath.Join(dir, "funnel.env.example")

	// If either .env or funnel.env exists, do not create .env.example
	if fileExists(envPath) || fileExists(funnelEnvPath) {
		return false, "", nil
	}

	// If either .env.example or funnel.env.example exists, it already exists
	if fileExists(envExamplePath) || fileExists(funnelEnvExamplePath) {
		return false, "", nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, "", fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	if err := os.WriteFile(envExamplePath, []byte(DefaultEnvExample), 0644); err != nil {
		return false, "", fmt.Errorf("failed to write %s: %w", envExamplePath, err)
	}

	return true, envExamplePath, nil
}

// LoadDotEnv parses and loads environment variables from .env or funnel.env if present.
func LoadDotEnv(dir string) {
	paths := []string{
		filepath.Join(dir, ".env"),
		filepath.Join(dir, "funnel.env"),
		".env",
	}
	for _, p := range paths {
		if fileExists(p) {
			parseAndSetEnvFile(p)
			break
		}
	}
}

func parseAndSetEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists && key != "" {
			_ = os.Setenv(key, val)
		}
	}
}

// Load loads configuration with hierarchical defaults based on detected environment.
func Load() (*Config, error) {
	configDir := DetermineConfigDir()
	if created, createdPath, err := EnsureEnvExample(configDir); err == nil && created {
		log.Printf("[CONFIG] Created default .env.example at %s", createdPath)
	}
	LoadDotEnv(configDir)

	isDocker := fileExists("/.dockerenv")
	isSystemd := fileExists("/etc/funnel/funnel.env")

	// Default host and port
	host := getEnv("FUNNEL_HOST", "")
	if host == "" {
		if isDocker {
			host = "0.0.0.0"
		} else {
			host = "127.0.0.1"
		}
	}

	portStr := getEnv("FUNNEL_PORT", "8000")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		port = 8000
	}

	// Database path hierarchical resolution
	dbPath := getEnv("DATABASE_PATH", "")
	if dbPath == "" {
		if isDocker {
			dbPath = "/data/funnel.db"
		} else if isSystemd {
			dbPath = "/var/lib/funnel/funnel.db"
		} else {
			dbPath = "./data/funnel.db"
		}
	}

	// Secret Key (used as HMAC pepper and session entropy)
	secretKey := getEnv("SECRET_KEY", "funnel-default-insecure-pepper-replace-in-production")

	// Proxy settings
	proxyMode := strings.ToLower(getEnv("PROXY_MODE", "reverse_proxy"))
	if proxyMode != "direct" && proxyMode != "reverse_proxy" && proxyMode != "cloudflare" {
		proxyMode = "reverse_proxy"
	}

	trustedProxiesStr := getEnv("TRUSTED_PROXIES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7")
	trustedProxies, err := ParseCIDRList(trustedProxiesStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}

	// Firewall settings
	fwBackend := strings.ToLower(getEnv("FIREWALL_BACKEND", "auto"))
	helperTransport := strings.ToLower(getEnv("FUNNEL_HELPER_TRANSPORT", "sudo"))
	if helperTransport != "internal" && helperTransport != "sudo" && helperTransport != "socket" {
		helperTransport = "sudo"
	}

	helperSocket := getEnv("FUNNEL_HELPER_SOCKET", "/run/funnel/helper.sock")
	useNsenter := strings.ToLower(getEnv("FUNNEL_USE_NSENTER", "auto"))

	ipv6PrefixStr := getEnv("IPV6_GRANT_PREFIX", "128")
	ipv6Prefix, err := strconv.Atoi(ipv6PrefixStr)
	if err != nil || (ipv6Prefix != 128 && ipv6Prefix != 64) {
		ipv6Prefix = 128
	}

	// Rate limiting & circuit breaker
	distThreshStr := getEnv("DISTRIBUTED_FAILED_IPS_THRESHOLD", "5")
	distThresh, err := strconv.Atoi(distThreshStr)
	if err != nil || distThresh < 1 {
		distThresh = 5
	}

	distLockoutStr := getEnv("DISTRIBUTED_LOCKOUT_DURATION_MINUTES", "15")
	distLockout, err := strconv.Atoi(distLockoutStr)
	if err != nil || distLockout < 1 {
		distLockout = 15
	}

	auditDaysStr := getEnv("AUDIT_LOG_RETENTION_DAYS", "90")
	auditDays, err := strconv.Atoi(auditDaysStr)
	if err != nil || auditDays < 0 {
		auditDays = 90
	}

	cookieSecure := strings.ToLower(getEnv("COOKIE_SECURE", "false")) == "true"

	adminPath := getEnv("FUNNEL_ADMIN_PATH", getEnv("ADMIN_PATH", "/admin"))
	if adminPath == "" || !strings.HasPrefix(adminPath, "/") {
		adminPath = "/admin"
	}

	return &Config{
		Host:                      host,
		Port:                      port,
		DatabasePath:              dbPath,
		SecretKey:                 secretKey,
		SessionIdleTimeout:        30 * time.Minute,
		SessionMaxLifetime:        8 * time.Hour,
		CookieSecure:              cookieSecure,
		AdminMinPasswordLen:       12,
		AdminPath:                 adminPath,
		ProxyMode:                 proxyMode,
		TrustedProxies:            trustedProxies,
		FirewallBackend:           fwBackend,
		HelperTransport:           helperTransport,
		HelperSocket:              helperSocket,
		UseNsenter:                useNsenter,
		IPv6GrantPrefix:           ipv6Prefix,
		RateLimitPerIPAttempts:    5,
		RateLimitPerIPWindow:      60 * time.Second,
		DistributedFailedIPThresh: distThresh,
		DistributedWindow:         5 * time.Minute,
		DistributedLockoutMinutes: distLockout,
		AuditRetentionDays:        auditDays,
		LogLevel:                  getEnv("LOG_LEVEL", "INFO"),
		IsDocker:                  isDocker,
		IsSystemd:                 isSystemd,
	}, nil
}

// ParseCIDRList parses comma-separated CIDRs into netip.Prefix slices.
func ParseCIDRList(input string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			// Try as single IP
			addr, addrErr := netip.ParseAddr(part)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid CIDR or IP '%s': %w", part, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.IsDir()
}
