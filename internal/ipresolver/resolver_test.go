package ipresolver

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}

	resolver := NewResolver("reverse_proxy", trusted)

	// 1. Direct untrusted connection - headers ignored
	req1, _ := http.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "203.0.113.195:45231"
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	if ip := resolver.ResolveClientIP(req1); ip.String() != "203.0.113.195" {
		t.Errorf("untrusted peer should ignore XFF: expected 203.0.113.195, got %s", ip.String())
	}

	// 2. Trusted proxy with X-Forwarded-For
	req2, _ := http.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.2:8000"
	req2.Header.Set("X-Forwarded-For", "198.51.100.5, 172.16.0.10")
	if ip := resolver.ResolveClientIP(req2); ip.String() != "198.51.100.5" {
		t.Errorf("trusted proxy XFF: expected 198.51.100.5, got %s", ip.String())
	}

	// 3. Cloudflare mode with CF-Connecting-IP
	resolver.SetProxyMode("cloudflare")
	req3, _ := http.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "10.0.0.2:8000"
	req3.Header.Set("CF-Connecting-IP", "203.0.113.88")
	if ip := resolver.ResolveClientIP(req3); ip.String() != "203.0.113.88" {
		t.Errorf("cloudflare mode: expected 203.0.113.88, got %s", ip.String())
	}

	// 4. RFC 7239 Forwarded header
	resolver.SetProxyMode("reverse_proxy")
	req4, _ := http.NewRequest("GET", "/", nil)
	req4.RemoteAddr = "127.0.0.1:8000"
	req4.Header.Set("Forwarded", "for=198.51.100.77;proto=https")
	if ip := resolver.ResolveClientIP(req4); ip.String() != "198.51.100.77" {
		t.Errorf("RFC 7239 Forwarded: expected 198.51.100.77, got %s", ip.String())
	}

	// 5. IPv6 handling
	req5, _ := http.NewRequest("GET", "/", nil)
	req5.RemoteAddr = "127.0.0.1:8000"
	req5.Header.Set("Forwarded", "for=\"[2001:db8::1234]\";proto=https")
	if ip := resolver.ResolveClientIP(req5); ip.String() != "2001:db8::1234" {
		t.Errorf("IPv6 Forwarded: expected 2001:db8::1234, got %s", ip.String())
	}
}
