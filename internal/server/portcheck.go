package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AhmadShamli/Funnel/internal/config"
	"github.com/AhmadShamli/Funnel/internal/models"
)

// PortCheckStatus describes the accessibility test result for a single port.
type PortCheckStatus struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Open      bool   `json:"open"`
	Status    string `json:"status"` // "open", "closed", "unreachable"
	Message   string `json:"message"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// CheckPortsConcurrently tests all given ports concurrently against candidate targets.
func CheckPortsConcurrently(ctx context.Context, ports []models.PortRule, candidates []string, perCandidateTimeout time.Duration) []PortCheckStatus {
	results := make([]PortCheckStatus, len(ports))
	var wg sync.WaitGroup

	if perCandidateTimeout <= 0 {
		perCandidateTimeout = 500 * time.Millisecond
	}

	for i, p := range ports {
		wg.Add(1)
		go func(idx int, rule models.PortRule) {
			defer wg.Done()
			results[idx] = testSinglePort(ctx, rule, candidates, perCandidateTimeout)
		}(i, p)
	}

	wg.Wait()
	return results
}

// GetProbeCandidates discovers candidate target IP addresses / hostnames for testing ports.
func GetProbeCandidates(reqHost string, cfg *config.Config) []string {
	var candidates []string
	seen := make(map[string]bool)

	addCandidate := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		candidates = append(candidates, h)
	}

	addCandidate("127.0.0.1")
	addCandidate("::1")

	if cfg != nil && cfg.Host != "" && cfg.Host != "0.0.0.0" && cfg.Host != "::" {
		addCandidate(cfg.Host)
	}

	if reqHost != "" {
		host, _, err := net.SplitHostPort(reqHost)
		if err == nil && host != "" {
			if host != "example.com" {
				addCandidate(host)
			}
		} else if reqHost != "" && reqHost != "example.com" {
			addCandidate(reqHost)
		}
	}

	if gw := detectDefaultGateway(); gw != "" {
		addCandidate(gw)
	}

	return candidates
}

func testSinglePort(ctx context.Context, rule models.PortRule, candidates []string, timeout time.Duration) PortCheckStatus {
	proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if proto == "" {
		proto = "tcp"
	}

	status := PortCheckStatus{
		Port:     rule.Port,
		Protocol: proto,
		Open:     false,
		Status:   "closed",
		Message:  "Port closed",
	}

	if proto == "udp" {
		// Test UDP listeners via Linux /proc/net/udp if available
		procPaths := []string{"/proc/net/udp", "/proc/net/udp6", "/proc/1/net/udp", "/proc/1/net/udp6"}
		if checkProcListening(procPaths, rule.Port, "") {
			status.Open = true
			status.Status = "open"
			status.Message = "UDP service active and listening"
			return status
		}

		// Fallback: test UDP socket connect
		for _, cand := range candidates {
			addr := net.JoinHostPort(cand, strconv.Itoa(rule.Port))
			conn, err := net.DialTimeout("udp", addr, timeout)
			if err == nil {
				_ = conn.Close()
				status.Open = true
				status.Status = "open"
				status.Message = "UDP port rule active"
				return status
			}
		}
		return status
	}

	// TCP testing: actively probe candidates
	var lastErr error
	var hadRefused bool
	for _, cand := range candidates {
		addr := net.JoinHostPort(cand, strconv.Itoa(rule.Port))
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			status.Open = true
			status.Status = "open"
			status.Message = "Port is open and accessible"
			status.LatencyMs = time.Since(start).Milliseconds()
			return status
		}
		lastErr = err

		if strings.Contains(err.Error(), "refused") {
			hadRefused = true
			if cand == "127.0.0.1" || cand == "::1" {
				continue
			}
		}
	}

	// Secondary check: examine /proc/net/tcp for local listening socket
	procPaths := []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/1/net/tcp", "/proc/1/net/tcp6"}
	if checkProcListening(procPaths, rule.Port, "0A") {
		status.Open = true
		status.Status = "open"
		status.Message = "Service is listening on host"
		return status
	}

	if hadRefused {
		status.Status = "closed"
		status.Message = "Connection refused (no service listening)"
	} else if lastErr != nil {
		if errors.Is(lastErr, context.DeadlineExceeded) || strings.Contains(lastErr.Error(), "timeout") {
			status.Status = "unreachable"
			status.Message = "Connection timed out"
		} else if strings.Contains(lastErr.Error(), "refused") {
			status.Status = "closed"
			status.Message = "Connection refused (no service listening)"
		} else {
			status.Status = "unreachable"
			status.Message = lastErr.Error()
		}
	}

	return status
}

func checkProcListening(procPaths []string, port int, targetState string) bool {
	targetPortSuffix := fmt.Sprintf(":%04X", port)

	for _, path := range procPaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				localAddr := strings.ToUpper(fields[1])
				state := strings.ToUpper(fields[3])
				if strings.HasSuffix(localAddr, targetPortSuffix) {
					if targetState == "" || state == targetState {
						_ = f.Close()
						return true
					}
				}
			}
		}
		_ = f.Close()
	}
	return false
}

func detectDefaultGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			if d, err := strconv.ParseUint(gwHex, 16, 32); err == nil && d != 0 {
				ip := net.IPv4(byte(d), byte(d>>8), byte(d>>16), byte(d>>24))
				return ip.String()
			}
		}
	}
	return ""
}

// SystemListeningSocket describes a local TCP/UDP socket detected on the host system.
type SystemListeningSocket struct {
	Protocol          string   `json:"protocol"` // "tcp" or "udp"
	IP                string   `json:"ip"`       // "0.0.0.0", "127.0.0.1", "::", etc.
	Port              int      `json:"port"`
	State             string   `json:"state"` // "LISTEN"
	Scope             string   `json:"scope"` // "public", "localhost", "private"
	FunnelStatus      string   `json:"funnel_status"` // "active_grant", "configured", "exposed", "localhost"
	MatchedPortGroups []string `json:"matched_port_groups,omitempty"`
	ActiveGrantsCount int      `json:"active_grants_count"`
}

// OpenPortGrantRef references an active grant associated with an open port.
type OpenPortGrantRef struct {
	GrantID          int64     `json:"grant_id"`
	SourceIP         string    `json:"source_ip"`
	GrantSource      string    `json:"grant_source"`
	SourceLabel      string    `json:"source_label"`
	GrantedAt        time.Time `json:"granted_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RemainingSeconds int       `json:"remaining_seconds"`
}

// OpenPortSummary aggregates an open port across active firewall grants.
type OpenPortSummary struct {
	Port              int                `json:"port"`
	Protocol          string             `json:"protocol"` // "tcp" or "udp"
	RuleKey           string             `json:"rule_key"` // "22/tcp"
	PortGroupName     string             `json:"port_group_name"`
	ActiveGrantsCount int                `json:"active_grants_count"`
	ClientIPs         []string           `json:"client_ips"`
	Grants            []OpenPortGrantRef `json:"grants"`
	KernelRuleActive  bool               `json:"kernel_rule_active"`
	Listening         bool               `json:"listening"`
}

// GetSystemListeningSockets discovers all currently listening TCP and UDP sockets from the host.
func GetSystemListeningSockets() []SystemListeningSocket {
	var sockets []SystemListeningSocket
	seen := make(map[string]bool)

	procConfigs := []struct {
		paths []string
		proto string
	}{
		{[]string{"/proc/net/tcp", "/proc/1/net/tcp"}, "tcp"},
		{[]string{"/proc/net/tcp6", "/proc/1/net/tcp6"}, "tcp"},
		{[]string{"/proc/net/udp", "/proc/1/net/udp"}, "udp"},
		{[]string{"/proc/net/udp6", "/proc/1/net/udp6"}, "udp"},
	}

	for _, pc := range procConfigs {
		for _, path := range pc.paths {
			f, err := os.Open(path)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(f)
			firstLine := true
			for scanner.Scan() {
				if firstLine {
					firstLine = false
					continue
				}

				fields := strings.Fields(scanner.Text())
				if len(fields) < 4 {
					continue
				}

				state := strings.ToUpper(fields[3])
				if pc.proto == "tcp" && state != "0A" {
					continue
				}
				if pc.proto == "udp" && state != "07" && !strings.HasSuffix(fields[2], ":0000") {
					continue
				}

				ip, port, err := parseProcAddress(fields[1])
				if err != nil || port <= 0 {
					continue
				}

				// Normalize IPv4-mapped IPv6
				if ip4 := ip.To4(); ip4 != nil {
					ip = ip4
				}

				ipStr := ip.String()
				key := fmt.Sprintf("%s:%s:%d", pc.proto, ipStr, port)
				if seen[key] {
					continue
				}
				seen[key] = true

				sockets = append(sockets, SystemListeningSocket{
					Protocol: pc.proto,
					IP:       ipStr,
					Port:     port,
					State:    "LISTEN",
					Scope:    determineScope(ip),
				})
			}
			_ = f.Close()
		}
	}

	sort.Slice(sockets, func(i, j int) bool {
		if sockets[i].Port != sockets[j].Port {
			return sockets[i].Port < sockets[j].Port
		}
		if sockets[i].Protocol != sockets[j].Protocol {
			return sockets[i].Protocol < sockets[j].Protocol
		}
		return sockets[i].IP < sockets[j].IP
	})

	return sockets
}

func parseProcAddress(hexAddr string) (net.IP, int, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return nil, 0, errors.New("invalid address format")
	}

	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	port := int(portVal)

	ipHex := parts[0]
	if len(ipHex) == 8 {
		// IPv4 (32-bit little-endian)
		val, err := strconv.ParseUint(ipHex, 16, 32)
		if err != nil {
			return nil, 0, err
		}
		ip := net.IPv4(byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
		return ip, port, nil
	} else if len(ipHex) == 32 {
		// IPv6 (four 32-bit words, each little-endian)
		var ipBytes [16]byte
		for i := 0; i < 4; i++ {
			wStr := ipHex[i*8 : (i+1)*8]
			wVal, err := strconv.ParseUint(wStr, 16, 32)
			if err != nil {
				return nil, 0, err
			}
			ipBytes[i*4] = byte(wVal)
			ipBytes[i*4+1] = byte(wVal >> 8)
			ipBytes[i*4+2] = byte(wVal >> 16)
			ipBytes[i*4+3] = byte(wVal >> 24)
		}
		return net.IP(ipBytes[:]), port, nil
	}

	return nil, 0, errors.New("unrecognized IP hex length")
}

func determineScope(ip net.IP) string {
	if ip.IsLoopback() || ip.String() == "::1" || ip.String() == "127.0.0.1" {
		return "localhost"
	}
	if ip.IsUnspecified() || ip.String() == "0.0.0.0" || ip.String() == "::" {
		return "public"
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "public"
}

