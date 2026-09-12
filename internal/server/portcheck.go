package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
			addCandidate(host)
		} else if reqHost != "" {
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

		// If local loopback explicitly refused the connection, check if any other candidate is non-loopback
		// If only loopbacks remain, no need to retry identical loopbacks
		if strings.Contains(err.Error(), "refused") && (cand == "127.0.0.1" || cand == "::1") {
			continue
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

	if lastErr != nil {
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
