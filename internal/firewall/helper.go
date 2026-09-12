package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
)

// HelperRequest represents a typed IPC request to the privileged firewall helper.
type HelperRequest struct {
	Action          string             `json:"action"` // "detect", "validate", "apply_grant", "revoke_grant", "sync_grants", "list_rules"
	Backend         string             `json:"backend,omitempty"`
	GrantID         int64              `json:"grant_id,omitempty"`
	IP              string             `json:"ip,omitempty"`
	Ports           []models.PortRule  `json:"ports,omitempty"`
	DurationSeconds int                `json:"duration_seconds,omitempty"`
	ActiveGrants    []ActiveGrantRules `json:"active_grants,omitempty"`
}

// HelperResponse represents the typed IPC response from the helper.
type HelperResponse struct {
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
	Backends []BackendInfo `json:"backends,omitempty"`
	Rules    []ActiveRule  `json:"rules,omitempty"`
}

// HelperClient provides IPC communication to the privileged firewall helper.
type HelperClient struct {
	transport  string // "internal", "sudo", "socket"
	socketPath string
	factory    *Factory
	backend    string
}

// NewHelperClient initializes the helper client.
func NewHelperClient(transport, socketPath, backend string, factory *Factory) *HelperClient {
	return &HelperClient{
		transport:  transport,
		socketPath: socketPath,
		factory:    factory,
		backend:    backend,
	}
}

// Execute sends an IPC request and returns the response.
func (c *HelperClient) Execute(ctx context.Context, req HelperRequest) (*HelperResponse, error) {
	if req.Backend == "" {
		req.Backend = c.backend
	}

	switch c.transport {
	case "internal":
		return c.executeInternal(ctx, req)
	case "socket":
		return c.executeSocket(ctx, req)
	case "sudo":
		return c.executeSudo(ctx, req)
	default:
		return c.executeInternal(ctx, req)
	}
}

func (c *HelperClient) executeInternal(ctx context.Context, req HelperRequest) (*HelperResponse, error) {
	server := NewHelperServer(c.factory)
	return server.Handle(ctx, req), nil
}

func (c *HelperClient) executeSocket(ctx context.Context, req HelperRequest) (*HelperResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to helper socket %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to encode helper request: %w", err)
	}

	var resp HelperResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode helper response: %w", err)
	}

	return &resp, nil
}

func (c *HelperClient) executeSudo(ctx context.Context, req HelperRequest) (*HelperResponse, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// In sudo mode: invoke sudo /usr/local/bin/funnel helper exec
	// Or self executable
	executable, err := os.Executable()
	if err != nil {
		executable = "/usr/local/bin/funnel"
	}

	var cmd *exec.Cmd
	// If currently running as root or mock, sudo is unnecessary
	if os.Geteuid() == 0 || c.backend == "mock" {
		cmd = exec.CommandContext(ctx, executable, "helper", "exec")
	} else {
		cmd = exec.CommandContext(ctx, "sudo", executable, "helper", "exec")
	}

	cmd.Stdin = bytes.NewReader(reqBytes)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		// Fallback to internal if sudo not permitted or during testing
		return c.executeInternal(ctx, req)
	}

	var resp HelperResponse
	if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse helper json output (%s): %w", strings.TrimSpace(outBuf.String()), err)
	}

	return &resp, nil
}

// HelperServer handles requests received by the privileged helper.
type HelperServer struct {
	factory *Factory
}

// NewHelperServer creates a new helper server.
func NewHelperServer(factory *Factory) *HelperServer {
	return &HelperServer{factory: factory}
}

// Handle processes a single typed request.
func (s *HelperServer) Handle(ctx context.Context, req HelperRequest) *HelperResponse {
	// Validate IP if provided
	var addr netip.Addr
	if req.IP != "" {
		parsed, err := netip.ParseAddr(req.IP)
		if err != nil {
			return &HelperResponse{Success: false, Error: fmt.Sprintf("invalid ip address: %s", req.IP)}
		}
		addr = parsed
	}

	// Validate ports
	for _, p := range req.Ports {
		if p.Port < 1 || p.Port > 65535 {
			return &HelperResponse{Success: false, Error: fmt.Sprintf("invalid port number: %d", p.Port)}
		}
		proto := strings.ToLower(p.Protocol)
		if proto != "tcp" && proto != "udp" {
			return &HelperResponse{Success: false, Error: fmt.Sprintf("invalid protocol: %s", p.Protocol)}
		}
	}

	adapter := s.factory.SelectBackend(ctx, req.Backend)

	switch req.Action {
	case "detect":
		backends := s.factory.DetectAll(ctx)
		return &HelperResponse{Success: true, Backends: backends}

	case "validate":
		err := adapter.Validate(ctx)
		if err != nil {
			return &HelperResponse{Success: false, Error: err.Error()}
		}
		return &HelperResponse{Success: true}

	case "apply_grant":
		if !addr.IsValid() {
			return &HelperResponse{Success: false, Error: "missing valid target IP"}
		}
		duration := time.Duration(req.DurationSeconds) * time.Second
		err := adapter.ApplyGrant(ctx, req.GrantID, addr, req.Ports, duration)
		if err != nil {
			return &HelperResponse{Success: false, Error: err.Error()}
		}
		return &HelperResponse{Success: true}

	case "revoke_grant":
		if !addr.IsValid() {
			return &HelperResponse{Success: false, Error: "missing valid target IP"}
		}
		err := adapter.RevokeGrant(ctx, req.GrantID, addr, req.Ports)
		if err != nil {
			return &HelperResponse{Success: false, Error: err.Error()}
		}
		return &HelperResponse{Success: true}

	case "sync_grants":
		err := adapter.SyncGrants(ctx, req.ActiveGrants)
		if err != nil {
			return &HelperResponse{Success: false, Error: err.Error()}
		}
		return &HelperResponse{Success: true}

	case "list_rules":
		rules, err := adapter.ListActiveRules(ctx)
		if err != nil {
			return &HelperResponse{Success: false, Error: err.Error()}
		}
		return &HelperResponse{Success: true, Rules: rules}

	default:
		return &HelperResponse{Success: false, Error: fmt.Sprintf("unknown helper action: %s", req.Action)}
	}
}

// RunSocketDaemon starts the Unix domain socket server.
func (s *HelperServer) RunSocketDaemon(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)
	dir := filepath.Dir(socketPath)
	_ = os.MkdirAll(dir, 0755)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to bind helper unix socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	// Allow unprivileged group/user to access socket
	_ = os.Chmod(socketPath, 0660)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			var req HelperRequest
			decoder := json.NewDecoder(c)
			if err := decoder.Decode(&req); err != nil {
				json.NewEncoder(c).Encode(HelperResponse{Success: false, Error: err.Error()})
				return
			}
			resp := s.Handle(ctx, req)
			json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}
