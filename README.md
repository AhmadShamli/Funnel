# ⚡ Funnel

> Secure, lightweight, high-performance web-authorized port access for Linux.

Funnel compiles to a single standalone static Go binary that grants a visitor's detected public IPv4 or IPv6 address temporary access to approved network ports.

Access is granted under two authorization modes:
1. **Always-Allowed**: Automated grants when an administrator has marked an IP/CIDR as always allowed.
2. **Password-Only Authenticated**: Visitor enters a valid access password associated with an administrator-managed access key. Visitors are anonymous and do not register or provide usernames.

---

## Key Features

- **Single Standalone Static Binary**: Zero Python or runtime dependencies on the host, embedded zero-CDN HTML/CSS/JS assets, instant sub-second startup, ~14MB binary, and tiny Docker image (~35MB).
- **Anonymous Visitor Access**: Visitors enter only an access password. Passwords are evaluated using keyed HMAC-SHA256 with an indexed O(1) database lookup and constant-time comparison (<0.01ms CPU, 0 MB RAM), completely preventing CPU/memory exhaustion attacks.
- **Shared NAT & Multi-User Privacy**: Multiple visitors behind the same public NAT/mobile CGNAT authenticate independently. The visitor view strictly shows only the current visitor's granted ports and duration, never disclosing peer sessions or open ports on that IP.
- **Immediate Port Delta Sync (Refcounting)**: When a grant expires or is revoked, Funnel queries remaining active grants for that IP and removes only the firewall port rules that no longer have any active claim from any user.
- **Dual-Mode Deployment**: First-class support for both **Docker** (bridging host network namespace via `nsenter`) and **Bare-Metal Linux** (native systemd service with locked-down sudoers).
- **Comprehensive Linux Firewall Backends**:
  - `nftables` (`table inet funnel`) with dual-stack IPv4/IPv6 support (Reference backend)
  - `iptables` / `ip6tables` (`FUNNEL_INPUT` chain)
  - `ufw`
  - `firewalld`
  - `mock` in-memory adapter for automated CI/CD and non-root test coverage.
- **Startup Recovery & Reconciliation**: Scans SQLite on service start, transitions offline-expired grants, flushes stale rules, and atomically re-applies active firewall rules.
- **Two-Tier Brute-Force Defense**:
  - **Level 1**: 5 attempts/minute per IP with progressive exponential backoff (30s to 300s). Confined strictly to the offending IP.
  - **Level 2 (Distributed Circuit Breaker)**: When failed attempts span multiple distinct IPs exceeding threshold (default 5 IPs), pauses password-only logins globally for a lockout cooldown while keeping active grants open.
- **Granular Extension Policy**: Configurable `allow_extend` on keys, port groups, users, and networks; `max_extensions` limits; password challenge prompt for visitors; and hard cumulative duration ceilings bounded by initial duration.
- **First-Run Bootstrap Wizard**: Web setup wizard at `/setup` protected by a one-time random 32-character hex bootstrap token logged to stdout. Permanently disables itself once the first administrator is created.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Visitor / Admin Browser   |
                      +--------------+--------------+
                                     |
                                   HTTPS
                                     |
                      +--------------v--------------+
                      | Reverse Proxy / Cloudflare  |
                      +--------------+--------------+
                                     | Forwarded Headers
                      +--------------v--------------+
                      |     Funnel Web Service      |
                      |  (Unprivileged: nonroot/65532)|
                      | - Safe Client IP Resolver   |
                      | - Keyed HMAC-SHA256 Auth    |
                      | - SQLite WAL Database       |
                      | - Embedded Worker Goroutine |
                      +--------------+--------------+
                                     |
                   Typed IPC: Sudo CLI or Unix Socket
                                     |
                      +--------------v--------------+
                      |   Privileged Helper Engine  |
                      | (nsenter --net=/proc/1/ns/net)|
                      +--------------+--------------+
                                     |
                      +--------------v--------------+
                      | Host Firewall: inet funnel  |
                      +-----------------------------+
```

---

## Quickstart: Docker Compose

1. Clone the repository and copy the environment configuration:
   ```bash
   git clone https://github.com/AhmadShamli/Funnel.git
   cd Funnel
   cp .env.example .env
   ```

2. Edit `.env` to configure your settings (e.g. `SECRET_KEY`, `EXTERNAL_NETWORK_NAME`).

3. Start the container:
   ```bash
   docker compose up -d
   ```

4. Retrieve the initial setup token from stdout:
   ```bash
   docker compose logs funnel | grep -A 4 "FUNNEL BOOTSTRAP"
   ```

5. Open `http://<your-server-or-domain>/setup`, enter the bootstrap token, and create your administrator account.

---

## Quickstart: Bare-Metal Linux (Systemd)

Funnel includes an idempotent installer script for bare-metal and VM environments running Debian, Ubuntu, RHEL, Rocky Linux, Fedora, or Arch Linux:

1. Build or download the static binary:
   ```bash
   CGO_ENABLED=0 go build -ldflags="-s -w" -o ./bin/funnel ./cmd/funnel
   ```

2. Run the automated installer as root:
   ```bash
   sudo bash deploy/install.sh
   ```

3. The installer creates system user `funnel`, installs `/etc/sudoers.d/funnel`, creates `/etc/funnel/funnel.env`, and starts `funnel.service`.

4. Retrieve the bootstrap setup token:
   ```bash
   journalctl -u funnel.service -n 25 --no-pager
   ```

5. Navigate to `http://127.0.0.1:8000/setup` to complete setup.

---

## Reverse Proxy Integration

Funnel is designed to run behind your existing reverse proxy. Example configurations are provided in `deploy/`:
- **Nginx**: [`deploy/nginx.conf.example`](file:///workspace/Funnel/deploy/nginx.conf.example)
- **Caddy**: [`deploy/caddy.conf.example`](file:///workspace/Funnel/deploy/caddy.conf.example)

Ensure that your reverse proxy forwards `X-Forwarded-For` or `Forwarded` headers, and that its IP is included in `TRUSTED_PROXIES` in `.env`.

---

## CLI Reference

The compiled `funnel` binary provides subcommands:

- `funnel serve`: Starts the web server, background reconciliation worker, and helper transport (default).
- `funnel helper exec`: Accepts typed JSON from stdin to execute privileged firewall mutations.
- `funnel helper daemon --socket <path>`: Runs a root Unix domain socket daemon.
- `funnel health`: Performs a health check against the local running service (exits 0 on success).
- `funnel version`: Displays version and build information.

---

## Running the Automated Test Suite

Funnel uses the in-memory `MockFirewallAdapter` and pure-Go SQLite driver for complete unit and integration test coverage without requiring root privileges:

```bash
# Run all tests across the codebase
go test -v ./...
```

---

## License

Apache License 2.0. See [LICENSE](file:///workspace/Funnel/LICENSE) for details.
