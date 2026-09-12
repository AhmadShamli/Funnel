# ⚡ Funnel by ExciteCreation

[![GitHub](https://img.shields.io/badge/GitHub-AhmadShamli%2FFunnel-blue?logo=github)](https://github.com/AhmadShamli/Funnel)
[![Version](https://img.shields.io/badge/version-0.1.0-emerald)](https://github.com/AhmadShamli/Funnel)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**On-demand, temporary firewall port access for your servers via a simple web interface.**
Maintained by [ExciteCreation](https://github.com/AhmadShamli/Funnel).

Instead of exposing management ports (SSH, databases, staging tools, internal dashboards) to the entire public internet 24/7 or wrestling with complicated VPN profiles on every visitor's device, **Funnel by ExciteCreation** gives you instant, web-authenticated access on demand.

A user visits your Funnel URL in their browser, enters an access password, and their detected public IP address is immediately authorized on the host firewall for a set duration. When time runs out or the user disconnects, the firewall rule automatically closes.

---

## 🎯 How It Works

### For End Users
```
   1. Visit Web Page       2. Enter Access Password       3. Connect Directly
+----------------------+     +---------------------+     +--------------------+
|  Detected IP:        |     |                     |     |  ✅ Access Active   |
|  203.0.113.42        | --> |  [ Password ]       | --> |  Ports: 22, 5432   |
|                      |     |  [ Grant Access ]   |     |  Time Left: 59:42  |
+----------------------+     +---------------------+     +--------------------+
                                                         Run: ssh user@server
```
1. **Visit your Funnel link** (e.g., `https://access.yourcompany.com`).
2. **Enter an access password** provided by your server administrator. No username, registration, or software installation required.
3. **Connect directly**: The firewall grants your public IP address access to approved ports. A live countdown timer shows how long your session remains active.
4. **Extend or Disconnect**: Extend your session if you need more time, or click **Disconnect** to close your ports immediately.
5. **Complete Privacy**: Users sharing a public office NAT or mobile carrier IP (CGNAT) authenticate independently. You will never see other active sessions or open ports on your network.

---

### For Server Administrators
Through an embedded web dashboard at `/admin`, administrators have complete control:
- **Port Groups**: Define reusable port bundles (e.g. `SSH: 22/tcp`, `Postgres: 5432/tcp`, `Dev Web: 8080/tcp`).
- **Access Keys**: Create labeled passwords (e.g. *"Dev Team"*, *"Contractor Bob"*, *"Staging Testing"*). Optionally set expiration dates, max concurrent IPs, or single-use limits.
- **Allowed Networks (CIDR Policies)**: Whitelist office or home IP ranges to be **Always-Allowed** (automatic access without needing a password) or enforce password requirements.
- **Immediate Port Refcounting**: If two people behind the same office IP have active sessions, closing one session only removes ports that are no longer needed by anyone.
- **Automatic Reboot Reconciliation**: If your server reboots, Funnel immediately scans active grants and re-applies their firewall rules, while purging any expired ones.
- **Brute-Force & Botnet Protection**: Built-in two-tier rate limiting slows down attackers on a single IP and trips a global circuit breaker if password spraying occurs across multiple IPs.
- **Zero-Dependency Single Binary**: Pure Go executable with zero host Python, C compiler, or npm dependencies. Ships with embedded HTML/CSS/JS.

---

## 🚀 Quickstart

### Option A: Docker Deployment (Recommended)

Funnel packages both the web server and the firewall engine in a single container. It connects to your existing reverse proxy network while securely managing the host's Linux firewall via standard kernel capabilities.

1. **Clone and create your configuration**:
   ```bash
   git clone https://github.com/AhmadShamli/Funnel.git
   cd Funnel
   cp .env.example .env
   ```

2. **Configure your `.env`**:
   At minimum, set a secure random secret and verify your external proxy network:
   ```env
   SECRET_KEY=generate-a-secure-random-secret-key-here
   EXTERNAL_NETWORK_NAME=web_proxy
   ```
   > [!TIP]
   > Funnel automatically runs as an unprivileged system user inside the container. If you want to match a specific host UID/GID (e.g. `1000`), you can set `FUNNEL_UID=1000` in `.env`.

3. **Start Funnel**:
   ```bash
   docker compose up -d
   ```

4. **Retrieve your one-time setup token**:
   ```bash
   docker compose logs funnel | grep -A 4 "FUNNEL BOOTSTRAP"
   ```

5. **Complete initial setup**:
   Navigate to `http://<your-domain>/setup`, enter the token from stdout, and create your master administrator account.

---

### Option B: Bare-Metal Linux (Systemd)

For standalone dedicated servers, VPS instances, or home labs running Debian, Ubuntu, RHEL, Rocky Linux, Fedora, or Arch Linux without Docker:

1. **Build or download the standalone static binary**:
   ```bash
   CGO_ENABLED=0 go build -ldflags="-s -w" -o ./bin/funnel ./cmd/funnel
   ```

2. **Run the automated installer as root**:
   ```bash
   sudo bash deploy/install.sh
   ```
   *The installer automatically creates the dedicated `funnel` system user, configures locked-down sudoers rules for firewall manipulation, deploys `/etc/systemd/system/funnel.service`, and starts the service on `127.0.0.1:8000`.*

3. **Retrieve your initial setup token**:
   ```bash
   sudo journalctl -u funnel.service -n 25 --no-pager
   ```

4. **Complete initial setup**:
   Open `http://127.0.0.1:8000/setup` (or via SSH port forward: `ssh -L 8000:127.0.0.1:8000 user@your-server`) to create your administrator account.

---

## 🌐 Reverse Proxy Configuration

Funnel expects to run behind a reverse proxy (such as Nginx, Caddy, or Cloudflare) that terminates TLS.

### Nginx
```nginx
server {
    listen 443 ssl http2;
    server_name access.example.com;

    ssl_certificate     /etc/letsencrypt/live/access.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/access.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy
```caddy
access.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

> [!IMPORTANT]
> In your `.env` file, ensure `TRUSTED_PROXIES` includes the internal IP or subnet of your reverse proxy (e.g. `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32`). This guarantees Funnel resolves the real visitor IP and prevents header spoofing.

---

## 🛡️ Supported Linux Firewall Engines

Funnel works with modern and legacy Linux firewall frameworks:

| Firewall Engine | Backend Identifier | Status & Description |
| :--- | :--- | :--- |
| **`nftables`** | `nftables` | **Recommended**. Atomic ruleset updates targeting `table inet funnel` with native dual-stack IPv4 and IPv6 support. |
| **`iptables`** | `iptables` | Legacy Linux support using dedicated `FUNNEL_INPUT` chains in `iptables` and `ip6tables`. |
| **`ufw`** | `ufw` | Ubuntu/Debian Uncomplicated Firewall integration. |
| **`firewalld`** | `firewalld` | Red Hat / Rocky / Fedora Rich Rule integration. |
| **`mock`** | `mock` | In-memory simulator for non-root local testing and automated CI/CD. |

By default, Funnel uses `FIREWALL_BACKEND=auto`, automatically probing and selecting the best available driver on your system in order of preference.

---

## ⚙️ Configuration Reference

All settings can be configured via environment variables or a `.env` file in the working directory:

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `FUNNEL_PORT` | `8000` | HTTP port the web server listens on. |
| `FUNNEL_HOST` | `127.0.0.1` (native) / `0.0.0.0` (Docker) | Bind address for incoming HTTP traffic. |
| `SECRET_KEY` | `(randomized)` | Pepper for HMAC-SHA256 password hashing and session signing. |
| `COOKIE_SECURE` | `false` | Set to `true` when serving behind an HTTPS reverse proxy. |
| `PROXY_MODE` | `reverse_proxy` | Ingress client IP strategy (`reverse_proxy`, `cloudflare`, or `direct`). |
| `TRUSTED_PROXIES` | `RFC1918 + loopback` | Subnets allowed to send `X-Forwarded-For` or `CF-Connecting-IP` headers. |
| `FIREWALL_BACKEND` | `auto` | Active firewall driver (`auto`, `nftables`, `firewalld`, `ufw`, `iptables`, `mock`). |
| `FUNNEL_HELPER_TRANSPORT` | `sudo` | Privilege escalation method (`sudo`, `socket`, or `internal`). |
| `DISTRIBUTED_FAILED_IPS_THRESHOLD` | `5` | Unique failed IPs required within 5 minutes to trip the circuit breaker. |
| `DISTRIBUTED_LOCKOUT_DURATION_MINUTES` | `15` | Minutes to pause public logins when the circuit breaker trips. |
| `AUDIT_LOG_RETENTION_DAYS` | `90` | Days to retain audit history (set to `0` for indefinite retention). |
| `DATABASE_PATH` | `/data/funnel.db` (Docker) / `/var/lib/funnel/funnel.db` | SQLite database file location. |
| `FUNNEL_UID` | `(system dynamic)` | Optional runtime UID override for the unprivileged container user. |
| `FUNNEL_GID` | `(system dynamic)` | Optional runtime GID override for the unprivileged container group. |

---

## 💻 CLI Commands

The single static binary `/usr/local/bin/funnel` supports the following commands:

```bash
# Start the web server and background maintenance worker (default)
funnel serve

# Perform a service health check (useful in Docker/Kubernetes health checks)
funnel health

# Execute privileged firewall helper action (used internally via sudo)
funnel helper exec

# Run privileged helper daemon on a Unix domain socket
funnel helper daemon --socket /run/funnel/helper.sock

# Print version information
funnel version
```

---

## 🧪 Testing

Funnel includes a full unit and integration test suite that tests database mutations, rate limiting, IP resolution, template rendering, and firewall logic using the in-memory mock adapter without needing root privileges:

```bash
go test -v ./...
```

---

## 📄 License

Apache License 2.0. See [LICENSE](file:///workspace/Funnel/LICENSE) for full details.
