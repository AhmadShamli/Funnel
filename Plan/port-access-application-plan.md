# Web-Authorized Port Access Application Plan (Go Implementation)

## 1. Goal

Build a secure, high-performance Go web application compiled to a single standalone static binary that grants a visitor's detected public IPv4 or IPv6 address access to approved network ports either automatically when an administrator has marked that IP/CIDR as always allowed, or after the visitor enters a valid access password. Visitors are anonymous and do not need usernames; administrators use named accounts to manage the system.

The application provides:
- A simple password-only access page displaying the detected client IP address.
- Temporary, policy-controlled port access after successful login.
- A success page showing the authorized IP, ports, and expiration time.
- An IP-scoped visitor view that shows only the current visitor's resolved IP, allowed ports, status, and expiration.
- Complete privacy on shared NAT/mobile IPs (never exposing other active sessions on the same public IP).
- Immediate port delta sync (refcounting) when grants expire or are revoked.
- Simple administration of access passwords, administrators, port groups, IP/CIDR rules, firewall backends, and audit history.
- Detection of supported host firewall applications, with explicit backend selection by an administrator.
- Safe client-IP detection for direct access, reverse proxies, Cloudflare, and custom Docker networks.
- Complete audit records for successful and failed logins and firewall changes.
- Maximum cross-distribution compatibility: zero host runtime dependencies, single static binary, embedded UI templates, and tiny Docker footprint (~25MB).

---

## 2. Scope and Assumptions

### In scope
- Password-only anonymous visitor access. Each password is represented by a named access key visible only to administrators.
- Access keys support optional maximum concurrent IP limits (`max_concurrent_ips`) and total use limits (`max_total_uses`).
- Separate username/password authentication for administrators with rolling 30-minute idle sessions and 12-character minimum passwords.
- Administrator-defined port lists/groups; visitors cannot enter arbitrary ports.
- Each port group can be configured as always-allowed by IP/CIDR, login-required by IP/CIDR, globally available by default, or available only through selected password-only access keys.
- Temporary access grants with automatic expiration.
- Native dual-stack IPv4 and IPv6 support from v1 (leveraging nftables 'inet' family, defaulting to /128 host scoping with configurable `IPV6_GRANT_PREFIX=128|64`).
- Responsive server-rendered web interface with zero npm/CDN dependencies, embedded directly into the Go binary.
- SQLite as the only database in WAL mode with foreign keys and busy timeout.
- Linux firewall backend detection and support for `nftables`, `iptables`, UFW, and firewalld, implemented through isolated Go adapter interfaces.
- Seamless dual-mode execution: single container under Docker (bridging host netns via `nsenter`) or native bare-metal under systemd.

### Out of scope for the first release
- Opening ports directly on cloud-provider security groups (AWS, GCP, Azure).
- Multi-host firewall orchestration or changing more than one firewall backend for a single grant.
- Visitor accounts, self-registration, SSO, LDAP, OAuth, or multi-factor authentication.
- Permanent firewall access requested by visitors.
- User-supplied firewall rules, commands, addresses, or port ranges.

---

## 3. Recommended Technology Stack (Go)

- **Language & Compiler**: Go 1.22+ (statically linked binary, `CGO_ENABLED=0` compatible).
- **HTTP Routing**: `github.com/go-chi/chi/v5` (idiomatic, lightweight standard `net/http` compatible router).
- **HTML Templating & Assets**: Standard library `html/template` with embedded templates and static CSS/JS via Go `embed.FS` (`//go:embed`).
- **Database & Persistence**: SQLite in WAL mode using pure-Go `modernc.org/sqlite` (no C compiler or external glibc dependencies).
- **Database Migrations**: Embedded SQL migrations via `pressly/goose/v3` or embedded SQL schema versioning.
- **Password Hashing**: Keyed `HMAC-SHA256(ServerPepper, Password)` for anonymous access keys (ultra-low CPU and 0 MB RAM footprint, <0.01ms); standard secure password hashing for administrator accounts.
- **Random Token Generation**: Standard library `crypto/rand`.
- **Configuration Management**: Standard environment parsing with hierarchical runtime auto-detection.
- **Firewall Integration**: Isolated Go interface (`FirewallAdapter`) wrapping `nftables`, `iptables`, `ufw`, and `firewalld` CLI/system calls.
- **Testing**: Standard library `testing`, `net/http/httptest`, and in-memory `MockFirewallAdapter`.

---

## 4. High-Level Architecture

1. A visitor connects directly or through an upstream reverse proxy (Nginx, Traefik, Caddy, Cloudflare).
2. The application resolves the client IP using Go `net/netip` from the socket peer and configured trusted proxy subnets. Untrusted headers are strictly ignored.
3. The application checks active always-allowed policies. If a matching policy exists, access is provisioned without login. Otherwise, the visitor is presented with a password form.
4. For the login path, the application evaluates candidate passwords using keyed `HMAC-SHA256(ServerPepper, Password)` with an indexed O(1) SQLite query and `crypto/subtle.ConstantTimeCompare`. This takes <0.01ms and 0 MB RAM, completely preventing CPU/RAM starvation attacks.
5. Multiple users sharing the same public NAT/mobile IP authenticate independently. The success view displays only the visitor's granted ports and duration.
6. The firewall engine applies the additive union of active ports for that public IP.
7. When an individual grant expires or is revoked, an immediate port delta sync removes only the ports no longer claimed by any active grant for that IP.
8. On service start or reboot, a full startup reconciliation scans SQLite, marks grants expired while offline, flushes stale firewall rules, and atomically re-applies rules for all currently valid grants.
9. A background Goroutine ticker loop handles periodic expiration checks, drift detection, and daily audit log pruning (default 90-day retention).

### Security Boundary
The web server runs as an unprivileged user (`funnel`, UID 10001). Privileged firewall mutations are isolated behind a pluggable transport:
- **CLI Mode**: Executes `sudo /usr/local/bin/funnel helper <operation>` via locked-down `/etc/sudoers.d/funnel`.
- **Socket Mode**: Communicates over a protected Unix domain socket (`/run/funnel/helper.sock`) served by a root daemon.
- **Docker Namespace Bridging**: When running in Docker with `pid: host`, the helper executes `nsenter --net=/proc/1/ns/net` to apply rules directly to host firewall tables.

---

## 5. User Roles

### Anonymous Visitor
- Enter only an access password; no username or registration required.
- View the IP detected for the current request (IPv4 or IPv6).
- Activate port groups assigned to the matched access key for the detected IP only.
- View only the current session's access, allowed ports, and expiration countdown. Other users' grants behind the same NAT IP are strictly concealed.
- Revoke current grant using an HttpOnly, cryptographically signed cookie token.

### Administrator & User Accounts
- Create, edit, disable, and unlock accounts (minimum 12-character passwords).
- Protected by the unified Two-Level brute-force defense: Level 1 locks offending IPs without locking the user account (preventing attacker DoS); Level 2 locks the targeted account (`locked_until`) if failed attempts originate from multiple distinct IPs (distributed attacks).
- Administrators can immediately unlock any locked account or reset the circuit breaker from the Admin Dashboard.
- Create, rotate, disable, and label access keys with optional `max_concurrent_ips` and `max_total_uses` caps.
- Create port groups and add approved ports (TCP/UDP).
- Configure port groups as global/default, key-only, always-allowed by CIDR, or login-required by CIDR.
- Inspect detected firewall backends and validate the active engine.
- Inspect active and historical grants, access attempts, and audit logs (with automated 90-day retention pruning).

---

## 6. Core Workflows

### Anonymous Access Grant Workflow
1. Resolve client IP and render the access page.
2. Check always-allowed CIDR policies. If matched, register an automated grant and display current access without requiring a password.
3. If no always-allowed rule matches, render password input.
4. Enforce two-tier rate limiting: Level 1 (5 attempts/min per IP with progressive backoff) and Level 2 distributed circuit breaker (if failed attempts span multiple distinct IPs exceeding the admin-configured threshold, temporarily pause password-only access or lock targeted admin user). When blocked, render an informative message with a live countdown timer and reassurance that existing active sessions remain open.
5. Evaluate password against active access keys using keyed `HMAC-SHA256(ServerPepper, Password)` with indexed SQLite lookup and `crypto/subtle.ConstantTimeCompare` (<0.01ms CPU, 0 MB RAM).
6. Check access key constraints: verify `is_active`, time window (`valid_from`/`valid_until`), `max_concurrent_ips`, and `max_total_uses`.
7. On match, record access grant in SQLite, issue secure HttpOnly cookie, increment key usage counters, and call firewall helper.
8. Redirect visitor to `/access/current`.

### Expiration & Port Delta Sync Workflow
1. When a visitor posts to `/access/revoke` or the background Goroutine identifies an expired grant:
2. Transition grant status to `revoked` or `expired` in SQLite with timestamp.
3. Query remaining active grants for that source IP.
4. Calculate port delta: determine which ports have zero remaining claims.
5. Invoke firewall helper to remove only the unreferenced ports.
6. If all grants for that IP are terminated, delete the entire IP element from the firewall set.

### Grant Duration Extension Workflow
Both user types see an identical primary **[ Extend Access ]** button on their `/access/current` status view:
1. **Granular Admin Controls (`allow_extend`)**: Administrators can toggle `allow_extend = true|false` individually on user accounts, access keys, port groups, and allowed network CIDR rules. If disabled on any governing part, the extension action is blocked.
2. **Maximum Extension Count (`max_extensions`)**: Administrators can cap the total number of allowed extensions (e.g. 1, 2, or unlimited). Each extension increments `extension_count`.
3. **Universal Start & End Windows (`valid_from` / `valid_until`)**: Administrators can set calendar validity windows across users, keys, port groups, and networks. Any entity can be set to **Forever / Never Expire** (`valid_until = NULL`). If a `valid_until` cutoff is defined, grants cannot be created or extended past that date.
4. **Named Authenticated Users (1-Click)**: Clicking `[ Extend Access ]` immediately triggers `POST /access/extend` based on their validated active session cookie, within configured policy limits.
5. **Password-Only Visitors (Password Prompt)**: Clicking `[ Extend Access ]` opens a password challenge prompt asking to re-enter the access password before submitting `POST /access/extend`. The server re-verifies the password against the active access key; if the key was revoked or rotated, extension is denied.
6. **Strict Maximum Duration Ceiling (Bounded by Initial Auth Duration)**: Extended time **shall never exceed the duration given during initial login/authentication**:
   - *No Time-Stacking*: Extending resets the countdown timer to at most the original duration from the moment of extension (`expires_at = now() + initial_grant_duration_seconds`), preventing time-banking beyond the initial grant.
   - *Cumulative Cap*: Total extra extended time cannot exceed the original duration given at login ($\text{max\_allowed\_lifetime} = \text{granted\_at} + 2 \times \text{initial\_grant\_duration_seconds}$, further bounded by any access key `valid_until` cutoff). Once reached, the extension button is disabled.
7. **Firewall Refresh**: On successful extension, the kernel `table inet funnel` element timeout is refreshed without resetting connection tracking, preserving active SSH/TCP streams.

---

## 7. Data Storage & Schema

### `admin_users`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `username` TEXT UNIQUE NOT NULL
- `password_hash` TEXT NOT NULL
- `role` TEXT NOT NULL DEFAULT 'admin'
- `is_active` INTEGER NOT NULL DEFAULT 1
- `allow_extend` INTEGER NOT NULL DEFAULT 1
- `max_extensions` INTEGER NULL
- `valid_from` TEXT NULL
- `valid_until` TEXT NULL
- `must_change_password` INTEGER NOT NULL DEFAULT 0
- `failed_login_count` INTEGER NOT NULL DEFAULT 0
- `locked_until` TEXT NULL
- `created_at` TEXT NOT NULL

### `admin_sessions`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `admin_user_id` INTEGER NOT NULL REFERENCES admin_users(id)
- `session_token_hash` TEXT UNIQUE NOT NULL
- `user_agent` TEXT NOT NULL
- `client_ip` TEXT NOT NULL
- `created_at` TEXT NOT NULL
- `last_activity_at` TEXT NOT NULL
- `expires_at` TEXT NOT NULL

### `access_keys`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `name` TEXT UNIQUE NOT NULL
- `password_hash` TEXT NOT NULL
- `is_active` INTEGER NOT NULL DEFAULT 1
- `allow_extend` INTEGER NOT NULL DEFAULT 1
- `max_extensions` INTEGER NULL
- `max_concurrent_ips` INTEGER NULL
- `max_total_uses` INTEGER NULL
- `use_count` INTEGER NOT NULL DEFAULT 0
- `max_duration_seconds` INTEGER NULL
- `valid_from` TEXT NULL
- `valid_until` TEXT NULL
- `last_used_at` TEXT NULL
- `created_by_admin_id` INTEGER REFERENCES admin_users(id)

### `port_groups`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `name` TEXT UNIQUE NOT NULL
- `description` TEXT NOT NULL DEFAULT ''
- `availability_mode` TEXT NOT NULL DEFAULT 'key_only'
- `allow_extend` INTEGER NOT NULL DEFAULT 1
- `max_extensions` INTEGER NULL
- `grant_duration_seconds` INTEGER NOT NULL DEFAULT 3600
- `max_duration_seconds` INTEGER NOT NULL DEFAULT 28800
- `valid_from` TEXT NULL
- `valid_until` TEXT NULL
- `network_match_mode` TEXT NOT NULL DEFAULT 'any'
- `is_active` INTEGER NOT NULL DEFAULT 1

### `port_group_ports`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `port_group_id` INTEGER NOT NULL REFERENCES port_groups(id) ON DELETE CASCADE
- `protocol` TEXT NOT NULL DEFAULT 'tcp'
- `port` INTEGER NOT NULL

### `allowed_networks`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `name` TEXT NOT NULL
- `network_cidr` TEXT NOT NULL
- `mode` TEXT NOT NULL DEFAULT 'always_allowed'
- `scope` TEXT NOT NULL DEFAULT 'global'
- `allow_extend` INTEGER NOT NULL DEFAULT 1
- `max_extensions` INTEGER NULL
- `valid_from` TEXT NULL
- `valid_until` TEXT NULL
- `access_key_id` INTEGER NULL REFERENCES access_keys(id)
- `grant_duration_seconds` INTEGER NOT NULL DEFAULT 3600
- `is_active` INTEGER NOT NULL DEFAULT 1

### `access_grants`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `access_key_id` INTEGER NULL REFERENCES access_keys(id)
- `allowed_network_id` INTEGER NULL REFERENCES allowed_networks(id)
- `grant_source` TEXT NOT NULL
- `source_ip` TEXT NOT NULL
- `ipv6_prefix_length` INTEGER NULL
- `extension_count` INTEGER NOT NULL DEFAULT 0
- `status` TEXT NOT NULL DEFAULT 'active'
- `visitor_token_hash` TEXT UNIQUE NOT NULL
- `granted_at` TEXT NOT NULL
- `expires_at` TEXT NOT NULL
- `revoked_at` TEXT NULL

### `access_grant_ports`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `access_grant_id` INTEGER NOT NULL REFERENCES access_grants(id) ON DELETE CASCADE
- `protocol` TEXT NOT NULL
- `port` INTEGER NOT NULL

### `audit_events`
- `id` INTEGER PRIMARY KEY AUTOINCREMENT
- `event_type` TEXT NOT NULL
- `actor_type` TEXT NOT NULL
- `actor_identifier` TEXT NOT NULL
- `target_ip` TEXT NOT NULL DEFAULT ''
- `details_json` TEXT NOT NULL DEFAULT '{}'
- `created_at` TEXT NOT NULL

---

## 8. Implementation Roadmap (Go)

### Phase 1: Project Foundation, Core Models & Setup Wizard
- Go module setup (`go.mod`), pure Go SQLite driver (`modernc.org/sqlite`).
- Database abstraction with WAL mode, foreign keys, and embedded migrations (`pressly/goose/v3` or embedded SQL schema).
- Setup wizard (`/setup`) gated by one-time random bootstrap token generated via `crypto/rand`.
- Unit tests for DB schema, password hashing, and setup wizard handler.

### Phase 2: Authentication & Core Visitor Flow
- Fast keyed `HMAC-SHA256` access key verification with `crypto/subtle.ConstantTimeCompare` (<0.01ms CPU, 0 MB RAM).
- Admin login, logout, and rolling session management with secure admin password hashing.
- Public visitor UI with zero external dependencies embedded via `//go:embed`.
- Two-tier rate limiting middleware: Level 1 per-IP progressive backoff + Level 2 distributed multi-IP circuit breaker (admin-configurable failed IP threshold and lockout duration).

### Phase 3: Port Groups & Network Policy Engine
- CRUD operations for port groups, ports, and allowed network CIDRs.
- IP matching engine using Go `net/netip` supporting IPv4 and IPv6 CIDRs.
- Access evaluation logic: always-allowed vs password-authenticated.

### Phase 4: Firewall Helper & Adapters
- Pluggable IPC helper interface: CLI sub-command (`funnel helper`) or Unix socket.
- `MockFirewallAdapter` for automated CI tests without root privileges.
- `NftablesAdapter` targeting `table inet funnel` with native element timeouts.
- `iptables`, `ufw`, and `firewalld` adapters.

### Phase 5: Expiration, Reconciliation & Background Worker
- Background Goroutine ticker loop with graceful context cancellation.
- Immediate port delta sync refcounting on grant revocation/expiration.
- Full startup reconciliation workflow (offline grant expiration + orphan rule purge).
- Daily audit event retention pruner.

### Phase 6: Proxy & Client IP Engine
- Safe client IP resolution: direct socket peer, RFC 7239 `Forwarded`, `X-Forwarded-For`, and `CF-Connecting-IP`.
- Trusted proxy CIDR verification with Docker/RFC1918 defaults.
- Cloudflare IP range refresh client and Admin inspection UI.

### Phase 7: Packaging, Verification & Production Hardening
- Multi-stage Dockerfile compiling a static Go binary into a ~25MB image.
- Automated `install.sh` native Linux installer (distro package detection, system user, systemd unit).
- Dual-mode verification (Docker with `nsenter` and bare-metal native execution).

---

## 9. Acceptance Criteria

- Login page accurately detects visitor public IPv4 or IPv6 address.
- Anonymous visitors enter only a password without a username.
- Users behind shared NAT/CGNAT authenticate independently with zero peer data leakage.
- Ports are refcounted: closing one session on a shared NAT IP preserves ports needed by active peer sessions.
- Full startup reconciliation cleans orphan rules and restores valid grants after reboot.
- Zero host runtime dependencies: single static binary runs on any Linux distribution.
- Docker image is lightweight (~25MB) and joins external proxy networks while modifying host firewall via `nsenter`.
- Full test suite passes without requiring root privileges using `MockFirewallAdapter`.
