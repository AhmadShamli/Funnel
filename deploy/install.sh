#!/usr/bin/env bash
set -euo pipefail

# Funnel Native Bare-Metal Linux Installer
# Supported: Debian/Ubuntu, RHEL/Rocky/Fedora, Arch Linux, Alpine

echo "================================================================================"
echo "                   Funnel Bare-Metal Linux Installer"
echo "================================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This installation script must be run as root (e.g. sudo bash install.sh)."
    exit 1
fi

# 1. Detect Package Manager & Install Dependencies
echo "[1/6] Detecting distribution and installing host prerequisites..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq nftables sudo util-linux curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nftables sudo util-linux curl
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm nftables sudo util-linux curl
else
    echo "[WARN] Unrecognized package manager. Ensure nftables and sudo are installed."
fi

# 2. Create System User & Group
echo "[2/6] Configuring dedicated system user 'funnel'..."
if ! getent group funnel >/dev/null 2>&1; then
    groupadd --system funnel
fi

if ! id -u funnel >/dev/null 2>&1; then
    useradd --system --gid funnel --home-dir /var/lib/funnel --shell /usr/sbin/nologin funnel
fi

mkdir -p /var/lib/funnel /run/funnel /etc/funnel
chown -R funnel:funnel /var/lib/funnel /run/funnel
chmod 0750 /var/lib/funnel /run/funnel

# 3. Install Funnel Executable
echo "[3/6] Installing Funnel static binary..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SOURCE="${SCRIPT_DIR}/../bin/funnel"

if [ -f "${BIN_SOURCE}" ]; then
    cp "${BIN_SOURCE}" /usr/local/bin/funnel
else
    echo "[INFO] Building static binary directly..."
    if command -v go >/dev/null 2>&1; then
        (cd "${SCRIPT_DIR}/.." && CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/funnel ./cmd/funnel)
    else
        echo "[ERROR] Compiled binary not found and 'go' compiler is not installed."
        exit 1
    fi
fi
chmod +x /usr/local/bin/funnel

# 4. Configure Sudoers Policy
echo "[4/6] Installing locked-down sudoers rule..."
cp "${SCRIPT_DIR}/funnel.sudoers" /etc/sudoers.d/funnel
chmod 0440 /etc/sudoers.d/funnel

# 5. Configure Default Environment
echo "[5/6] Initializing configuration at /etc/funnel/funnel.env..."
if [ ! -f /etc/funnel/funnel.env ]; then
    RAND_SECRET=$(head -c 32 /dev/urandom | od -A n -t x | tr -d ' \n')
    cat <<EOF > /etc/funnel/funnel.env
FUNNEL_HOST=127.0.0.1
FUNNEL_PORT=8000
SECRET_KEY=${RAND_SECRET}
COOKIE_SECURE=false
PROXY_MODE=reverse_proxy
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7
FIREWALL_BACKEND=auto
FUNNEL_HELPER_TRANSPORT=sudo
FUNNEL_USE_NSENTER=auto
DATABASE_PATH=/var/lib/funnel/funnel.db
AUDIT_LOG_RETENTION_DAYS=90
LOG_LEVEL=INFO
EOF
    chmod 0600 /etc/funnel/funnel.env
    chown funnel:funnel /etc/funnel/funnel.env
fi

# 6. Deploy & Start Systemd Service
echo "[6/6] Installing and starting systemd service..."
cp "${SCRIPT_DIR}/funnel.service" /etc/systemd/system/funnel.service
systemctl daemon-reload
systemctl enable --now funnel.service

echo ""
echo "================================================================================"
echo "              Funnel Successfully Installed & Started!"
echo "================================================================================"
echo "Service Status: $(systemctl is-active funnel.service)"
echo "Service Address: http://127.0.0.1:8000"
echo ""
echo "To view initial setup token and logs, run:"
echo "  journalctl -u funnel.service -n 25 --no-pager"
echo "================================================================================"
