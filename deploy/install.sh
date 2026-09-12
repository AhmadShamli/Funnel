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
    apt-get install -y -qq nftables sudo util-linux curl tar
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nftables sudo util-linux curl tar
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm nftables sudo util-linux curl tar
else
    echo "[WARN] Unrecognized package manager. Ensure nftables, sudo, and tar are installed."
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
REPO="AhmadShamli/Funnel"

ARCH_RAW="$(uname -m)"
case "${ARCH_RAW}" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    armv7*|armhf)
        ARCH="armv7"
        ;;
    *)
        ARCH=""
        ;;
esac

INSTALLED=false

if [ -f "${BIN_SOURCE}" ]; then
    echo "[INFO] Found pre-compiled binary at ${BIN_SOURCE}."
    cp "${BIN_SOURCE}" /usr/local/bin/funnel
    INSTALLED=true
else
    INSTALL_METHOD="${FUNNEL_INSTALL_METHOD:-${INSTALL_METHOD:-}}"

    if [ -z "${INSTALL_METHOD}" ]; then
        if [ -t 0 ]; then
            echo ""
            echo "Funnel static binary was not found at ${BIN_SOURCE}."
            echo "Select how you would like to proceed:"
            echo "  1) Download latest binary from GitHub release (or use bundled dist archive) [Default]"
            echo "  2) Install Go compiler & dependencies, then build from source"
            read -r -p "Enter choice [1 or 2] (default: 1): " USER_CHOICE
            case "${USER_CHOICE}" in
                2|"build"|"source")
                    INSTALL_METHOD="build"
                    ;;
                *)
                    INSTALL_METHOD="download"
                    ;;
            esac
        else
            echo "[INFO] Non-interactive session detected. Defaulting to downloading pre-compiled release."
            INSTALL_METHOD="download"
        fi
    fi

    if [ "${INSTALL_METHOD}" = "download" ]; then
        # Check bundled dist archive first
        if [ -n "${ARCH}" ]; then
            DIST_MATCH="$(ls -1 "${SCRIPT_DIR}/../dist/"*"-linux-${ARCH}.tar.gz" 2>/dev/null | sort -V | tail -n1 || true)"
            if [ -n "${DIST_MATCH}" ] && [ -f "${DIST_MATCH}" ]; then
                echo "[INFO] Found bundled release archive for ${ARCH} in dist/ (${DIST_MATCH##*/}). Extracting..."
                TMP_D="$(mktemp -d)"
                if tar -xzf "${DIST_MATCH}" -C "${TMP_D}" 2>/dev/null; then
                    FOUND_BIN="$(find "${TMP_D}" -type f -name funnel | head -n 1)"
                    if [ -n "${FOUND_BIN}" ] && [ -f "${FOUND_BIN}" ]; then
                        cp "${FOUND_BIN}" /usr/local/bin/funnel
                        INSTALLED=true
                    fi
                fi
                rm -rf "${TMP_D}"
            fi
        fi

        # If not found in dist, download from GitHub Releases
        if [ "${INSTALLED}" = false ] && [ -n "${ARCH}" ] && command -v curl >/dev/null 2>&1; then
            echo "[INFO] Attempting to download latest release from GitHub (${REPO}) for ${ARCH}..."
            TMP_D="$(mktemp -d)"
            EFFECTIVE_URL="$(curl -sIL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
            RELEASE_TAG="$(basename "${EFFECTIVE_URL}")"
            if [ -z "${RELEASE_TAG}" ] || [ "${RELEASE_TAG}" = "latest" ] || [ "${RELEASE_TAG}" = "releases" ]; then
                RELEASE_TAG="v0.2.0"
            fi

            DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/funnel-${RELEASE_TAG}-linux-${ARCH}.tar.gz"
            echo "[INFO] Downloading from ${DOWNLOAD_URL}..."
            if curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_D}/funnel.tar.gz" 2>/dev/null; then
                if tar -xzf "${TMP_D}/funnel.tar.gz" -C "${TMP_D}" 2>/dev/null; then
                    FOUND_BIN="$(find "${TMP_D}" -type f -name funnel | head -n 1)"
                    if [ -n "${FOUND_BIN}" ] && [ -f "${FOUND_BIN}" ]; then
                        cp "${FOUND_BIN}" /usr/local/bin/funnel
                        INSTALLED=true
                        echo "[INFO] Successfully installed pre-compiled Funnel ${RELEASE_TAG} from GitHub releases."
                    fi
                fi
            else
                echo "[WARN] Could not download release archive from GitHub. Falling back to Go compiler..."
            fi
            rm -rf "${TMP_D}"
        fi

        if [ "${INSTALLED}" = false ]; then
            echo "[WARN] Could not obtain pre-compiled release. Falling back to building from source..."
            INSTALL_METHOD="build"
        fi
    fi

    if [ "${INSTALL_METHOD}" = "build" ]; then
        if ! command -v go >/dev/null 2>&1; then
            echo "[INFO] Go compiler not detected. Installing Go compiler and build dependencies..."
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y -qq golang-go git
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y -q golang git
            elif command -v yum >/dev/null 2>&1; then
                yum install -y -q golang git
            elif command -v pacman >/dev/null 2>&1; then
                pacman -Sy --noconfirm go git
            elif command -v apk >/dev/null 2>&1; then
                apk add --no-cache go git
            else
                echo "[ERROR] Unsupported package manager. Please install Go manually."
                exit 1
            fi
        fi

        echo "[INFO] Building static binary directly with go compiler..."
        (cd "${SCRIPT_DIR}/.." && CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/funnel ./cmd/funnel)
        INSTALLED=true
    fi
fi

if [ ! -f /usr/local/bin/funnel ]; then
    echo "[ERROR] Funnel binary could not be installed at /usr/local/bin/funnel."
    exit 1
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
