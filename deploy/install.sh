#!/usr/bin/env bash
set -euo pipefail

# Funnel Native Bare-Metal Linux Installer & Upgrade Assistant
# Supported: Debian/Ubuntu, RHEL/Rocky/Fedora, Arch Linux, Alpine

REPO="AhmadShamli/Funnel"
DEFAULT_FALLBACK_TAG="v0.3.0"

# Ensure standard binary directories are in PATH (important under sudo/secure_path)
for extra_path in /usr/local/go/bin /usr/local/bin /usr/bin; do
    if [ -d "${extra_path}" ] && [[ ":$PATH:" != *":${extra_path}:"* ]]; then
        export PATH="${extra_path}:$PATH"
    fi
done

# Shell color helpers (only if attached to terminal)
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    RED="\033[0;31m"
    CYAN="\033[0;36m"
    RESET="\033[0m"
else
    BOLD=""
    GREEN=""
    YELLOW=""
    RED=""
    CYAN=""
    RESET=""
fi

log_info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
log_success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

print_help() {
    cat <<EOF
Funnel Bare-Metal Linux Installer & Upgrade Assistant

Usage:
  sudo bash deploy/install.sh [OPTIONS]

Options:
  -u, --upgrade            Run in upgrade mode (automatically detected if Funnel is already installed)
  -v, --version <tag>      Specify target release version (e.g. v0.2.0 or latest)
  -m, --method <method>    Installation method: 'download' (GitHub release) or 'build' (compile from source)
  --check                  Check currently installed version against latest release without upgrading
  --skip-backup            Skip pre-upgrade database and configuration backup
  -f, --force              Force reinstall/upgrade even if already on the target version
  -h, --help               Show this help message

Environment Variables:
  FUNNEL_VERSION           Target release version
  FUNNEL_INSTALL_METHOD    'download' or 'build'
  FUNNEL_SKIP_BACKUP       Set to 'true' to skip pre-upgrade backups

Examples:
  sudo bash deploy/install.sh                       # Fresh install or automatic upgrade
  sudo bash deploy/install.sh --upgrade             # Explicit upgrade with automated backup
  sudo bash deploy/install.sh -v v0.2.0             # Upgrade or install specific version
  sudo bash deploy/install.sh --check               # Check for available updates
  sudo bash deploy/install.sh -m build              # Compile latest binary from local source
EOF
}

# Resolve location of this script
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi

# Parse Command-line Options
TARGET_VERSION="${FUNNEL_VERSION:-${VERSION:-}}"
INSTALL_METHOD="${FUNNEL_INSTALL_METHOD:-${INSTALL_METHOD:-}}"
FORCE_UPGRADE=false
FORCE_ACTION=false
SKIP_BACKUP="${FUNNEL_SKIP_BACKUP:-false}"
CHECK_ONLY=false

while [ $# -gt 0 ]; do
    case "$1" in
        -u|--upgrade)
            FORCE_UPGRADE=true
            shift
            ;;
        -v|--version)
            if [ -z "${2:-}" ]; then
                log_error "Option '$1' requires a version argument (e.g. v0.2.0)."
                exit 1
            fi
            TARGET_VERSION="$2"
            shift 2
            ;;
        -m|--method)
            if [ -z "${2:-}" ]; then
                log_error "Option '$1' requires a method argument ('download' or 'build')."
                exit 1
            fi
            INSTALL_METHOD="$2"
            shift 2
            ;;
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        -f|--force)
            FORCE_ACTION=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Helper: Detect active systemd init system
is_systemd_active() {
    if command -v systemctl >/dev/null 2>&1; then
        if [ -d /run/systemd/system ] && systemctl list-units >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Helper: Query latest release tag from GitHub
get_latest_release_tag() {
    local tag=""
    if command -v curl >/dev/null 2>&1; then
        tag="$(curl -fsSL -m 5 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)"
        if [ -z "${tag}" ]; then
            local effective_url
            effective_url="$(curl -sIL -m 5 -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
            local base
            base="$(basename "${effective_url}")"
            if [ -n "${base}" ] && [ "${base}" != "latest" ] && [ "${base}" != "releases" ]; then
                tag="${base}"
            fi
        fi
    fi
    if [ -z "${tag}" ]; then
        tag="${DEFAULT_FALLBACK_TAG}"
    fi
    if [[ "${tag}" =~ ^[0-9]+\.[0-9]+ ]]; then
        tag="v${tag}"
    fi
    echo "${tag}"
}

# Detect existing installation status
IS_INSTALLED=false
CURRENT_VERSION="unknown"

if [ -f /usr/local/bin/funnel ] || [ -f /etc/funnel/funnel.env ] || [ -f /etc/systemd/system/funnel.service ]; then
    IS_INSTALLED=true
fi

if [ -x /usr/local/bin/funnel ]; then
    DETECTED_VER="$(/usr/local/bin/funnel version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9.]+)?' | head -n1 || true)"
    if [ -n "${DETECTED_VER}" ]; then
        CURRENT_VERSION="${DETECTED_VER}"
    fi
fi

if [ "${FORCE_UPGRADE}" = true ] || [ "${IS_INSTALLED}" = true ]; then
    MODE="upgrade"
else
    MODE="install"
fi

# Handle --check flag
if [ "${CHECK_ONLY}" = true ]; then
    echo "================================================================================"
    echo "                      Funnel Version Check"
    echo "================================================================================"
    echo "Installed version: ${CURRENT_VERSION}"
    LATEST_TAG="$(get_latest_release_tag)"
    echo "Latest release:    ${LATEST_TAG}"
    echo "--------------------------------------------------------------------------------"
    if [ "${CURRENT_VERSION}" != "unknown" ] && [ "${CURRENT_VERSION}" = "${LATEST_TAG}" ]; then
        log_success "Funnel is already at the latest release (${LATEST_TAG})."
    else
        log_info "A different or newer release is available (${LATEST_TAG})."
        echo "To upgrade, run:"
        echo "  sudo bash deploy/install.sh --upgrade"
    fi
    echo "================================================================================"
    exit 0
fi

# Root privilege validation (required for install and upgrade operations)
if [ "$(id -u)" -ne 0 ]; then
    log_error "Installation and upgrade operations must be run as root (e.g. sudo bash deploy/install.sh)."
    exit 1
fi

# Detect host architecture
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

# Print banner
echo "================================================================================"
if [ "${MODE}" = "upgrade" ]; then
    echo "                    Funnel Bare-Metal Linux Upgrade"
else
    echo "                   Funnel Bare-Metal Linux Installer"
fi
echo "================================================================================"
if [ "${MODE}" = "upgrade" ]; then
    echo "Operation Mode    : Upgrade"
    echo "Installed Version : ${CURRENT_VERSION}"
    if [ -n "${TARGET_VERSION}" ]; then
        echo "Target Version    : ${TARGET_VERSION}"
    fi
else
    echo "Operation Mode    : Fresh Installation"
fi
echo "Host Architecture : ${ARCH_RAW} (${ARCH:-unsupported for pre-compiled releases})"
echo "================================================================================"
echo ""

# Detect Systemd Status and active state
SYSTEMD_ACTIVE=false
SERVICE_WAS_ACTIVE=false

if is_systemd_active; then
    SYSTEMD_ACTIVE=true
    if systemctl is-active --quiet funnel.service 2>/dev/null; then
        SERVICE_WAS_ACTIVE=true
    fi
fi

# Setup staging workspace with cleanup trap
STAGING_DIR="$(mktemp -d /tmp/funnel-staging.XXXXXX)"
cleanup() {
    rm -rf "${STAGING_DIR}"
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# 1. Detect Distribution & Verify Prerequisites
# -----------------------------------------------------------------------------
echo "[1/6] Verifying host prerequisites..."
MISSING_PKGS=()

if ! command -v nft >/dev/null 2>&1; then
    MISSING_PKGS+=("nftables")
fi
if ! command -v sudo >/dev/null 2>&1; then
    MISSING_PKGS+=("sudo")
fi
if ! command -v curl >/dev/null 2>&1; then
    MISSING_PKGS+=("curl")
fi
if ! command -v tar >/dev/null 2>&1; then
    MISSING_PKGS+=("tar")
fi
if ! command -v nsenter >/dev/null 2>&1; then
    MISSING_PKGS+=("util-linux")
fi

if [ ${#MISSING_PKGS[@]} -eq 0 ]; then
    log_success "Host prerequisites verified (nftables, sudo, curl, tar, util-linux)."
else
    log_info "Missing prerequisites: ${MISSING_PKGS[*]}. Installing via package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq "${MISSING_PKGS[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "${MISSING_PKGS[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm "${MISSING_PKGS[@]}"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "${MISSING_PKGS[@]}"
    else
        log_warn "Unrecognized package manager. Ensure ${MISSING_PKGS[*]} are installed manually."
    fi
fi

# -----------------------------------------------------------------------------
# 2. Configure Dedicated System User & Directories
# -----------------------------------------------------------------------------
echo "[2/6] Configuring dedicated system user 'funnel' and directory structure..."
if ! getent group funnel >/dev/null 2>&1; then
    groupadd --system funnel
fi

if ! id -u funnel >/dev/null 2>&1; then
    useradd --system --gid funnel --home-dir /var/lib/funnel --shell /usr/sbin/nologin funnel
fi

mkdir -p /var/lib/funnel /var/lib/funnel/backups /run/funnel /etc/funnel
chown -R funnel:funnel /var/lib/funnel /run/funnel
chmod 0750 /var/lib/funnel /run/funnel
chmod 0700 /var/lib/funnel/backups

# -----------------------------------------------------------------------------
# 3. Pre-Upgrade Backup (if upgrading)
# -----------------------------------------------------------------------------
BACKUP_DIR=""
if [ "${MODE}" = "upgrade" ]; then
    if [ "${SKIP_BACKUP}" = true ]; then
        log_info "Skipping pre-upgrade backup as requested (--skip-backup)."
    else
        BACKUP_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
        BACKUP_DIR="/var/lib/funnel/backups/upgrade-${BACKUP_TIMESTAMP}"
        mkdir -p "${BACKUP_DIR}"
        chmod 0700 "${BACKUP_DIR}"
        chown funnel:funnel "${BACKUP_DIR}"

        BACKED_UP_ANY=false
        # Backup database files safely
        if [ -f /var/lib/funnel/funnel.db ]; then
            cp -p /var/lib/funnel/funnel.db* "${BACKUP_DIR}/" 2>/dev/null || true
            BACKED_UP_ANY=true
        fi
        # Backup environment configuration
        if [ -f /etc/funnel/funnel.env ]; then
            cp -p /etc/funnel/funnel.env "${BACKUP_DIR}/funnel.env"
            chmod 0600 "${BACKUP_DIR}/funnel.env"
            BACKED_UP_ANY=true
        fi
        # Backup currently installed binary for rollback capability
        if [ -f /usr/local/bin/funnel ]; then
            cp -p /usr/local/bin/funnel "${BACKUP_DIR}/funnel.previous"
            chmod 0755 "${BACKUP_DIR}/funnel.previous"
            BACKED_UP_ANY=true
        fi

        if [ "${BACKED_UP_ANY}" = true ]; then
            log_success "Pre-upgrade backup successfully created at ${BACKUP_DIR}"
            # Retain the 5 most recent upgrade backups
            (ls -1dt /var/lib/funnel/backups/upgrade-* 2>/dev/null | tail -n +6 | xargs -r rm -rf 2>/dev/null || true)
        fi
    fi
fi

# -----------------------------------------------------------------------------
# 4. Acquire and Validate Candidate Binary
# -----------------------------------------------------------------------------
echo "[3/6] Acquiring and verifying Funnel static binary..."
BIN_SOURCE="${SCRIPT_DIR}/../bin/funnel"

if [ -z "${INSTALL_METHOD}" ]; then
    if [ -f "${BIN_SOURCE}" ]; then
        INSTALL_METHOD="local"
    elif [ -t 0 ]; then
        echo ""
        if [ "${MODE}" = "upgrade" ]; then
            echo "Select upgrade source:"
        else
            echo "Select installation method:"
        fi
        echo "  1) Download pre-compiled release from GitHub (or use bundled dist archive) [Default]"
        echo "  2) Compile and build static binary from source code"
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
        INSTALL_METHOD="download"
    fi
fi

BINARY_STAGED=false

# Method A: Local pre-compiled binary in bin/
if [ "${INSTALL_METHOD}" = "local" ] && [ -f "${BIN_SOURCE}" ]; then
    log_info "Using pre-compiled binary found at ${BIN_SOURCE}..."
    cp "${BIN_SOURCE}" "${STAGING_DIR}/funnel"
    BINARY_STAGED=true
fi

# Method B: Download release archive or bundled dist
if [ "${BINARY_STAGED}" = false ] && [ "${INSTALL_METHOD}" = "download" ]; then
    # Check bundled dist archive first
    if [ -n "${ARCH}" ]; then
        DIST_MATCH="$(ls -1 "${SCRIPT_DIR}/../dist/"*"-linux-${ARCH}.tar.gz" 2>/dev/null | sort -V | tail -n1 || true)"
        if [ -n "${DIST_MATCH}" ] && [ -f "${DIST_MATCH}" ]; then
            log_info "Found bundled release archive in dist/ (${DIST_MATCH##*/}). Extracting..."
            if tar -xzf "${DIST_MATCH}" -C "${STAGING_DIR}" 2>/dev/null; then
                FOUND_BIN="$(find "${STAGING_DIR}" -type f -name funnel | head -n 1)"
                if [ -n "${FOUND_BIN}" ] && [ -f "${FOUND_BIN}" ]; then
                    if [ "${FOUND_BIN}" != "${STAGING_DIR}/funnel" ]; then
                        mv "${FOUND_BIN}" "${STAGING_DIR}/funnel"
                    fi
                    BINARY_STAGED=true
                fi
            fi
        fi
    fi

    # Download from GitHub Releases if not found in dist
    if [ "${BINARY_STAGED}" = false ] && [ -n "${ARCH}" ] && command -v curl >/dev/null 2>&1; then
        RELEASE_TAG="${TARGET_VERSION}"
        if [ -z "${RELEASE_TAG}" ] || [ "${RELEASE_TAG}" = "latest" ]; then
            RELEASE_TAG="$(get_latest_release_tag)"
        fi
        if [[ "${RELEASE_TAG}" =~ ^[0-9]+\.[0-9]+ ]]; then
            RELEASE_TAG="v${RELEASE_TAG}"
        fi

        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/funnel-${RELEASE_TAG}-linux-${ARCH}.tar.gz"
        log_info "Downloading Funnel ${RELEASE_TAG} from GitHub (${DOWNLOAD_URL})..."

        if curl -fsSL "${DOWNLOAD_URL}" -o "${STAGING_DIR}/funnel.tar.gz" 2>/dev/null; then
            if tar -xzf "${STAGING_DIR}/funnel.tar.gz" -C "${STAGING_DIR}" 2>/dev/null; then
                FOUND_BIN="$(find "${STAGING_DIR}" -type f -name funnel | head -n 1)"
                if [ -n "${FOUND_BIN}" ] && [ -f "${FOUND_BIN}" ]; then
                    if [ "${FOUND_BIN}" != "${STAGING_DIR}/funnel" ]; then
                        mv "${FOUND_BIN}" "${STAGING_DIR}/funnel"
                    fi
                    FOUND_ENV="$(find "${STAGING_DIR}" -type f -name .env.example | head -n 1)"
                    if [ -n "${FOUND_ENV}" ]; then
                        cp "${FOUND_ENV}" "${STAGING_DIR}/funnel.env.example"
                    fi
                    BINARY_STAGED=true
                    log_success "Downloaded and extracted Funnel ${RELEASE_TAG}."
                fi
            fi
        else
            log_warn "Could not download release archive from GitHub for tag '${RELEASE_TAG}'."
        fi
    fi

    if [ "${BINARY_STAGED}" = false ]; then
        log_warn "Pre-compiled release could not be obtained. Falling back to building from source..."
        INSTALL_METHOD="build"
    fi
fi

# Method C: Build directly from Go source
if [ "${BINARY_STAGED}" = false ] && [ "${INSTALL_METHOD}" = "build" ]; then
    if ! command -v go >/dev/null 2>&1; then
        log_info "Go compiler not detected. Installing Go compiler and build dependencies..."
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
            log_error "Unsupported package manager. Please install Go manually."
            exit 1
        fi
    fi

    BUILD_DIR=""
    if [ -f "${SCRIPT_DIR}/../cmd/funnel/main.go" ]; then
        BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    elif [ -f "./cmd/funnel/main.go" ]; then
        BUILD_DIR="$(pwd)"
    fi

    if [ -n "${BUILD_DIR}" ]; then
        log_info "Compiling Funnel static binary directly from source (${BUILD_DIR})..."
        (cd "${BUILD_DIR}" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "${STAGING_DIR}/funnel" ./cmd/funnel)
        BINARY_STAGED=true
    else
        log_info "Cloning repository source from https://github.com/${REPO}.git to build..."
        git clone --depth 1 "https://github.com/${REPO}.git" "${STAGING_DIR}/repo"
        (cd "${STAGING_DIR}/repo" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "${STAGING_DIR}/funnel" ./cmd/funnel)
        BINARY_STAGED=true
    fi
fi

# Validate candidate binary
if [ "${BINARY_STAGED}" = false ] || [ ! -f "${STAGING_DIR}/funnel" ]; then
    log_error "Funnel binary could not be prepared."
    exit 1
fi

chmod +x "${STAGING_DIR}/funnel"

# Host execution test
if ! CANDIDATE_OUT="$("${STAGING_DIR}/funnel" version 2>&1)"; then
    log_error "Candidate binary validation failed on this host:"
    echo "${CANDIDATE_OUT}" >&2
    log_error "Aborting. Existing installation has not been modified."
    exit 1
fi

CANDIDATE_VERSION="$(echo "${CANDIDATE_OUT}" | grep -oE 'v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9.]+)?' | head -n1 || true)"
log_success "Candidate Funnel binary verified (${CANDIDATE_VERSION:-valid})."

# Check if already on the same version during upgrade
if [ "${MODE}" = "upgrade" ] && [ "${CURRENT_VERSION}" != "unknown" ] && [ "${CURRENT_VERSION}" = "${CANDIDATE_VERSION}" ] && [ "${FORCE_ACTION}" = false ]; then
    if [ -t 0 ]; then
        echo ""
        log_warn "Funnel is already at version ${CURRENT_VERSION}."
        read -r -p "Reinstall and refresh configuration anyway? [y/N]: " REINSTALL_PROMPT
        case "${REINSTALL_PROMPT}" in
            y*|Y*)
                log_info "Proceeding with reinstall..."
                ;;
            *)
                log_info "Funnel is up to date. Exiting."
                exit 0
                ;;
        esac
    else
        log_info "Funnel is already at version ${CURRENT_VERSION}. Re-applying binary and service configurations..."
    fi
fi

# -----------------------------------------------------------------------------
# 5. Quiesce Service & Install Binary Atomically
# -----------------------------------------------------------------------------
if [ "${MODE}" = "upgrade" ] && [ "${SERVICE_WAS_ACTIVE}" = true ]; then
    log_info "Temporarily stopping funnel.service to apply update..."
    systemctl stop funnel.service || true
fi

# Atomic binary replacement using install (unlinks inode, preventing ETXTBSY)
install -m 0755 -o root -g root "${STAGING_DIR}/funnel" /usr/local/bin/funnel
log_success "Installed static binary to /usr/local/bin/funnel."

# -----------------------------------------------------------------------------
# 6. Sudoers Policy Configuration
# -----------------------------------------------------------------------------
echo "[4/6] Installing locked-down sudoers rule..."
SUDOERS_TMP="${STAGING_DIR}/funnel.sudoers"
if [ -f "${SCRIPT_DIR}/funnel.sudoers" ]; then
    cp "${SCRIPT_DIR}/funnel.sudoers" "${SUDOERS_TMP}"
else
    cat <<'EOF' > "${SUDOERS_TMP}"
# Restricted execution rights for unprivileged 'funnel' user
funnel ALL=(root) NOPASSWD: /usr/local/bin/funnel helper *, /usr/bin/nsenter --net=/proc/1/ns/net /usr/local/bin/funnel helper *
EOF
fi

if command -v visudo >/dev/null 2>&1; then
    if visudo -c -f "${SUDOERS_TMP}" >/dev/null 2>&1; then
        install -m 0440 -o root -g root "${SUDOERS_TMP}" /etc/sudoers.d/funnel
        log_success "Verified and installed sudoers policy to /etc/sudoers.d/funnel."
    else
        log_error "Generated sudoers rule failed visudo syntax check. Sudoers update skipped to protect system access."
    fi
else
    install -m 0440 -o root -g root "${SUDOERS_TMP}" /etc/sudoers.d/funnel
    log_success "Installed sudoers policy to /etc/sudoers.d/funnel."
fi

# -----------------------------------------------------------------------------
# 7. Environment & Configuration Management
# -----------------------------------------------------------------------------
echo "[5/6] Managing configuration in /etc/funnel..."
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
    log_success "Initialized configuration at /etc/funnel/funnel.env."
else
    log_success "Preserving existing configuration at /etc/funnel/funnel.env."
    chmod 0600 /etc/funnel/funnel.env
    chown funnel:funnel /etc/funnel/funnel.env
fi

# Deploy or update reference .env.example
ENV_EXAMPLE_SRC=""
if [ -f "${SCRIPT_DIR}/../.env.example" ]; then
    ENV_EXAMPLE_SRC="${SCRIPT_DIR}/../.env.example"
elif [ -f "${STAGING_DIR}/funnel.env.example" ]; then
    ENV_EXAMPLE_SRC="${STAGING_DIR}/funnel.env.example"
fi

if [ -n "${ENV_EXAMPLE_SRC}" ] && [ -f "${ENV_EXAMPLE_SRC}" ]; then
    install -m 0644 "${ENV_EXAMPLE_SRC}" /etc/funnel/funnel.env.example
    log_info "Updated reference configuration template at /etc/funnel/funnel.env.example."
fi

# -----------------------------------------------------------------------------
# 8. Deploy & Start / Restart Systemd Service
# -----------------------------------------------------------------------------
echo "[6/6] Configuring systemd service..."
SERVICE_TMP="${STAGING_DIR}/funnel.service"
if [ -f "${SCRIPT_DIR}/funnel.service" ]; then
    cp "${SCRIPT_DIR}/funnel.service" "${SERVICE_TMP}"
else
    cat <<'EOF' > "${SERVICE_TMP}"
[Unit]
Description=Funnel Port Access Web Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=funnel
Group=funnel
EnvironmentFile=-/etc/funnel/funnel.env
ExecStart=/usr/local/bin/funnel serve
Restart=always
RestartSec=3s
LimitNOFILE=65536

# Security sandbox
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=false
ReadWritePaths=/var/lib/funnel /run/funnel

[Install]
WantedBy=multi-user.target
EOF
fi

install -m 0644 -o root -g root "${SERVICE_TMP}" /etc/systemd/system/funnel.service
log_success "Deployed systemd unit to /etc/systemd/system/funnel.service."

SERVICE_STARTED=false
if [ "${SYSTEMD_ACTIVE}" = true ]; then
    systemctl daemon-reload

    if [ "${MODE}" = "upgrade" ]; then
        if [ "${SERVICE_WAS_ACTIVE}" = true ]; then
            log_info "Restarting funnel.service with updated binary..."
            systemctl start funnel.service
            SERVICE_STARTED=true
        else
            log_info "funnel.service was inactive prior to upgrade. Keeping service stopped."
            echo "To start the upgraded service, run: sudo systemctl start funnel.service"
        fi
    else
        systemctl enable --now funnel.service
        SERVICE_STARTED=true
    fi

    if [ "${SERVICE_STARTED}" = true ]; then
        log_info "Verifying service startup..."
        SERVICE_OK=false
        for i in $(seq 1 10); do
            if systemctl is-active --quiet funnel.service 2>/dev/null; then
                SERVICE_OK=true
                break
            fi
            sleep 1
        done

        if [ "${SERVICE_OK}" = false ]; then
            log_error "funnel.service failed to become active after installation/upgrade!"
            echo "--- Recent journal logs for funnel.service ---" >&2
            journalctl -u funnel.service -n 25 --no-pager >&2 || true
            echo "----------------------------------------------" >&2

            # Rollback to previous binary if available
            if [ "${MODE}" = "upgrade" ] && [ -n "${BACKUP_DIR}" ] && [ -f "${BACKUP_DIR}/funnel.previous" ]; then
                log_warn "Attempting automatic rollback to previous binary..."
                install -m 0755 -o root -g root "${BACKUP_DIR}/funnel.previous" /usr/local/bin/funnel
                systemctl restart funnel.service 2>/dev/null || true
                if systemctl is-active --quiet funnel.service 2>/dev/null; then
                    log_warn "Rolled back successfully to ${CURRENT_VERSION}. Service is running."
                else
                    log_error "Rollback attempted, but service remains inactive. Check journal logs."
                fi
            fi
            exit 1
        fi
        log_success "funnel.service is active and healthy."
    fi
else
    log_warn "Systemd is not running as PID 1 (container or custom environment detected)."
    log_info "Service file deployed. Start or restart Funnel using your process supervisor."
fi

# -----------------------------------------------------------------------------
# Summary Output
# -----------------------------------------------------------------------------
echo ""
echo "================================================================================"
if [ "${MODE}" = "upgrade" ]; then
    echo "                 Funnel Successfully Upgraded!"
    echo "================================================================================"
    echo "Previous Version: ${CURRENT_VERSION}"
    echo "Current Version : ${CANDIDATE_VERSION:-${CURRENT_VERSION}}"
    if [ -n "${BACKUP_DIR}" ]; then
        echo "Database Backup : ${BACKUP_DIR}"
    fi
    if [ "${SYSTEMD_ACTIVE}" = true ]; then
        echo "Service Status  : $(systemctl is-active funnel.service 2>/dev/null || echo 'inactive')"
    fi
    echo "Service Address : http://127.0.0.1:8000"
    echo ""
    echo "All existing databases, port groups, access keys, and logs have been preserved."
else
    echo "              Funnel Successfully Installed & Started!"
    echo "================================================================================"
    if [ "${SYSTEMD_ACTIVE}" = true ]; then
        echo "Service Status  : $(systemctl is-active funnel.service 2>/dev/null || echo 'inactive')"
    fi
    echo "Service Address : http://127.0.0.1:8000"
    echo ""
    echo "To view initial setup token and logs, run:"
    echo "  journalctl -u funnel.service -n 25 --no-pager"
fi
echo "================================================================================"
