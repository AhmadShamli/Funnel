#!/usr/bin/env bash
set -euo pipefail

# Funnel Docker Entrypoint Script
# Runs as root initially to initialize permissions, dynamic UID/GID, and transport, then drops privileges to 'funnel' user.

DATA_DIR="/data"
RUN_DIR="/run/funnel"

# Allow configurable runtime UID/GID (supports FUNNEL_UID/FUNNEL_GID or PUID/PGID)
TARGET_UID="${FUNNEL_UID:-${PUID:-}}"
TARGET_GID="${FUNNEL_GID:-${PGID:-}}"

CURRENT_UID=$(id -u funnel 2>/dev/null || echo "")
CURRENT_GID=$(id -g funnel 2>/dev/null || echo "")

if [ -n "${TARGET_GID}" ] && [ "${TARGET_GID}" != "${CURRENT_GID}" ]; then
    echo "[ENTRYPOINT] Adjusting group 'funnel' GID to ${TARGET_GID}..."
    groupmod -o -g "${TARGET_GID}" funnel 2>/dev/null || true
fi

if [ -n "${TARGET_UID}" ] && [ "${TARGET_UID}" != "${CURRENT_UID}" ]; then
    echo "[ENTRYPOINT] Adjusting user 'funnel' UID to ${TARGET_UID}..."
    usermod -o -u "${TARGET_UID}" funnel 2>/dev/null || true
fi

ACTUAL_UID=$(id -u funnel)
ACTUAL_GID=$(id -g funnel)

# Ensure runtime and data directories exist with proper ownership
mkdir -p "${DATA_DIR}" "${RUN_DIR}"
chown -R funnel:funnel "${DATA_DIR}" "${RUN_DIR}"
chmod 0750 "${DATA_DIR}" "${RUN_DIR}"

HELPER_TRANSPORT="${FUNNEL_HELPER_TRANSPORT:-sudo}"

if [ "${HELPER_TRANSPORT}" = "socket" ]; then
    echo "[ENTRYPOINT] Initializing root helper daemon on unix socket ${RUN_DIR}/helper.sock..."
    /usr/local/bin/funnel helper daemon --socket "${RUN_DIR}/helper.sock" &
    sleep 0.5
    chown funnel:funnel "${RUN_DIR}/helper.sock" 2>/dev/null || true
    chmod 0660 "${RUN_DIR}/helper.sock" 2>/dev/null || true
else
    # Configure sudoers for locked-down privilege escalation
    echo "funnel ALL=(root) NOPASSWD: /usr/local/bin/funnel helper *, /usr/bin/nsenter --net=/proc/1/ns/net /usr/local/bin/funnel helper *" > /etc/sudoers.d/funnel
    chmod 0440 /etc/sudoers.d/funnel
fi

# Drop privileges and execute command as unprivileged 'funnel' user
echo "[ENTRYPOINT] Dropping privileges to user 'funnel' (UID ${ACTUAL_UID}, GID ${ACTUAL_GID})..."
exec su -s /bin/bash funnel -c "$*"
