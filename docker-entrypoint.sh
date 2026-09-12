#!/usr/bin/env bash
set -euo pipefail

# Funnel Docker Entrypoint Script
# Runs as root initially to initialize permissions and transport, then drops privileges to 'funnel' user.

DATA_DIR="/data"
RUN_DIR="/run/funnel"

# Ensure runtime and data directories exist with proper ownership
mkdir -p "${DATA_DIR}" "${RUN_DIR}"
chown -R funnel:funnel "${DATA_DIR}" "${RUN_DIR}"
chmod 0750 "${DATA_DIR}" "${RUN_DIR}"

HELPER_TRANSPORT="${FUNNEL_HELPER_TRANSPORT:-sudo}"

if [ "${HELPER_TRANSPORT}" = "socket" ]; then
    echo "[ENTRYPOINT] Initializing root helper daemon on unix socket ${RUN_DIR}/helper.sock..."
    /usr/local/bin/funnel helper daemon --socket "${RUN_DIR}/helper.sock" &
    # Allow socket to be created and grant permissions
    sleep 0.5
    chown funnel:funnel "${RUN_DIR}/helper.sock" 2>/dev/null || true
    chmod 0660 "${RUN_DIR}/helper.sock" 2>/dev/null || true
else
    # Configure sudoers for locked-down privilege escalation
    echo "funnel ALL=(root) NOPASSWD: /usr/local/bin/funnel helper *, /usr/bin/nsenter --net=/proc/1/ns/net /usr/local/bin/funnel helper *" > /etc/sudoers.d/funnel
    chmod 0440 /etc/sudoers.d/funnel
fi

# Drop privileges and execute command as unprivileged 'funnel' user
echo "[ENTRYPOINT] Dropping privileges to user 'funnel' (UID 10001)..."
exec su -s /bin/bash funnel -c "$*"
