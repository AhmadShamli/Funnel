// Funnel Web Application JavaScript

document.addEventListener('DOMContentLoaded', () => {
  initCountdownTimers();
  initPasswordVisibilityToggles();
  initModals();
  initPortAccessibilityChecker();
  initAdminOpenPorts();

  const createKeyModal = document.getElementById('create-key-modal');
  if (createKeyModal) {
    preventModalAutofill(createKeyModal);
  }
});

// Countdown Timer functionality
function initCountdownTimers() {
  const timerElements = document.querySelectorAll('[data-countdown-seconds]');
  timerElements.forEach(el => {
    let remaining = parseInt(el.getAttribute('data-countdown-seconds'), 10);
    if (isNaN(remaining)) return;

    const displayEl = el.querySelector('.countdown-digits') || el;
    const isMinuteFormat = el.hasAttribute('data-format-minutes');

    function update() {
      if (remaining <= 0) {
        displayEl.textContent = isMinuteFormat ? '0s' : '00:00:00';
        const refreshNotice = document.getElementById('session-expired-notice');
        if (refreshNotice) refreshNotice.style.display = 'block';
        const submitBtn = document.getElementById('submit-btn');
        if (submitBtn) submitBtn.removeAttribute('disabled');
        return;
      }

      if (isMinuteFormat) {
        if (remaining >= 60) {
          const m = Math.floor(remaining / 60);
          const s = remaining % 60;
          displayEl.textContent = `${m}m ${s}s`;
        } else {
          displayEl.textContent = `${remaining}s`;
        }
      } else {
        const hours = Math.floor(remaining / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const seconds = remaining % 60;

        const hStr = String(hours).padStart(2, '0');
        const mStr = String(minutes).padStart(2, '0');
        const sStr = String(seconds).padStart(2, '0');

        displayEl.textContent = `${hStr}:${mStr}:${sStr}`;
      }

      remaining--;
    }

    update();
    setInterval(update, 1000);
  });
}

// Password visibility toggle
function initPasswordVisibilityToggles() {
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (input) {
        if (input.type === 'password') {
          input.type = 'text';
          btn.textContent = 'Hide';
        } else {
          input.type = 'password';
          btn.textContent = 'Show';
        }
      }
    });
  });
}

// Modal handling
function initModals() {
  document.querySelectorAll('[data-modal-open]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const modalId = btn.getAttribute('data-modal-open');
      const modal = document.getElementById(modalId);
      if (modal) {
        preventModalAutofill(modal);
        modal.style.display = 'flex';
      }
    });
  });

  document.querySelectorAll('[data-modal-close]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const modal = btn.closest('.modal-overlay');
      if (modal) modal.style.display = 'none';
    });
  });

  window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.style.display = 'none';
    }
  });
}

// Clear any credentials browser autofill may have pre-populated into creation modals
function preventModalAutofill(modal) {
  if (!modal) return;
  const keyName = modal.querySelector('#key_name');
  const keyPassword = modal.querySelector('#key_password');
  if (!keyName && !keyPassword) return;

  const clearUnfocused = () => {
    if (keyName && document.activeElement !== keyName) keyName.value = '';
    if (keyPassword && document.activeElement !== keyPassword) keyPassword.value = '';
  };

  clearUnfocused();
  setTimeout(clearUnfocused, 50);
  setTimeout(clearUnfocused, 200);
}

// Helper to open modal by ID
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) {
    preventModalAutofill(modal);
    modal.style.display = 'flex';
  }
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'none';
}

// Dynamic Port Adder in Admin Forms
function addPortRow(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'flex-row form-group port-row';
  row.innerHTML = `
    <select name="port_protocol[]" style="width: 110px;">
      <option value="tcp" selected>TCP</option>
      <option value="udp">UDP</option>
    </select>
    <input type="text" name="port_number[]" placeholder="Port (e.g. 22 or 8000-8010)" required style="flex: 1;">
    <button type="button" class="btn btn-danger btn-sm" onclick="this.closest('.port-row').remove()">✕</button>
  `;
  container.appendChild(row);
}

// Dynamic Port Range Adder in Admin Forms
function addPortRangeRow(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'flex-row form-group port-row port-range-row';
  row.style.alignItems = 'center';
  row.style.gap = '0.5rem';
  row.innerHTML = `
    <select name="port_range_protocol[]" style="width: 110px;">
      <option value="tcp" selected>TCP</option>
      <option value="udp">UDP</option>
    </select>
    <input type="number" name="port_range_start[]" min="1" max="65535" placeholder="From (e.g. 8000)" required style="flex: 1;">
    <span style="color: var(--text-secondary); font-weight: bold;">&ndash;</span>
    <input type="number" name="port_range_end[]" min="1" max="65535" placeholder="To (e.g. 8010)" required style="flex: 1;">
    <button type="button" class="btn btn-danger btn-sm" onclick="this.closest('.port-row').remove()">✕</button>
  `;
  container.appendChild(row);
}

// Periodic port accessibility testing for active visitor sessions
function initPortAccessibilityChecker() {
  const portContainer = document.getElementById('visitor-ports-list');
  if (!portContainer) return;

  const portElements = portContainer.querySelectorAll('.port-item[data-port]');
  if (portElements.length === 0) return;

  const metaEl = document.getElementById('port-check-status-meta');
  const recheckBtn = document.getElementById('recheck-ports-btn');
  let isChecking = false;
  let intervalId = null;

  function updatePortStatus(port, protocol, open, status, message) {
    const protoLower = (protocol || 'tcp').toLowerCase();
    const item = Array.from(portElements).find(el => {
      const elPort = el.getAttribute('data-port');
      const elProto = (el.getAttribute('data-protocol') || 'tcp').toLowerCase();
      return elPort === String(port) && elProto === protoLower;
    });

    if (!item) return;

    const badge = item.querySelector('.port-status-badge');
    if (!badge) return;

    badge.className = 'port-status-badge';
    const textEl = badge.querySelector('.status-indicator-text');

    if (open) {
      badge.classList.add('status-open');
      badge.setAttribute('title', message || `Port ${port}/${protocol} is open and accessible`);
      if (textEl) textEl.textContent = 'Accessible';
    } else if (status === 'unreachable') {
      badge.classList.add('status-unreachable');
      badge.setAttribute('title', message || `Port ${port}/${protocol} is unreachable`);
      if (textEl) textEl.textContent = 'Unreachable';
    } else {
      badge.classList.add('status-closed');
      badge.setAttribute('title', message || `Port ${port}/${protocol} is closed (no service listening)`);
      if (textEl) textEl.textContent = 'Closed';
    }
  }

  async function checkPorts() {
    if (isChecking) return;
    isChecking = true;

    if (metaEl) metaEl.textContent = 'Testing ports...';
    if (recheckBtn) recheckBtn.setAttribute('disabled', 'disabled');

    try {
      const res = await fetch('/access/ports/check', {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      });

      if (res.status === 401 || res.status === 403) {
        if (metaEl) metaEl.textContent = 'Session ended';
        if (intervalId) clearInterval(intervalId);
        const refreshNotice = document.getElementById('session-expired-notice');
        if (refreshNotice) refreshNotice.style.display = 'block';
        return;
      }

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();
      if (data && Array.isArray(data.ports)) {
        data.ports.forEach(p => {
          updatePortStatus(p.port, p.protocol, p.open, p.status, p.message);
        });

        const now = new Date();
        const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        if (metaEl) metaEl.textContent = `Tested ${timeStr}`;
      }
    } catch (err) {
      if (metaEl) metaEl.textContent = 'Check paused';
    } finally {
      isChecking = false;
      if (recheckBtn) recheckBtn.removeAttribute('disabled');
    }
  }

  // Initial check immediately on load
  checkPorts();

  // Periodically check every 10 seconds
  intervalId = setInterval(checkPorts, 10000);

  // Manual re-check trigger
  if (recheckBtn) {
    recheckBtn.addEventListener('click', (e) => {
      e.preventDefault();
      checkPorts();
    });
  }

  // Cleanup if window unloads
  window.addEventListener('beforeunload', () => {
    if (intervalId) clearInterval(intervalId);
  });
}

// Admin Open Ports page reachability testing and real-time filtering
function initAdminOpenPorts() {
  const probeBtn = document.getElementById('probe-all-ports-btn');
  const searchInput = document.getElementById('open-ports-search-input');
  const filterPills = document.querySelectorAll('[data-section-filter]');
  const metaEl = document.getElementById('probe-status-meta');

  if (!probeBtn && !searchInput && filterPills.length === 0) return;

  // 1. Search filter functionality
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      const rows = document.querySelectorAll('.filterable-table .port-row-item');
      rows.forEach(row => {
        const text = (row.getAttribute('data-search') || row.textContent).toLowerCase();
        if (!q || text.includes(q)) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });
  }

  // 2. Section pill filters
  filterPills.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      filterPills.forEach(b => {
        b.classList.remove('active-filter', 'btn-primary');
        b.classList.add('btn-secondary');
      });
      btn.classList.add('active-filter', 'btn-primary');
      btn.classList.remove('btn-secondary');

      const filter = btn.getAttribute('data-section-filter');
      const fwSection = document.getElementById('section-firewall-ports');
      const socketsSection = document.getElementById('section-listening-sockets');

      if (filter === 'firewall') {
        if (fwSection) fwSection.style.display = 'block';
        if (socketsSection) socketsSection.style.display = 'none';
      } else if (filter === 'sockets') {
        if (fwSection) fwSection.style.display = 'none';
        if (socketsSection) socketsSection.style.display = 'block';
      } else {
        if (fwSection) fwSection.style.display = 'block';
        if (socketsSection) socketsSection.style.display = 'block';
      }
    });
  });

  // 3. Reachability probe execution
  let isProbing = false;

  async function runProbe() {
    if (isProbing) return;
    isProbing = true;

    if (probeBtn) {
      probeBtn.setAttribute('disabled', 'disabled');
      probeBtn.textContent = '⏳ Probing Ports...';
    }
    if (metaEl) metaEl.textContent = 'Testing port reachability...';

    // Mark badges as probing
    const badges = document.querySelectorAll('.port-status-badge[data-probe-port]');
    badges.forEach(b => {
      b.className = 'port-status-badge status-checking';
      const text = b.querySelector('.status-indicator-text');
      if (text) text.textContent = 'Probing...';
    });

    try {
      const res = await fetch('/admin/open-ports/check', {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const data = await res.json();
      if (data && Array.isArray(data.ports)) {
        data.ports.forEach(p => {
          const protoLower = (p.protocol || 'tcp').toLowerCase();
          badges.forEach(badge => {
            const bPort = badge.getAttribute('data-probe-port');
            const bProto = (badge.getAttribute('data-probe-protocol') || 'tcp').toLowerCase();
            if (bPort === String(p.port) && bProto === protoLower) {
              badge.className = 'port-status-badge';
              const textEl = badge.querySelector('.status-indicator-text');
              if (p.open) {
                badge.classList.add('status-open');
                const lat = p.latency_ms > 0 ? ` (${p.latency_ms}ms)` : '';
                badge.setAttribute('title', (p.message || `Port ${p.port}/${p.protocol} is open and reachable`) + lat);
                if (textEl) textEl.textContent = `Open${lat}`;
              } else if (p.status === 'unreachable') {
                badge.classList.add('status-unreachable');
                badge.setAttribute('title', p.message || `Port ${p.port}/${p.protocol} timed out`);
                if (textEl) textEl.textContent = 'Unreachable';
              } else {
                badge.classList.add('status-closed');
                badge.setAttribute('title', p.message || `Port ${p.port}/${p.protocol} closed`);
                if (textEl) textEl.textContent = 'Closed';
              }
            }
          });
        });

        const now = new Date();
        const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        if (metaEl) metaEl.textContent = `Probed ${data.ports.length} ports at ${timeStr}`;
      }
    } catch (err) {
      if (metaEl) metaEl.textContent = 'Probe request failed';
    } finally {
      isProbing = false;
      if (probeBtn) {
        probeBtn.removeAttribute('disabled');
        probeBtn.textContent = '▶ Probe Port Reachability';
      }
    }
  }

  if (probeBtn) {
    probeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      runProbe();
    });
  }
}


