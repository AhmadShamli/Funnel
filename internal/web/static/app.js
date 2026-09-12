// Funnel Web Application JavaScript

document.addEventListener('DOMContentLoaded', () => {
  initCountdownTimers();
  initPasswordVisibilityToggles();
  initModals();
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
      if (modal) modal.style.display = 'flex';
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

// Helper to open modal by ID
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'flex';
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
    <input type="number" name="port_number[]" min="1" max="65535" placeholder="Port (e.g. 22)" required style="flex: 1;">
    <button type="button" class="btn btn-danger btn-sm" onclick="this.closest('.port-row').remove()">✕</button>
  `;
  container.appendChild(row);
}
