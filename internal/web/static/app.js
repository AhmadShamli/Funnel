// Funnel Web Application JavaScript

document.addEventListener('DOMContentLoaded', () => {
  initCountdownTimers();
  initPasswordVisibilityToggles();
  initModals();
  initPortAccessibilityChecker();
  initTablePagination();
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
          row.setAttribute('data-external-filtered', 'false');
          row.style.display = '';
        } else {
          row.setAttribute('data-external-filtered', 'true');
          row.style.display = 'none';
        }
      });
      document.querySelectorAll('.filterable-table').forEach(tbl => {
        if (typeof tbl.refreshPagination === 'function') {
          if (typeof tbl.setPage === 'function') {
            tbl.setPage(1);
          }
          tbl.refreshPagination();
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

// Universal Table Pagination & Filtering functionality
function initTablePagination() {
  const containers = document.querySelectorAll('.table-container');
  containers.forEach((container, idx) => {
    const table = container.querySelector('table');
    if (!table || table.getAttribute('data-no-paginate') === 'true') return;
    setupTablePagination(table, container, idx);
  });
}

function setupTablePagination(table, container, tableIdx) {
  if (table.getAttribute('data-paginated') === 'true') return;
  table.setAttribute('data-paginated', 'true');

  const tbody = table.querySelector('tbody');
  if (!tbody) return;

  const tableId = table.id || ('paginated-table-' + tableIdx);
  const savedLimit = localStorage.getItem('funnel_table_limit');
  const attrLimit = table.getAttribute('data-page-size');
  let pageSize = parseInt(attrLimit || savedLimit || '10', 10);
  if (isNaN(pageSize)) pageSize = 10;
  let currentPage = 1;
  let searchQuery = '';

  // 1. Build Top Toolbar
  const toolbar = document.createElement('div');
  toolbar.className = 'table-toolbar';

  const limitWrapper = document.createElement('div');
  limitWrapper.className = 'table-limit-control';

  const limitLabel = document.createElement('label');
  limitLabel.htmlFor = `table-limit-${tableId}`;
  limitLabel.textContent = 'Show';

  const limitSelect = document.createElement('select');
  limitSelect.id = `table-limit-${tableId}`;
  limitSelect.className = 'table-limit-select';
  limitSelect.setAttribute('aria-label', 'Entries per page');

  const options = [
    { val: 5, text: '5' },
    { val: 10, text: '10' },
    { val: 25, text: '25' },
    { val: 50, text: '50' },
    { val: 100, text: '100' },
    { val: -1, text: 'All' }
  ];

  let limitMatched = false;
  options.forEach(opt => {
    const optEl = document.createElement('option');
    optEl.value = opt.val;
    optEl.textContent = opt.text;
    if (opt.val === pageSize) {
      optEl.selected = true;
      limitMatched = true;
    }
    limitSelect.appendChild(optEl);
  });
  if (!limitMatched) {
    const customOpt = document.createElement('option');
    customOpt.value = pageSize;
    customOpt.textContent = String(pageSize);
    customOpt.selected = true;
    limitSelect.insertBefore(customOpt, limitSelect.lastElementChild);
  }

  const limitSuffix = document.createElement('span');
  limitSuffix.textContent = 'entries per page';

  limitWrapper.appendChild(limitLabel);
  limitWrapper.appendChild(limitSelect);
  limitWrapper.appendChild(limitSuffix);
  toolbar.appendChild(limitWrapper);

  let searchInput = null;
  if (table.getAttribute('data-no-search') !== 'true') {
    const searchWrapper = document.createElement('div');
    searchWrapper.className = 'table-search-control';

    searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'table-search-input';
    searchInput.placeholder = 'Search table...';
    searchInput.setAttribute('aria-label', 'Search table records');

    searchWrapper.appendChild(searchInput);
    toolbar.appendChild(searchWrapper);
  }

  container.insertBefore(toolbar, table);

  // 2. Build Bottom Pagination Bar
  const pagination = document.createElement('div');
  pagination.className = 'table-pagination';

  const infoEl = document.createElement('div');
  infoEl.className = 'table-pagination-info';

  const navEl = document.createElement('div');
  navEl.className = 'table-pagination-nav';

  const btnFirst = document.createElement('button');
  btnFirst.type = 'button';
  btnFirst.className = 'page-btn page-first';
  btnFirst.innerHTML = '«';
  btnFirst.title = 'First Page';

  const btnPrev = document.createElement('button');
  btnPrev.type = 'button';
  btnPrev.className = 'page-btn page-prev';
  btnPrev.innerHTML = '‹';
  btnPrev.title = 'Previous Page';

  const numbersEl = document.createElement('div');
  numbersEl.className = 'page-numbers';

  const btnNext = document.createElement('button');
  btnNext.type = 'button';
  btnNext.className = 'page-btn page-next';
  btnNext.innerHTML = '›';
  btnNext.title = 'Next Page';

  const btnLast = document.createElement('button');
  btnLast.type = 'button';
  btnLast.className = 'page-btn page-last';
  btnLast.innerHTML = '»';
  btnLast.title = 'Last Page';

  navEl.appendChild(btnFirst);
  navEl.appendChild(btnPrev);
  navEl.appendChild(numbersEl);
  navEl.appendChild(btnNext);
  navEl.appendChild(btnLast);

  pagination.appendChild(infoEl);
  pagination.appendChild(navEl);
  container.appendChild(pagination);

  function getDataRows() {
    return Array.from(tbody.querySelectorAll('tr')).filter(tr => {
      return !tr.classList.contains('table-search-empty-row') && !tr.querySelector('td[colspan]');
    });
  }

  function render() {
    const allDataRows = getDataRows();
    const totalAll = allDataRows.length;

    if (totalAll === 0) {
      infoEl.textContent = 'Showing 0 to 0 of 0 entries';
      btnFirst.disabled = true;
      btnPrev.disabled = true;
      btnNext.disabled = true;
      btnLast.disabled = true;
      numbersEl.innerHTML = '';
      return;
    }

    const visibleRows = allDataRows.filter(row => {
      if (row.getAttribute('data-external-filtered') === 'true') {
        return false;
      }
      if (!searchQuery) {
        return true;
      }
      const text = (row.getAttribute('data-search') || row.textContent).toLowerCase();
      return text.includes(searchQuery);
    });

    const totalMatching = visibleRows.length;
    const isLimited = pageSize > 0;
    const totalPages = isLimited ? Math.max(1, Math.ceil(totalMatching / pageSize)) : 1;

    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const startIdx = isLimited ? (currentPage - 1) * pageSize : 0;
    const endIdx = isLimited ? Math.min(startIdx + pageSize, totalMatching) : totalMatching;

    // Hide all data rows
    allDataRows.forEach(row => {
      row.style.display = 'none';
    });

    // Display rows for the current page
    for (let i = startIdx; i < endIdx; i++) {
      if (visibleRows[i]) {
        visibleRows[i].style.display = '';
      }
    }

    // Handle empty search feedback row
    let noResultsRow = tbody.querySelector('.table-search-empty-row');
    if (totalMatching === 0) {
      if (!noResultsRow) {
        noResultsRow = document.createElement('tr');
        noResultsRow.className = 'table-search-empty-row';
        const cols = table.querySelectorAll('thead th').length || 6;
        noResultsRow.innerHTML = `<td colspan="${cols}" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching records found</td>`;
        tbody.appendChild(noResultsRow);
      }
      noResultsRow.style.display = '';
    } else if (noResultsRow) {
      noResultsRow.style.display = 'none';
    }

    // Info display
    if (totalMatching === 0) {
      infoEl.innerHTML = `Showing <strong>0</strong> to <strong>0</strong> of <strong>0</strong> entries (filtered from ${totalAll} total)`;
    } else if (totalMatching < totalAll) {
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}</strong> to <strong>${endIdx}</strong> of <strong>${totalMatching}</strong> entries (filtered from ${totalAll} total)`;
    } else {
      infoEl.innerHTML = `Showing <strong>${startIdx + 1}</strong> to <strong>${endIdx}</strong> of <strong>${totalMatching}</strong> entries`;
    }

    // Navigation buttons
    btnFirst.disabled = (currentPage <= 1 || !isLimited);
    btnPrev.disabled = (currentPage <= 1 || !isLimited);
    btnNext.disabled = (currentPage >= totalPages || !isLimited);
    btnLast.disabled = (currentPage >= totalPages || !isLimited);

    renderPageNumbers(totalPages);
  }

  function renderPageNumbers(totalPages) {
    numbersEl.innerHTML = '';
    if (totalPages <= 1 || pageSize <= 0) return;

    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, currentPage + 2);

    if (currentPage <= 3) {
      endPage = Math.min(totalPages, 5);
    } else if (currentPage >= totalPages - 2) {
      startPage = Math.max(1, totalPages - 4);
    }

    if (startPage > 1) {
      addPageButton(1);
      if (startPage > 2) {
        const ellipsis = document.createElement('span');
        ellipsis.className = 'page-ellipsis';
        ellipsis.textContent = '…';
        numbersEl.appendChild(ellipsis);
      }
    }

    for (let p = startPage; p <= endPage; p++) {
      addPageButton(p);
    }

    if (endPage < totalPages) {
      if (endPage < totalPages - 1) {
        const ellipsis = document.createElement('span');
        ellipsis.className = 'page-ellipsis';
        ellipsis.textContent = '…';
        numbersEl.appendChild(ellipsis);
      }
      addPageButton(totalPages);
    }
  }

  function addPageButton(pageNum) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'page-btn' + (pageNum === currentPage ? ' active' : '');
    btn.textContent = pageNum;
    btn.setAttribute('aria-label', `Page ${pageNum}`);
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      currentPage = pageNum;
      render();
    });
    numbersEl.appendChild(btn);
  }

  limitSelect.addEventListener('change', () => {
    pageSize = parseInt(limitSelect.value, 10);
    try {
      localStorage.setItem('funnel_table_limit', limitSelect.value);
    } catch (e) {}
    currentPage = 1;
    render();
  });

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value.trim().toLowerCase();
      currentPage = 1;
      render();
    });
  }

  btnFirst.addEventListener('click', (e) => {
    e.preventDefault();
    if (currentPage > 1) {
      currentPage = 1;
      render();
    }
  });

  btnPrev.addEventListener('click', (e) => {
    e.preventDefault();
    if (currentPage > 1) {
      currentPage--;
      render();
    }
  });

  btnNext.addEventListener('click', (e) => {
    e.preventDefault();
    currentPage++;
    render();
  });

  btnLast.addEventListener('click', (e) => {
    e.preventDefault();
    const allDataRows = getDataRows();
    const visibleRows = allDataRows.filter(row => row.getAttribute('data-external-filtered') !== 'true' && (!searchQuery || (row.getAttribute('data-search') || row.textContent).toLowerCase().includes(searchQuery)));
    const totalPages = pageSize > 0 ? Math.ceil(visibleRows.length / pageSize) : 1;
    currentPage = totalPages;
    render();
  });

  table.refreshPagination = function() {
    render();
  };
  table.setPage = function(p) {
    currentPage = p;
    render();
  };
  table.setPageSize = function(s) {
    pageSize = s;
    limitSelect.value = s;
    render();
  };

  render();
}


