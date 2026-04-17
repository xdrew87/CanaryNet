// GitHub Honeypot Monitor — Dashboard JS
// Vanilla JS, no framework required.

const API = '';  // Same origin
let adminKey = localStorage.getItem('adminKey') || '';

// ─── State ────────────────────────────────────────────────────────────────
const state = {
  eventsOffset: 0,
  eventsLimit: 50,
  eventsTotal: 0,
  actorsOffset: 0,
  actorsLimit: 50,
  actorsTotal: 0,
  activeTab: 'dashboard',
  chartDaily: null,
  chartRisk: null,
};

// ─── Navigation ──────────────────────────────────────────────────────────
document.getElementById('nav').addEventListener('click', e => {
  const item = e.target.closest('[data-tab]');
  if (!item) return;
  const tab = item.dataset.tab;
  switchTab(tab);
});

function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.tab === tab);
  });
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.id === `tab-${tab}`);
  });
  if (tab === 'dashboard') loadDashboard();
  if (tab === 'events') loadEvents();
  if (tab === 'actors') loadActors();
  if (tab === 'canaries') loadCanaries();
}

// ─── Fetch helper ─────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (adminKey) headers['X-Admin-Key'] = adminKey;
  const resp = await fetch(API + path, { ...options, headers });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const ct = resp.headers.get('content-type') || '';
  if (ct.includes('application/json')) return resp.json();
  return resp.blob();
}

// ─── Toast ─────────────────────────────────────────────────────────────────
let _toastTimer;
function toast(msg, type = 'info') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = type === 'error' ? '#ef4444' : type === 'success' ? '#22c55e' : '#6366f1';
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ─── Risk badge ───────────────────────────────────────────────────────────
function riskBadge(level) {
  return `<span class="badge badge-${level || 'low'}">${level || 'low'}</span>`;
}

// ─── Format helpers ───────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}
function trunc(s, n = 60) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ─── Dashboard ────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [stats, canaries] = await Promise.all([
      apiFetch('/api/events/stats'),
      apiFetch('/api/canaries'),
    ]);
    document.getElementById('stat-total').textContent = stats.total_events ?? '—';
    document.getElementById('stat-ips').textContent = stats.unique_ips ?? '—';
    document.getElementById('stat-critical').textContent = stats.risk_breakdown?.critical ?? 0;
    document.getElementById('stat-canaries').textContent =
      (canaries.items || []).filter(c => c.is_active).length;

    // Update events badge
    const badge = document.getElementById('events-badge');
    if (stats.total_events > 0) {
      badge.textContent = stats.total_events;
      badge.classList.remove('hidden');
    }

    renderDailyChart(stats.daily_events || []);
    renderRiskChart(stats.risk_breakdown || {});
    renderTopIPs(stats.top_ips || []);
    updateRefreshTime();
  } catch (err) {
    toast('Failed to load dashboard: ' + err.message, 'error');
  }
}

function renderDailyChart(data) {
  const ctx = document.getElementById('chart-daily').getContext('2d');
  if (state.chartDaily) state.chartDaily.destroy();
  state.chartDaily = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => d.date),
      datasets: [{
        label: 'Events',
        data: data.map(d => d.count),
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99,102,241,0.15)',
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: '#6366f1',
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#9ca3af', maxRotation: 45 }, grid: { color: '#1f2937' } },
        y: { ticks: { color: '#9ca3af' }, grid: { color: '#1f2937' } },
      },
    },
  });
}

function renderRiskChart(breakdown) {
  const ctx = document.getElementById('chart-risk').getContext('2d');
  if (state.chartRisk) state.chartRisk.destroy();
  const labels = ['Low', 'Medium', 'High', 'Critical'];
  const values = [breakdown.low || 0, breakdown.medium || 0, breakdown.high || 0, breakdown.critical || 0];
  const colors = ['#22c55e', '#eab308', '#f97316', '#ef4444'];
  state.chartRisk = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true,
      cutout: '65%',
      plugins: { legend: { display: false } },
    },
  });
  // Custom legend
  const legend = document.getElementById('risk-legend');
  legend.innerHTML = labels.map((l, i) =>
    `<div class="flex justify-between"><span style="color:${colors[i]}">${l}</span><span class="font-mono">${values[i]}</span></div>`
  ).join('');
}

function renderTopIPs(topIPs) {
  const el = document.getElementById('top-ips-table');
  if (!topIPs.length) { el.innerHTML = '<p class="text-gray-500 text-sm">No data.</p>'; return; }
  el.innerHTML = `<table>
    <thead><tr><th>IP Address</th><th>Event Count</th></tr></thead>
    <tbody>
      ${topIPs.map(r => `<tr><td class="font-mono">${r.ip}</td><td>${r.count}</td></tr>`).join('')}
    </tbody>
  </table>`;
}

// ─── Events ───────────────────────────────────────────────────────────────
async function loadEvents() {
  const ip = document.getElementById('events-ip-filter').value.trim();
  const risk = document.getElementById('events-risk-filter').value;
  const params = new URLSearchParams({
    limit: state.eventsLimit,
    offset: state.eventsOffset,
  });
  if (ip) params.set('ip', ip);
  if (risk) params.set('risk_level', risk);

  const tbody = document.getElementById('events-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="text-center py-8"><div class="spinner mx-auto"></div></td></tr>';

  try {
    const data = await apiFetch('/api/events?' + params);
    state.eventsTotal = data.total;
    document.getElementById('events-total-label').textContent = `${data.total} total events`;
    document.getElementById('events-prev').disabled = state.eventsOffset === 0;
    document.getElementById('events-next').disabled = state.eventsOffset + state.eventsLimit >= data.total;

    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-8 text-gray-500">No events found.</td></tr>';
      return;
    }
    tbody.innerHTML = data.items.map(e => `
      <tr onclick="showEventDetail('${e.id}')" style="cursor:pointer">
        <td class="text-xs text-gray-400 whitespace-nowrap">${fmtDate(e.timestamp)}</td>
        <td class="font-mono text-indigo-300">${e.source_ip}</td>
        <td>${e.geo_country || '—'}</td>
        <td>${riskBadge(e.risk_level)}</td>
        <td><span class="text-gray-400 text-xs">${e.event_type}</span></td>
        <td>${e.canary_label ? `<span class="text-yellow-400 text-xs">🪤 ${trunc(e.canary_label, 20)}</span>` : '—'}</td>
        <td class="text-xs text-gray-400">${trunc(e.user_agent, 40)}</td>
        <td>
          <button class="btn btn-ghost text-xs" onclick="event.stopPropagation();deleteEvent('${e.id}')">🗑</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-red-400">Error: ${err.message}</td></tr>`;
  }
}

function eventsPage(dir) {
  state.eventsOffset = Math.max(0, state.eventsOffset + dir * state.eventsLimit);
  loadEvents();
}

document.getElementById('events-ip-filter').addEventListener('keydown', e => {
  if (e.key === 'Enter') { state.eventsOffset = 0; loadEvents(); }
});
document.getElementById('events-risk-filter').addEventListener('change', () => {
  state.eventsOffset = 0; loadEvents();
});

async function showEventDetail(id) {
  const panel = document.getElementById('event-detail-panel');
  const content = document.getElementById('event-detail-content');
  panel.classList.remove('hidden');
  content.innerHTML = '<div class="spinner mx-auto my-4"></div>';
  try {
    const e = await apiFetch(`/api/events/${id}`);
    const rows = [
      ['ID', `<span class="font-mono text-xs">${e.id}</span>`],
      ['Timestamp', fmtDate(e.timestamp)],
      ['Source IP', `<span class="font-mono text-indigo-300">${e.source_ip}</span>`],
      ['Risk', riskBadge(e.risk_level) + ` (score: ${e.risk_score})`],
      ['Event Type', e.event_type],
      ['Path', `<span class="font-mono text-xs break-all">${e.path || '—'}</span>`],
      ['Method', e.method || '—'],
      ['Referrer', e.referrer || '—'],
      ['User-Agent', `<span class="text-xs break-all">${e.user_agent || '—'}</span>`],
      ['Country', e.geo_country || '—'],
      ['City', e.geo_city || '—'],
      ['ASN', e.geo_asn || '—'],
      ['ISP', e.geo_isp || '—'],
      ['Is Bot', e.ua_is_bot ? '✅ Yes' : '❌ No'],
      ['Browser', e.ua_browser || '—'],
      ['OS', e.ua_os || '—'],
      ['AbuseIPDB Score', e.abuseipdb_score ?? '—'],
      ['GreyNoise', e.greynoise_classification || '—'],
      ['Canary', e.canary_label || '—'],
      ['Notes', e.notes || '—'],
    ];
    content.innerHTML = rows.map(([k, v]) =>
      `<div class="detail-row"><span class="detail-label">${k}</span><span>${v}</span></div>`
    ).join('');
  } catch (err) {
    content.innerHTML = `<div class="text-red-400">Error loading event: ${err.message}</div>`;
  }
}

function closeEventDetail() {
  document.getElementById('event-detail-panel').classList.add('hidden');
}

async function deleteEvent(id) {
  if (!confirm('Delete this event?')) return;
  try {
    await apiFetch(`/api/events/${id}`, { method: 'DELETE' });
    toast('Event deleted.', 'success');
    loadEvents();
  } catch (err) {
    toast('Failed to delete: ' + err.message, 'error');
  }
}

// ─── Actors ────────────────────────────────────────────────────────────────
async function loadActors() {
  const risk = document.getElementById('actors-risk-filter').value;
  const bl = document.getElementById('actors-blocklist-filter').value;
  const params = new URLSearchParams({
    limit: state.actorsLimit,
    offset: state.actorsOffset,
  });
  if (risk) params.set('risk_level', risk);
  if (bl !== '') params.set('is_blocklisted', bl);

  const tbody = document.getElementById('actors-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="text-center py-8"><div class="spinner mx-auto"></div></td></tr>';
  try {
    const data = await apiFetch('/api/actors?' + params);
    state.actorsTotal = data.total;
    document.getElementById('actors-total-label').textContent = `${data.total} actors`;
    document.getElementById('actors-prev').disabled = state.actorsOffset === 0;
    document.getElementById('actors-next').disabled = state.actorsOffset + state.actorsLimit >= data.total;

    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-8 text-gray-500">No actors found.</td></tr>';
      return;
    }
    tbody.innerHTML = data.items.map(a => `
      <tr>
        <td class="font-mono text-indigo-300">${a.ip_address}</td>
        <td class="text-xs text-gray-400">${fmtDate(a.first_seen)}</td>
        <td class="text-xs text-gray-400">${fmtDate(a.last_seen)}</td>
        <td>${a.total_hits}</td>
        <td>${riskBadge(a.risk_level)}</td>
        <td>${(a.tags || []).map(t => `<span class="badge bg-gray-700 text-gray-300 mr-1">${t}</span>`).join('')}</td>
        <td>${a.is_blocklisted
          ? '<span class="badge badge-critical">Blocked</span>'
          : '<span class="badge bg-gray-800 text-gray-400">No</span>'
        }</td>
        <td>
          <button class="btn btn-ghost text-xs mr-1" onclick="toggleBlocklist('${a.id}', ${a.is_blocklisted})">
            ${a.is_blocklisted ? '✅ Unblock' : '🚫 Block'}
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-red-400">Error: ${err.message}</td></tr>`;
  }
}

function actorsPage(dir) {
  state.actorsOffset = Math.max(0, state.actorsOffset + dir * state.actorsLimit);
  loadActors();
}

document.getElementById('actors-risk-filter').addEventListener('change', () => {
  state.actorsOffset = 0; loadActors();
});
document.getElementById('actors-blocklist-filter').addEventListener('change', () => {
  state.actorsOffset = 0; loadActors();
});

async function toggleBlocklist(id, current) {
  try {
    const data = await apiFetch(`/api/actors/${id}/blocklist`, { method: 'POST' });
    toast(data.is_blocklisted ? 'Actor blocklisted.' : 'Actor unblocked.', 'success');
    loadActors();
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

// ─── Canaries ─────────────────────────────────────────────────────────────
async function loadCanaries() {
  const tbody = document.getElementById('canaries-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="text-center py-8"><div class="spinner mx-auto"></div></td></tr>';
  try {
    const data = await apiFetch('/api/canaries');
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-8 text-gray-500">No canary tokens yet. Create one!</td></tr>';
      return;
    }
    tbody.innerHTML = data.items.map(t => `
      <tr>
        <td class="font-semibold">${t.label}</td>
        <td><span class="badge bg-indigo-900 text-indigo-300">${t.bait_type}</span></td>
        <td>${t.hit_count}</td>
        <td class="text-xs text-gray-400">${fmtDate(t.last_hit)}</td>
        <td>${t.is_active
          ? '<span class="badge badge-low">Active</span>'
          : '<span class="badge bg-gray-800 text-gray-500">Inactive</span>'
        }</td>
        <td>
          <input type="text" value="${t.url || ''}" class="text-xs w-64 font-mono" readonly onclick="this.select()" />
        </td>
        <td>
          <button class="btn btn-ghost text-xs mr-1" onclick="copyURL('${t.url}')">📋 Copy</button>
          ${t.is_active
            ? `<button class="btn btn-danger text-xs" onclick="deactivateCanary('${t.id}')">Deactivate</button>`
            : ''
          }
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-red-400">Error: ${err.message}</td></tr>`;
  }
}

function copyURL(url) {
  navigator.clipboard.writeText(url).then(
    () => toast('URL copied to clipboard!', 'success'),
    () => toast('Failed to copy.', 'error')
  );
}

async function deactivateCanary(id) {
  if (!confirm('Deactivate this canary token?')) return;
  try {
    await apiFetch(`/api/canaries/${id}`, { method: 'DELETE' });
    toast('Canary deactivated.', 'success');
    loadCanaries();
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

function openCreateCanaryModal() {
  document.getElementById('modal-canary').classList.add('show');
  document.getElementById('modal-error').classList.add('hidden');
  document.getElementById('modal-label').value = '';
  document.getElementById('modal-description').value = '';
}

function closeCreateCanaryModal() {
  document.getElementById('modal-canary').classList.remove('show');
}

async function createCanary() {
  const label = document.getElementById('modal-label').value.trim();
  const bait_type = document.getElementById('modal-bait-type').value;
  const description = document.getElementById('modal-description').value.trim() || null;
  const errEl = document.getElementById('modal-error');

  if (!label) {
    errEl.textContent = 'Label is required.';
    errEl.classList.remove('hidden');
    return;
  }
  errEl.classList.add('hidden');

  try {
    const token = await apiFetch('/api/canaries', {
      method: 'POST',
      body: JSON.stringify({ label, bait_type, description }),
    });
    toast(`Canary "${token.label}" created!`, 'success');
    closeCreateCanaryModal();
    switchTab('canaries');
    loadCanaries();
  } catch (err) {
    errEl.textContent = 'Failed to create: ' + err.message;
    errEl.classList.remove('hidden');
  }
}

// Close modal on backdrop click
document.getElementById('modal-canary').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeCreateCanaryModal();
});

// ─── Export ────────────────────────────────────────────────────────────────
async function downloadExport(type, format) {
  try {
    let url, filename;
    if (type === 'events' && format === 'json') {
      url = '/api/events?limit=10000';
      filename = 'events.json';
    } else if (type === 'events' && format === 'csv') {
      // Fetch all and create CSV client-side would be complex; use canaries export endpoint
      // For events CSV, we'll use a simple approach
      const data = await apiFetch('/api/events?limit=10000');
      const csv = toCSV(data.items || []);
      downloadBlob(csv, 'text/csv', 'events.csv');
      return;
    } else if (type === 'actors') {
      const data = await apiFetch('/api/actors?limit=10000');
      const json = JSON.stringify(data.items || [], null, 2);
      downloadBlob(json, 'application/json', 'actors.json');
      return;
    } else if (type === 'canaries') {
      const blob = await apiFetch('/api/canaries/export');
      downloadBlobObj(blob, 'canaries.csv');
      return;
    }
    toast('Export started…', 'info');
  } catch (err) {
    toast('Export failed: ' + err.message, 'error');
  }
}

function toCSV(items) {
  if (!items.length) return '';
  const keys = Object.keys(items[0]);
  const escape = v => {
    const s = String(v ?? '');
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };
  return [keys.join(','), ...items.map(r => keys.map(k => escape(r[k])).join(','))].join('\n');
}

function downloadBlob(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
  downloadBlobObj(blob, filename);
}

function downloadBlobObj(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  toast(`Downloading ${filename}…`, 'success');
}

// ─── Refresh time ─────────────────────────────────────────────────────────
function updateRefreshTime() {
  document.getElementById('last-refresh').textContent =
    'Last: ' + new Date().toLocaleTimeString();
}

// ─── Auto-refresh every 30s ───────────────────────────────────────────────
setInterval(() => {
  if (state.activeTab === 'dashboard') loadDashboard();
  if (state.activeTab === 'events') loadEvents();
}, 30000);

// ─── Init ─────────────────────────────────────────────────────────────────
loadDashboard();
