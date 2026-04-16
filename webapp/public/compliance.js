/* Compliance page */
let compData = { rows: [], total: 0, page: 1, per_page: 50, pages: 0 };
let currentPage = 1;
let sortBy = 'severity';
let sortDir = 'ASC';
let loadingCount = 0;

/* ── Loading overlay ─────────────────────────── */

const loadingOverlay = (() => {
  const el = document.createElement('div');
  el.id = 'loading-overlay';
  el.innerHTML = '<div class="loading-spinner"></div><div class="loading-text">Loading…</div>';
  Object.assign(el.style, {
    position: 'fixed', inset: '0', zIndex: '9999',
    display: 'none', alignItems: 'center', justifyContent: 'center', flexDirection: 'column',
    background: 'rgba(0,0,0,.45)', backdropFilter: 'blur(4px)',
  });
  const sheet = document.createElement('style');
  sheet.textContent = [
    '.loading-spinner{width:40px;height:40px;border:4px solid rgba(255,255,255,.25);border-top-color:#0ea5e9;border-radius:50%;animation:ldspin .7s linear infinite}',
    '.loading-text{margin-top:12px;color:#fff;font-size:14px;font-weight:600;letter-spacing:.3px}',
    '@keyframes ldspin{to{transform:rotate(360deg)}}',
  ].join('');
  document.head.appendChild(sheet);
  document.body.appendChild(el);
  return el;
})();

function showLoading(msg) {
  loadingCount++;
  loadingOverlay.querySelector('.loading-text').textContent = msg || 'Loading…';
  loadingOverlay.style.display = 'flex';
}
function hideLoading() {
  loadingCount = Math.max(0, loadingCount - 1);
  if (loadingCount === 0) loadingOverlay.style.display = 'none';
}

/* ── Helpers ──────────────────────────────────── */

function F() {
  const t = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
  return (url, opts = {}) => {
    opts.headers = opts.headers || {};
    if (t) opts.headers['X-Tenant'] = t;
    return fetch(url, opts);
  };
}
function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
function num(n) { return Number(n || 0).toLocaleString(); }

const SEV_COLORS = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };
const RT_LABELS = { host: 'Hosts', image: 'Container Images', registryImage: 'Registry Images' };

document.addEventListener('DOMContentLoaded', async () => {
  showLoading('Loading compliance data…');
  try {
    await loadSummary();
    await loadData();
  } finally {
    hideLoading();
  }
});

/* ── Filters ─────────────────────────────────── */

function captureFilterState() {
  return {
    sev: document.getElementById('filter-sev').value,
    type: document.getElementById('filter-type').value,
    template: document.getElementById('filter-template').value,
    rt: document.getElementById('filter-rt').value,
    collection: document.getElementById('filter-collection').value,
    search: document.getElementById('search').value.trim(),
  };
}

function getFilterParams() {
  const s = captureFilterState();
  const params = new URLSearchParams();
  if (s.sev) params.set('severity', s.sev);
  if (s.type) params.set('type', s.type);
  if (s.template) params.set('template', s.template);
  if (s.rt) params.set('resource_type', s.rt);
  if (s.collection) params.set('collection', s.collection);
  if (s.search) params.set('search', s.search);
  return params;
}

async function applyFilters() {
  currentPage = 1;
  const state = captureFilterState();
  showLoading('Filtering…');
  try {
    await loadSummary(state);
    await loadData();
  } finally {
    hideLoading();
  }
}

/* ── Summary / KPI ───────────────────────────── */

async function loadSummary(preserveState) {
  const f = F();
  try {
    const params = getFilterParams();
    const res = await f('/api/compliance/summary?' + params);
    const data = await res.json();
    renderKpi(data);
    populateFilters(data, preserveState);
  } catch (_) {}
}

function renderKpi(data) {
  const kpi = document.getElementById('kpi-row');
  kpi.innerHTML = [
    '<div class="kpi-card"><div class="kpi-label">Total Checks</div><div class="kpi-value">' + num(data.total) + '</div></div>',
    '<div class="kpi-card" style="border-left:3px solid var(--sev-critical)"><div class="kpi-label">Critical</div><div class="kpi-value">' + num(data.critical) + '</div></div>',
    '<div class="kpi-card" style="border-left:3px solid var(--sev-high)"><div class="kpi-label">High</div><div class="kpi-value">' + num(data.high) + '</div></div>',
    '<div class="kpi-card" style="border-left:3px solid var(--sev-medium)"><div class="kpi-label">Medium</div><div class="kpi-value">' + num(data.medium) + '</div></div>',
    '<div class="kpi-card" style="border-left:3px solid var(--sev-low)"><div class="kpi-label">Low</div><div class="kpi-value">' + num(data.low) + '</div></div>',
    '<div class="kpi-card"><div class="kpi-label">Resources</div><div class="kpi-value">' + num(data.resource_count) + '</div></div>',
  ].join('');
}

function populateFilters(data, preserveState) {
  const s = preserveState || captureFilterState();

  const typeSel = document.getElementById('filter-type');
  typeSel.innerHTML = '<option value="">All Types</option>' + (data.types || []).map(t => '<option value="' + esc(t) + '"' + (t === s.type ? ' selected' : '') + '>' + esc(t) + '</option>').join('');

  const tplSel = document.getElementById('filter-template');
  tplSel.innerHTML = '<option value="">All Frameworks</option>' + (data.templates || []).map(t => '<option value="' + esc(t) + '"' + (t === s.template ? ' selected' : '') + '>' + esc(t) + '</option>').join('');

  const rtSel = document.getElementById('filter-rt');
  rtSel.innerHTML = '<option value="">All Resource Types</option>' + (data.resource_types || []).map(t => '<option value="' + esc(t) + '"' + (t === s.rt ? ' selected' : '') + '>' + esc(RT_LABELS[t] || t) + '</option>').join('');

  const colSel = document.getElementById('filter-collection');
  colSel.innerHTML = '<option value="">All Collections</option>' + (data.collections || []).map(c => '<option value="' + esc(c) + '"' + (c === s.collection ? ' selected' : '') + '>' + esc(c) + '</option>').join('');
}

/* ── Data table ──────────────────────────────── */

async function loadData() {
  const f = F();
  const params = getFilterParams();
  params.set('page', currentPage);
  params.set('per_page', 50);
  params.set('sort_by', sortBy);
  params.set('sort_dir', sortDir);
  try {
    const res = await f('/api/compliance?' + params);
    compData = await res.json();
    renderTable();
    renderPager();
  } catch (_) {}
}

function toggleSort(col) {
  if (sortBy === col) { sortDir = sortDir === 'ASC' ? 'DESC' : 'ASC'; } else { sortBy = col; sortDir = 'ASC'; }
  currentPage = 1;
  showLoading('Sorting…');
  loadData().finally(hideLoading);
}

function renderTable() {
  const wrap = document.getElementById('table-wrap');
  if (!compData.rows || !compData.rows.length) {
    wrap.innerHTML = '<div style="text-align:center;padding:var(--space-6);color:var(--muted)">No compliance findings match your filters.</div>';
    return;
  }

  const arrow = (col) => sortBy === col ? (sortDir === 'ASC' ? ' \u2191' : ' \u2193') : '';

  let html = '<table class="comp-table"><thead><tr>';
  html += '<th onclick="toggleSort(\'comp_id\')">ID' + arrow('comp_id') + '</th>';
  html += '<th onclick="toggleSort(\'severity\')">Severity' + arrow('severity') + '</th>';
  html += '<th onclick="toggleSort(\'title\')">Title' + arrow('title') + '</th>';
  html += '<th>Type</th>';
  html += '<th>Frameworks</th>';
  html += '<th>Resources</th>';
  html += '<th></th>';
  html += '</tr></thead><tbody>';

  for (const row of compData.rows) {
    const rid = 'comp-' + row.comp_id;
    html += '<tr class="data-row" onclick="toggleRow(\'' + rid + '\')">';
    html += '<td class="comp-id">' + row.comp_id + '</td>';
    html += '<td><span class="badge badge-' + row.severity + '">' + row.severity.charAt(0).toUpperCase() + row.severity.slice(1) + '</span></td>';
    html += '<td class="comp-title">' + esc(row.title) + '</td>';
    html += '<td><span class="comp-type">' + esc(row.comp_type) + '</span></td>';
    html += '<td>' + (row.templates || []).map(t => '<span class="tpl-tag">' + esc(t) + '</span>').join('') + '</td>';
    html += '<td class="res-count">' + num(row.resource_count) + '</td>';
    html += '<td style="font-size:11px;color:var(--muted)">\u25B8</td>';
    html += '</tr>';
    html += '<tr class="expand-row hidden" id="' + rid + '"><td colspan="7"><div class="detail-inner">';
    html += '<div style="font-size:var(--text-sm);color:var(--text-2)">' + esc(row.description) + '</div>';
    if (row.cause) html += '<div class="detail-cause"><strong>Cause:</strong> ' + esc(row.cause) + '</div>';
    for (const rtype of ['host', 'image', 'registryImage']) {
      const list = row.resources[rtype];
      if (!list || !list.length) continue;
      html += '<div class="detail-res-type">' + esc(RT_LABELS[rtype] || rtype) + ' (' + list.length + ')</div>';
      html += '<ul class="detail-res-list">';
      const show = list.slice(0, 20);
      for (const r of show) {
        html += '<li>' + esc(r.name) + (r.os ? ' <span style="color:var(--muted);font-size:10px">' + esc(r.os) + '</span>' : '') + '</li>';
      }
      if (list.length > 20) html += '<li style="color:var(--muted)">+' + (list.length - 20) + ' more\u2026</li>';
      html += '</ul>';
    }
    html += '</div></td></tr>';
  }
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function toggleRow(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('hidden');
}

/* ── Pager ────────────────────────────────────── */

function renderPager() {
  const el = document.getElementById('pager');
  if (compData.pages <= 1) { el.innerHTML = ''; return; }
  el.innerHTML = '<button ' + (currentPage <= 1 ? 'disabled' : '') + ' onclick="goPage(' + (currentPage - 1) + ')">\u2190 Prev</button>'
    + '<span class="pager-info">Page ' + compData.page + ' of ' + compData.pages + ' (' + num(compData.total) + ' results)</span>'
    + '<button ' + (currentPage >= compData.pages ? 'disabled' : '') + ' onclick="goPage(' + (currentPage + 1) + ')">Next \u2192</button>';
}

function goPage(p) {
  currentPage = p;
  showLoading('Loading page ' + p + '…');
  loadData().finally(hideLoading);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ── Export ───────────────────────────────────── */

function toggleExportMenu() {
  const menu = document.getElementById('export-dropdown');
  menu.classList.toggle('open');
  const handler = (e) => {
    if (!e.target.closest('.export-wrap')) { menu.classList.remove('open'); document.removeEventListener('click', handler); }
  };
  if (menu.classList.contains('open')) {
    setTimeout(() => document.addEventListener('click', handler), 0);
  }
}

async function doExport(format) {
  document.getElementById('export-dropdown').classList.remove('open');
  showLoading('Generating ' + format.toUpperCase() + ' export…');
  const f = F();
  const s = captureFilterState();
  const body = {
    format,
    severity: s.sev || undefined,
    type: s.type || undefined,
    template: s.template || undefined,
    resource_type: s.rt || undefined,
    collection: s.collection || undefined,
    search: s.search || undefined,
    sort_by: sortBy,
    sort_dir: sortDir,
  };

  try {
    const res = await f('/api/compliance/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = data.tenant || (window.TenantCtx ? TenantCtx.getCurrentTenant() : '');
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a');
      a.href = dlUrl; a.download = data.file;
      document.body.appendChild(a); a.click(); a.remove();
    } else {
      alert('Export failed: ' + (data.error || 'Unknown'));
    }
  } catch (err) {
    alert('Export error: ' + err.message);
  } finally {
    hideLoading();
  }
}

/* ── Tenant switch ────────────────────────────── */

if (window.TenantCtx) {
  const origSet = TenantCtx.setTenant;
  if (origSet) {
    TenantCtx.setTenant = function(slug) {
      origSet.call(TenantCtx, slug);
      currentPage = 1;
      showLoading('Switching tenant…');
      Promise.all([loadSummary(), loadData()]).finally(hideLoading);
    };
  }
}
