/* Explorer – search, sort, filter, export */
const ALL_COLS = [
  { key: 'cve_id',       label: 'CVE ID',        sortable: true,  cls: 'mono', default: true },
  { key: 'severity',     label: 'Severity',       sortable: true,  default: true },
  { key: 'cvss',         label: 'CVSS',           sortable: true,  cls: 'mono', default: true },
  { key: 'description',  label: 'Description',    sortable: false, cls: 'desc-cell', default: false },
  { key: 'fix_status',   label: 'Fix Status',     sortable: true,  default: true },
  { key: 'is_kev',       label: 'KEV',            sortable: true,  default: true },
  { key: 'packages',     label: 'Packages',       sortable: false, default: true },
  { key: 'resources',    label: 'Resources',      sortable: false, default: false },
  { key: 'risk_factors', label: 'Risk Factors',   sortable: false, default: true },
  { key: 'os_labels',    label: 'OS',             sortable: false, default: false },
  { key: 'collections',  label: 'Collections',    sortable: false, default: true },
  { key: 'repos',        label: 'Repos',          sortable: false, default: false },
  { key: 'link',         label: 'Link',           sortable: false, default: false },
];

const state = {
  page: 1, pageSize: 50, total: 0, totalPages: 1,
  sortBy: 'cvss', sortDir: 'DESC',
  q: '',
  filters: {},
  rows: [],
  filterMeta: {},
  expandedId: null,
  exporting: false,
  visibleCols: ALL_COLS.filter(c => c.default).map(c => c.key),
  groupBy: '',
  collapsedGroups: {},
};

const FILTER_LABELS = {
  severity: 'Severity', fix_status: 'Fix Status', is_kev: 'KEV',
  os: 'OS', risk_factor: 'Risk Factor', collection: 'Collection',
  repo: 'Repo', resource_type: 'Resource Type'
};

const RT_MAP = { host: 'Hosts', image: 'Images', registryImage: 'Registry' };
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function visCols() { return ALL_COLS.filter(c => state.visibleCols.includes(c.key)); }
function colCount() { return visCols().length + 1; /* +1 for expand btn col */ }

/* ── Column picker ────────────────────────────────────── */

function toggleColumnPicker() {
  const menu = document.getElementById('col-picker-menu');
  menu.classList.toggle('open');
  const handler = (e) => {
    if (!e.target.closest('.col-picker-wrap')) { menu.classList.remove('open'); document.removeEventListener('click', handler); }
  };
  if (menu.classList.contains('open')) {
    setTimeout(() => document.addEventListener('click', handler), 0);
  }
}

function renderColPicker() {
  const el = document.getElementById('col-picker-list');
  el.innerHTML = ALL_COLS.map(c =>
    '<label class="col-pick-item"><input type="checkbox" value="' + c.key + '"' +
    (state.visibleCols.includes(c.key) ? ' checked' : '') +
    '> ' + esc(c.label) + '</label>'
  ).join('');
  el.querySelectorAll('input').forEach(inp => inp.addEventListener('change', onColToggle));
  updateColCount();
}

function onColToggle() {
  const checked = [...document.querySelectorAll('#col-picker-list input:checked')].map(i => i.value);
  if (!checked.length) return;
  state.visibleCols = checked;
  updateColCount();
  renderHead();
  renderBody();
}

function updateColCount() {
  const badge = document.getElementById('col-count-badge');
  if (badge) badge.textContent = state.visibleCols.length + '/' + ALL_COLS.length;
}

/* ── Save as Template ─────────────────────────────────── */

function onGroupByChange() {
  state.groupBy = document.getElementById('group-by-select').value;
  state.collapsedGroups = {};
  state.page = 1;
  loadData();
}

function toggleGroup(groupKey) {
  state.collapsedGroups[groupKey] = !state.collapsedGroups[groupKey];
  renderBody();
}

function extractGroupValue(row, field) {
  if (field === 'severity') return row.severity || 'unknown';
  if (field === 'fix_status') return row.fix_status || 'unknown';
  if (field === 'resource_type') {
    if (!row.resources || typeof row.resources !== 'object') return '(none)';
    const types = Object.keys(row.resources).filter(t => (row.resources[t] || []).length > 0);
    return types.length ? types.map(t => RT_MAP[t] || t).join(', ') : '(none)';
  }
  if (field === 'collection') {
    const c = Array.isArray(row.collections) ? row.collections : [];
    return c.length ? c.join(', ') : '(none)';
  }
  if (field === 'os') {
    const o = Array.isArray(row.os_labels) ? row.os_labels : [];
    return o.length ? o.join(', ') : '(none)';
  }
  if (field === 'risk_factor') {
    const r = Array.isArray(row.risk_factors) ? row.risk_factors : [];
    return r.length ? r.join(', ') : '(none)';
  }
  return '(none)';
}

const GROUP_SORT_ORDER = {
  severity: { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 },
};

function groupRows(rows, field) {
  const map = new Map();
  for (const row of rows) {
    const vals = [];
    if (['collection', 'os', 'risk_factor'].includes(field)) {
      const arr = field === 'collection' ? (row.collections || [])
        : field === 'os' ? (row.os_labels || [])
        : (row.risk_factors || []);
      if (arr.length) { for (const v of arr) vals.push(v); }
      else vals.push('(none)');
    } else if (field === 'resource_type') {
      const types = row.resources && typeof row.resources === 'object'
        ? Object.keys(row.resources).filter(t => (row.resources[t] || []).length > 0) : [];
      if (types.length) { for (const t of types) vals.push(RT_MAP[t] || t); }
      else vals.push('(none)');
    } else {
      vals.push(extractGroupValue(row, field));
    }
    for (const v of vals) {
      if (!map.has(v)) map.set(v, []);
      map.get(v).push(row);
    }
  }
  let keys = [...map.keys()];
  const sortMap = GROUP_SORT_ORDER[field];
  if (sortMap) {
    keys.sort((a, b) => (sortMap[a] ?? 99) - (sortMap[b] ?? 99));
  } else {
    keys.sort((a, b) => {
      if (a === '(none)') return 1;
      if (b === '(none)') return -1;
      return a.localeCompare(b);
    });
  }
  return keys.map(k => ({ key: k, rows: map.get(k) }));
}

function openSaveModal() {
  document.getElementById('save-modal').classList.add('open');
  const inp = document.getElementById('save-tpl-name');
  inp.value = '';
  inp.focus();
}

function closeSaveModal() {
  document.getElementById('save-modal').classList.remove('open');
}

async function doSaveTemplate() {
  const name = (document.getElementById('save-tpl-name').value || '').trim() || 'Explorer Report';
  const config = {
    data_source: state.filters.is_kev ? 'kev' : 'all',
    filters: {},
    columns: [...state.visibleCols],
    sort_by: state.sortBy,
    sort_dir: state.sortDir,
    group_by: state.groupBy || undefined,
    limit: 5000,
  };
  for (const [k, v] of Object.entries(state.filters)) {
    if (k === 'is_kev') continue;
    if (Array.isArray(v) && v.length) config.filters[k] = v;
  }
  const btn = document.getElementById('save-tpl-btn');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  try {
    const f = F();
    const res = await f('/api/templates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, config }),
    });
    const data = await res.json();
    closeSaveModal();
    const toast = document.getElementById('export-toast');
    if (data.id) {
      toast.className = 'export-toast show success';
      toast.innerHTML = '&#10003; Template "' + esc(name) + '" saved';
    } else {
      toast.className = 'export-toast show error';
      toast.innerHTML = 'Save failed: ' + esc(data.error || 'Unknown');
    }
    setTimeout(() => { toast.className = 'export-toast'; }, 4000);
  } catch (err) {
    closeSaveModal();
    const toast = document.getElementById('export-toast');
    toast.className = 'export-toast show error';
    toast.innerHTML = 'Error: ' + esc(err.message);
    setTimeout(() => { toast.className = 'export-toast'; }, 5000);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Template';
  }
}

function F() {
  const t = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
  return (url, opts = {}) => {
    opts.headers = opts.headers || {};
    if (t) opts.headers['X-Tenant'] = t;
    return fetch(url, opts);
  };
}

/* ── Filter sidebar ────────────────────────────────────── */

function toggleSection(headEl) {
  headEl.classList.toggle('collapsed');
  headEl.nextElementSibling.classList.toggle('is-collapsed');
}

function buildChecks(containerId, items, filterKey) {
  const el = document.getElementById(containerId);
  if (!items || !items.length) { el.innerHTML = '<span style="color:var(--muted);font-size:10px">None available</span>'; return; }
  el.innerHTML = items.map(v =>
    '<label class="filter-check"><input type="checkbox" value="' + esc(v) + '" data-filter="' + filterKey + '"> ' + esc(v) + '</label>'
  ).join('');
  el.querySelectorAll('input').forEach(inp => inp.addEventListener('change', onFilterChange));
}

function onFilterChange() {
  collectFilters();
  state.page = 1;
  renderActiveFilters();
  loadData();
}

function collectFilters() {
  state.filters = {};
  document.querySelectorAll('#sidebar input[type=checkbox][data-filter]:checked').forEach(inp => {
    const k = inp.dataset.filter;
    if (!state.filters[k]) state.filters[k] = [];
    state.filters[k].push(inp.value);
  });
  if (document.getElementById('f-kev').checked) state.filters.is_kev = true;
}

function clearAllFilters() {
  document.querySelectorAll('#sidebar input[type=checkbox]:checked').forEach(inp => { inp.checked = false; });
  document.getElementById('f-kev').checked = false;
  document.getElementById('search-input').value = '';
  document.getElementById('group-by-select').value = '';
  state.q = '';
  state.groupBy = '';
  state.collapsedGroups = {};
  onFilterChange();
}

function removeFilter(key, value) {
  if (key === 'is_kev') {
    document.getElementById('f-kev').checked = false;
  } else if (key === 'q') {
    document.getElementById('search-input').value = '';
    state.q = '';
  } else if (key === 'groupBy') {
    state.groupBy = '';
    state.collapsedGroups = {};
    document.getElementById('group-by-select').value = '';
  } else {
    document.querySelectorAll('#sidebar input[data-filter="' + key + '"]').forEach(inp => {
      if (inp.value === value) inp.checked = false;
    });
  }
  onFilterChange();
}

function renderActiveFilters() {
  const bar = document.getElementById('active-filters');
  const parts = [];
  for (const [k, vals] of Object.entries(state.filters)) {
    if (k === 'is_kev') {
      parts.push('<span class="af-pill" onclick="removeFilter(\'is_kev\')">KEV Only <span class="af-x">&times;</span></span>');
    } else if (Array.isArray(vals)) {
      for (const v of vals) {
        parts.push('<span class="af-pill" onclick="removeFilter(\'' + esc(k) + '\',\'' + esc(v).replace(/'/g, "\\'") + '\')">' + esc(FILTER_LABELS[k] || k) + ': ' + esc(v) + ' <span class="af-x">&times;</span></span>');
      }
    }
  }
  if (state.q) {
    parts.push('<span class="af-pill" onclick="removeFilter(\'q\')">Search: "' + esc(state.q) + '" <span class="af-x">&times;</span></span>');
  }
  if (state.groupBy) {
    const gLabels = { severity:'Severity', fix_status:'Fix Status', resource_type:'Resource Type', collection:'Collection', os:'OS', risk_factor:'Risk Factor' };
    parts.push('<span class="af-pill" onclick="removeFilter(\'groupBy\')">Group: ' + esc(gLabels[state.groupBy] || state.groupBy) + ' <span class="af-x">&times;</span></span>');
  }
  if (parts.length) {
    bar.innerHTML = parts.join('') + '<button class="af-clear" onclick="clearAllFilters()">Clear all</button>';
    bar.style.display = 'flex';
  } else {
    bar.innerHTML = '';
    bar.style.display = 'none';
  }
}

function activeFilterCount() {
  let n = 0;
  for (const [k, v] of Object.entries(state.filters)) {
    if (k === 'is_kev') n++;
    else if (Array.isArray(v)) n += v.length;
  }
  if (state.q) n++;
  if (state.groupBy) n++;
  return n;
}

async function loadFilterOptions() {
  const f = F();
  const [filters, statuses] = await Promise.all([
    f('/api/filters').then(r => r.json()),
    f('/api/explorer/fix-statuses').then(r => r.json()),
  ]);
  state.filterMeta = filters;
  buildChecks('f-severity', ['critical','high','medium','low'], 'severity');
  buildChecks('f-fix-status', statuses, 'fix_status');
  buildChecks('f-os', filters.os, 'os');
  buildChecks('f-risk-factor', filters.risk_factors, 'risk_factor');
  buildChecks('f-collection', filters.collections, 'collection');
  buildChecks('f-repo', filters.repos, 'repo');
  buildChecks('f-resource-type', (filters.resource_types || []).map(r => r), 'resource_type');
  document.getElementById('f-kev').addEventListener('change', onFilterChange);
}

/* ── Table rendering ────────────────────────────────────── */

function renderHead() {
  const tr = document.querySelector('#table-head tr');
  const cols = visCols();
  tr.innerHTML = '<th style="width:28px"></th>' + cols.map(c => {
    const active = state.sortBy === c.key;
    const arrow = active ? '<span class="sort-arrow ' + state.sortDir.toLowerCase() + '"></span>' : '';
    return '<th' + (c.sortable ? ' onclick="toggleSort(\'' + c.key + '\')"' : '') + '>' + c.label + arrow + '</th>';
  }).join('');
}

function toggleSort(key) {
  if (state.sortBy === key) { state.sortDir = state.sortDir === 'DESC' ? 'ASC' : 'DESC'; }
  else { state.sortBy = key; state.sortDir = 'DESC'; }
  state.page = 1;
  loadData();
}

function fmtCell(col, val) {
  if (val == null) return '<span style="color:var(--muted)">—</span>';
  if (col === 'severity') return '<span class="badge badge-' + val + '">' + esc(val) + '</span>';
  if (col === 'cvss') return '<span class="mono">' + Number(val).toFixed(1) + '</span>';
  if (col === 'is_kev') return val ? '<span class="badge badge-critical">Yes</span>' : '<span style="color:var(--muted)">No</span>';
  if (col === 'fix_status') return '<span class="badge badge-' + (val === 'fixed' ? 'low' : val === 'will not fix' ? 'medium' : 'sky') + '">' + esc(val) + '</span>';
  if (col === 'description') return '<span class="desc-cell" title="' + esc(val) + '">' + esc(val) + '</span>';
  if (col === 'link') return val ? '<a href="' + esc(val) + '" target="_blank" style="color:var(--sky);font-size:10px" title="' + esc(val) + '">Link</a>' : '<span style="color:var(--muted)">—</span>';
  if (col === 'packages' && typeof val === 'object') {
    const entries = Object.entries(val);
    if (!entries.length) return '<span style="color:var(--muted)">—</span>';
    const shown = entries.slice(0, 3);
    let html = '<ul class="pkg-list">' + shown.map(([n,v]) => '<li><span class="pkg-name">' + esc(n) + '</span>' + ((v||[]).length ? ' <span class="pkg-ver">' + v.map(esc).join(', ') + '</span>' : '') + '</li>').join('') + '</ul>';
    if (entries.length > 3) html += '<span style="color:var(--muted);font-size:9px">+' + (entries.length - 3) + ' more</span>';
    return html;
  }
  if (col === 'risk_factors' && Array.isArray(val)) {
    if (!val.length) return '<span style="color:var(--muted)">—</span>';
    return val.slice(0, 3).map(f => '<span class="tag tag-rf">' + esc(f) + '</span>').join(' ') + (val.length > 3 ? ' <span style="color:var(--muted);font-size:9px">+' + (val.length-3) + '</span>' : '');
  }
  if (col === 'collections') {
    let colList = Array.isArray(val) ? val : [];
    if (!colList.length) return '<span style="color:var(--muted)">—</span>';
    return colList.slice(0, 3).map(f => '<span class="tag tag-col">' + esc(f) + '</span>').join(' ') + (colList.length > 3 ? ' <span style="color:var(--muted);font-size:9px">+' + (colList.length-3) + '</span>' : '');
  }
  if (col === 'os_labels' && Array.isArray(val)) {
    if (!val.length) return '<span style="color:var(--muted)">—</span>';
    return val.slice(0, 3).map(o => '<span class="tag tag-os">' + esc(o) + '</span>').join(' ') + (val.length > 3 ? ' <span style="color:var(--muted);font-size:9px">+' + (val.length-3) + '</span>' : '');
  }
  if (col === 'repos' && Array.isArray(val)) {
    if (!val.length) return '<span style="color:var(--muted)">—</span>';
    return val.slice(0, 2).map(r => '<span class="tag tag-repo">' + esc(r) + '</span>').join(' ') + (val.length > 2 ? ' <span style="color:var(--muted);font-size:9px">+' + (val.length-2) + '</span>' : '');
  }
  if (col === 'resources' && typeof val === 'object') {
    const types = Object.entries(val);
    if (!types.length) return '<span style="color:var(--muted)">—</span>';
    let total = 0;
    for (const [, list] of types) total += (list || []).length;
    return '<span style="color:var(--text-2);font-size:10px">' + total + ' resource' + (total !== 1 ? 's' : '') + '</span>';
  }
  if (typeof val === 'object') return esc(Array.isArray(val) ? val.join(', ') : JSON.stringify(val));
  return esc(String(val));
}

function renderDetailRow(row) {
  let html = '<div class="detail-grid">';
  html += '<div class="detail-field"><div class="detail-label">Description</div><div class="detail-value">' + esc(row.description || '—') + '</div></div>';
  if (row.link) html += '<div class="detail-field"><div class="detail-label">Link</div><div class="detail-value"><a href="' + esc(row.link) + '" target="_blank" style="color:var(--sky)">' + esc(row.link) + '</a></div></div>';
  if (row.os_labels && row.os_labels.length) {
    html += '<div class="detail-field"><div class="detail-label">Operating Systems</div><div class="detail-value">' + row.os_labels.map(o => '<span class="tag tag-os">' + esc(o) + '</span>').join(' ') + '</div></div>';
  }
  if (row.repos && row.repos.length) {
    html += '<div class="detail-field"><div class="detail-label">Repositories</div><div class="detail-value">' + row.repos.map(r => '<span class="tag tag-repo">' + esc(r) + '</span>').join(' ') + '</div></div>';
  }
  if (row.risk_factors && row.risk_factors.length) {
    html += '<div class="detail-field"><div class="detail-label">All Risk Factors</div><div class="detail-value">' + row.risk_factors.map(f => '<span class="tag tag-rf">' + esc(f) + '</span>').join(' ') + '</div></div>';
  }
  if (row.collections && row.collections.length) {
    html += '<div class="detail-field"><div class="detail-label">All Collections</div><div class="detail-value">' + row.collections.map(c => '<span class="tag tag-col">' + esc(c) + '</span>').join(' ') + '</div></div>';
  }
  if (row.packages && typeof row.packages === 'object') {
    const entries = Object.entries(row.packages);
    if (entries.length) {
      html += '<div class="detail-field" style="grid-column:span 2"><div class="detail-label">All Packages (' + entries.length + ')</div><div class="detail-value"><ul class="pkg-list">' + entries.map(([n,v]) => '<li><span class="pkg-name">' + esc(n) + '</span>' + ((v||[]).length ? ' <span class="pkg-ver">' + v.map(esc).join(', ') + '</span>' : '') + '</li>').join('') + '</ul></div></div>';
    }
  }
  if (row.resources && typeof row.resources === 'object') {
    const types = Object.entries(row.resources);
    if (types.length) {
      let resHtml = '';
      for (const [rtype, list] of types) {
        if (!list || !list.length) continue;
        const label = RT_MAP[rtype] || rtype;
        const byNs = {};
        for (const r of list) {
          const nsList = (r.namespaces && r.namespaces.length) ? r.namespaces : ['(no namespace)'];
          for (const ns of nsList) { if (!byNs[ns]) byNs[ns] = []; byNs[ns].push(r); }
        }
        resHtml += '<div class="res-grp"><div class="res-type-hd">' + esc(label) + ' (' + list.length + ')</div>';
        for (const [ns, res] of Object.entries(byNs).sort((a,b) => a[0].localeCompare(b[0]))) {
          resHtml += '<div class="res-ns"><div class="res-ns-name">' + esc(ns) + '</div><ul class="res-list">';
          resHtml += res.slice(0, 20).map(r => '<li>' + esc(r.name) + (r.os ? '<span class="os-sm">' + esc(r.os) + '</span>' : '') + '</li>').join('');
          if (res.length > 20) resHtml += '<li style="color:var(--muted)">+' + (res.length - 20) + ' more</li>';
          resHtml += '</ul></div>';
        }
        resHtml += '</div>';
      }
      html += '<div class="detail-field" style="grid-column:span 2"><div class="detail-label">Resources</div><div class="detail-value">' + resHtml + '</div></div>';
    }
  }
  html += '</div>';
  return html;
}

function renderBody() {
  const tbody = document.getElementById('table-body');
  const cols = visCols();
  const cc = colCount();
  if (!state.rows.length) {
    tbody.innerHTML = '<tr><td colspan="' + cc + '" style="text-align:center;padding:40px;color:var(--muted)">No results match your search and filters</td></tr>';
    return;
  }

  if (state.groupBy) {
    const groups = groupRows(state.rows, state.groupBy);
    let html = '';
    for (const g of groups) {
      const collapsed = !!state.collapsedGroups[g.key];
      html += '<tr class="group-header-row" onclick="toggleGroup(\'' + esc(g.key).replace(/'/g, "\\'") + '\')">'
        + '<td colspan="' + cc + '">'
        + '<span class="group-chevron' + (collapsed ? ' collapsed' : '') + '">&#9660;</span>'
        + esc(g.key) + '<span class="group-count">' + g.rows.length + ' CVE' + (g.rows.length !== 1 ? 's' : '') + '</span>'
        + '</td></tr>';
      if (!collapsed) {
        for (const row of g.rows) {
          html += renderDataRow(row, cols, cc);
        }
      }
    }
    tbody.innerHTML = html;
    return;
  }

  let html = '';
  for (const row of state.rows) {
    html += renderDataRow(row, cols, cc);
  }
  tbody.innerHTML = html;
}

function renderDataRow(row, cols, cc) {
  const isExpanded = state.expandedId === row.cve_id;
  let html = '<tr>';
  html += '<td><button class="expand-btn" onclick="toggleExpand(\'' + esc(row.cve_id) + '\')">' + (isExpanded ? '▾' : '▸') + '</button></td>';
  for (const c of cols) {
    html += '<td' + (c.cls ? ' class="' + c.cls + '"' : '') + '>' + fmtCell(c.key, row[c.key]) + '</td>';
  }
  html += '</tr>';
  if (isExpanded) {
    html += '<tr class="detail-row"><td colspan="' + cc + '">' + renderDetailRow(row) + '</td></tr>';
  }
  return html;
}

function toggleExpand(cveId) {
  state.expandedId = state.expandedId === cveId ? null : cveId;
  renderBody();
}

function updatePager() {
  state.totalPages = Math.max(1, Math.ceil(state.total / state.pageSize));
  document.getElementById('result-count').innerHTML = '<strong>' + state.total.toLocaleString() + '</strong> vulnerabilities found';
  document.getElementById('cur-page').textContent = state.page;
  document.getElementById('total-pages').textContent = state.totalPages;
  const start = state.total ? ((state.page - 1) * state.pageSize + 1) : 0;
  const end = Math.min(state.page * state.pageSize, state.total);
  document.getElementById('pg-range').textContent = state.total ? (start + '–' + end + ' of ' + state.total.toLocaleString()) : '0 results';
  document.getElementById('pg-first').disabled = state.page <= 1;
  document.getElementById('pg-prev').disabled = state.page <= 1;
  document.getElementById('pg-next').disabled = state.page >= state.totalPages;
  document.getElementById('pg-last').disabled = state.page >= state.totalPages;
}

function goPage(n) {
  if (n < 1 || n > state.totalPages) return;
  state.page = n;
  loadData();
}

/* ── Data fetching ────────────────────────────────────── */

let loadTimer = null;
function scheduleLoad() {
  clearTimeout(loadTimer);
  loadTimer = setTimeout(() => { state.page = 1; renderActiveFilters(); loadData(); }, 300);
}

async function loadData() {
  const f = F();
  const params = new URLSearchParams({
    page: state.page,
    pageSize: state.pageSize,
    sort_by: state.sortBy,
    sort_dir: state.sortDir,
  });
  if (state.q) params.set('q', state.q);
  if (Object.keys(state.filters).length) params.set('filters', JSON.stringify(state.filters));

  renderHead();
  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '<tr><td colspan="' + colCount() + '" style="text-align:center;padding:40px;color:var(--muted)"><div class="spinner" style="margin:0 auto"></div></td></tr>';

  try {
    const res = await f('/api/explorer?' + params.toString());
    const data = await res.json();
    state.rows = data.rows || [];
    state.total = data.total || 0;
    state.page = data.page || 1;
    renderBody();
    updatePager();
    updateExportBtnLabel();
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="' + colCount() + '" style="text-align:center;padding:40px;color:var(--red)">Error: ' + esc(err.message) + '</td></tr>';
  }
}

/* ── Export ────────────────────────────────────────────── */

function toggleExportMenu() {
  const menu = document.getElementById('export-menu');
  menu.classList.toggle('open');
  const handler = (e) => {
    if (!e.target.closest('.export-wrap')) { menu.classList.remove('open'); document.removeEventListener('click', handler); }
  };
  if (menu.classList.contains('open')) {
    setTimeout(() => document.addEventListener('click', handler), 0);
  }
}

function updateExportBtnLabel() {
  const n = activeFilterCount();
  const badge = document.getElementById('export-filter-badge');
  if (n > 0) {
    badge.textContent = n + ' filter' + (n > 1 ? 's' : '');
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
  document.getElementById('export-total').textContent = state.total.toLocaleString() + ' rows';
}

async function doExport(format) {
  if (state.exporting) return;
  state.exporting = true;
  const menu = document.getElementById('export-menu');
  menu.classList.remove('open');

  const toast = document.getElementById('export-toast');
  toast.className = 'export-toast show';
  toast.innerHTML = '<div class="spinner spinner-sm"></div> Generating ' + format.toUpperCase() + ' export&hellip;';

  const f = F();
  const body = {
    format,
    filters: state.filters,
    q: state.q,
    sort_by: state.sortBy,
    sort_dir: state.sortDir,
    columns: [...state.visibleCols],
    group_by: state.groupBy || undefined,
  };
  try {
    const res = await f('/api/explorer/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = data.tenant || (window.TenantCtx ? TenantCtx.getCurrentTenant() : '');
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      toast.className = 'export-toast show success';
      toast.innerHTML = '&#10003; ' + format.toUpperCase() + ' ready — ' + (data.count || 0).toLocaleString() + ' rows exported';
      const a = document.createElement('a');
      a.href = dlUrl; a.download = data.file;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => { toast.className = 'export-toast'; }, 4000);
    } else {
      toast.className = 'export-toast show error';
      toast.innerHTML = 'Export failed: ' + esc(data.error || 'Unknown error');
      setTimeout(() => { toast.className = 'export-toast'; }, 5000);
    }
  } catch (err) {
    toast.className = 'export-toast show error';
    toast.innerHTML = 'Export error: ' + esc(err.message);
    setTimeout(() => { toast.className = 'export-toast'; }, 5000);
  } finally {
    state.exporting = false;
  }
}

/* ── Init ────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('search-input').addEventListener('input', (e) => {
    state.q = e.target.value;
    scheduleLoad();
  });

  renderColPicker();
  await loadFilterOptions();
  renderActiveFilters();
  loadData();
});

if (window.TenantCtx) {
  const origSet = TenantCtx.setTenant;
  if (origSet) {
    TenantCtx.setTenant = function(slug) {
      origSet.call(TenantCtx, slug);
      state.page = 1;
      state.filters = {};
      state.q = '';
      document.querySelectorAll('#sidebar input:checked').forEach(i => { i.checked = false; });
      document.getElementById('search-input').value = '';
      loadFilterOptions().then(() => { renderActiveFilters(); loadData(); });
    };
  }
}
