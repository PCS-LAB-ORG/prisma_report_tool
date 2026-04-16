let currentStep = 1;
let wizardConfig = { data_source: 'all', filters: {}, columns: ['cve_id','severity','cvss','description','fix_status'], sort_by: 'cvss', sort_dir: 'DESC', limit: 100 };
let filterData = {};
const F = () => window.TenantCtx ? TenantCtx.apiFetch : fetch;

const ALL_COLUMNS = [
  { key: 'cve_id', label: 'CVE ID' },
  { key: 'severity', label: 'Severity' },
  { key: 'cvss', label: 'CVSS Score' },
  { key: 'description', label: 'Description' },
  { key: 'fix_status', label: 'Fix Status' },
  { key: 'packages', label: 'Packages' },
  { key: 'resources', label: 'Resources' },
  { key: 'risk_factors', label: 'Risk Factors' },
  { key: 'os_labels', label: 'OS Labels' },
  { key: 'repos', label: 'Repositories' },
  { key: 'collections', label: 'Collections' },
];

document.addEventListener('DOMContentLoaded', async () => {
  buildColumnGrid();
  try {
    const r = await F()('/api/filters');
    filterData = await r.json();
    buildFilterChecks('os-checks', filterData.os || []);
    buildFilterChecks('rf-checks', filterData.risk_factors || []);
    buildFilterChecks('col-checks', filterData.collections || []);
    buildFilterChecks('rt-checks', (filterData.resource_types || []).map(rtLabel));
  } catch (_) {}

  const params = new URLSearchParams(window.location.search);
  const tplId = params.get('template');
  if (tplId) {
    try {
      const r = await F()('/api/templates/' + tplId);
      const tpl = await r.json();
      if (tpl && tpl.config) {
        wizardConfig = { ...wizardConfig, ...tpl.config };
        wizardConfig._templateId = tpl.id;
        const nameEl = document.getElementById('report-name');
        if (nameEl) nameEl.value = tpl.name || '';
        applyConfigToUI();
      }
    } catch (_) {}
  }
});

function applyConfigToUI() {
  const c = wizardConfig;
  if (c.data_source) pickSource(c.data_source);
  buildColumnGrid();
  const sortSel = document.getElementById('sort-by');
  if (sortSel && c.sort_by) sortSel.value = c.sort_by;
  const dirSel = document.getElementById('sort-dir');
  if (dirSel && c.sort_dir) dirSel.value = c.sort_dir;
  const limitEl = document.getElementById('row-limit');
  if (limitEl && c.limit) limitEl.value = c.limit;
  const f = c.filters || {};
  setFilterChecks('os-checks', f.os || []);
  setFilterChecks('rf-checks', f.risk_factors || []);
  setFilterChecks('col-checks', f.collections || []);
  setFilterChecks('rt-checks', (f.resource_types || []).map(rtLabel));
}

function setFilterChecks(containerId, values) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.querySelectorAll('input[type=checkbox]').forEach(cb => {
    cb.checked = values.includes(cb.value);
  });
}

function buildColumnGrid() {
  const grid = document.getElementById('col-checks-grid');
  grid.innerHTML = ALL_COLUMNS.map(c =>
    `<label class="col-option"><input type="checkbox" value="${c.key}" ${wizardConfig.columns.includes(c.key) ? 'checked' : ''}> ${c.label}</label>`
  ).join('');
}

function buildFilterChecks(containerId, values) {
  const el = document.getElementById(containerId);
  if (!values.length) { el.innerHTML = '<span class="text-muted text-xs">None available</span>'; return; }
  el.innerHTML = values.map(v => `<label><input type="checkbox" value="${esc(v)}"> ${esc(v)}</label>`).join('');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

const RT_LABEL_MAP = { host: 'Hosts', image: 'Container Images', registryImage: 'Registry Images' };
function rtLabel(rt) { return RT_LABEL_MAP[rt] || rt; }
function rtSlug(label) { for (const [k,v] of Object.entries(RT_LABEL_MAP)) { if (v === label) return k; } return label; }

function pickSource(src) {
  wizardConfig.data_source = src;
  document.getElementById('src-all').classList.toggle('selected', src === 'all');
  document.getElementById('src-kev').classList.toggle('selected', src === 'kev');
}

function goStep(n) {
  if (n < 1 || n > 5) return;
  if (n > currentStep + 1) return;

  if (n > currentStep) collectCurrentStep();
  if (n === 4) loadPreview();

  document.querySelectorAll('.step-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('step-' + n).classList.add('active');

  document.querySelectorAll('.wz-step').forEach(s => {
    const sn = Number(s.dataset.step);
    s.classList.remove('active', 'done');
    if (sn === n) s.classList.add('active');
    else if (sn < n) s.classList.add('done');
  });
  for (let i = 1; i <= 4; i++) {
    const line = document.getElementById('wz-line-' + i);
    if (line) line.classList.toggle('done', i < n);
  }
  currentStep = n;
}

function collectCurrentStep() {
  if (currentStep === 2) {
    wizardConfig.filters.severity = getChecked('sev-checks');
    wizardConfig.filters.os = getChecked('os-checks');
    wizardConfig.filters.risk_factor = getChecked('rf-checks');
    wizardConfig.filters.collection = getChecked('col-checks');
    wizardConfig.filters.resource_type = getChecked('rt-checks').map(rtSlug);
  }
  if (currentStep === 3) {
    wizardConfig.columns = [...document.querySelectorAll('#col-checks-grid input:checked')].map(i => i.value);
    if (!wizardConfig.columns.length) wizardConfig.columns = ['cve_id', 'severity', 'cvss'];
    wizardConfig.sort_by = document.getElementById('sort-by').value;
    wizardConfig.sort_dir = document.getElementById('sort-dir').value;
    wizardConfig.limit = Number(document.getElementById('row-limit').value) || 100;
  }
}

function getChecked(containerId) {
  return [...document.querySelectorAll('#' + containerId + ' input:checked')].map(i => i.value);
}

async function loadPreview() {
  collectCurrentStep();
  const head = document.getElementById('preview-head');
  const body = document.getElementById('preview-body');
  const count = document.getElementById('preview-count');
  head.innerHTML = wizardConfig.columns.map(c => `<th>${colLabel(c)}</th>`).join('');
  body.innerHTML = '<tr><td colspan="' + wizardConfig.columns.length + '" style="text-align:center;padding:24px;color:var(--muted)">Loading preview…</td></tr>';

  try {
    const previewCfg = { ...wizardConfig, limit: 25 };
    const r = await F()('/api/reports/preview?config=' + encodeURIComponent(JSON.stringify(previewCfg)));
    const rows = await r.json();
    count.textContent = rows.length + ' rows (preview)';
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="' + wizardConfig.columns.length + '" style="text-align:center;padding:24px;color:var(--muted)">No results match your filters</td></tr>';
      return;
    }
    let rowsHtml = '';
    const hasCols = wizardConfig.columns.includes('collections') && rows.some(r => r.collections && r.collections.length);
    if (hasCols) {
      const groups = {};
      for (const r of rows) {
        const cs = (r.collections && r.collections.length) ? r.collections : ['(Ungrouped)'];
        for (const c of cs) { if (!groups[c]) groups[c] = []; groups[c].push(r); }
      }
      const seen = new Set();
      for (const [grp, gRows] of Object.entries(groups).sort((a,b) => a[0].localeCompare(b[0]))) {
        rowsHtml += '<tr style="background:var(--surface-2)"><td colspan="' + wizardConfig.columns.length + '" style="padding:8px 10px 4px;border-bottom:2px solid var(--border)"><strong>' + esc(grp) + '</strong> <span style="color:var(--muted)">' + gRows.length + ' CVEs</span></td></tr>';
        for (const r of gRows) {
          if (seen.has(r.cve_id)) continue;
          seen.add(r.cve_id);
          rowsHtml += '<tr>' + wizardConfig.columns.map(c => renderCell(c, r)).join('') + '</tr>';
        }
      }
    } else {
      rowsHtml = rows.map(row => '<tr>' + wizardConfig.columns.map(c => renderCell(c, row)).join('') + '</tr>').join('');
    }
    body.innerHTML = rowsHtml;
  } catch (e) {
    body.innerHTML = '<tr><td colspan="' + wizardConfig.columns.length + '">Error: ' + esc(e.message) + '</td></tr>';
  }
}

function colLabel(key) {
  const m = { cve_id: 'CVE ID', severity: 'Severity', cvss: 'CVSS', description: 'Description', fix_status: 'Fix Status', packages: 'Packages', resources: 'Resources', risk_factors: 'Risk Factors', os_labels: 'OS', repos: 'Repos', collections: 'Collections' };
  return m[key] || key;
}

function renderCell(col, row) {
  const val = row[col];
  if (val == null) return '<td></td>';
  if (col === 'severity') return '<td><span class="badge badge-' + val + '">' + val + '</span></td>';
  if (col === 'cvss') return '<td class="mono">' + (val != null ? Number(val).toFixed(1) : '') + '</td>';
  if (col === 'is_kev') return '<td>' + (val ? '<span class="badge badge-critical">Yes</span>' : 'No') + '</td>';
  if (col === 'description') return '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(String(val).slice(0, 120)) + '</td>';
  if (col === 'packages' && typeof val === 'object') {
    const entries = Object.entries(val);
    if (!entries.length) return '<td style="color:var(--muted)">—</td>';
    return '<td style="font-size:11px">' + entries.map(([n,v]) => '<div><strong>' + esc(n) + '</strong>' + ((v||[]).length ? ' <span style="color:var(--muted)">' + v.map(esc).join(', ') + '</span>' : '') + '</div>').join('') + '</td>';
  }
  if (col === 'resources' && typeof val === 'object') {
    const types = Object.entries(val);
    if (!types.length) return '<td style="color:var(--muted)">—</td>';
    let html = '<td style="font-size:10px">';
    for (const [rtype, list] of types) {
      if (!list || !list.length) continue;
      const label = rtLabel(rtype);
      html += '<div style="margin-bottom:3px"><strong style="text-transform:uppercase;font-size:9px;color:var(--muted)">' + esc(label) + ' (' + list.length + ')</strong>';
      const byNs = {};
      for (const r of list) { const nsList = (r.namespaces && r.namespaces.length) ? r.namespaces : ['—']; for (const ns of nsList) { if (!byNs[ns]) byNs[ns]=[]; byNs[ns].push(r); } }
      for (const [ns, res] of Object.entries(byNs).sort((a,b)=>a[0].localeCompare(b[0]))) {
        html += '<div style="margin-left:6px;border-left:2px solid var(--border);padding-left:4px;margin-top:2px"><span style="font-size:9px;color:var(--sky-dark);font-weight:600">' + esc(ns) + '</span>';
        html += res.slice(0,5).map(r => '<div>' + esc(r.name) + (r.os ? ' <span style="color:var(--muted);font-size:9px">' + esc(r.os) + '</span>' : '') + '</div>').join('');
        if (res.length > 5) html += '<div style="color:var(--muted)">+' + (res.length-5) + ' more</div>';
        html += '</div>';
      }
      html += '</div>';
    }
    return html + '</td>';
  }
  if ((col === 'risk_factors' || col === 'collections' || col === 'repos' || col === 'os_labels') && Array.isArray(val)) {
    if (!val.length) return '<td style="color:var(--muted)">—</td>';
    return '<td>' + val.map(v => '<span class="badge badge-sky" style="margin:1px">' + esc(v) + '</span>').join(' ') + '</td>';
  }
  if (typeof val === 'object') return '<td>' + esc(Array.isArray(val) ? val.join(', ') : JSON.stringify(val)) + '</td>';
  return '<td>' + esc(String(val)) + '</td>';
}

async function generateNow() {
  collectCurrentStep();
  const name = document.getElementById('report-name').value || 'Untitled Report';
  const format = document.getElementById('report-format').value;
  const btn = document.getElementById('btn-generate');
  const overlay = document.getElementById('loading-overlay');

  btn.disabled = true;
  overlay.classList.remove('hidden');

  try {
    const r = await F()('/api/reports/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config: wizardConfig, title: name, format }),
    });
    const result = await r.json();
    overlay.classList.add('hidden');

    if (result.ok) {
      const el = document.getElementById('generate-result');
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = result.history_id
        ? '/api/reports/download/' + result.history_id + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '')
        : '/api/reports/file/' + encodeURIComponent(result.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      el.innerHTML = `<div class="badge badge-green lg" style="margin-bottom:8px">Report generated!</div><br>
        <a href="${dlUrl}" class="btn btn-secondary sm" download>Download ${result.format.toUpperCase()}</a>`;
    } else {
      alert('Generation failed: ' + (result.error || 'Unknown error'));
    }
  } catch (e) {
    overlay.classList.add('hidden');
    alert('Error: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function saveTemplate() {
  collectCurrentStep();
  const name = document.getElementById('report-name').value || 'Untitled Template';
  const existing = wizardConfig._templateId;
  const cleanConfig = { ...wizardConfig };
  delete cleanConfig._templateId;
  try {
    const url = existing ? '/api/templates/' + existing : '/api/templates';
    const method = existing ? 'PUT' : 'POST';
    const r = await F()(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, config: cleanConfig }),
    });
    const t = await r.json();
    if (t.id) {
      wizardConfig._templateId = t.id;
      const el = document.getElementById('generate-result');
      el.innerHTML = '<span class="badge badge-green lg">Template "' + esc(name) + '" ' + (existing ? 'updated' : 'saved') + '!</span>';
    } else {
      alert('Failed to save: ' + (t.error || 'Unknown'));
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}
