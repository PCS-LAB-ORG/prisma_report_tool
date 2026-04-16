/* Diff page logic */
let diffData = null;
let loadingCount = 0;

/* ── Loading overlay ─────────────────────────── */

const loadingOverlay = (() => {
  const el = document.createElement('div');
  el.id = 'loading-overlay';
  el.innerHTML = '<div class="ld-spin"></div><div class="ld-text">Loading…</div>';
  Object.assign(el.style, {
    position: 'fixed', inset: '0', zIndex: '9999',
    display: 'none', alignItems: 'center', justifyContent: 'center', flexDirection: 'column',
    background: 'rgba(0,0,0,.45)', backdropFilter: 'blur(4px)',
  });
  const sheet = document.createElement('style');
  sheet.textContent = '.ld-spin{width:40px;height:40px;border:4px solid rgba(255,255,255,.25);border-top-color:#0ea5e9;border-radius:50%;animation:ldspin .7s linear infinite}.ld-text{margin-top:12px;color:#fff;font-size:14px;font-weight:600;letter-spacing:.3px}@keyframes ldspin{to{transform:rotate(360deg)}}';
  document.head.appendChild(sheet);
  document.body.appendChild(el);
  return el;
})();

function showLoading(msg) {
  loadingCount++;
  loadingOverlay.querySelector('.ld-text').textContent = msg || 'Loading…';
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

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

document.addEventListener('DOMContentLoaded', async () => {
  showLoading('Loading scans…');
  try { await loadScans(); } finally { hideLoading(); }
});

async function loadScans() {
  const f = F();
  try {
    const res = await f('/api/diff/scans');
    const data = await res.json();
    const snaps = data.snapshots || [];
    const selA = document.getElementById('scan-a');
    const selB = document.getElementById('scan-b');
    selA.innerHTML = '';
    selB.innerHTML = '';
    for (const s of snaps) {
      const label = 'Scan #' + s.scan_id + ' \u2014 ' + s.run_date + ' (' + num(s.total_cves) + ' CVEs)';
      selA.innerHTML += '<option value="' + s.scan_id + '">' + esc(label) + '</option>';
      selB.innerHTML += '<option value="' + s.scan_id + '">' + esc(label) + '</option>';
    }
    if (snaps.length >= 2) {
      selA.value = snaps[1].scan_id;
      selB.value = snaps[0].scan_id;
    }
  } catch (_) {}
}

async function runDiff() {
  const scanA = document.getElementById('scan-a').value;
  const scanB = document.getElementById('scan-b').value;
  if (!scanA || !scanB || scanA === scanB) return;

  document.getElementById('empty-state').style.display = 'none';
  document.getElementById('diff-content').style.display = 'none';
  document.getElementById('kpi-row').style.display = 'none';
  showLoading('Comparing scans…');

  const f = F();
  try {
    const res = await f('/api/diff?scan_a=' + scanA + '&scan_b=' + scanB);
    diffData = await res.json();
    if (diffData.error) {
      document.getElementById('kpi-row').style.display = 'grid';
      document.getElementById('kpi-row').innerHTML = '<div style="text-align:center;grid-column:1/-1;padding:var(--space-4);color:var(--red)">' + esc(diffData.error) + '</div>';
      return;
    }
    renderKpi();
    renderTables();
    document.getElementById('diff-content').style.display = 'block';
  } catch (err) {
    document.getElementById('kpi-row').style.display = 'grid';
    document.getElementById('kpi-row').innerHTML = '<div style="text-align:center;grid-column:1/-1;padding:var(--space-4);color:var(--red)">Error: ' + esc(err.message) + '</div>';
  } finally {
    hideLoading();
  }
}

function renderKpi() {
  const d = diffData;
  const net = d.new_cves_count - d.removed_cves_count;
  const resRem = d.resources_remediated || 0;
  const kpi = document.getElementById('kpi-row');
  kpi.innerHTML = [
    kpiCard(d.new_cves_count, 'New CVEs', 'kpi-up'),
    kpiCard(d.removed_cves_count, 'Resolved', 'kpi-down'),
    kpiCard(d.changed_cves_count, 'Changed', 'kpi-neutral'),
    kpiCard((net > 0 ? '+' : '') + num(net), 'Net Change', net > 0 ? 'kpi-up' : net < 0 ? 'kpi-down' : 'kpi-neutral'),
    kpiCard(resRem, 'Resources Remediated', 'kpi-down'),
  ].join('');
  kpi.style.display = 'grid';
}

function kpiCard(value, label, cls) {
  return '<div class="kpi-card"><div class="kpi-value ' + cls + '">' + (typeof value === 'number' ? num(value) : value) + '</div><div class="kpi-label">' + esc(label) + '</div></div>';
}

function renderTables() {
  const detail = diffData.diff_detail || { new: [], removed: [], changed: [] };

  const newSorted = (detail.new || []).sort((a, b) => (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4) || (b.cvss || 0) - (a.cvss || 0));
  const remSorted = (detail.removed || []).sort((a, b) => (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4) || (b.cvss || 0) - (a.cvss || 0));
  const chgSorted = (detail.changed || []).sort((a, b) => (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4) || (b.cvss || 0) - (a.cvss || 0));

  document.getElementById('new-badge').textContent = newSorted.length;
  document.getElementById('resolved-badge').textContent = remSorted.length;
  document.getElementById('changed-badge').textContent = chgSorted.length;

  document.getElementById('new-table-wrap').innerHTML = newSorted.length ? cveTable(newSorted) : '<div class="empty-msg">No new vulnerabilities</div>';
  document.getElementById('resolved-table-wrap').innerHTML = remSorted.length ? cveTable(remSorted) : '<div class="empty-msg">No resolved vulnerabilities</div>';
  document.getElementById('changed-table-wrap').innerHTML = chgSorted.length ? changedTable(chgSorted) : '<div class="empty-msg">No changed vulnerabilities</div>';
}

function cveTable(rows) {
  let html = '<table class="diff-table"><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Fix Status</th><th>KEV</th><th>Resources</th><th>Packages</th></tr></thead><tbody>';
  for (const r of rows) {
    html += '<tr>';
    html += '<td class="mono">' + esc(r.cve_id) + '</td>';
    html += '<td><span class="badge badge-' + r.severity + '">' + esc(r.severity) + '</span></td>';
    html += '<td class="mono">' + (r.cvss != null ? Number(r.cvss).toFixed(1) : '\u2014') + '</td>';
    html += '<td>' + esc(r.fix_status || '\u2014') + '</td>';
    html += '<td>' + (r.is_kev ? '<span class="badge badge-critical">Yes</span>' : '<span style="color:var(--muted)">No</span>') + '</td>';
    html += '<td class="mono" style="font-weight:700">' + num(r.resource_count || 0) + '</td>';
    const pkgs = r.packages || [];
    html += '<td>' + (pkgs.length ? '<ul class="pkg-list">' + pkgs.slice(0, 5).map(p => '<li><span class="pkg-name">' + esc(p) + '</span></li>').join('') + (pkgs.length > 5 ? '<li style="color:var(--muted)">+' + (pkgs.length - 5) + ' more</li>' : '') + '</ul>' : '<span style="color:var(--muted)">\u2014</span>') + '</td>';
    html += '</tr>';
  }
  return html + '</tbody></table>';
}

function changedTable(rows) {
  let html = '<table class="diff-table"><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Resources</th><th>Field</th><th>Old Value</th><th>New Value</th></tr></thead><tbody>';
  for (const r of rows) {
    const changes = r.changes || [];
    for (let i = 0; i < changes.length; i++) {
      const c = changes[i];
      html += '<tr>';
      if (i === 0) {
        html += '<td class="mono"' + (changes.length > 1 ? ' rowspan="' + changes.length + '"' : '') + '>' + esc(r.cve_id) + '</td>';
        html += '<td' + (changes.length > 1 ? ' rowspan="' + changes.length + '"' : '') + '><span class="badge badge-' + r.severity + '">' + esc(r.severity) + '</span></td>';
        html += '<td class="mono"' + (changes.length > 1 ? ' rowspan="' + changes.length + '"' : '') + '>' + (r.cvss != null ? Number(r.cvss).toFixed(1) : '\u2014') + '</td>';
        html += '<td class="mono" style="font-weight:700"' + (changes.length > 1 ? ' rowspan="' + changes.length + '"' : '') + '>' + num(r.resource_count || 0) + '</td>';
      }
      html += '<td>' + esc(c.field) + '</td>';
      html += '<td><span class="change-old">' + fmtChangeVal(c.field, c.old) + '</span></td>';
      html += '<td><span class="change-new">' + fmtChangeVal(c.field, c.new) + '</span></td>';
      html += '</tr>';
    }
  }
  return html + '</tbody></table>';
}

function fmtChangeVal(field, val) {
  if (val == null) return '\u2014';
  if (field === 'severity') return '<span class="badge badge-' + val + '">' + esc(String(val)) + '</span>';
  if (field === 'is_kev') return val ? 'Yes' : 'No';
  if (field === 'cvss') return Number(val).toFixed(1);
  return esc(String(val));
}

/* ── Export ─────────────────────────────────── */

function toggleExportMenu() {
  const menu = document.getElementById('export-menu');
  menu.classList.toggle('open');
  const handler = (e) => {
    if (!e.target.closest('.export-wrap')) { menu.classList.remove('open'); document.removeEventListener('click', handler); }
  };
  if (menu.classList.contains('open')) setTimeout(() => document.addEventListener('click', handler), 0);
}

async function doExport(format) {
  document.getElementById('export-menu').classList.remove('open');
  if (!diffData || !diffData.diff_detail) { alert('Run a comparison first.'); return; }
  const scanA = document.getElementById('scan-a').value;
  const scanB = document.getElementById('scan-b').value;

  showLoading('Generating ' + format.toUpperCase() + ' export…');
  const f = F();
  try {
    const res = await f('/api/diff/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format, scan_a: scanA, scan_b: scanB }),
    });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a');
      a.href = dlUrl; a.download = data.file;
      document.body.appendChild(a); a.click(); a.remove();
    } else {
      alert('Export failed: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Export error: ' + err.message);
  } finally {
    hideLoading();
  }
}

/* ── Tenant switch ─────────────────────────── */

if (window.TenantCtx) {
  const origSet = TenantCtx.setTenant;
  if (origSet) {
    TenantCtx.setTenant = function(slug) {
      origSet.call(TenantCtx, slug);
      diffData = null;
      document.getElementById('diff-content').style.display = 'none';
      document.getElementById('kpi-row').style.display = 'none';
      document.getElementById('empty-state').style.display = 'block';
      loadScans();
    };
  }
}
