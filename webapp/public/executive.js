/* Executive Summary page */
let execData = null;
let selectedScanA = null;
let selectedScanB = null;

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

const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

document.addEventListener('DOMContentLoaded', async () => {
  await loadScanList();
  loadExecutive();
});

async function loadScanList() {
  const f = F();
  try {
    const res = await f('/api/diff/scans');
    const data = await res.json();
    const snaps = data.snapshots || [];
    const selA = document.getElementById('exec-scan-a');
    const selB = document.getElementById('exec-scan-b');
    if (!selA || !selB || !snaps.length) return;
    selA.innerHTML = '';
    selB.innerHTML = '';
    for (const s of snaps) {
      const label = s.run_date + ' (Scan #' + s.scan_id + ' — ' + Number(s.total_cves || 0).toLocaleString() + ' CVEs)';
      selA.innerHTML += '<option value="' + s.scan_id + '">' + esc(label) + '</option>';
      selB.innerHTML += '<option value="' + s.scan_id + '">' + esc(label) + '</option>';
    }
    if (snaps.length >= 2) {
      selB.value = String(snaps[0].scan_id);
      selA.value = String(snaps[1].scan_id);
    } else if (snaps.length === 1) {
      selA.value = String(snaps[0].scan_id);
      selB.value = String(snaps[0].scan_id);
    }
    selectedScanB = snaps[0] ? snaps[0].scan_id : null;
    selectedScanA = snaps[1] ? snaps[1].scan_id : (snaps[0] ? snaps[0].scan_id : null);
  } catch (_) {}
}

function applyScans() {
  const selA = document.getElementById('exec-scan-a');
  const selB = document.getElementById('exec-scan-b');
  selectedScanA = selA ? Number(selA.value) : null;
  selectedScanB = selB ? Number(selB.value) : null;
  loadExecutive();
}

async function loadExecutive() {
  document.getElementById('loading').style.display = 'block';
  document.getElementById('exec-body').style.display = 'none';
  const f = F();
  try {
    const params = new URLSearchParams();
    if (selectedScanA) params.set('scan_a', selectedScanA);
    if (selectedScanB) params.set('scan_b', selectedScanB);
    const qs = params.toString();
    const res = await f('/api/executive' + (qs ? '?' + qs : ''));
    execData = await res.json();
    render();
  } catch (err) {
    document.getElementById('loading').innerHTML = '<div style="color:var(--red)">Error: ' + esc(err.message) + '</div>';
  }
}

function render() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('exec-body').style.display = 'block';
  const { current, previous, snapshots, diff, narrative, tenant } = execData;
  if (!current) {
    document.getElementById('exec-body').innerHTML = '<div style="text-align:center;padding:var(--space-6);color:var(--muted)">No scan data available. Run a data fetch first.</div>';
    return;
  }

  document.getElementById('exec-meta').textContent = (tenant || 'Default') + ' — Scan date: ' + current.run_date + (previous ? ' | Compared to: ' + previous.run_date : '');

  renderKpi(current, previous);
  renderDeltaTable(current, previous);
  renderSevBar(current);
  renderSevTrend(current, previous);
  renderNarrative(narrative);
}

function renderKpi(cur, prev) {
  const kpi = document.getElementById('kpi-row');
  kpi.innerHTML = [
    kpiCard('Total CVEs', cur.total_cves, prev ? prev.total_cves : null),
    kpiCard('Critical', cur.critical_count, prev ? prev.critical_count : null),
    kpiCard('KEV', cur.total_kev, prev ? prev.total_kev : null),
    kpiCard('Resources', cur.total_resources, prev ? prev.total_resources : null),
    kpiCard('Fixed Available', cur.total_fixed, prev ? prev.total_fixed : null),
  ].join('');
}

function kpiCard(label, current, previous) {
  let deltaHtml = '';
  if (previous != null) {
    const d = current - previous;
    const pct = previous ? ((d / previous) * 100).toFixed(1) : '0';
    const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'delta-flat';
    const arrow = d > 0 ? '▲' : d < 0 ? '▼' : '—';
    const sign = d > 0 ? '+' : '';
    deltaHtml = '<div class="kpi-delta ' + cls + '">' + arrow + ' ' + sign + num(d) + ' (' + (d > 0 ? '+' : '') + pct + '%)</div>';
  }
  return '<div class="kpi-card"><div class="kpi-label">' + esc(label) + '</div><div class="kpi-value">' + num(current) + '</div>' + deltaHtml + '</div>';
}

function renderDeltaTable(cur, prev) {
  const wrap = document.getElementById('delta-table-wrap');
  const metrics = [
    { label: 'Total CVEs', key: 'total_cves' },
    { label: 'Critical', key: 'critical_count' },
    { label: 'High', key: 'high_count' },
    { label: 'Medium', key: 'medium_count' },
    { label: 'Low', key: 'low_count' },
    { label: 'Known Exploited (KEV)', key: 'total_kev' },
    { label: 'Total Packages', key: 'total_packages' },
    { label: 'Total Resources', key: 'total_resources' },
    { label: 'Fixes Available', key: 'total_fixed' },
    { label: 'Avg CVSS', key: 'avg_cvss', dec: 1 },
    { label: 'Max CVSS', key: 'max_cvss', dec: 1 },
  ];
  let html = '<table class="delta-table"><thead><tr><th>Metric</th><th>Current</th>';
  if (prev) html += '<th>Previous</th><th>Change</th>';
  html += '</tr></thead><tbody>';
  for (const m of metrics) {
    let cVal = cur[m.key] || 0;
    let pVal = prev ? (prev[m.key] || 0) : null;
    if (m.round) { cVal = Math.round(cVal); if (pVal != null) pVal = Math.round(pVal); }
    const fmt = m.dec != null ? (v => Number(v).toFixed(m.dec)) : num;
    html += '<tr><td>' + esc(m.label) + '</td><td class="mono">' + fmt(cVal) + '</td>';
    if (prev) {
      const d = cVal - pVal;
      const pct = pVal ? ((d / pVal) * 100).toFixed(1) : '0';
      const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'delta-flat';
      html += '<td class="mono">' + fmt(pVal) + '</td>';
      html += '<td class="' + cls + '">' + (d > 0 ? '+' : '') + fmt(d) + ' (' + (d > 0 ? '+' : '') + pct + '%)</td>';
    }
    html += '</tr>';
  }
  wrap.innerHTML = html + '</tbody></table>';
}

/* SVG Charts */

function renderSevBar(cur) {
  const el = document.getElementById('sev-bar-chart');
  const sevs = ['critical', 'high', 'medium', 'low'];
  const vals = sevs.map(s => cur[s + '_count'] || 0);
  el.innerHTML = barChart(sevs, vals, sevs.map(s => SEV_COLORS[s]));
}

function renderSevTrend(cur, prev) {
  const el = document.getElementById('sev-trend-chart');
  if (!prev) {
    el.innerHTML = '<div style="text-align:center;color:var(--muted);padding:var(--space-4)">Need a previous scan for comparison</div>';
    return;
  }
  el.innerHTML = groupedBarChart(
    ['Critical', 'High', 'Medium', 'Low'],
    ['critical', 'high', 'medium', 'low'].map(s => prev[s + '_count'] || 0),
    ['critical', 'high', 'medium', 'low'].map(s => cur[s + '_count'] || 0),
    'Previous', 'Current'
  );
}

function barChart(labels, values, colors) {
  const W = 340, H = 220, padL = 50, padR = 10, padT = 10, padB = 40;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const maxV = Math.max(...values, 1);
  const barW = plotW / labels.length * 0.6;
  const gap = plotW / labels.length;

  let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px">';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (i / 4) * plotH;
    const val = maxV - (i / 4) * maxV;
    svg += '<line x1="' + padL + '" y1="' + y + '" x2="' + (W - padR) + '" y2="' + y + '" stroke="var(--border)" stroke-dasharray="3,3"/>';
    svg += '<text x="' + (padL - 6) + '" y="' + (y + 3) + '" text-anchor="end" fill="var(--muted)" font-size="9">' + Math.round(val).toLocaleString() + '</text>';
  }
  for (let i = 0; i < labels.length; i++) {
    const x = padL + gap * i + gap / 2;
    const h = (values[i] / maxV) * plotH;
    const y = padT + plotH - h;
    svg += '<rect x="' + (x - barW / 2) + '" y="' + y + '" width="' + barW + '" height="' + h + '" fill="' + colors[i] + '" rx="3"/>';
    svg += '<text x="' + x + '" y="' + (y - 5) + '" text-anchor="middle" fill="var(--text)" font-size="10" font-weight="700">' + num(values[i]) + '</text>';
    svg += '<text x="' + x + '" y="' + (H - 10) + '" text-anchor="middle" fill="var(--muted)" font-size="10">' + labels[i] + '</text>';
  }
  svg += '</svg>';
  return svg;
}

function groupedBarChart(labels, valsA, valsB, labelA, labelB) {
  const W = 340, H = 240, padL = 50, padR = 10, padT = 10, padB = 60;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const maxV = Math.max(...valsA, ...valsB, 1);
  const group = plotW / labels.length;
  const barW = group * 0.3;

  let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px">';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (i / 4) * plotH;
    const val = maxV - (i / 4) * maxV;
    svg += '<line x1="' + padL + '" y1="' + y + '" x2="' + (W - padR) + '" y2="' + y + '" stroke="var(--border)" stroke-dasharray="3,3"/>';
    svg += '<text x="' + (padL - 6) + '" y="' + (y + 3) + '" text-anchor="end" fill="var(--muted)" font-size="9">' + Math.round(val).toLocaleString() + '</text>';
  }
  for (let i = 0; i < labels.length; i++) {
    const cx = padL + group * i + group / 2;
    const hA = (valsA[i] / maxV) * plotH;
    const hB = (valsB[i] / maxV) * plotH;
    const yA = padT + plotH - hA;
    const yB = padT + plotH - hB;
    svg += '<rect x="' + (cx - barW - 1) + '" y="' + yA + '" width="' + barW + '" height="' + hA + '" fill="var(--muted)" rx="2" opacity="0.5"/>';
    svg += '<rect x="' + (cx + 1) + '" y="' + yB + '" width="' + barW + '" height="' + hB + '" fill="' + SEV_COLORS[labels[i].toLowerCase()] + '" rx="2"/>';
    svg += '<text x="' + cx + '" y="' + (H - 30) + '" text-anchor="middle" fill="var(--muted)" font-size="10">' + labels[i] + '</text>';
  }
  svg += '<rect x="' + padL + '" y="' + (H - 18) + '" width="12" height="10" fill="var(--muted)" opacity="0.5" rx="2"/>';
  svg += '<text x="' + (padL + 16) + '" y="' + (H - 10) + '" fill="var(--muted)" font-size="9">' + labelA + '</text>';
  svg += '<rect x="' + (padL + 80) + '" y="' + (H - 18) + '" width="12" height="10" fill="var(--sky)" rx="2"/>';
  svg += '<text x="' + (padL + 96) + '" y="' + (H - 10) + '" fill="var(--muted)" font-size="9">' + labelB + '</text>';
  svg += '</svg>';
  return svg;
}

function renderNarrative(paragraphs) {
  const el = document.getElementById('narrative');
  if (!paragraphs || !paragraphs.length) {
    el.innerHTML = '<p style="color:var(--muted)">No analysis available.</p>';
    return;
  }
  el.innerHTML = paragraphs.map(p => '<p>' + esc(p) + '</p>').join('');
}

/* Export */
async function doExport(format) {
  if (!execData || !execData.current) return;
  const f = F();
  try {
    const payload = { format };
    if (selectedScanA) payload.scan_a = selectedScanA;
    if (selectedScanB) payload.scan_b = selectedScanB;
    const res = await f('/api/executive/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a'); a.href = dlUrl; a.download = data.file; document.body.appendChild(a); a.click(); a.remove();
    }
  } catch (_) {}
}

if (window.TenantCtx) {
  const origSet = TenantCtx.setTenant;
  if (origSet) {
    TenantCtx.setTenant = function(slug) {
      origSet.call(TenantCtx, slug);
      loadScanList().then(() => loadExecutive());
    };
  }
}
