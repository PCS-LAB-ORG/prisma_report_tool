let summaryData = {};
const SEV_ORDER = ['critical','high','medium','low'];
const SEV_META = {
  critical: { color: 'var(--sev-critical)', bg: 'var(--sev-critical-light)', cls: 'critical' },
  high:     { color: 'var(--sev-high)', bg: 'var(--sev-high-light)', cls: 'high' },
  medium:   { color: 'var(--sev-medium)', bg: 'var(--sev-medium-light)', cls: 'medium' },
  low:      { color: 'var(--sev-low)', bg: 'var(--sev-low-light)', cls: 'low' },
};
const RT_LABELS = { host:'Hosts', image:'Container Images', registryImage:'Registry Images' };
const RT_ICONS = {
  host:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>',
  image:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 002 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0022 16z"/></svg>',
  registryImage:'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7"/><ellipse cx="12" cy="7" rx="8" ry="4"/></svg>',
};
function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
function num(n) { return Number(n || 0).toLocaleString(); }

function showLoading(msg, sub) {
  const o = document.getElementById('loading-overlay');
  document.getElementById('loading-text').textContent = msg || 'Loading\u2026';
  const se = document.getElementById('loading-sub');
  if (se) se.textContent = sub || '';
  else if (sub) { const s = document.createElement('div'); s.className='loading-sub'; s.id='loading-sub'; s.textContent=sub; document.getElementById('loading-text').after(s); }
  o.classList.remove('hidden', 'fade-out');
}
function hideLoading() {
  const o = document.getElementById('loading-overlay');
  o.classList.add('fade-out');
  setTimeout(() => o.classList.add('hidden'), 400);
}

document.addEventListener('DOMContentLoaded', init);
async function init() {
  showLoading('Connecting to data source\u2026');
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    showLoading('Loading summary & filters\u2026');
    const [summary, filters] = await Promise.all([apiFetch('/api/summary').then(r=>r.json()), apiFetch('/api/filters').then(r=>r.json())]);
    summaryData = summary;
    document.getElementById('header-subtitle').textContent = 'Images \u00b7 Registry \u00b7 Hosts \u2014 ' + num(summary.total) + ' CVEs \u00b7 ' + num(summary.kev) + ' KEV';
    populateSelect('os-filter', filters.os, 'All Operating Systems');
    populateSelect('rf-filter', filters.risk_factors, 'All Risk Factors');
    populateSelect('col-filter', filters.collections, 'All Collections');
    populateSelect('repo-filter', filters.repos, 'All Repositories');
    showLoading('Loading templates\u2026');
    await loadTemplates();
  } finally { hideLoading(); }
}
function populateSelect(id, values, allLabel) { const s = document.getElementById(id); if(!s) return; s.innerHTML = '<option value="" selected>' + esc(allLabel) + '</option>' + values.map(v => '<option value="' + esc(v) + '">' + esc(v) + '</option>').join(''); }

function showTiles() {
  document.getElementById('view-tiles').style.display = '';
  document.getElementById('view-top10').style.display = 'none';
  document.getElementById('view-kev').style.display = 'none';
  window.scrollTo(0, 0);
}
function showTop10View() {
  document.getElementById('view-tiles').style.display = 'none';
  document.getElementById('view-top10').style.display = '';
  document.getElementById('view-kev').style.display = 'none';
  document.getElementById('top10-subtitle').textContent = summaryData.total ? num(summaryData.total) + ' CVEs across all resources' : '';
  window.scrollTo(0, 0);
  loadTop10();
}
function showKevView() {
  document.getElementById('view-tiles').style.display = 'none';
  document.getElementById('view-top10').style.display = 'none';
  document.getElementById('view-kev').style.display = '';
  document.getElementById('kev-subtitle').textContent = summaryData.kev ? num(summaryData.kev) + ' Known Exploited Vulnerabilities' : '';
  window.scrollTo(0, 0);
  loadKev();
}

async function loadTop10() {
  showLoading('Loading Top 10 report\u2026');
  try {
    const os = document.getElementById('os-filter').value;
    const rf = document.getElementById('rf-filter').value;
    const params = new URLSearchParams(); if(os) params.set('os',os); if(rf) params.set('rf',rf);
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const data = await apiFetch('/api/top10?' + params).then(r => r.json());
    renderTop10Summary(data); renderTop10Sections(data);
  } finally { hideLoading(); }
}
function renderTop10Summary(data) {
  let total = 0; const counts = {};
  for (const s of SEV_ORDER) { counts[s] = data[s] ? data[s].total : 0; total += counts[s]; }
  let html = '<div class="kpi-card sky"><div class="kpi-label">Total CVEs</div><div class="kpi-number">' + num(total) + '</div><div class="kpi-delta delta-neu">' + num(summaryData.packages) + ' packages</div></div>';
  for (const s of SEV_ORDER) {
    const m = SEV_META[s]; const pct = total > 0 ? (counts[s]/total*100).toFixed(1) : '0.0';
    html += '<div class="kpi-card ' + m.cls + '"><div class="kpi-label">' + s.charAt(0).toUpperCase()+s.slice(1) + '</div><div class="kpi-number">' + num(counts[s]) + '</div><div class="kpi-delta delta-neu">' + pct + '% of total</div></div>';
  }
  document.getElementById('top10-summary').innerHTML = html;
}
function renderTop10Sections(data) {
  let html = '', globalMax = 1;
  for (const s of SEV_ORDER) { const entries = data[s]?data[s].entries:[]; for (const e of entries) globalMax = Math.max(globalMax, Object.keys(e.packages).length); }
  for (const s of SEV_ORDER) { const d = data[s]||{total:0,entries:[]}; html += buildSeveritySection(s, d.entries, d.total, globalMax); }
  document.getElementById('top10-sections').innerHTML = html;
}
function buildSeveritySection(sev, entries, total, globalMax) {
  const m = SEV_META[sev]; let rows = '';
  entries.forEach((e,i) => { rows += buildTop10Row(e, sev, i+1, globalMax, m); });
  return '<section class="severity-section" id="' + sev + '"><div class="section-header" onclick="toggleSection(\'' + sev + '\')"><div class="sev-indicator" style="background:' + m.color + '"></div><span class="sev-label">' + sev.charAt(0).toUpperCase()+sev.slice(1) + '</span><span class="badge badge-' + m.cls + ' lg">Top ' + entries.length + ' of ' + num(total) + '</span><span class="chevron" id="chevron-' + sev + '"><svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></span></div><div class="section-body" id="body-' + sev + '"><div class="table-wrap"><table class="s-table"><thead><tr><th class="rank-col">#</th><th>CVE</th><th class="rt-col">Resources</th><th>Packages</th><th class="right">CVSS</th><th class="right">Fix Status</th><th class="expand-col"></th></tr></thead><tbody>' + rows + '</tbody></table></div></div></section>';
}
function buildTop10Row(e, sev, rank, globalMax, meta) {
  const rid = sev+'-'+rank, nPkgs = Object.keys(e.packages).length, nRes = Object.values(e.resources).reduce((a,r)=>a+r.length,0);
  const cvss = e.cvss?e.cvss.toFixed(1):'', barPct = globalMax?(nPkgs/globalMax*100).toFixed(1):0;
  const desc = (e.description||'').slice(0,180), rtIcons = buildRtIcons(e.resources);
  return '<tr class="data-row" onclick="togglePkgs(\'' + rid + '\')"><td class="rank-cell">' + rank + '</td><td class="cve-cell"><a href="' + esc(e.link) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">' + esc(e.cve_id) + '</a><div class="cve-desc">' + esc(desc) + ((e.description||'').length>180?'\u2026':'') + '</div></td><td class="rt-cell">' + rtIcons + '<span class="rt-count">' + nRes + '</span></td><td class="bar-cell"><div class="bar-wrap"><div class="bar-fill" style="width:' + barPct + '%;background:' + meta.color + '"></div><span class="bar-label">' + nPkgs + '</span></div></td><td class="right cvss-cell">' + cvss + '</td><td class="right">' + esc(e.fix_status||'') + '</td><td class="expand-cell"><span class="expand-icon" id="exp-' + rid + '"><svg width="14" height="14" viewBox="0 0 14 14"><path d="M5.25 3.5L8.75 7L5.25 10.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></span></td></tr><tr class="pkg-row hidden" id="pkgs-' + rid + '"><td colspan="7"><div class="pkg-detail" style="border-left-color:' + meta.color + '"><div class="pkg-header"><span class="pkg-title">Packages (' + nPkgs + ')</span></div><div class="pkg-list">' + buildPkgPills(e.packages) + '</div>' + buildRfTags(e.risk_factors) + '<div class="resource-section"><div class="rs-label">Affected Resources (' + nRes + ')</div>' + buildResourceDetail(e.resources) + '</div></div></td></tr>';
}

async function loadKev() {
  showLoading('Loading KEV report\u2026');
  try {
    const col = document.getElementById('col-filter').value;
    const repo = document.getElementById('repo-filter').value;
    const params = new URLSearchParams(); if(col) params.set('collection',col); if(repo) params.set('repo',repo);
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const data = await apiFetch('/api/kev?' + params).then(r => r.json());
    renderKevSummary(data); renderKevTable(data);
  } finally { hideLoading(); }
}
function renderKevSummary(entries) {
  const counts = {critical:0,high:0,medium:0,low:0}; const total = entries.length;
  for (const e of entries) { if(counts.hasOwnProperty(e.severity)) counts[e.severity]++; }
  let html = '<div class="kpi-card red"><div class="kpi-label">KEV CVEs</div><div class="kpi-number">' + num(total) + '</div><div class="kpi-delta delta-neu">Known Exploited</div></div>';
  for (const s of SEV_ORDER) { const m = SEV_META[s]; const pct = total>0?(counts[s]/total*100).toFixed(1):'0.0'; html += '<div class="kpi-card ' + m.cls + '"><div class="kpi-label">' + s.charAt(0).toUpperCase()+s.slice(1) + '</div><div class="kpi-number">' + num(counts[s]) + '</div><div class="kpi-delta delta-neu">' + pct + '% of KEV</div></div>'; }
  document.getElementById('kev-summary').innerHTML = html;
}
function renderKevTable(entries) {
  let rows = ''; entries.forEach((e,i) => { rows += buildKevRow(e, i+1); });
  document.getElementById('kev-sections').innerHTML = '<section class="severity-section"><div class="section-header" onclick="toggleSection(\'kev-body\')"><div class="sev-indicator" style="background:var(--crimson)"></div><span class="sev-label">Known Exploited Vulnerabilities</span><span class="badge badge-red lg">' + num(entries.length) + ' CVEs</span><span class="chevron" id="chevron-kev-body"><svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></span></div><div class="section-body" id="body-kev-body"><div class="table-wrap"><table class="s-table"><thead><tr><th class="rank-col">#</th><th>CVE</th><th>Severity</th><th class="rt-col">Resources</th><th class="right">Packages</th><th class="right">CVSS</th><th class="right">Fix Status</th><th class="expand-col"></th></tr></thead><tbody>' + rows + '</tbody></table></div></div></section>';
}
function buildKevRow(e, rank) {
  const rid = 'kev-'+rank, m = SEV_META[e.severity]||SEV_META.medium;
  const nPkgs = Object.keys(e.packages).length, nRes = Object.values(e.resources).reduce((a,r)=>a+r.length,0);
  const cvss = e.cvss?e.cvss.toFixed(1):'', desc = (e.description||'').slice(0,180);
  const rtIcons = buildRtIcons(e.resources);
  const repoTags = (e.repos||[]).length ? '<div class="repo-row">' + (e.repos||[]).map(r=>'<span class="repo-tag">'+esc(r)+'</span>').join(' ') + '</div>' : '';
  return '<tr class="data-row" onclick="togglePkgs(\'' + rid + '\')"><td class="rank-cell">' + rank + '</td><td class="cve-cell"><a href="' + esc(e.link) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">' + esc(e.cve_id) + '</a><div class="cve-desc">' + esc(desc) + ((e.description||'').length>180?'\u2026':'') + '</div></td><td class="sev-cell"><span class="badge badge-' + m.cls + '">' + e.severity.charAt(0).toUpperCase()+e.severity.slice(1) + '</span></td><td class="rt-cell">' + rtIcons + '<span class="rt-count">' + nRes + '</span></td><td class="right mono">' + nPkgs + '</td><td class="right cvss-cell">' + cvss + '</td><td class="right">' + esc(e.fix_status||'') + '</td><td class="expand-cell"><span class="expand-icon" id="exp-' + rid + '"><svg width="14" height="14" viewBox="0 0 14 14"><path d="M5.25 3.5L8.75 7L5.25 10.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg></span></td></tr><tr class="pkg-row hidden" id="pkgs-' + rid + '"><td colspan="8"><div class="pkg-detail" style="border-left-color:' + m.color + '"><div class="pkg-header"><span class="pkg-title">Packages (' + nPkgs + ')</span></div><div class="pkg-list">' + buildPkgPills(e.packages) + '</div>' + buildRfTags(e.risk_factors) + repoTags + '<div class="resource-section"><div class="rs-label">Affected Resources (' + nRes + ')</div>' + buildResourceDetail(e.resources) + '</div></div></td></tr>';
}

function buildPkgPills(packages) {
  return Object.keys(packages).sort().map(name => { const vers = (packages[name]||[]).sort(); if(vers.length===1&&vers[0]) return '<span class="pkg-pill"><span class="pkg-name">'+esc(name)+'</span><span class="pkg-ver">'+esc(vers[0])+'</span></span>'; if(vers.length>1) return '<span class="pkg-pill"><span class="pkg-name">'+esc(name)+'</span><span class="pkg-ver">'+vers.length+' ver</span></span>'; return '<span class="pkg-pill"><span class="pkg-name">'+esc(name)+'</span></span>'; }).join(' ');
}
function buildRfTags(rfs) { if(!rfs||!rfs.length) return ''; return '<div class="rf-row">'+rfs.sort().map(r=>'<span class="rf-tag">'+esc(r)+'</span>').join(' ')+'</div>'; }
function buildRtIcons(resources) { return ['host','image','registryImage'].filter(t=>resources[t]&&resources[t].length).map(t=>'<span class="rt-tiny" title="'+RT_LABELS[t]+'">'+RT_ICONS[t]+'</span>').join(' '); }
function buildResourceDetail(resources) {
  let parts = '';
  for (const rtype of ['host','image','registryImage']) {
    const list = resources[rtype]; if(!list||!list.length) continue;
    const label = RT_LABELS[rtype]||rtype, icon = RT_ICONS[rtype]||'';
    const byNs = {}, noNs = [];
    for (const r of list) { if(r.namespaces&&r.namespaces.length) { for(const ns of r.namespaces) { if(!byNs[ns]) byNs[ns]=[]; byNs[ns].push(r); } } else noNs.push(r); }
    let items = '';
    for (const ns of Object.keys(byNs).sort()) { const rl = byNs[ns].slice(0,20); items += '<div class="ns-group"><div class="ns-label">'+esc(ns)+'</div>'+rl.map(r=>'<div class="res-item"><span class="res-name">'+esc(r.name)+'</span><span class="res-os">'+esc(r.os||'')+'</span></div>').join(''); if(byNs[ns].length>20) items+='<div class="res-more">+'+(byNs[ns].length-20)+' more</div>'; items+='</div>'; }
    if (noNs.length) { const rl = noNs.slice(0,30); items += '<div class="ns-group"><div class="ns-label">No Namespace</div>'+rl.map(r=>'<div class="res-item"><span class="res-name">'+esc(r.name)+'</span><span class="res-os">'+esc(r.os||'')+'</span></div>').join(''); if(noNs.length>30) items+='<div class="res-more">+'+(noNs.length-30)+' more</div>'; items+='</div>'; }
    parts += '<div class="rt-block"><div class="rt-header"><span class="rt-icon">'+icon+'</span><span class="rt-label">'+label+'</span><span class="rt-badge">'+list.length+'</span></div><div class="rt-body">'+items+'</div></div>';
  }
  return parts;
}
function toggleSection(id) { document.getElementById('body-'+id).classList.toggle('hidden'); document.getElementById('chevron-'+id).classList.toggle('collapsed'); }
function togglePkgs(id) { document.getElementById('pkgs-'+id).classList.toggle('hidden'); document.getElementById('exp-'+id).classList.toggle('open'); }

/* ── Export dropdowns for Top 10 & KEV ────────── */
function closeAllExportMenus() { document.querySelectorAll('.export-menu').forEach(m => m.classList.remove('open')); }
function toggleTop10Export(e) { e.stopPropagation(); const m = document.getElementById('top10-export-menu'); const open = m.classList.contains('open'); closeAllExportMenus(); if (!open) m.classList.add('open'); }
function toggleKevExport(e) { e.stopPropagation(); const m = document.getElementById('kev-export-menu'); const open = m.classList.contains('open'); closeAllExportMenus(); if (!open) m.classList.add('open'); }
document.addEventListener('click', () => closeAllExportMenus());

async function exportTop10(format) {
  closeAllExportMenus();
  showLoading('Generating ' + format.toUpperCase() + ' export\u2026');
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const os = document.getElementById('os-filter').value;
    const rf = document.getElementById('rf-filter').value;
    const body = { format };
    if (os) body.os = os;
    if (rf) body.rf = rf;
    const res = await apiFetch('/api/top10/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a'); a.href = dlUrl; a.download = data.file; document.body.appendChild(a); a.click(); a.remove();
    }
  } catch (err) { console.error('Top10 export error:', err); }
  finally { hideLoading(); }
}

async function exportKev(format) {
  closeAllExportMenus();
  showLoading('Generating ' + format.toUpperCase() + ' export\u2026');
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const col = document.getElementById('col-filter').value;
    const repo = document.getElementById('repo-filter').value;
    const body = { format };
    if (col) body.collection = col;
    if (repo) body.repo = repo;
    const res = await apiFetch('/api/kev/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.ok && data.file) {
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a'); a.href = dlUrl; a.download = data.file; document.body.appendChild(a); a.click(); a.remove();
    }
  } catch (err) { console.error('KEV export error:', err); }
  finally { hideLoading(); }
}

/* ── Report Template Tiles ────────────────────── */

const TILE_ICONS = {
  doc: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 3v4a1 1 0 001 1h4"/><path d="M17 21H7a2 2 0 01-2-2V5a2 2 0 012-2h7l5 5v11a2 2 0 01-2 2z"/><path d="M9 9h1"/><path d="M9 13h6"/><path d="M9 17h6"/></svg>',
  chart: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 17V11"/><path d="M12 17V7"/><path d="M15 17v-4"/></svg>',
  shield: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  search: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>',
  diff: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16 3h5v5"/><path d="M8 21H3v-5"/><path d="M21 3l-9 9"/><path d="M3 21l9-9"/></svg>',
  globe: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 014 10 15 15 0 01-4 10 15 15 0 01-4-10A15 15 0 0112 2z"/></svg>',
  server: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>',
  check: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>',
  wrench: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>',
  layers: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>',
  alert: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
  users: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
};

const PENCIL_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';

const BUILT_IN_REPORTS = [
  { name: 'Agency Specific Report', badge: 'asset collections', icon: 'users', desc: 'Assets and vulnerabilities filtered by agency collection \u2014 group by collection name to isolate agency-owned machines', href: '/explorer.html' },
  { name: 'Audit Report', badge: 'images', icon: 'doc', desc: 'Comprehensive details about discovered assets, vulnerabilities, and users across all scanned images', href: '/explorer.html' },
  { name: 'Baseline Comparison', badge: 'images', icon: 'diff', desc: 'Compare current scan results against earlier baseline \u2014 view vulnerability counts and severity changes over time', href: '/diff.html' },
  { name: 'Compliance Report Card', badge: 'compliance results', icon: 'check', desc: 'Compliance test results per resource showing pass/fail status, severity, and type \u2014 filterable by framework', href: '/compliance.html' },
  { name: 'Custom Query Report', badge: 'vulnerabilities', icon: 'search', desc: 'Flexible report built from custom query filters \u2014 select any data source, columns, and filter criteria to compile a CSV', href: '/wizard.html' },
  { name: 'Executive Overview', badge: 'images', icon: 'chart', desc: 'High-level security data with severity distribution charts and KPI summaries for leadership review', href: '/executive.html' },
  { name: 'Internet Exposed Assets', badge: 'hosts', icon: 'globe', desc: 'Internet-exposed hosts with Critical and High severity vulnerabilities \u2014 includes cloud metadata and CVSS scores', href: '/hosts.html' },
  { name: 'KEV Report', badge: 'vulnerabilities', icon: 'alert', desc: 'CISA Known Exploited Vulnerabilities across all assets \u2014 filterable by collection, severity, and fix status', href: null, action: 'showKevView()' },
  { name: 'New vs Remediated', badge: 'vulnerabilities', icon: 'diff', desc: 'Vulnerabilities sorted and grouped by discovered date showing new findings versus previously remediated items', href: '/diff.html' },
  { name: 'Newly Discovered Assets', badge: 'images', icon: 'server', desc: 'New assets discovered within a specific time period \u2014 track changes to your network environment over time', href: '/explorer.html' },
  { name: 'Remediation Plan', badge: 'vulnerabilities', icon: 'wrench', desc: 'Detailed remediation instructions per vulnerability with affected package versions, fix availability, and reference links', href: '/explorer.html' },
  { name: 'Risk Factor Analysis', badge: 'vuln risk factors', icon: 'layers', desc: 'Vulnerabilities broken out by individual risk factor \u2014 filter and group by specific risk indicators like remote execution, has fix, and attack complexity', href: '/explorer.html' },
  { name: 'Top 10 Vulnerabilities', badge: 'all resources', icon: 'chart', desc: 'Top 10 vulnerabilities by severity across images, hosts, and registry \u2014 filterable by OS and risk factor', href: null, action: 'showTop10View()' },
];

let templates = [];

async function loadTemplates() {
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const res = await apiFetch('/api/templates');
    templates = await res.json();
  } catch (_) {}
  renderTemplateTiles();
}

function renderTemplateTiles() {
  const wrap = document.getElementById('template-tiles');
  let html = '';

  for (const r of BUILT_IN_REPORTS) {
    const icon = TILE_ICONS[r.icon] || TILE_ICONS.doc;
    html += buildTileHtml(r.name, r.badge, icon, r.desc, r.href, null, r.action || null);
  }

  for (const t of templates) {
    const c = t.config || {};
    const badge = c.data_source === 'kev' ? 'kev only' : 'custom report';
    html += buildTileHtml(t.name, badge, TILE_ICONS.doc, '', null, t.id);
  }

  wrap.innerHTML = html;
}

function buildTileHtml(name, badge, iconSvg, desc, href, templateId, action) {
  const tag = href ? 'a' : 'div';
  const linkAttr = href ? ' href="' + href + '" style="text-decoration:none;color:inherit"' : '';
  const clickAttr = action ? ' onclick="' + action + '" style="cursor:pointer"'
    : (templateId ? ' onclick="generateFromTile(' + templateId + ',\'pdf\')" style="cursor:pointer"' : '');
  const editBtn = templateId
    ? '<button class="tile-edit" onclick="event.stopPropagation();event.preventDefault();toggleTileMenu(' + templateId + ')" title="Actions">' + PENCIL_ICON + '</button>'
      + '<div class="tile-menu" id="tile-menu-' + templateId + '">'
      + '<button onclick="event.stopPropagation();generateFromTile(' + templateId + ',\'pdf\')">Generate PDF</button>'
      + '<button onclick="event.stopPropagation();generateFromTile(' + templateId + ',\'html\')">Generate HTML</button>'
      + '<button onclick="event.stopPropagation();generateFromTile(' + templateId + ',\'csv\')">Generate CSV</button>'
      + '<button onclick="event.stopPropagation();editTemplate(' + templateId + ')">Edit in Wizard</button>'
      + '<button class="danger" onclick="event.stopPropagation();deleteTemplate(' + templateId + ')">Delete</button>'
      + '</div>'
    : '<span class="tile-edit">' + PENCIL_ICON + '</span>';

  return '<' + tag + ' class="report-tile"' + linkAttr + clickAttr + '>'
    + '<div class="tile-top">'
    + '<div class="tile-icon">' + iconSvg + '</div>'
    + editBtn
    + '</div>'
    + '<div class="tile-name">' + esc(name) + '</div>'
    + '<div><span class="tile-badge">' + esc(badge) + '</span></div>'
    + (desc ? '<div class="tile-desc">' + esc(desc) + '</div>' : '')
    + '</' + tag + '>';
}

function toggleTileMenu(id) {
  const menu = document.getElementById('tile-menu-' + id);
  const wasOpen = menu.classList.contains('open');
  document.querySelectorAll('.tile-menu.open').forEach(m => m.classList.remove('open'));
  if (!wasOpen) menu.classList.add('open');
}

async function generateFromTile(templateId, format) {
  document.querySelectorAll('.tile-menu.open').forEach(m => m.classList.remove('open'));
  const tpl = templates.find(t => t.id === templateId);
  if (!tpl) return;
  showLoading('Generating ' + format.toUpperCase() + ' report\u2026', '"' + tpl.name + '"');
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    const res = await apiFetch('/api/reports/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config: tpl.config, format, title: tpl.name }),
    });
    const data = await res.json();
    if (data.file) {
      const tenant = window.TenantCtx ? TenantCtx.getCurrentTenant() : '';
      const dlUrl = '/api/reports/file/' + encodeURIComponent(data.file) + (tenant ? '?tenant=' + encodeURIComponent(tenant) : '');
      const a = document.createElement('a'); a.href = dlUrl; a.download = data.file; document.body.appendChild(a); a.click(); a.remove();
    } else {
      alert('Generation failed: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Generation failed: ' + err.message);
  } finally {
    hideLoading();
  }
}

function editTemplate(id) {
  document.querySelectorAll('.tile-menu.open').forEach(m => m.classList.remove('open'));
  window.location.href = '/wizard.html?template=' + id;
}

async function deleteTemplate(id) {
  document.querySelectorAll('.tile-menu.open').forEach(m => m.classList.remove('open'));
  if (!confirm('Delete this report template? This cannot be undone.')) return;
  try {
    const apiFetch = window.TenantCtx ? TenantCtx.apiFetch : fetch;
    await apiFetch('/api/templates/' + id, { method: 'DELETE' });
    templates = templates.filter(t => t.id !== id);
    renderTemplateTiles();
  } catch (_) {}
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('.tile-edit') && !e.target.closest('.tile-menu')) {
    document.querySelectorAll('.tile-menu.open').forEach(m => m.classList.remove('open'));
  }
});
