const express = require('express');
const Database = require('better-sqlite3');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.resolve(__dirname, '..');
const FETCH_SCRIPT = path.resolve(DATA_DIR, 'fetch_vulns.py');
const REPORTS_DIR = path.resolve(__dirname, 'generated_reports');
if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

function discoverDbFile() {
  const tenants = loadTenants();
  if (tenants.length) return tenants[0].db_file;
  return path.resolve(DATA_DIR, 'vuln_data.db');
}

const TENANTS_FILE = path.resolve(DATA_DIR, 'tenants.json');
const CRED_FILE = '/root/.prismacloud/credentials.json';

function generateTenantsFromCreds() {
  try {
    const raw = fs.readFileSync(CRED_FILE, 'utf8');
    const creds = JSON.parse(raw);
    if (!Array.isArray(creds) || !creds.length) return null;
    const tenants = creds.map((c, i) => {
      const name = c.name || c.url || ('Tenant ' + (i + 1));
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || ('tenant_' + i);
      return { slug, name, db_file: '/app/data/vuln_data_' + slug + '.db', cred_index: i };
    });
    fs.writeFileSync(TENANTS_FILE, JSON.stringify(tenants, null, 2) + '\n');
    console.log('Auto-generated tenants.json with ' + tenants.length + ' tenant(s) from credentials');
    return tenants;
  } catch (e) {
    console.log('Could not auto-generate tenants.json:', e.message);
    return null;
  }
}

function loadTenants() {
  try {
    const raw = fs.readFileSync(TENANTS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    const generated = generateTenantsFromCreds();
    if (generated) return generated;
    return [{ slug: 'default', name: 'Default', db_file: path.resolve(DATA_DIR, 'vuln_data.db') }];
  }
}

const tenantConnections = {};

function openTenantDb(dbFile, readonly) {
  const conn = new Database(dbFile, { readonly: readonly !== false });
  conn.pragma('journal_mode = WAL');
  if (!readonly) conn.pragma('foreign_keys = ON');
  return conn;
}

function getTenantDb(slug) {
  if (tenantConnections[slug]) return tenantConnections[slug];
  const tenants = loadTenants();
  const t = tenants.find(x => x.slug === slug);
  if (!t) return null;
  try {
    const conn = openTenantDb(t.db_file, true);
    tenantConnections[slug] = conn;
    return conn;
  } catch (_) { return null; }
}

function resolveTenantSlug(req) {
  const slug = req.headers['x-tenant'] || req.query.tenant || '';
  const tenants = loadTenants();
  if (slug && tenants.some(t => t.slug === slug)) return slug;
  return tenants[0]?.slug || 'default';
}

function getDb(req) {
  const slug = resolveTenantSlug(req);
  return getTenantDb(slug);
}

function getDbRW(req) {
  const slug = resolveTenantSlug(req);
  const tenants = loadTenants();
  const t = tenants.find(x => x.slug === slug);
  if (!t) return null;
  return openTenantDb(t.db_file, false);
}

const DB_FILE = process.env.DB_PATH || discoverDbFile();

function ensureReportingTables() {
  const tenants = loadTenants();
  const dbFiles = tenants.map(t => t.db_file);
  if (!dbFiles.length) dbFiles.push(DB_FILE);

  const schema = `
    CREATE TABLE IF NOT EXISTS scan_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_date TEXT NOT NULL,
      total_cves INTEGER DEFAULT 0,
      total_kev INTEGER DEFAULT 0,
      total_packages INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS cves (
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL,
      severity TEXT NOT NULL, description TEXT, link TEXT,
      cvss REAL DEFAULT 0, fix_status TEXT, is_kev INTEGER DEFAULT 0,
      PRIMARY KEY (cve_id, scan_id)
    );
    CREATE TABLE IF NOT EXISTS cve_packages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL,
      package_name TEXT NOT NULL, package_version TEXT
    );
    CREATE TABLE IF NOT EXISTS cve_resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL,
      resource_name TEXT NOT NULL, resource_type TEXT NOT NULL, os_label TEXT
    );
    CREATE TABLE IF NOT EXISTS cve_resource_namespaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      resource_id INTEGER NOT NULL, namespace TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_risk_factors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL, risk_factor TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_os_labels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL, os_label TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_repos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL, repo TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_collections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL, scan_id INTEGER NOT NULL, collection TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS compliance_issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      comp_id INTEGER NOT NULL, scan_id INTEGER NOT NULL,
      severity TEXT NOT NULL, title TEXT, description TEXT,
      cause TEXT, comp_type TEXT, templates TEXT,
      UNIQUE(comp_id, scan_id)
    );
    CREATE TABLE IF NOT EXISTS compliance_resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      comp_id INTEGER NOT NULL, scan_id INTEGER NOT NULL,
      resource_name TEXT NOT NULL, resource_type TEXT NOT NULL, os_label TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_comp_scan_sev ON compliance_issues(scan_id, severity);
    CREATE INDEX IF NOT EXISTS idx_compres_scan ON compliance_resources(comp_id, scan_id);
    CREATE INDEX IF NOT EXISTS idx_compres_resname ON compliance_resources(resource_name, scan_id);
    CREATE INDEX IF NOT EXISTS idx_cveres_resname ON cve_resources(resource_name, scan_id);
    CREATE TABLE IF NOT EXISTS report_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      config TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS report_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT, template_id INTEGER,
      title TEXT, format TEXT, file_path TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS report_schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT, template_id INTEGER NOT NULL,
      name TEXT NOT NULL, cron_expr TEXT NOT NULL,
      format TEXT DEFAULT 'pdf', email_to TEXT, enabled INTEGER DEFAULT 1,
      last_run TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS email_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      host TEXT, port INTEGER, secure INTEGER DEFAULT 0,
      user TEXT, pass TEXT, from_addr TEXT, from_name TEXT
    );
    CREATE TABLE IF NOT EXISTS scan_snapshots (
      scan_id INTEGER PRIMARY KEY,
      run_date TEXT NOT NULL,
      total_cves INTEGER DEFAULT 0, total_kev INTEGER DEFAULT 0,
      total_packages INTEGER DEFAULT 0, total_resources INTEGER DEFAULT 0,
      total_fixed INTEGER DEFAULT 0,
      critical_count INTEGER DEFAULT 0, high_count INTEGER DEFAULT 0,
      medium_count INTEGER DEFAULT 0, low_count INTEGER DEFAULT 0,
      critical_kev INTEGER DEFAULT 0, high_kev INTEGER DEFAULT 0,
      medium_kev INTEGER DEFAULT 0, low_kev INTEGER DEFAULT 0,
      avg_cvss REAL DEFAULT 0, max_cvss REAL DEFAULT 0,
      resource_hosts INTEGER DEFAULT 0, resource_images INTEGER DEFAULT 0,
      resource_registry INTEGER DEFAULT 0,
      risk_score REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS scan_diffs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id_old INTEGER NOT NULL, scan_id_new INTEGER NOT NULL,
      computed_at TEXT DEFAULT (datetime('now')),
      new_cves_count INTEGER DEFAULT 0, removed_cves_count INTEGER DEFAULT 0,
      changed_cves_count INTEGER DEFAULT 0,
      new_kev_count INTEGER DEFAULT 0, removed_kev_count INTEGER DEFAULT 0,
      severity_summary TEXT, diff_detail TEXT,
      UNIQUE(scan_id_old, scan_id_new)
    );
  `;

  for (const dbf of dbFiles) {
    try {
      const rw = openTenantDb(dbf, false);
      rw.exec(schema);
      const migrate = (table, col, type) => {
        const cols = rw.prepare('PRAGMA table_info(' + table + ')').all();
        if (!cols.some(c => c.name === col)) rw.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + col + ' ' + type);
      };
      migrate('report_history', 'title', 'TEXT');
      migrate('report_history', 'format', 'TEXT');
      migrate('report_history', 'file_path', 'TEXT');
      migrate('report_schedules', 'name', 'TEXT');
      migrate('report_schedules', 'format', "TEXT DEFAULT 'pdf'");
      migrate('report_schedules', 'email_to', 'TEXT');
      migrate('report_schedules', 'last_run', 'TEXT');
      rw.close();
      console.log('  Schema OK: ' + dbf);
    } catch (err) {
      console.warn('  Schema init warning for ' + dbf + ': ' + err.message);
    }
  }
}
ensureReportingTables();

function backfillSnapshots() {
  for (const t of loadTenants()) {
    try {
      const rw = openTenantDb(t.db_file, false);
      const scans = rw.prepare('SELECT id, run_date FROM scan_runs ORDER BY id').all();
      const existing = new Set(rw.prepare('SELECT scan_id FROM scan_snapshots').all().map(r => r.scan_id));
      let filled = 0;
      for (const scan of scans) {
        if (existing.has(scan.id)) continue;
        const hasCves = rw.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=?').get(scan.id);
        if (!hasCves || !hasCves.cnt) continue;
        const sevCounts = {};
        const sevKev = {};
        for (const r of rw.prepare('SELECT severity, COUNT(*) as cnt FROM cves WHERE scan_id=? GROUP BY severity').all(scan.id)) sevCounts[r.severity] = r.cnt;
        for (const r of rw.prepare('SELECT severity, COUNT(*) as cnt FROM cves WHERE scan_id=? AND is_kev=1 GROUP BY severity').all(scan.id)) sevKev[r.severity] = r.cnt;
        const agg = rw.prepare('SELECT COUNT(*) as total, SUM(is_kev) as kev, AVG(cvss) as avg_cvss, MAX(cvss) as max_cvss, SUM(CASE WHEN fix_status=\'fixed\' THEN 1 ELSE 0 END) as fixed FROM cves WHERE scan_id=?').get(scan.id);
        const pkgCount = rw.prepare('SELECT COUNT(DISTINCT package_name) as cnt FROM cve_packages WHERE scan_id=?').get(scan.id);
        const resCounts = {};
        for (const r of rw.prepare('SELECT resource_type, COUNT(*) as cnt FROM cve_resources WHERE scan_id=? GROUP BY resource_type').all(scan.id)) resCounts[r.resource_type] = r.cnt;
        const totalRes = Object.values(resCounts).reduce((a, b) => a + b, 0);
        const c = sevCounts.critical || 0, h = sevCounts.high || 0, m = sevCounts.medium || 0, l = sevCounts.low || 0;
        const risk = c * 10 + h * 5 + m * 2 + l;
        rw.prepare('INSERT OR IGNORE INTO scan_snapshots (scan_id,run_date,total_cves,total_kev,total_packages,total_resources,total_fixed,critical_count,high_count,medium_count,low_count,critical_kev,high_kev,medium_kev,low_kev,avg_cvss,max_cvss,resource_hosts,resource_images,resource_registry,risk_score) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
          scan.id, scan.run_date, agg.total || 0, agg.kev || 0, pkgCount.cnt || 0, totalRes, agg.fixed || 0,
          c, h, m, l, sevKev.critical || 0, sevKev.high || 0, sevKev.medium || 0, sevKev.low || 0,
          agg.avg_cvss || 0, agg.max_cvss || 0, resCounts.host || 0, resCounts.image || 0, resCounts.registryImage || 0, risk
        );
        filled++;
      }
      rw.close();
      if (filled) console.log('  Backfilled ' + filled + ' snapshot(s) for ' + t.slug);
    } catch (err) {
      console.warn('  Backfill warning for ' + t.slug + ': ' + err.message);
    }
  }
}
backfillSnapshots();

app.use(express.static(path.join(__dirname, 'public')));

function resolveScanId(req, conn) {
  if (req.query.scan_id) return Number(req.query.scan_id);
  const row = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get();
  return row ? row.id : null;
}

function normalizeOs(label) {
  if (!label) return label;
  const d = label.trim();
  if (d.toLowerCase().startsWith('windows')) return d;
  const cleaned = d.replace(/\s+[\d][\d.]*.*$/, '');
  return cleaned || d;
}

app.get('/api/tenants', (_req, res) => {
  res.json(loadTenants().map(({ slug, name }) => ({ slug, name })));
});

app.get('/api/scans', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json([]);
  const scans = conn.prepare('SELECT sr.*, ss.total_cves, ss.total_kev, ss.critical_count, ss.high_count, ss.medium_count, ss.low_count FROM scan_runs sr LEFT JOIN scan_snapshots ss ON ss.scan_id = sr.id ORDER BY sr.id DESC').all();
  res.json(scans);
});

app.delete('/api/scans/:id', (req, res) => {
  const scanId = Number(req.params.id);
  if (!scanId) return res.status(400).json({ error: 'Invalid scan ID' });
  const rw = getDbRW(req);
  if (!rw) return res.status(400).json({ error: 'No database' });
  try {
    const scan = rw.prepare('SELECT id FROM scan_runs WHERE id = ?').get(scanId);
    if (!scan) { rw.close(); return res.status(404).json({ error: 'Scan not found' }); }

    const resIds = rw.prepare('SELECT id FROM cve_resources WHERE scan_id = ?').all(scanId).map(r => r.id);
    if (resIds.length) {
      for (let i = 0; i < resIds.length; i += 500) {
        const batch = resIds.slice(i, i + 500);
        rw.prepare('DELETE FROM cve_resource_namespaces WHERE resource_id IN (' + batch.map(() => '?').join(',') + ')').run(...batch);
      }
    }
    rw.prepare('DELETE FROM cves WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_packages WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_resources WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_risk_factors WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_os_labels WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_repos WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM cve_collections WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM compliance_issues WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM compliance_resources WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM scan_snapshots WHERE scan_id = ?').run(scanId);
    rw.prepare('DELETE FROM scan_diffs WHERE scan_id_old = ? OR scan_id_new = ?').run(scanId, scanId);
    rw.prepare('DELETE FROM scan_runs WHERE id = ?').run(scanId);

    res.json({ ok: true });
  } finally { rw.close(); }
});

app.get('/api/summary', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ total: 0, kev: 0, packages: 0, counts: {} });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json({ total: 0, kev: 0, packages: 0, counts: {} });
  const run = conn.prepare('SELECT * FROM scan_runs WHERE id = ?').get(scanId);
  const sevRows = conn.prepare('SELECT severity, COUNT(*) as cnt FROM cves WHERE scan_id = ? GROUP BY severity').all(scanId);
  const counts = {}; for (const r of sevRows) counts[r.severity] = r.cnt;
  const kevRows = conn.prepare('SELECT severity, COUNT(*) as cnt FROM cves WHERE scan_id = ? AND is_kev = 1 GROUP BY severity').all(scanId);
  const kevCounts = {}; for (const r of kevRows) kevCounts[r.severity] = r.cnt;
  res.json({ scan_id: scanId, run_date: run ? run.run_date : null, total: run ? run.total_cves : 0, kev: run ? run.total_kev : 0, packages: run ? run.total_packages : 0, counts, kevCounts });
});

app.get('/api/filters', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ os: [], risk_factors: [], repos: [], collections: [], resource_types: [] });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json({ os: [], risk_factors: [], repos: [], collections: [], resource_types: [] });
  const os = [...new Set(conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE scan_id = ? ORDER BY os_label').all(scanId).map(r => normalizeOs(r.os_label)))].sort();
  const rf = conn.prepare('SELECT DISTINCT risk_factor FROM cve_risk_factors WHERE scan_id = ? ORDER BY risk_factor').all(scanId).map(r => r.risk_factor);
  const repos = conn.prepare('SELECT DISTINCT repo FROM cve_repos WHERE scan_id = ? ORDER BY repo').all(scanId).map(r => r.repo);
  const collections = conn.prepare('SELECT DISTINCT collection FROM cve_collections WHERE scan_id = ? ORDER BY collection').all(scanId).map(r => r.collection);
  const resourceTypes = conn.prepare('SELECT DISTINCT resource_type FROM cve_resources WHERE scan_id = ? ORDER BY resource_type').all(scanId).map(r => r.resource_type);
  res.json({ os, risk_factors: rf, repos, collections, resource_types: resourceTypes });
});

app.get('/api/top10', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({});
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json([]);
  const top = Number(req.query.top) || 10;
  const osFilter = req.query.os || null;
  const rfFilter = req.query.rf || null;

  let resolvedOsLabels = null;
  if (osFilter) {
    resolvedOsLabels = conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE scan_id=?').all(scanId)
      .map(r => r.os_label).filter(l => normalizeOs(l) === osFilter);
    if (!resolvedOsLabels.length) resolvedOsLabels = [osFilter];
  }

  let cveIds;
  if (resolvedOsLabels && rfFilter) {
    const osPh = resolvedOsLabels.map(() => '?').join(',');
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_os_labels o ON o.cve_id=c.cve_id AND o.scan_id=c.scan_id JOIN cve_risk_factors r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND o.os_label IN (' + osPh + ') AND r.risk_factor=?').all(scanId, ...resolvedOsLabels, rfFilter).map(r => r.cve_id);
  } else if (resolvedOsLabels) {
    const osPh = resolvedOsLabels.map(() => '?').join(',');
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_os_labels o ON o.cve_id=c.cve_id AND o.scan_id=c.scan_id WHERE c.scan_id=? AND o.os_label IN (' + osPh + ')').all(scanId, ...resolvedOsLabels).map(r => r.cve_id);
  } else if (rfFilter) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_risk_factors r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND r.risk_factor=?').all(scanId, rfFilter).map(r => r.cve_id);
  } else { cveIds = null; }

  const severities = ['critical','high','medium','low'];
  const result = {};
  for (const sev of severities) {
    if (cveIds !== null) {
      if (cveIds.length === 0) { result[sev] = { total: 0, entries: [] }; continue; }
      const ph = cveIds.map(() => '?').join(',');
      const totalRow = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=? AND severity=? AND cve_id IN (' + ph + ')').get(scanId, sev, ...cveIds);
      const cves = conn.prepare('SELECT c.*, COUNT(DISTINCT p.package_name) as pkg_count FROM cves c LEFT JOIN cve_packages p ON p.cve_id=c.cve_id AND p.scan_id=c.scan_id WHERE c.scan_id=? AND c.severity=? AND c.cve_id IN (' + ph + ') GROUP BY c.cve_id ORDER BY pkg_count DESC LIMIT ?').all(scanId, sev, ...cveIds, top);
      result[sev] = { total: totalRow.cnt, entries: cves.map(c => enrichCve(conn, c, scanId)) };
    } else {
      const totalRow = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=? AND severity=?').get(scanId, sev);
      const cves = conn.prepare('SELECT c.*, COUNT(DISTINCT p.package_name) as pkg_count FROM cves c LEFT JOIN cve_packages p ON p.cve_id=c.cve_id AND p.scan_id=c.scan_id WHERE c.scan_id=? AND c.severity=? GROUP BY c.cve_id ORDER BY pkg_count DESC LIMIT ?').all(scanId, sev, top);
      result[sev] = { total: totalRow.cnt, entries: cves.map(c => enrichCve(conn, c, scanId)) };
    }
  }
  res.json(result);
});

app.get('/api/kev', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json([]);
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json([]);
  const colFilter = req.query.collection || null;
  const repoFilter = req.query.repo || null;
  let cveIds;
  if (colFilter && repoFilter) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_collections co ON co.cve_id=c.cve_id AND co.scan_id=c.scan_id JOIN cve_repos r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND co.collection=? AND r.repo=?').all(scanId, colFilter, repoFilter).map(r => r.cve_id);
  } else if (colFilter) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_collections co ON co.cve_id=c.cve_id AND co.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND co.collection=?').all(scanId, colFilter).map(r => r.cve_id);
  } else if (repoFilter) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_repos r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND r.repo=?').all(scanId, repoFilter).map(r => r.cve_id);
  } else { cveIds = null; }

  let cves;
  if (cveIds !== null) {
    if (cveIds.length === 0) return res.json([]);
    const ph = cveIds.map(() => '?').join(',');
    cves = conn.prepare("SELECT * FROM cves WHERE scan_id=? AND is_kev=1 AND cve_id IN (" + ph + ") ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cvss DESC").all(scanId, ...cveIds);
  } else {
    cves = conn.prepare("SELECT * FROM cves WHERE scan_id=? AND is_kev=1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cvss DESC").all(scanId);
  }
  res.json(cves.map(c => enrichCve(conn, c, scanId, true)));
});

app.post('/api/top10/export', async (req, res) => {
  const { format, os, rf } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.status(400).json({ error: 'No scan' });

  let resolvedOsLabels = null;
  if (os) {
    resolvedOsLabels = conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE scan_id=?').all(scanId)
      .map(r => r.os_label).filter(l => normalizeOs(l) === os);
    if (!resolvedOsLabels.length) resolvedOsLabels = [os];
  }

  let cveIds;
  if (resolvedOsLabels && rf) {
    const osPh = resolvedOsLabels.map(() => '?').join(',');
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_os_labels o ON o.cve_id=c.cve_id AND o.scan_id=c.scan_id JOIN cve_risk_factors r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND o.os_label IN (' + osPh + ') AND r.risk_factor=?').all(scanId, ...resolvedOsLabels, rf).map(r => r.cve_id);
  } else if (resolvedOsLabels) {
    const osPh = resolvedOsLabels.map(() => '?').join(',');
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_os_labels o ON o.cve_id=c.cve_id AND o.scan_id=c.scan_id WHERE c.scan_id=? AND o.os_label IN (' + osPh + ')').all(scanId, ...resolvedOsLabels).map(r => r.cve_id);
  } else if (rf) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_risk_factors r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND r.risk_factor=?').all(scanId, rf).map(r => r.cve_id);
  } else { cveIds = null; }

  const allRows = [];
  for (const sev of ['critical','high','medium','low']) {
    let cves;
    if (cveIds !== null) {
      if (!cveIds.length) continue;
      const ph = cveIds.map(() => '?').join(',');
      cves = conn.prepare('SELECT c.* FROM cves c WHERE c.scan_id=? AND c.severity=? AND c.cve_id IN (' + ph + ') ORDER BY c.cvss DESC').all(scanId, sev, ...cveIds);
    } else {
      cves = conn.prepare('SELECT c.* FROM cves c WHERE c.scan_id=? AND c.severity=? ORDER BY c.cvss DESC').all(scanId, sev);
    }
    for (const c of cves) allRows.push(enrichCve(conn, c, scanId));
  }

  const columns = ['cve_id','severity','cvss','description','fix_status','packages','resources','risk_factors','os_labels'];
  const title = 'Top Vulnerabilities Report';
  try {
    const result = await generateReportFromRows(allRows, columns, title, format);
    res.json({ ok: true, file: path.basename(result.file), format: result.format });
  } catch (err) {
    console.error('Top10 export error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/kev/export', async (req, res) => {
  const { format, collection, repo } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.status(400).json({ error: 'No scan' });

  let cveIds;
  if (collection && repo) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_collections co ON co.cve_id=c.cve_id AND co.scan_id=c.scan_id JOIN cve_repos r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND co.collection=? AND r.repo=?').all(scanId, collection, repo).map(r => r.cve_id);
  } else if (collection) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_collections co ON co.cve_id=c.cve_id AND co.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND co.collection=?').all(scanId, collection).map(r => r.cve_id);
  } else if (repo) {
    cveIds = conn.prepare('SELECT DISTINCT c.cve_id FROM cves c JOIN cve_repos r ON r.cve_id=c.cve_id AND r.scan_id=c.scan_id WHERE c.scan_id=? AND c.is_kev=1 AND r.repo=?').all(scanId, repo).map(r => r.cve_id);
  } else { cveIds = null; }

  let cves;
  if (cveIds !== null) {
    if (!cveIds.length) cves = [];
    else {
      const ph = cveIds.map(() => '?').join(',');
      cves = conn.prepare("SELECT * FROM cves WHERE scan_id=? AND is_kev=1 AND cve_id IN (" + ph + ") ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cvss DESC").all(scanId, ...cveIds);
    }
  } else {
    cves = conn.prepare("SELECT * FROM cves WHERE scan_id=? AND is_kev=1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cvss DESC").all(scanId);
  }

  const allRows = cves.map(c => enrichCve(conn, c, scanId, true));
  const columns = ['cve_id','severity','cvss','description','fix_status','packages','resources','risk_factors','repos'];
  const title = 'KEV Report — Known Exploited Vulnerabilities';
  try {
    const result = await generateReportFromRows(allRows, columns, title, format);
    res.json({ ok: true, file: path.basename(result.file), format: result.format });
  } catch (err) {
    console.error('KEV export error:', err);
    res.status(500).json({ error: err.message });
  }
});

function enrichCve(conn, cve, scanId, includeRepos) {
  const packages = conn.prepare('SELECT DISTINCT package_name, package_version FROM cve_packages WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId);
  const pkgMap = {};
  for (const p of packages) { if (!pkgMap[p.package_name]) pkgMap[p.package_name] = []; if (p.package_version) pkgMap[p.package_name].push(p.package_version); }
  const resources = conn.prepare('SELECT id, resource_name, resource_type, os_label FROM cve_resources WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId);
  const resMap = {};
  for (const r of resources) {
    if (!resMap[r.resource_type]) resMap[r.resource_type] = [];
    const ns = conn.prepare('SELECT namespace FROM cve_resource_namespaces WHERE resource_id=?').all(r.id).map(n => n.namespace);
    resMap[r.resource_type].push({ name: r.resource_name, os: normalizeOs(r.os_label), namespaces: ns });
  }
  const riskFactors = conn.prepare('SELECT DISTINCT risk_factor FROM cve_risk_factors WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId).map(r => r.risk_factor);
  const osLabels = [...new Set(conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId).map(r => normalizeOs(r.os_label)))];
  const enriched = { cve_id: cve.cve_id, severity: cve.severity, description: cve.description, link: cve.link, cvss: cve.cvss, fix_status: cve.fix_status, is_kev: cve.is_kev, packages: pkgMap, resources: resMap, risk_factors: riskFactors, os_labels: osLabels };
  if (includeRepos) {
    enriched.repos = conn.prepare('SELECT DISTINCT repo FROM cve_repos WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId).map(r => r.repo);
    enriched.collections = conn.prepare('SELECT DISTINCT collection FROM cve_collections WHERE cve_id=? AND scan_id=?').all(cve.cve_id, scanId).map(r => r.collection);
  }
  return enriched;
}

let refreshInProgress = false;
app.post('/api/refresh', (req, res) => {
  if (refreshInProgress) return res.status(409).json({ error: 'Refresh already in progress' });
  refreshInProgress = true;
  const slug = resolveTenantSlug(req);
  const logs = [];
  const child = spawn('python3', [FETCH_SCRIPT, '--tenant', slug], { cwd: path.dirname(FETCH_SCRIPT) });
  child.stdout.on('data', (chunk) => { const l = chunk.toString().trim(); if (l) logs.push(l); });
  child.stderr.on('data', (chunk) => { const l = chunk.toString().trim(); if (l) logs.push('[err] ' + l); });
  child.on('close', (code) => {
    refreshInProgress = false;
    if (tenantConnections[slug]) { try { tenantConnections[slug].close(); } catch(_){} delete tenantConnections[slug]; }
    if (code === 0) { res.json({ success: true, logs }); } else { res.status(500).json({ success: false, code, logs }); }
  });
  child.on('error', (err) => { refreshInProgress = false; res.status(500).json({ success: false, error: err.message }); });
});
app.get('/api/refresh/status', (_req, res) => { res.json({ in_progress: refreshInProgress }); });

// ── Data Sync (manual trigger + schedule + SSE logs + history) ──

const SYNC_DB_PATH = path.resolve(DATA_DIR, 'data', 'sync.db');
function getSyncDb() {
  const dir = path.dirname(SYNC_DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const db = new Database(SYNC_DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS sync_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      started_at TEXT DEFAULT (datetime('now')),
      finished_at TEXT,
      status TEXT DEFAULT 'running',
      tenant TEXT,
      exit_code INTEGER,
      log TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS sync_schedule (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL DEFAULT '',
      cron_expr TEXT NOT NULL,
      tenant TEXT DEFAULT 'all',
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
  return db;
}
(function initSyncDb() {
  const db = getSyncDb();
  const cols = db.prepare("PRAGMA table_info(sync_schedule)").all();
  if (cols.some(c => c.name === 'id' && c.pk === 1)) {
    const hasName = cols.some(c => c.name === 'name');
    const hasCreated = cols.some(c => c.name === 'created_at');
    if (!hasName) try { db.exec('ALTER TABLE sync_schedule ADD COLUMN name TEXT NOT NULL DEFAULT ""'); } catch(_){}
    if (!hasCreated) try { db.exec("ALTER TABLE sync_schedule ADD COLUMN created_at TEXT DEFAULT (datetime('now'))"); } catch(_){}
  }
  db.close();
})();

let syncProcess = null;
let syncRunId = null;
const syncSseClients = new Set();

function broadcastSyncEvent(event, data) {
  const msg = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const c of syncSseClients) { try { c.write(msg); } catch (_) { syncSseClients.delete(c); } }
}

function startSync(tenant) {
  if (syncProcess) return { error: 'Sync already in progress', id: syncRunId };

  const args = [FETCH_SCRIPT];
  if (tenant && tenant !== 'all') args.push('--tenant', tenant);

  const db = getSyncDb();
  const info = db.prepare('INSERT INTO sync_history (tenant) VALUES (?)').run(tenant || 'all');
  syncRunId = info.lastInsertRowid;
  db.close();

  const child = spawn('python3', args, {
    cwd: path.dirname(FETCH_SCRIPT),
    env: { ...process.env, PYTHONUNBUFFERED: '1' }
  });
  syncProcess = child;

  const appendLog = (line) => {
    const sdb = getSyncDb();
    sdb.prepare('UPDATE sync_history SET log = log || ? WHERE id = ?').run(line + '\n', syncRunId);
    sdb.close();
    broadcastSyncEvent('log', { id: syncRunId, line });
  };

  child.stdout.on('data', (chunk) => {
    for (const l of chunk.toString().split('\n')) {
      const t = l.replace(/\r/g, '').trim();
      if (t) appendLog(t);
    }
  });
  child.stderr.on('data', (chunk) => {
    for (const l of chunk.toString().split('\n')) {
      const t = l.replace(/\r/g, '').trim();
      if (t) appendLog('[err] ' + t);
    }
  });

  child.on('close', (code) => {
    const status = code === 0 ? 'success' : 'failed';
    const sdb = getSyncDb();
    sdb.prepare("UPDATE sync_history SET finished_at = datetime('now'), status = ?, exit_code = ? WHERE id = ?").run(status, code, syncRunId);
    sdb.close();
    broadcastSyncEvent('done', { id: syncRunId, status, exit_code: code });

    for (const t of loadTenants()) {
      const slug = t.slug;
      if (tenantConnections[slug]) { try { tenantConnections[slug].close(); } catch(_){} delete tenantConnections[slug]; }
    }
    syncProcess = null;
    refreshInProgress = false;
  });

  child.on('error', (err) => {
    const sdb = getSyncDb();
    sdb.prepare("UPDATE sync_history SET finished_at = datetime('now'), status = 'failed', log = log || ? WHERE id = ?").run('[error] ' + err.message + '\n', syncRunId);
    sdb.close();
    broadcastSyncEvent('done', { id: syncRunId, status: 'failed', error: err.message });
    syncProcess = null;
    refreshInProgress = false;
  });

  refreshInProgress = true;
  broadcastSyncEvent('start', { id: syncRunId, tenant: tenant || 'all' });
  return { ok: true, id: syncRunId };
}

app.post('/api/sync', (req, res) => {
  const tenant = req.body.tenant || 'all';
  const result = startSync(tenant);
  if (result.error) return res.status(409).json(result);
  res.json(result);
});

app.get('/api/sync/status', (_req, res) => {
  res.json({ in_progress: !!syncProcess, run_id: syncRunId });
});

app.get('/api/sync/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(':\n\n');

  if (syncProcess && syncRunId) {
    const db = getSyncDb();
    const row = db.prepare('SELECT log FROM sync_history WHERE id = ?').get(syncRunId);
    db.close();
    if (row && row.log) {
      for (const line of row.log.split('\n')) {
        if (line) res.write('event: log\ndata: ' + JSON.stringify({ id: syncRunId, line }) + '\n\n');
      }
    }
    res.write('event: status\ndata: ' + JSON.stringify({ in_progress: true, run_id: syncRunId }) + '\n\n');
  }

  syncSseClients.add(res);
  req.on('close', () => { syncSseClients.delete(res); });
});

app.get('/api/sync/history', (_req, res) => {
  const db = getSyncDb();
  const rows = db.prepare('SELECT id, started_at, finished_at, status, tenant, exit_code FROM sync_history ORDER BY id DESC LIMIT 50').all();
  db.close();
  res.json(rows);
});

app.get('/api/sync/history/:id/log', (req, res) => {
  const db = getSyncDb();
  const row = db.prepare('SELECT log FROM sync_history WHERE id = ?').get(req.params.id);
  db.close();
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json({ log: row.log });
});

app.get('/api/sync/schedule', (_req, res) => {
  const db = getSyncDb();
  const rows = db.prepare('SELECT * FROM sync_schedule ORDER BY id').all();
  db.close();
  res.json(rows);
});

const syncCronJobs = {};

function registerSyncCron(row) {
  unregisterSyncCron(row.id);
  if (row.enabled && row.cron_expr && cron.validate(row.cron_expr)) {
    syncCronJobs[row.id] = cron.schedule(row.cron_expr, () => {
      if (!syncProcess) startSync(row.tenant || 'all');
    });
  }
}

function unregisterSyncCron(id) {
  if (syncCronJobs[id]) { syncCronJobs[id].stop(); delete syncCronJobs[id]; }
}

app.post('/api/sync/schedule', (req, res) => {
  const { name, cron_expr, tenant, enabled } = req.body;
  if (!cron_expr) return res.status(400).json({ error: 'cron_expr is required' });
  if (!cron.validate(cron_expr)) return res.status(400).json({ error: 'Invalid cron expression' });
  const db = getSyncDb();
  const info = db.prepare('INSERT INTO sync_schedule (name, cron_expr, tenant, enabled) VALUES (?,?,?,?)').run(name || '', cron_expr, tenant || 'all', enabled !== false ? 1 : 0);
  const row = db.prepare('SELECT * FROM sync_schedule WHERE id=?').get(info.lastInsertRowid);
  db.close();
  registerSyncCron(row);
  res.json(row);
});

app.put('/api/sync/schedule/:id', (req, res) => {
  const { name, cron_expr, tenant, enabled } = req.body;
  if (cron_expr && !cron.validate(cron_expr)) return res.status(400).json({ error: 'Invalid cron expression' });
  const db = getSyncDb();
  db.prepare('UPDATE sync_schedule SET name=COALESCE(?,name), cron_expr=COALESCE(?,cron_expr), tenant=COALESCE(?,tenant), enabled=COALESCE(?,enabled) WHERE id=?')
    .run(name !== undefined ? name : null, cron_expr || null, tenant || null, enabled !== undefined ? (enabled ? 1 : 0) : null, req.params.id);
  const row = db.prepare('SELECT * FROM sync_schedule WHERE id=?').get(req.params.id);
  db.close();
  if (!row) return res.status(404).json({ error: 'Not found' });
  registerSyncCron(row);
  res.json(row);
});

app.delete('/api/sync/schedule/:id', (req, res) => {
  unregisterSyncCron(Number(req.params.id));
  const db = getSyncDb();
  db.prepare('DELETE FROM sync_schedule WHERE id=?').run(req.params.id);
  db.close();
  res.json({ ok: true });
});

(function loadSyncSchedules() {
  try {
    const db = getSyncDb();
    const rows = db.prepare('SELECT * FROM sync_schedule WHERE enabled=1').all();
    db.close();
    let count = 0;
    for (const row of rows) {
      if (row.cron_expr && cron.validate(row.cron_expr)) { registerSyncCron(row); count++; }
    }
    if (count) console.log('  Sync schedules loaded: ' + count + ' active');
  } catch (_) {}
})();

// Templates CRUD
app.get('/api/templates', (req, res) => { const rw = getDbRW(req); if (!rw) return res.json([]); try { const rows = rw.prepare('SELECT * FROM report_templates ORDER BY updated_at DESC').all(); res.json(rows.map(r => ({ ...r, config: JSON.parse(r.config) }))); } finally { rw.close(); } });
app.get('/api/templates/:id', (req, res) => { const rw = getDbRW(req); if (!rw) return res.status(404).json({ error: 'Not found' }); try { const row = rw.prepare('SELECT * FROM report_templates WHERE id=?').get(req.params.id); if (!row) return res.status(404).json({ error: 'Not found' }); res.json({ ...row, config: JSON.parse(row.config) }); } finally { rw.close(); } });
app.post('/api/templates', (req, res) => { const { name, config } = req.body; if (!name || !config) return res.status(400).json({ error: 'name and config required' }); const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { const info = rw.prepare('INSERT INTO report_templates (name, config) VALUES (?,?)').run(name, JSON.stringify(config)); const row = rw.prepare('SELECT * FROM report_templates WHERE id=?').get(info.lastInsertRowid); res.json({ ...row, config: JSON.parse(row.config) }); } finally { rw.close(); } });
app.put('/api/templates/:id', (req, res) => { const { name, config } = req.body; const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { rw.prepare("UPDATE report_templates SET name=COALESCE(?,name), config=COALESCE(?,config), updated_at=datetime('now') WHERE id=?").run(name||null, config?JSON.stringify(config):null, req.params.id); const row = rw.prepare('SELECT * FROM report_templates WHERE id=?').get(req.params.id); if (!row) return res.status(404).json({ error: 'Not found' }); res.json({ ...row, config: JSON.parse(row.config) }); } finally { rw.close(); } });
app.delete('/api/templates/:id', (req, res) => { const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { rw.prepare('DELETE FROM report_templates WHERE id=?').run(req.params.id); res.json({ ok: true }); } finally { rw.close(); } });

function executeReportQuery(config, conn) {
  const scanId = (() => { const r = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get(); return r ? r.id : null; })();
  if (!scanId) return [];
  const source = config.data_source || 'all';
  const filters = config.filters || {};
  const columns = config.columns || ['cve_id','severity','cvss','description','fix_status'];
  const sortBy = config.sort_by || 'cvss';
  const sortDir = config.sort_dir === 'ASC' ? 'ASC' : 'DESC';
  const limit = Math.min(config.limit || 1000, 5000);
  let where = ['c.scan_id=?'], params = [scanId], joins = '';
  if (source === 'kev') where.push('c.is_kev=1');
  if (filters.severity && filters.severity.length) { where.push('c.severity IN (' + filters.severity.map(()=>'?').join(',') + ')'); params.push(...filters.severity); }
  if (filters.fix_status && filters.fix_status.length) { where.push('c.fix_status IN (' + filters.fix_status.map(()=>'?').join(',') + ')'); params.push(...filters.fix_status); }
  if (filters.os && filters.os.length) {
    const allOsRaw = conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE scan_id=?').all(scanId).map(r => r.os_label);
    const resolved = allOsRaw.filter(l => filters.os.includes(normalizeOs(l)));
    if (resolved.length) { joins += ' JOIN cve_os_labels ol ON ol.cve_id=c.cve_id AND ol.scan_id=c.scan_id'; where.push('ol.os_label IN (' + resolved.map(()=>'?').join(',') + ')'); params.push(...resolved); }
  }
  if (filters.risk_factor && filters.risk_factor.length) { joins += ' JOIN cve_risk_factors rf ON rf.cve_id=c.cve_id AND rf.scan_id=c.scan_id'; where.push('rf.risk_factor IN (' + filters.risk_factor.map(()=>'?').join(',') + ')'); params.push(...filters.risk_factor); }
  if (filters.collection && filters.collection.length) { joins += ' JOIN cve_collections cc ON cc.cve_id=c.cve_id AND cc.scan_id=c.scan_id'; where.push('cc.collection IN (' + filters.collection.map(()=>'?').join(',') + ')'); params.push(...filters.collection); }
  if (filters.repo && filters.repo.length) { joins += ' JOIN cve_repos cr ON cr.cve_id=c.cve_id AND cr.scan_id=c.scan_id'; where.push('cr.repo IN (' + filters.repo.map(()=>'?').join(',') + ')'); params.push(...filters.repo); }
  if (filters.resource_type && filters.resource_type.length) { joins += ' JOIN cve_resources rt ON rt.cve_id=c.cve_id AND rt.scan_id=c.scan_id'; where.push('rt.resource_type IN (' + filters.resource_type.map(()=>'?').join(',') + ')'); params.push(...filters.resource_type); }
  const allowed = ['cvss','cve_id','severity','fix_status'];
  const rs = allowed.includes(sortBy) ? sortBy : 'cvss';
  const order = rs === 'severity' ? "ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END " + sortDir : 'ORDER BY c.' + rs + ' ' + sortDir;
  params.push(limit);
  const rows = conn.prepare('SELECT DISTINCT c.* FROM cves c' + joins + ' WHERE ' + where.join(' AND ') + ' ' + order + ' LIMIT ?').all(...params);
  return rows.map(c => { const e = enrichCve(conn, c, scanId, true); const out = {}; for (const col of columns) { out[col] = e[col]; } return out; });
}

function flattenForCsv(rows, columns) {
  const EXPAND_MAP = {
    packages:     { type: 'dict', cols: ['package_name', 'package_version'] },
    resources:    { type: 'resource', cols: ['resource_type', 'resource_name', 'resource_os', 'resource_namespace'] },
    risk_factors: { type: 'array', cols: ['risk_factor'] },
    os_labels:    { type: 'array', cols: ['os_label'] },
    repos:        { type: 'array', cols: ['repo'] },
    collections:  { type: 'array', cols: ['collection'] },
  };

  const scalarCols = [];
  const expandCols = [];
  for (const c of columns) {
    if (EXPAND_MAP[c]) expandCols.push(c);
    else scalarCols.push(c);
  }

  const COL_LABELS = { cve_id:'CVE ID', severity:'Severity', cvss:'CVSS', description:'Description', fix_status:'Fix Status', is_kev:'KEV', link:'Link', package_name:'Package', package_version:'Version', resource_type:'Resource Type', resource_name:'Resource', resource_os:'OS', resource_namespace:'Namespace', risk_factor:'Risk Factor', os_label:'OS', repo:'Repo', collection:'Collection' };
  const headers = [...scalarCols];
  for (const c of expandCols) headers.push(...EXPAND_MAP[c].cols);
  const headerLabels = headers.map(h => COL_LABELS[h] || h);

  function expandField(field, value) {
    const spec = EXPAND_MAP[field];
    if (!spec) return [{}];
    if (spec.type === 'array') {
      const arr = Array.isArray(value) ? value : [];
      if (!arr.length) return [{ [spec.cols[0]]: '' }];
      return arr.map(v => ({ [spec.cols[0]]: v }));
    }
    if (spec.type === 'dict') {
      const tuples = [];
      if (value && typeof value === 'object') {
        for (const [name, versions] of Object.entries(value)) {
          const vers = Array.isArray(versions) ? versions : [];
          if (vers.length) {
            for (const ver of vers) tuples.push({ package_name: name, package_version: ver });
          } else {
            tuples.push({ package_name: name, package_version: '' });
          }
        }
      }
      return tuples.length ? tuples : [{ package_name: '', package_version: '' }];
    }
    if (spec.type === 'resource') {
      const tuples = [];
      if (value && typeof value === 'object') {
        for (const [rtype, list] of Object.entries(value)) {
          const entries = Array.isArray(list) ? list : [];
          for (const r of entries) {
            const ns = Array.isArray(r.namespaces) ? r.namespaces : [];
            if (ns.length) {
              for (const n of ns) tuples.push({ resource_type: rtype, resource_name: r.name || '', resource_os: r.os || '', resource_namespace: n });
            } else {
              tuples.push({ resource_type: rtype, resource_name: r.name || '', resource_os: r.os || '', resource_namespace: '' });
            }
          }
        }
      }
      return tuples.length ? tuples : [{ resource_type: '', resource_name: '', resource_os: '', resource_namespace: '' }];
    }
    return [{}];
  }

  function crossProduct(arrays) {
    if (!arrays.length) return [{}];
    return arrays.reduce((acc, cur) => {
      const out = [];
      for (const a of acc) { for (const b of cur) out.push({ ...a, ...b }); }
      return out;
    }, [{}]);
  }

  const flatRows = [];
  const sourceIndices = [];
  for (let ri = 0; ri < rows.length; ri++) {
    const row = rows[ri];
    const base = {};
    for (const c of scalarCols) base[c] = row[c] != null ? row[c] : '';

    if (!expandCols.length) {
      flatRows.push(base);
      sourceIndices.push(ri);
      continue;
    }

    const expanded = expandCols.map(c => expandField(c, row[c]));
    const combos = crossProduct(expanded);
    for (const combo of combos) {
      flatRows.push({ ...base, ...combo });
      sourceIndices.push(ri);
    }
  }

  return { headers, headerLabels, flatRows, sourceIndices };
}

async function renderReportHtmlPdf(rows, columns, title, format, groupBy) {
  const ts = Date.now();
  const colLabels = { cve_id:'CVE ID', severity:'Severity', cvss:'CVSS', description:'Description', fix_status:'Fix Status', packages:'Packages', resources:'Resources', risk_factors:'Risk Factors', os_labels:'OS', repos:'Repos', collections:'Collections', link:'Link', is_kev:'KEV' };

  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const RT_LABELS = { host:'Hosts', image:'Images', registryImage:'Registry' };

  function fmtCell(c, v) {
    if (v == null) return '';
    if (c === 'severity') return '<span class="badge badge-' + v + '">' + esc(v) + '</span>';
    if (c === 'cvss') return '<span class="mono">' + Number(v).toFixed(1) + '</span>';
    if (c === 'is_kev') return v ? '<span class="badge badge-critical">Yes</span>' : 'No';
    if (c === 'link') return v ? '<a href="' + esc(v) + '">' + esc(v).slice(0,40) + '</a>' : '';
    if (c === 'description') return '<span class="desc">' + esc(String(v).slice(0,200)) + (String(v).length>200?'&hellip;':'') + '</span>';
    if (c === 'packages' && typeof v === 'object') {
      const entries = Object.entries(v);
      if (!entries.length) return '<span class="muted">—</span>';
      return '<ul class="cell-list">' + entries.map(([name,vers]) => {
        const vstr = (vers||[]).length ? ' <span class="ver">' + vers.join(', ') + '</span>' : '';
        return '<li><span class="pkg">' + esc(name) + '</span>' + vstr + '</li>';
      }).join('') + '</ul>';
    }
    if (c === 'resources' && typeof v === 'object') {
      const types = Object.entries(v);
      if (!types.length) return '<span class="muted">—</span>';
      let html = '';
      for (const [rtype, list] of types) {
        if (!list || !list.length) continue;
        const label = RT_LABELS[rtype] || rtype;
        const byNs = {};
        for (const r of list) {
          const nsList = (r.namespaces && r.namespaces.length) ? r.namespaces : ['(no namespace)'];
          for (const ns of nsList) { if (!byNs[ns]) byNs[ns] = []; byNs[ns].push(r); }
        }
        html += '<div class="res-group"><div class="res-type">' + esc(label) + ' <span class="cnt">(' + list.length + ')</span></div>';
        for (const [ns, resources] of Object.entries(byNs).sort((a,b) => a[0].localeCompare(b[0]))) {
          html += '<div class="ns-block"><div class="ns-name">' + esc(ns) + '</div>';
          html += '<ul class="cell-list">' + resources.slice(0,15).map(r =>
            '<li>' + esc(r.name) + (r.os ? ' <span class="os-tag">' + esc(r.os) + '</span>' : '') + '</li>'
          ).join('');
          if (resources.length > 15) html += '<li class="muted">+' + (resources.length-15) + ' more</li>';
          html += '</ul></div>';
        }
        html += '</div>';
      }
      return html;
    }
    if (c === 'risk_factors' && Array.isArray(v)) {
      if (!v.length) return '<span class="muted">—</span>';
      return v.map(f => '<span class="tag tag-rf">' + esc(f) + '</span>').join(' ');
    }
    if (c === 'collections' && Array.isArray(v)) {
      if (!v.length) return '<span class="muted">—</span>';
      return v.map(f => '<span class="tag tag-col">' + esc(f) + '</span>').join(' ');
    }
    if (c === 'repos' && Array.isArray(v)) {
      if (!v.length) return '<span class="muted">—</span>';
      return v.map(f => '<span class="tag tag-repo">' + esc(f) + '</span>').join(' ');
    }
    if (c === 'os_labels' && Array.isArray(v)) {
      if (!v.length) return '<span class="muted">—</span>';
      return v.map(f => '<span class="tag tag-os">' + esc(f) + '</span>').join(' ');
    }
    if (typeof v === 'object') return esc(Array.isArray(v) ? v.join(', ') : JSON.stringify(v));
    return esc(String(v));
  }

  const RT_LABELS_EXP = { host:'Hosts', image:'Images', registryImage:'Registry' };

  function groupValue(r, field) {
    if (field === 'severity') return r.severity || 'unknown';
    if (field === 'fix_status') return r.fix_status || 'unknown';
    if (field === 'resource_type') {
      if (!r.resources || typeof r.resources !== 'object') return '(none)';
      const types = Object.keys(r.resources).filter(t => (r.resources[t]||[]).length > 0);
      return types.length ? types.map(t => RT_LABELS_EXP[t]||t).join(', ') : '(none)';
    }
    if (field === 'collection') { const c = Array.isArray(r.collections) ? r.collections : []; return c.length ? c : ['(none)']; }
    if (field === 'os') { const o = Array.isArray(r.os_labels) ? r.os_labels : []; return o.length ? o : ['(none)']; }
    if (field === 'risk_factor') { const f = Array.isArray(r.risk_factors) ? r.risk_factors : []; return f.length ? f : ['(none)']; }
    return '(none)';
  }

  const hasCollections = !groupBy && columns.includes('collections') && rows.some(r => r.collections && r.collections.length);
  const effectiveGroup = groupBy || (hasCollections ? 'collection' : '');
  let tbodyHtml = '';

  if (effectiveGroup) {
    const groups = {};
    const multiVal = ['collection', 'os', 'risk_factor'];
    for (const r of rows) {
      const vals = multiVal.includes(effectiveGroup) ? groupValue(r, effectiveGroup) : [groupValue(r, effectiveGroup)];
      const vArr = Array.isArray(vals) ? vals : [vals];
      for (const v of vArr) { if (!groups[v]) groups[v] = []; groups[v].push(r); }
    }
    const sevOrder = { critical:0, high:1, medium:2, low:3, unknown:4 };
    const keys = Object.keys(groups).sort((a,b) => {
      if (effectiveGroup === 'severity') return (sevOrder[a]??99) - (sevOrder[b]??99);
      if (a === '(none)') return 1; if (b === '(none)') return -1;
      return a.localeCompare(b);
    });
    const seen = new Set();
    for (const grp of keys) {
      const grpRows = groups[grp];
      tbodyHtml += '<tr class="group-row"><td colspan="' + columns.length + '"><span class="group-label">' + esc(grp) + '</span> <span class="group-cnt">' + grpRows.length + ' CVEs</span></td></tr>';
      for (const r of grpRows) {
        if (seen.has(r.cve_id)) continue;
        seen.add(r.cve_id);
        tbodyHtml += '<tr>' + columns.map(c => '<td>' + fmtCell(c, r[c]) + '</td>').join('') + '</tr>';
      }
    }
  } else {
    tbodyHtml = rows.map(r => '<tr>' + columns.map(c => '<td>' + fmtCell(c, r[c]) + '</td>').join('') + '</tr>').join('\n');
  }

  const thCells = columns.map(c => '<th>' + (colLabels[c]||c) + '</th>').join('');
  const reportCss = `body{font-family:"Plus Jakarta Sans",system-ui,sans-serif;font-size:11px;color:#0f172a;margin:24px}
h1{font-size:20px;font-weight:800;margin-bottom:4px}
.sub{font-size:12px;color:#94a3b8;margin-bottom:16px}
table{width:100%;border-collapse:collapse}
th{background:#f1f5f9;text-align:left;padding:6px 10px;font-size:9px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #e2e8f0}
td{padding:6px 10px;border-bottom:1px solid #f1f5f9;color:#374151;vertical-align:top}
.mono{font-family:"JetBrains Mono",monospace}
a{color:#0ea5e9;text-decoration:none}
.muted{color:#94a3b8;font-style:italic}
.desc{display:block;max-width:280px;line-height:1.4}
.badge{display:inline-block;padding:1px 6px;border-radius:12px;font-size:9px;font-weight:600}
.badge-critical{background:#fee2e2;color:#dc2626}
.badge-high{background:#fff7ed;color:#ea580c}
.badge-medium{background:#fef3c7;color:#d97706}
.badge-low{background:#d1fae5;color:#059669}
.cell-list{margin:0;padding:0;list-style:none}
.cell-list li{padding:1px 0;font-size:10px;line-height:1.3}
.pkg{font-family:"JetBrains Mono",monospace;font-size:10px;font-weight:600}
.ver{color:#64748b;font-family:"JetBrains Mono",monospace;font-size:9px}
.res-group{margin-bottom:4px}
.res-type{font-weight:700;font-size:9px;text-transform:uppercase;color:#64748b;letter-spacing:.5px;margin-bottom:2px}
.res-type .cnt{font-weight:400}
.ns-block{margin-left:8px;margin-bottom:3px;border-left:2px solid #e2e8f0;padding-left:6px}
.ns-name{font-size:9px;font-weight:600;color:#0ea5e9;margin-bottom:1px}
.os-tag{font-size:8px;color:#94a3b8;margin-left:4px}
.tag{display:inline-block;padding:1px 5px;border-radius:8px;font-size:9px;margin:1px 2px 1px 0;white-space:nowrap}
.tag-rf{background:#fef3c7;color:#92400e}
.tag-col{background:#dbeafe;color:#1e40af}
.tag-repo{background:#f3e8ff;color:#7c3aed}
.tag-os{background:#ecfdf5;color:#065f46}
.group-row td{background:#f8fafc;padding:8px 10px 4px;border-bottom:2px solid #e2e8f0}
.group-label{font-weight:800;font-size:12px;color:#0f172a}
.group-cnt{font-size:10px;color:#94a3b8;font-weight:400}`;

  const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + esc(title||'Report') + '</title><style>' + reportCss + '</style></head><body><h1>' + esc(title||'Vulnerability Report') + '</h1><div class="sub">Generated ' + new Date().toISOString().slice(0,19).replace('T',' ') + ' &middot; ' + rows.length + ' results</div><table><thead><tr>' + thCells + '</tr></thead><tbody>' + tbodyHtml + '</tbody></table></body></html>';
  if (format === 'html') { const fp = path.join(REPORTS_DIR, 'report_' + ts + '.html'); fs.writeFileSync(fp, html); return { file: fp, format: 'html' }; }
  const fp = path.join(REPORTS_DIR, 'report_' + ts + '.pdf');
  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox','--disable-setuid-sandbox'] });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  await page.pdf({ path: fp, format: 'A4', landscape: true, margin: { top: '16px', bottom: '16px', left: '16px', right: '16px' } });
  await browser.close();
  return { file: fp, format: 'pdf' };
}

async function generateReportFromRows(rows, columns, title, format, groupBy) {
  if (format === 'csv') {
    const { headers, headerLabels, flatRows } = flattenForCsv(rows, columns);
    const ts = Date.now();
    const fp = path.join(REPORTS_DIR, 'explorer_' + ts + '.csv');
    const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
    function csvVal(h, v) { if (h === 'is_kev') return v ? 'Yes' : 'No'; return v; }
    const lines = [headerLabels.map(csvEnc).join(',')];
    for (const row of flatRows) lines.push(headers.map(h => csvEnc(csvVal(h, row[h]))).join(','));
    fs.writeFileSync(fp, lines.join('\n'));
    return { file: fp, format: 'csv' };
  }
  return renderReportHtmlPdf(rows, columns, title, format, groupBy);
}

async function generateReport(config, title, format, conn) {
  const rows = executeReportQuery(config, conn);
  const columns = config.columns || ['cve_id','severity','cvss','description','fix_status'];
  const groupBy = config.group_by || '';
  if (format === 'csv') {
    const { headers, headerLabels, flatRows } = flattenForCsv(rows, columns);
    const ts = Date.now();
    const fp = path.join(REPORTS_DIR, 'report_' + ts + '.csv');
    const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
    function csvVal(h, v) { if (h === 'is_kev') return v ? 'Yes' : 'No'; return v; }
    const lines = [headerLabels.map(csvEnc).join(',')];
    for (const row of flatRows) lines.push(headers.map(h => csvEnc(csvVal(h, row[h]))).join(','));
    fs.writeFileSync(fp, lines.join('\n'));
    return { file: fp, format: 'csv' };
  }
  return renderReportHtmlPdf(rows, columns, title, format, groupBy);
}

app.post('/api/reports/generate', async (req, res) => {
  const { config, title, format } = req.body;
  if (!config) return res.status(400).json({ error: 'config required' });
  try {
    const conn = getDb(req);
    if (!conn) return res.status(400).json({ error: 'No database available for this tenant' });
    const result = await generateReport(config, title || 'Report', format || 'pdf', conn);
    const rw = getDbRW(req);
    let historyId = null;
    if (rw) { const info = rw.prepare('INSERT INTO report_history (template_id, title, format, file_path) VALUES (?,?,?,?)').run(req.body.template_id||null, title||'Report', result.format, result.file); historyId = Number(info.lastInsertRowid); rw.close(); }
    res.json({ ok: true, history_id: historyId, format: result.format, file: path.basename(result.file) });
  } catch (err) { console.error('Report generation error:', err); res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/preview', (req, res) => {
  const config = JSON.parse(req.query.config || '{}');
  const conn = getDb(req);
  if (!conn) return res.json([]);
  res.json(executeReportQuery({ ...config, limit: Math.min(config.limit || 25, 25) }, conn));
});

app.get('/api/reports/history', (req, res) => { const rw = getDbRW(req); if (!rw) return res.json([]); try { const rows = rw.prepare('SELECT * FROM report_history ORDER BY created_at DESC LIMIT 50').all(); res.json(rows); } finally { rw.close(); } });

app.get('/api/reports/download/:id', (req, res) => {
  const rw = getDbRW(req); if (!rw) return res.status(404).json({ error: 'No database' }); try { const row = rw.prepare('SELECT * FROM report_history WHERE id=?').get(req.params.id); rw.close();
  if (!row || !row.file_path || !fs.existsSync(row.file_path)) return res.status(404).json({ error: 'Report file not found' });
  const mm = { pdf: 'application/pdf', html: 'text/html', csv: 'text/csv' };
  res.setHeader('Content-Type', mm[row.format] || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="' + path.basename(row.file_path) + '"');
  fs.createReadStream(row.file_path).pipe(res);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports/file/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const fp = path.join(REPORTS_DIR, filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File not found' });
  const ext = path.extname(filename).slice(1);
  const mm = { pdf: 'application/pdf', html: 'text/html', csv: 'text/csv' };
  res.setHeader('Content-Type', mm[ext] || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  fs.createReadStream(fp).pipe(res);
});

// Schedules
const cronJobs = {};
app.get('/api/schedules', (req, res) => { const rw = getDbRW(req); if (!rw) return res.json([]); try { const rows = rw.prepare('SELECT s.*, t.name as template_name FROM report_schedules s LEFT JOIN report_templates t ON t.id=s.template_id ORDER BY s.created_at DESC').all(); res.json(rows); } finally { rw.close(); } });
app.post('/api/schedules', (req, res) => {
  const { template_id, name, cron_expr, format, email_to, enabled } = req.body;
  if (!template_id || !name || !cron_expr) return res.status(400).json({ error: 'template_id, name, cron_expr required' });
  if (!cron.validate(cron_expr)) return res.status(400).json({ error: 'Invalid cron expression' });
  const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' });
  try {
    const info = rw.prepare('INSERT INTO report_schedules (template_id,name,cron_expr,format,email_to,enabled) VALUES (?,?,?,?,?,?)').run(template_id, name, cron_expr, format||'pdf', email_to||null, enabled!==false?1:0);
    const row = rw.prepare('SELECT * FROM report_schedules WHERE id=?').get(info.lastInsertRowid);
    if (row.enabled) registerCron(row.id, row.cron_expr, resolveTenantSlug(req));
    res.json(row);
  } finally { rw.close(); }
});
app.put('/api/schedules/:id', (req, res) => {
  const { name, cron_expr, format, email_to, enabled } = req.body;
  if (cron_expr && !cron.validate(cron_expr)) return res.status(400).json({ error: 'Invalid cron expression' });
  const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' });
  try {
    rw.prepare('UPDATE report_schedules SET name=COALESCE(?,name), cron_expr=COALESCE(?,cron_expr), format=COALESCE(?,format), email_to=COALESCE(?,email_to), enabled=COALESCE(?,enabled) WHERE id=?').run(name||null, cron_expr||null, format||null, email_to!==undefined?email_to:null, enabled!==undefined?(enabled?1:0):null, req.params.id);
    const row = rw.prepare('SELECT * FROM report_schedules WHERE id=?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Not found' });
    unregisterCron(row.id); if (row.enabled) registerCron(row.id, row.cron_expr, resolveTenantSlug(req));
    res.json(row);
  } finally { rw.close(); }
});
app.delete('/api/schedules/:id', (req, res) => { unregisterCron(Number(req.params.id)); const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { rw.prepare('DELETE FROM report_schedules WHERE id=?').run(req.params.id); res.json({ ok: true }); } finally { rw.close(); } });

function registerCron(id, expr, tenantSlug) { unregisterCron(id); cronJobs[id] = cron.schedule(expr, () => executeScheduledJob(id, tenantSlug)); }
function unregisterCron(id) { if (cronJobs[id]) { cronJobs[id].stop(); delete cronJobs[id]; } }
async function executeScheduledJob(jobId, tenantSlug) {
  const tenants = loadTenants();
  const t = tenants.find(x => x.slug === tenantSlug) || tenants[0];
  if (!t) return;
  const rw = openTenantDb(t.db_file, false);
  const sched = rw.prepare('SELECT s.*, t.config, t.name as template_name FROM report_schedules s JOIN report_templates t ON t.id=s.template_id WHERE s.id=?').get(jobId);
  if (!sched) { rw.close(); return; }
  try {
    const config = JSON.parse(sched.config);
    const conn = openTenantDb(t.db_file, true);
    const result = await generateReport(config, sched.template_name + ' - ' + sched.name, sched.format||'pdf', conn);
    conn.close();
    rw.prepare('INSERT INTO report_history (template_id,title,format,file_path) VALUES (?,?,?,?)').run(sched.template_id, sched.template_name + ' - ' + sched.name, result.format, result.file);
    rw.prepare("UPDATE report_schedules SET last_run=datetime('now') WHERE id=?").run(jobId);
    if (sched.email_to) {
      const ec = rw.prepare('SELECT * FROM email_config WHERE id=1').get();
      if (ec && ec.host) {
        const tr = nodemailer.createTransport({ host: ec.host, port: ec.port||587, secure: !!ec.secure, auth: ec.user ? { user: ec.user, pass: ec.pass } : undefined });
        await tr.sendMail({ from: ec.from_addr ? '"' + (ec.from_name||'Prisma Cloud') + '" <' + ec.from_addr + '>' : undefined, to: sched.email_to, subject: 'Report: ' + sched.template_name, text: 'Attached is your scheduled report.', attachments: [{ filename: path.basename(result.file), path: result.file }] });
      }
    }
  } catch (err) { console.error('Schedule ' + jobId + ' failed:', err.message); }
  rw.close();
}
function loadScheduledJobs() {
  let totalActive = 0;
  for (const t of loadTenants()) {
    try {
      const rw = openTenantDb(t.db_file, false);
      const rows = rw.prepare('SELECT * FROM report_schedules WHERE enabled=1').all();
      rw.close();
      for (const r of rows) {
        if (cron.validate(r.cron_expr)) { registerCron(r.id, r.cron_expr, t.slug); totalActive++; }
      }
    } catch (_) {}
  }
  console.log('  Schedules: ' + totalActive + ' active');
}

// Email config
app.get('/api/email-config', (req, res) => { const rw = getDbRW(req); if (!rw) return res.json({}); try { const row = rw.prepare('SELECT * FROM email_config WHERE id=1').get(); if (!row) return res.json({}); const s = { ...row }; if (s.pass) s.pass = '********'; res.json(s); } finally { rw.close(); } });
app.put('/api/email-config', (req, res) => { const { host, port, secure, user, pass, from_addr, from_name } = req.body; const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { rw.prepare('INSERT INTO email_config (id,host,port,secure,user,pass,from_addr,from_name) VALUES (1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET host=excluded.host,port=excluded.port,secure=excluded.secure,user=excluded.user,pass=excluded.pass,from_addr=excluded.from_addr,from_name=excluded.from_name').run(host||null, port||587, secure?1:0, user||null, pass||null, from_addr||null, from_name||null); res.json({ ok: true }); } finally { rw.close(); } });
app.post('/api/email-config/test', async (req, res) => { const { to } = req.body; const rw = getDbRW(req); if (!rw) return res.status(400).json({ error: 'No database' }); try { const c = rw.prepare('SELECT * FROM email_config WHERE id=1').get(); rw.close(); if (!c||!c.host) return res.status(400).json({ error: 'Email not configured' }); const tr = nodemailer.createTransport({ host: c.host, port: c.port||587, secure: !!c.secure, auth: c.user ? { user: c.user, pass: c.pass } : undefined }); await tr.sendMail({ from: c.from_addr ? '"' + (c.from_name||'Prisma Cloud') + '" <' + c.from_addr + '>' : undefined, to: to||c.from_addr, subject: 'Test Email', text: 'This is a test from Prisma Cloud Reports.' }); res.json({ ok: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

// Compliance API
app.get('/api/compliance', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json([]);
  const scanId = (() => { const r = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get(); return r ? r.id : null; })();
  if (!scanId) return res.json([]);

  const severity = req.query.severity || '';
  const compType = req.query.type || '';
  const template = req.query.template || '';
  const resourceType = req.query.resource_type || '';
  const collection = req.query.collection || '';
  const search = (req.query.search || '').trim();
  const page = Math.max(1, Number(req.query.page) || 1);
  const perPage = Math.min(5000, Math.max(10, Number(req.query.per_page) || 50));
  const sortBy = req.query.sort_by || 'severity';
  const sortDir = (req.query.sort_dir || 'ASC').toUpperCase() === 'DESC' ? 'DESC' : 'ASC';

  let where = 'ci.scan_id = ?';
  const params = [scanId];
  let joins = '';
  if (severity) { where += " AND ci.severity = ?"; params.push(severity); }
  if (compType) { where += " AND ci.comp_type = ?"; params.push(compType); }
  if (template) { where += " AND ci.templates LIKE ?"; params.push('%' + template + '%'); }
  if (search) { where += " AND (ci.title LIKE ? OR ci.description LIKE ? OR CAST(ci.comp_id AS TEXT) LIKE ?)"; params.push('%'+search+'%', '%'+search+'%', '%'+search+'%'); }
  if (resourceType) { joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id'; where += ' AND cr.resource_type=?'; params.push(resourceType); }
  if (collection) {
    const resNames = conn.prepare(
      'SELECT DISTINCT cvr.resource_name FROM cve_resources cvr JOIN cve_collections cc ON cc.cve_id=cvr.cve_id AND cc.scan_id=cvr.scan_id WHERE cvr.scan_id=? AND cc.collection=?'
    ).all(scanId, collection).map(r => r.resource_name);
    if (resNames.length) {
      if (!joins.includes('compliance_resources cr')) joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id';
      where += ' AND cr.resource_name IN (' + resNames.map(() => '?').join(',') + ')';
      params.push(...resNames);
    } else {
      return res.json({ rows: [], total: 0, page: 1, per_page: perPage, pages: 0 });
    }
  }

  const countQ = 'SELECT COUNT(DISTINCT ci.comp_id) as cnt FROM compliance_issues ci' + joins + ' WHERE ' + where;
  const total = conn.prepare(countQ).get(...params).cnt;

  const sevOrder = "CASE ci.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END";
  const orderCol = sortBy === 'severity' ? sevOrder : sortBy === 'title' ? 'ci.title' : sortBy === 'comp_id' ? 'ci.comp_id' : sevOrder;

  let dataQ;
  const dataParams = [...params];
  if (joins) {
    dataQ = 'SELECT DISTINCT ci.* FROM compliance_issues ci' + joins + ' WHERE ' + where + ' ORDER BY ' + orderCol + ' ' + sortDir + ' LIMIT ? OFFSET ?';
  } else {
    dataQ = 'SELECT ci.* FROM compliance_issues ci WHERE ' + where + ' ORDER BY ' + orderCol + ' ' + sortDir + ' LIMIT ? OFFSET ?';
  }
  dataParams.push(perPage, (page - 1) * perPage);

  const rows = conn.prepare(dataQ).all(...dataParams);

  const enriched = rows.map(row => {
    const resources = {};
    const resList = conn.prepare('SELECT resource_name, resource_type, os_label FROM compliance_resources WHERE comp_id=? AND scan_id=?').all(row.comp_id, scanId);
    for (const r of resList) {
      if (!resources[r.resource_type]) resources[r.resource_type] = [];
      resources[r.resource_type].push({ name: r.resource_name, os: r.os_label });
    }
    return {
      comp_id: row.comp_id,
      severity: row.severity,
      title: row.title,
      description: row.description,
      cause: row.cause,
      comp_type: row.comp_type,
      templates: row.templates ? JSON.parse(row.templates) : [],
      resources,
      resource_count: resList.length,
    };
  });

  res.json({ rows: enriched, total, page, per_page: perPage, pages: Math.ceil(total / perPage) });
});

app.get('/api/compliance/summary', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({});
  const scanId = (() => { const r = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get(); return r ? r.id : null; })();
  if (!scanId) return res.json({});

  const severity = req.query.severity || '';
  const compType = req.query.type || '';
  const template = req.query.template || '';
  const resourceType = req.query.resource_type || '';
  const collection = req.query.collection || '';
  const search = (req.query.search || '').trim();

  let where = 'ci.scan_id = ?';
  const params = [scanId];
  let joins = '';
  if (severity) { where += " AND ci.severity = ?"; params.push(severity); }
  if (compType) { where += " AND ci.comp_type = ?"; params.push(compType); }
  if (template) { where += " AND ci.templates LIKE ?"; params.push('%' + template + '%'); }
  if (search) { where += " AND (ci.title LIKE ? OR ci.description LIKE ? OR CAST(ci.comp_id AS TEXT) LIKE ?)"; params.push('%'+search+'%', '%'+search+'%', '%'+search+'%'); }
  if (resourceType) { joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id'; where += ' AND cr.resource_type=?'; params.push(resourceType); }
  if (collection) {
    const resNames = conn.prepare(
      'SELECT DISTINCT cvr.resource_name FROM cve_resources cvr JOIN cve_collections cc ON cc.cve_id=cvr.cve_id AND cc.scan_id=cvr.scan_id WHERE cvr.scan_id=? AND cc.collection=?'
    ).all(scanId, collection).map(r => r.resource_name);
    if (resNames.length) {
      if (!joins.includes('compliance_resources cr')) joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id';
      where += ' AND cr.resource_name IN (' + resNames.map(() => '?').join(',') + ')';
      params.push(...resNames);
    } else {
      const types = conn.prepare('SELECT DISTINCT comp_type FROM compliance_issues WHERE scan_id=? ORDER BY comp_type').all(scanId).map(r => r.comp_type).filter(Boolean);
      const tplSet = new Set();
      for (const r of conn.prepare("SELECT templates FROM compliance_issues WHERE scan_id=? AND templates != '[]'").all(scanId)) { try { for (const t of JSON.parse(r.templates)) tplSet.add(t); } catch (_) {} }
      const resourceTypes = conn.prepare('SELECT DISTINCT resource_type FROM compliance_resources WHERE scan_id=? ORDER BY resource_type').all(scanId).map(r => r.resource_type);
      const collections = conn.prepare('SELECT DISTINCT cc.collection FROM cve_collections cc WHERE cc.scan_id=? ORDER BY cc.collection').all(scanId).map(r => r.collection);
      return res.json({ total: 0, critical: 0, high: 0, medium: 0, low: 0, types, templates: [...tplSet].sort(), resource_types: resourceTypes, resource_count: 0, collections });
    }
  }

  const sevRows = conn.prepare('SELECT ci.severity, COUNT(DISTINCT ci.comp_id) as cnt FROM compliance_issues ci' + joins + ' WHERE ' + where + ' GROUP BY ci.severity').all(...params);
  const sevCounts = {};
  for (const r of sevRows) sevCounts[r.severity] = r.cnt;
  const total = Object.values(sevCounts).reduce((a, b) => a + b, 0);

  const resCountQ = collection || resourceType
    ? 'SELECT COUNT(DISTINCT cr.resource_name || cr.resource_type) as cnt FROM compliance_issues ci' + joins + ' WHERE ' + where
    : 'SELECT COUNT(DISTINCT resource_name || resource_type) as cnt FROM compliance_resources WHERE scan_id=?';
  const resCountParams = collection || resourceType ? params : [scanId];
  const resourceCount = conn.prepare(resCountQ).get(...resCountParams).cnt;

  const types = conn.prepare('SELECT DISTINCT comp_type FROM compliance_issues WHERE scan_id=? ORDER BY comp_type').all(scanId).map(r => r.comp_type).filter(Boolean);
  const templates = new Set();
  for (const r of conn.prepare("SELECT templates FROM compliance_issues WHERE scan_id=? AND templates != '[]'").all(scanId)) {
    try { for (const t of JSON.parse(r.templates)) templates.add(t); } catch (_) {}
  }
  const resourceTypes = conn.prepare('SELECT DISTINCT resource_type FROM compliance_resources WHERE scan_id=? ORDER BY resource_type').all(scanId).map(r => r.resource_type);

  const collections = conn.prepare('SELECT DISTINCT cc.collection FROM cve_collections cc WHERE cc.scan_id=? ORDER BY cc.collection').all(scanId).map(r => r.collection);

  res.json({
    total,
    critical: sevCounts.critical || 0,
    high: sevCounts.high || 0,
    medium: sevCounts.medium || 0,
    low: sevCounts.low || 0,
    types,
    templates: [...templates].sort(),
    resource_types: resourceTypes,
    resource_count: resourceCount,
    collections,
  });
});

app.post('/api/compliance/export', async (req, res) => {
  const { format } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });
  const scanId = (() => { const r = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get(); return r ? r.id : null; })();
  if (!scanId) return res.status(400).json({ error: 'No scan data' });

  const severity = req.body.severity || '';
  const compType = req.body.type || '';
  const template = req.body.template || '';
  const resourceType = req.body.resource_type || '';
  const collection = req.body.collection || '';
  const search = (req.body.search || '').trim();
  const sortBy = req.body.sort_by || 'severity';
  const sortDir = (req.body.sort_dir || 'ASC').toUpperCase() === 'DESC' ? 'DESC' : 'ASC';

  let where = 'ci.scan_id = ?';
  const params = [scanId];
  let joins = '';
  if (severity) { where += " AND ci.severity = ?"; params.push(severity); }
  if (compType) { where += " AND ci.comp_type = ?"; params.push(compType); }
  if (template) { where += " AND ci.templates LIKE ?"; params.push('%' + template + '%'); }
  if (search) { where += " AND (ci.title LIKE ? OR ci.description LIKE ? OR CAST(ci.comp_id AS TEXT) LIKE ?)"; params.push('%'+search+'%', '%'+search+'%', '%'+search+'%'); }
  if (resourceType) { joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id'; where += ' AND cr.resource_type=?'; params.push(resourceType); }
  if (collection) {
    const resNames = conn.prepare(
      'SELECT DISTINCT cvr.resource_name FROM cve_resources cvr JOIN cve_collections cc ON cc.cve_id=cvr.cve_id AND cc.scan_id=cvr.scan_id WHERE cvr.scan_id=? AND cc.collection=?'
    ).all(scanId, collection).map(r => r.resource_name);
    if (resNames.length) {
      if (!joins.includes('compliance_resources cr')) joins += ' JOIN compliance_resources cr ON cr.comp_id=ci.comp_id AND cr.scan_id=ci.scan_id';
      where += ' AND cr.resource_name IN (' + resNames.map(() => '?').join(',') + ')';
      params.push(...resNames);
    } else {
      if (format === 'csv') { res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="compliance.csv"'); return res.send('No data'); }
      return res.status(200).send('<html><body>No matching compliance data</body></html>');
    }
  }

  const sevOrder = "CASE ci.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END";
  const orderCol = sortBy === 'severity' ? sevOrder : sortBy === 'title' ? 'ci.title' : sortBy === 'comp_id' ? 'ci.comp_id' : sevOrder;
  const dataQ = 'SELECT DISTINCT ci.* FROM compliance_issues ci' + joins + ' WHERE ' + where + ' ORDER BY ' + orderCol + ' ' + sortDir + ' LIMIT 5000';

  try {
    const rows = conn.prepare(dataQ).all(...params);
    const RT_LABELS_C = { host:'Hosts', image:'Images', registryImage:'Registry' };
    const enriched = rows.map(row => {
      const resources = {};
      const resList = conn.prepare('SELECT resource_name, resource_type, os_label FROM compliance_resources WHERE comp_id=? AND scan_id=?').all(row.comp_id, scanId);
      for (const r of resList) { if (!resources[r.resource_type]) resources[r.resource_type] = []; resources[r.resource_type].push({ name: r.resource_name, os: r.os_label }); }
      return { comp_id: row.comp_id, severity: row.severity, title: row.title, description: row.description, cause: row.cause, comp_type: row.comp_type, templates: row.templates ? JSON.parse(row.templates) : [], resources, resource_count: resList.length };
    });

    const ts = Date.now();
    const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    if (format === 'csv') {
      const fp = path.join(REPORTS_DIR, 'compliance_' + ts + '.csv');
      const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
      const headers = ['ID','Severity','Title','Type','Description','Cause','Frameworks','Resource Type','Resource Name','OS'];
      const lines = [headers.map(csvEnc).join(',')];
      for (const r of enriched) {
        for (const rtype of ['host','image','registryImage']) {
          for (const res of (r.resources[rtype] || [])) {
            lines.push([
              csvEnc(r.comp_id), csvEnc(r.severity), csvEnc(r.title), csvEnc(r.comp_type),
              csvEnc(r.description), csvEnc(r.cause), csvEnc((r.templates||[]).join('; ')),
              csvEnc(RT_LABELS_C[rtype]||rtype), csvEnc(res.name), csvEnc(res.os)
            ].join(','));
          }
        }
        const hasRes = Object.values(r.resources).some(l => l && l.length);
        if (!hasRes) {
          lines.push([csvEnc(r.comp_id), csvEnc(r.severity), csvEnc(r.title), csvEnc(r.comp_type), csvEnc(r.description), csvEnc(r.cause), csvEnc((r.templates||[]).join('; ')), '', '', ''].join(','));
        }
      }
      fs.writeFileSync(fp, lines.join('\n'));
      const tenant = resolveTenantSlug(req);
      return res.json({ ok: true, file: path.basename(fp), count: enriched.length, tenant });
    }

    const colLabels = { comp_id:'ID', severity:'Severity', title:'Title', comp_type:'Type', frameworks:'Frameworks', resources:'Resources', resource_count:'Res Count' };
    const columns = ['comp_id','severity','title','comp_type','frameworks','resources','resource_count'];
    function fmtCompCell(c, row) {
      if (c === 'severity') return '<span class="badge badge-' + row.severity + '">' + esc(row.severity) + '</span>';
      if (c === 'comp_id') return '<span class="mono">' + esc(String(row.comp_id)) + '</span>';
      if (c === 'title') return esc(row.title || '');
      if (c === 'comp_type') return esc(row.comp_type || '');
      if (c === 'frameworks') return (row.templates||[]).map(t => '<span class="tag tag-col">' + esc(t) + '</span>').join(' ') || '<span class="muted">—</span>';
      if (c === 'resource_count') return '<span class="mono">' + row.resource_count + '</span>';
      if (c === 'resources') {
        const parts = [];
        for (const rtype of ['host','image','registryImage']) {
          const list = row.resources[rtype]; if (!list || !list.length) continue;
          parts.push('<div class="res-group"><div class="res-type">' + esc(RT_LABELS_C[rtype]||rtype) + ' (' + list.length + ')</div><ul class="cell-list">' + list.slice(0,10).map(r => '<li>' + esc(r.name) + (r.os ? ' <span class="os-tag">' + esc(r.os) + '</span>' : '') + '</li>').join('') + (list.length > 10 ? '<li class="muted">+' + (list.length-10) + ' more</li>' : '') + '</ul></div>');
        }
        return parts.join('') || '<span class="muted">—</span>';
      }
      return '';
    }
    const thCells = columns.map(c => '<th>' + (colLabels[c]||c) + '</th>').join('');
    const tbodyHtml = enriched.map(r => '<tr>' + columns.map(c => '<td>' + fmtCompCell(c, r) + '</td>').join('') + '</tr>').join('\n');
    const reportCss = `body{font-family:"Plus Jakarta Sans",system-ui,sans-serif;font-size:11px;color:#0f172a;margin:24px}
h1{font-size:20px;font-weight:800;margin-bottom:4px}
.sub{font-size:12px;color:#94a3b8;margin-bottom:16px}
table{width:100%;border-collapse:collapse}
th{background:#f1f5f9;text-align:left;padding:6px 10px;font-size:9px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #e2e8f0}
td{padding:6px 10px;border-bottom:1px solid #f1f5f9;color:#374151;vertical-align:top}
.mono{font-family:"JetBrains Mono",monospace}
.muted{color:#94a3b8;font-style:italic}
.badge{display:inline-block;padding:1px 6px;border-radius:12px;font-size:9px;font-weight:600}
.badge-critical{background:#fee2e2;color:#dc2626}
.badge-high{background:#fff7ed;color:#ea580c}
.badge-medium{background:#fef3c7;color:#d97706}
.badge-low{background:#d1fae5;color:#059669}
.cell-list{margin:0;padding:0;list-style:none}
.cell-list li{padding:1px 0;font-size:10px;line-height:1.3}
.res-group{margin-bottom:4px}
.res-type{font-weight:700;font-size:9px;text-transform:uppercase;color:#64748b;letter-spacing:.5px;margin-bottom:2px}
.os-tag{font-size:8px;color:#94a3b8;margin-left:4px}
.tag{display:inline-block;padding:1px 5px;border-radius:8px;font-size:9px;margin:1px 2px 1px 0}
.tag-col{background:#dbeafe;color:#1e40af}`;
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Compliance Report</title><style>' + reportCss + '</style></head><body><h1>Compliance Report Card</h1><div class="sub">Generated ' + new Date().toISOString().slice(0,19).replace('T',' ') + ' &middot; ' + enriched.length + ' findings</div><table><thead><tr>' + thCells + '</tr></thead><tbody>' + tbodyHtml + '</tbody></table></body></html>';

    if (format === 'html') {
      const fp = path.join(REPORTS_DIR, 'compliance_' + ts + '.html');
      fs.writeFileSync(fp, html);
      const tenant = resolveTenantSlug(req);
      return res.json({ ok: true, file: path.basename(fp), format: 'html', count: enriched.length, tenant });
    }
    const fp = path.join(REPORTS_DIR, 'compliance_' + ts + '.pdf');
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox','--disable-setuid-sandbox'] });
    const pg = await browser.newPage();
    await pg.setContent(html, { waitUntil: 'networkidle0' });
    await pg.pdf({ path: fp, format: 'A4', landscape: true, margin: { top: '16px', bottom: '16px', left: '16px', right: '16px' } });
    await browser.close();
    const tenant = resolveTenantSlug(req);
    res.json({ ok: true, file: path.basename(fp), format: 'pdf', count: enriched.length, tenant });
  } catch (err) { console.error('Compliance export error:', err); res.status(500).json({ error: err.message }); }
});

// Diff API
app.get('/api/diff/scans', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json([]);
  const snapshots = conn.prepare('SELECT scan_id, run_date, total_cves, total_kev FROM scan_snapshots ORDER BY scan_id DESC').all();
  const diffs = conn.prepare('SELECT scan_id_old, scan_id_new, new_cves_count, removed_cves_count, changed_cves_count FROM scan_diffs ORDER BY scan_id_new DESC').all();
  res.json({ snapshots, diffs });
});

app.get('/api/diff', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ error: 'No database' });
  const scanA = Number(req.query.scan_a);
  const scanB = Number(req.query.scan_b);
  if (!scanA || !scanB) return res.status(400).json({ error: 'scan_a and scan_b required' });
  const older = Math.min(scanA, scanB);
  const newer = Math.max(scanA, scanB);

  const precomputed = conn.prepare('SELECT * FROM scan_diffs WHERE scan_id_old=? AND scan_id_new=?').get(older, newer);
  if (precomputed) {
    const detail = precomputed.diff_detail ? JSON.parse(precomputed.diff_detail) : { new: [], removed: [], changed: [] };

    const oldResCounts = {};
    for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(older)) oldResCounts[r.cve_id] = r.cnt;
    const newResCounts = {};
    for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(newer)) newResCounts[r.cve_id] = r.cnt;
    for (const r of (detail.new || [])) r.resource_count = r.resource_count || newResCounts[r.cve_id] || 0;
    for (const r of (detail.removed || [])) r.resource_count = r.resource_count || oldResCounts[r.cve_id] || 0;
    for (const r of (detail.changed || [])) r.resource_count = r.resource_count || newResCounts[r.cve_id] || 0;
    const resources_remediated = (detail.removed || []).reduce((sum, r) => sum + r.resource_count, 0);

    return res.json({
      scan_id_old: older, scan_id_new: newer,
      new_cves_count: precomputed.new_cves_count,
      removed_cves_count: precomputed.removed_cves_count,
      changed_cves_count: precomputed.changed_cves_count,
      resources_remediated,
      new_kev_count: precomputed.new_kev_count,
      removed_kev_count: precomputed.removed_kev_count,
      severity_summary: precomputed.severity_summary ? JSON.parse(precomputed.severity_summary) : {},
      diff_detail: detail,
      snapshots: {
        old: conn.prepare('SELECT * FROM scan_snapshots WHERE scan_id=?').get(older),
        new: conn.prepare('SELECT * FROM scan_snapshots WHERE scan_id=?').get(newer),
      }
    });
  }

  const hasOld = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=?').get(older);
  const hasNew = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=?').get(newer);
  if (!hasOld || !hasOld.cnt || !hasNew || !hasNew.cnt) {
    return res.json({ error: 'Full data not available for these scans. Only precomputed diffs are available for purged scans.', scan_id_old: older, scan_id_new: newer });
  }

  const oldCves = {};
  for (const r of conn.prepare('SELECT cve_id, severity, cvss, fix_status, is_kev FROM cves WHERE scan_id=?').all(older)) oldCves[r.cve_id] = r;
  const newCves = {};
  for (const r of conn.prepare('SELECT cve_id, severity, cvss, fix_status, is_kev FROM cves WHERE scan_id=?').all(newer)) newCves[r.cve_id] = r;

  const oldPkgs = {};
  for (const r of conn.prepare('SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?').all(older)) { if (!oldPkgs[r.cve_id]) oldPkgs[r.cve_id] = []; oldPkgs[r.cve_id].push(r.package_name); }
  const newPkgs = {};
  for (const r of conn.prepare('SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?').all(newer)) { if (!newPkgs[r.cve_id]) newPkgs[r.cve_id] = []; newPkgs[r.cve_id].push(r.package_name); }

  const oldResCounts = {};
  for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(older)) oldResCounts[r.cve_id] = r.cnt;
  const newResCounts = {};
  for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(newer)) newResCounts[r.cve_id] = r.cnt;

  const oldIds = new Set(Object.keys(oldCves));
  const newIds = new Set(Object.keys(newCves));
  const addedIds = [...newIds].filter(id => !oldIds.has(id));
  const removedIds = [...oldIds].filter(id => !newIds.has(id));
  const commonIds = [...newIds].filter(id => oldIds.has(id));

  const newList = addedIds.map(id => ({ cve_id: id, ...newCves[id], is_kev: !!newCves[id].is_kev, packages: [...new Set(newPkgs[id] || [])].slice(0, 10), resource_count: newResCounts[id] || 0 }));
  const removedList = removedIds.map(id => ({ cve_id: id, ...oldCves[id], is_kev: !!oldCves[id].is_kev, packages: [...new Set(oldPkgs[id] || [])].slice(0, 10), resource_count: oldResCounts[id] || 0 }));
  const changedList = [];
  for (const id of commonIds) {
    const o = oldCves[id], n = newCves[id];
    const changes = [];
    if (o.severity !== n.severity) changes.push({ field: 'severity', old: o.severity, new: n.severity });
    if (Math.abs((o.cvss || 0) - (n.cvss || 0)) > 0.01) changes.push({ field: 'cvss', old: o.cvss, new: n.cvss });
    if (o.fix_status !== n.fix_status) changes.push({ field: 'fix_status', old: o.fix_status, new: n.fix_status });
    if (o.is_kev !== n.is_kev) changes.push({ field: 'is_kev', old: !!o.is_kev, new: !!n.is_kev });
    if (changes.length) changedList.push({ cve_id: id, severity: n.severity, cvss: n.cvss, changes, resource_count: newResCounts[id] || 0 });
  }

  const resources_remediated = removedList.reduce((sum, r) => sum + r.resource_count, 0);

  res.json({
    scan_id_old: older, scan_id_new: newer,
    new_cves_count: newList.length, removed_cves_count: removedList.length,
    changed_cves_count: changedList.length,
    resources_remediated,
    new_kev_count: newList.filter(x => x.is_kev).length,
    removed_kev_count: removedList.filter(x => x.is_kev).length,
    severity_summary: (() => { const s = {}; for (const sev of ['critical','high','medium','low']) { s[sev] = { new: newList.filter(x => x.severity === sev).length, removed: removedList.filter(x => x.severity === sev).length }; } return s; })(),
    diff_detail: { new: newList, removed: removedList, changed: changedList },
    snapshots: {
      old: conn.prepare('SELECT * FROM scan_snapshots WHERE scan_id=?').get(older),
      new: conn.prepare('SELECT * FROM scan_snapshots WHERE scan_id=?').get(newer),
    }
  });
});

// Diff export (PDF/HTML/CSV) — deltas only, matching GUI layout
app.post('/api/diff/export', async (req, res) => {
  const { format, scan_a, scan_b } = req.body;
  if (!format || !scan_a || !scan_b) return res.status(400).json({ error: 'format, scan_a, scan_b required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });

  const older = Math.min(Number(scan_a), Number(scan_b));
  const newer = Math.max(Number(scan_a), Number(scan_b));

  /* Fetch diff data — reuse same logic as GET /api/diff */
  let diffResult;
  const precomputed = conn.prepare('SELECT * FROM scan_diffs WHERE scan_id_old=? AND scan_id_new=?').get(older, newer);
  if (precomputed) {
    diffResult = {
      new_cves_count: precomputed.new_cves_count,
      removed_cves_count: precomputed.removed_cves_count,
      changed_cves_count: precomputed.changed_cves_count,
      diff_detail: precomputed.diff_detail ? JSON.parse(precomputed.diff_detail) : { new: [], removed: [], changed: [] },
    };
  } else {
    const hasOld = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=?').get(older);
    const hasNew = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=?').get(newer);
    if (!hasOld || !hasOld.cnt || !hasNew || !hasNew.cnt) return res.status(400).json({ error: 'Scan data unavailable' });

    const oldCves = {};
    for (const r of conn.prepare('SELECT cve_id, severity, cvss, fix_status, is_kev FROM cves WHERE scan_id=?').all(older)) oldCves[r.cve_id] = r;
    const newCves = {};
    for (const r of conn.prepare('SELECT cve_id, severity, cvss, fix_status, is_kev FROM cves WHERE scan_id=?').all(newer)) newCves[r.cve_id] = r;

    const oldPkgs = {};
    for (const r of conn.prepare('SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?').all(older)) { if (!oldPkgs[r.cve_id]) oldPkgs[r.cve_id] = []; oldPkgs[r.cve_id].push(r.package_name); }
    const newPkgs = {};
    for (const r of conn.prepare('SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?').all(newer)) { if (!newPkgs[r.cve_id]) newPkgs[r.cve_id] = []; newPkgs[r.cve_id].push(r.package_name); }

    const oldIds = new Set(Object.keys(oldCves));
    const newIds = new Set(Object.keys(newCves));
    const addedIds = [...newIds].filter(id => !oldIds.has(id));
    const removedIds = [...oldIds].filter(id => !newIds.has(id));
    const commonIds = [...newIds].filter(id => oldIds.has(id));

    const newList = addedIds.map(id => ({ cve_id: id, ...newCves[id], is_kev: !!newCves[id].is_kev, packages: [...new Set(newPkgs[id] || [])].slice(0, 10) }));
    const removedList = removedIds.map(id => ({ cve_id: id, ...oldCves[id], is_kev: !!oldCves[id].is_kev, packages: [...new Set(oldPkgs[id] || [])].slice(0, 10) }));
    const changedList = [];
    for (const id of commonIds) {
      const o = oldCves[id], n = newCves[id];
      const changes = [];
      if (o.severity !== n.severity) changes.push({ field: 'severity', old: o.severity, new: n.severity });
      if (Math.abs((o.cvss || 0) - (n.cvss || 0)) > 0.01) changes.push({ field: 'cvss', old: o.cvss, new: n.cvss });
      if (o.fix_status !== n.fix_status) changes.push({ field: 'fix_status', old: o.fix_status, new: n.fix_status });
      if (o.is_kev !== n.is_kev) changes.push({ field: 'is_kev', old: !!o.is_kev, new: !!n.is_kev });
      if (changes.length) changedList.push({ cve_id: id, severity: n.severity, cvss: n.cvss, changes });
    }
    diffResult = { new_cves_count: newList.length, removed_cves_count: removedList.length, changed_cves_count: changedList.length, diff_detail: { new: newList, removed: removedList, changed: changedList } };
  }

  /* Enrich with resource counts */
  const oldResCounts = {};
  for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(older)) oldResCounts[r.cve_id] = r.cnt;
  const newResCounts = {};
  for (const r of conn.prepare('SELECT cve_id, COUNT(DISTINCT resource_name) as cnt FROM cve_resources WHERE scan_id=? GROUP BY cve_id').all(newer)) newResCounts[r.cve_id] = r.cnt;

  const detail = diffResult.diff_detail || { new: [], removed: [], changed: [] };
  for (const r of (detail.new || [])) r.resource_count = r.resource_count || newResCounts[r.cve_id] || 0;
  for (const r of (detail.removed || [])) r.resource_count = r.resource_count || oldResCounts[r.cve_id] || 0;
  for (const r of (detail.changed || [])) r.resource_count = r.resource_count || newResCounts[r.cve_id] || 0;
  const resources_remediated = (detail.removed || []).reduce((sum, r) => sum + r.resource_count, 0);
  const sevSort = (a, b) => ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] || 4) - ({ critical: 0, high: 1, medium: 2, low: 3 }[b.severity] || 4) || (b.cvss || 0) - (a.cvss || 0);
  const newSorted = (detail.new || []).sort(sevSort);
  const remSorted = (detail.removed || []).sort(sevSort);
  const chgSorted = (detail.changed || []).sort(sevSort);

  const title = 'New vs Remediated Report (Scan #' + older + ' \u2192 #' + newer + ')';
  const ts = Date.now();
  const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  try {
    /* ── CSV ─────────────────────────────────── */
    if (format === 'csv') {
      const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
      const headers = ['Status', 'CVE ID', 'Severity', 'CVSS', 'Fix Status', 'KEV', 'Resources', 'Packages', 'Changed Fields'];
      const lines = [headers.map(csvEnc).join(',')];
      for (const r of newSorted) {
        lines.push(['New', r.cve_id, r.severity, r.cvss != null ? Number(r.cvss).toFixed(1) : '', r.fix_status || '', r.is_kev ? 'Yes' : 'No', r.resource_count || 0, (r.packages || []).join('; '), ''].map(csvEnc).join(','));
      }
      for (const r of remSorted) {
        lines.push(['Resolved', r.cve_id, r.severity, r.cvss != null ? Number(r.cvss).toFixed(1) : '', r.fix_status || '', r.is_kev ? 'Yes' : 'No', r.resource_count || 0, (r.packages || []).join('; '), ''].map(csvEnc).join(','));
      }
      for (const r of chgSorted) {
        const desc = (r.changes || []).map(c => c.field + ': ' + String(c.old) + ' \u2192 ' + String(c.new)).join('; ');
        lines.push(['Changed', r.cve_id, r.severity, r.cvss != null ? Number(r.cvss).toFixed(1) : '', '', '', r.resource_count || 0, '', desc].map(csvEnc).join(','));
      }
      const fp = path.join(REPORTS_DIR, 'diff_' + ts + '.csv');
      fs.writeFileSync(fp, lines.join('\n'));
      return res.json({ ok: true, file: path.basename(fp) });
    }

    /* ── HTML / PDF ──────────────────────────── */
    const badgeHtml = sev => '<span class="badge badge-' + sev + '">' + esc(sev) + '</span>';
    const net = (diffResult.new_cves_count || 0) - (diffResult.removed_cves_count || 0);

    function cveTableHtml(rows) {
      if (!rows.length) return '<div class="empty">No vulnerabilities in this category</div>';
      let h = '<table><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Fix Status</th><th>KEV</th><th>Resources</th><th>Packages</th></tr></thead><tbody>';
      for (const r of rows) {
        h += '<tr>';
        h += '<td class="mono">' + esc(r.cve_id) + '</td>';
        h += '<td>' + badgeHtml(r.severity) + '</td>';
        h += '<td class="mono">' + (r.cvss != null ? Number(r.cvss).toFixed(1) : '\u2014') + '</td>';
        h += '<td>' + esc(r.fix_status || '\u2014') + '</td>';
        h += '<td>' + (r.is_kev ? '<span class="badge badge-critical">Yes</span>' : '<span class="muted">No</span>') + '</td>';
        h += '<td class="mono">' + (r.resource_count || 0) + '</td>';
        const pkgs = r.packages || [];
        h += '<td>' + (pkgs.length ? pkgs.slice(0, 8).map(p => '<span class="pkg">' + esc(p) + '</span>').join(', ') + (pkgs.length > 8 ? ' +' + (pkgs.length - 8) + ' more' : '') : '<span class="muted">\u2014</span>') + '</td>';
        h += '</tr>';
      }
      return h + '</tbody></table>';
    }

    function changedTableHtml(rows) {
      if (!rows.length) return '<div class="empty">No changed vulnerabilities</div>';
      let h = '<table><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Resources</th><th>Field</th><th>Old Value</th><th>New Value</th></tr></thead><tbody>';
      for (const r of rows) {
        const changes = r.changes || [];
        for (let i = 0; i < changes.length; i++) {
          const c = changes[i];
          h += '<tr>';
          if (i === 0) {
            const rs = changes.length > 1 ? ' rowspan="' + changes.length + '"' : '';
            h += '<td class="mono"' + rs + '>' + esc(r.cve_id) + '</td>';
            h += '<td' + rs + '>' + badgeHtml(r.severity) + '</td>';
            h += '<td class="mono"' + rs + '>' + (r.cvss != null ? Number(r.cvss).toFixed(1) : '\u2014') + '</td>';
            h += '<td class="mono"' + rs + '>' + (r.resource_count || 0) + '</td>';
          }
          h += '<td>' + esc(c.field) + '</td>';
          h += '<td><span class="change-old">' + fmtChangeExport(c.field, c.old) + '</span></td>';
          h += '<td><span class="change-new">' + fmtChangeExport(c.field, c.new) + '</span></td>';
          h += '</tr>';
        }
      }
      return h + '</tbody></table>';
    }

    function fmtChangeExport(field, val) {
      if (val == null) return '\u2014';
      if (field === 'severity') return '<span class="badge badge-' + val + '">' + esc(String(val)) + '</span>';
      if (field === 'is_kev') return val ? 'Yes' : 'No';
      if (field === 'cvss') return Number(val).toFixed(1);
      return esc(String(val));
    }

    const reportCss = `body{font-family:"Plus Jakarta Sans",system-ui,sans-serif;font-size:11px;color:#0f172a;margin:24px}
h1{font-size:20px;font-weight:800;margin-bottom:4px}
.sub{font-size:12px;color:#94a3b8;margin-bottom:20px}
.kpi-row{display:flex;gap:16px;margin-bottom:24px}
.kpi-card{flex:1;padding:14px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;text-align:center}
.kpi-value{font-size:22px;font-weight:800;font-family:"JetBrains Mono",monospace}
.kpi-label{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.kpi-up{color:#dc2626} .kpi-down{color:#16a34a} .kpi-neutral{color:#94a3b8}
.section{margin-bottom:28px}
.section-head{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.section-title{font-size:16px;font-weight:800}
.count-badge{padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700}
.count-new{background:rgba(239,68,68,.12);color:#dc2626}
.count-resolved{background:rgba(34,197,94,.12);color:#16a34a}
.count-changed{background:rgba(14,165,233,.12);color:#0ea5e9}
table{width:100%;border-collapse:collapse}
th{background:#f1f5f9;text-align:left;padding:6px 10px;font-size:9px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #e2e8f0}
td{padding:6px 10px;border-bottom:1px solid #f1f5f9;color:#374151;vertical-align:top}
.mono{font-family:"JetBrains Mono",monospace}
.pkg{font-family:"JetBrains Mono",monospace;font-size:10px;font-weight:600}
.badge{display:inline-block;padding:1px 6px;border-radius:12px;font-size:9px;font-weight:600}
.badge-critical{background:#fee2e2;color:#dc2626}
.badge-high{background:#fff7ed;color:#ea580c}
.badge-medium{background:#fef3c7;color:#d97706}
.badge-low{background:#d1fae5;color:#059669}
.muted{color:#94a3b8;font-style:italic}
.empty{text-align:center;padding:16px;color:#94a3b8;font-style:italic}
.change-old{text-decoration:line-through;color:#94a3b8;margin-right:6px}
.change-new{font-weight:700}`;

    const kpiHtml = '<div class="kpi-row">'
      + '<div class="kpi-card"><div class="kpi-value kpi-up">' + (newSorted.length).toLocaleString() + '</div><div class="kpi-label">New CVEs</div></div>'
      + '<div class="kpi-card"><div class="kpi-value kpi-down">' + (remSorted.length).toLocaleString() + '</div><div class="kpi-label">Resolved</div></div>'
      + '<div class="kpi-card"><div class="kpi-value kpi-neutral">' + (chgSorted.length).toLocaleString() + '</div><div class="kpi-label">Changed</div></div>'
      + '<div class="kpi-card"><div class="kpi-value ' + (net > 0 ? 'kpi-up' : net < 0 ? 'kpi-down' : 'kpi-neutral') + '">' + (net > 0 ? '+' : '') + net.toLocaleString() + '</div><div class="kpi-label">Net Change</div></div>'
      + '<div class="kpi-card"><div class="kpi-value kpi-down">' + resources_remediated.toLocaleString() + '</div><div class="kpi-label">Resources Remediated</div></div>'
      + '</div>';

    const bodyHtml = '<div class="section"><div class="section-head"><span class="section-title">New Vulnerabilities</span><span class="count-badge count-new">' + newSorted.length + '</span></div>' + cveTableHtml(newSorted) + '</div>'
      + '<div class="section"><div class="section-head"><span class="section-title">Resolved Vulnerabilities</span><span class="count-badge count-resolved">' + remSorted.length + '</span></div>' + cveTableHtml(remSorted) + '</div>'
      + '<div class="section"><div class="section-head"><span class="section-title">Changed Vulnerabilities</span><span class="count-badge count-changed">' + chgSorted.length + '</span></div>' + changedTableHtml(chgSorted) + '</div>';

    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + esc(title) + '</title><style>' + reportCss + '</style></head><body>'
      + '<h1>' + esc(title) + '</h1><div class="sub">Generated ' + new Date().toISOString().slice(0, 19).replace('T', ' ') + ' &middot; Deltas only</div>'
      + kpiHtml + bodyHtml
      + '</body></html>';

    if (format === 'html') {
      const fp = path.join(REPORTS_DIR, 'diff_' + ts + '.html');
      fs.writeFileSync(fp, html);
      return res.json({ ok: true, file: path.basename(fp) });
    }

    const fp = path.join(REPORTS_DIR, 'diff_' + ts + '.pdf');
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    await page.pdf({ path: fp, format: 'A4', landscape: true, margin: { top: '16px', bottom: '16px', left: '16px', right: '16px' } });
    await browser.close();
    return res.json({ ok: true, file: path.basename(fp) });

  } catch (err) {
    console.error('Diff export error:', err);
    return res.status(500).json({ error: err.message });
  }
});

// Executive API
app.get('/api/executive', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ snapshots: [], current: null, previous: null, diff: null, narrative: [] });
  const snapshots = conn.prepare('SELECT * FROM scan_snapshots ORDER BY scan_id ASC').all();
  if (!snapshots.length) return res.json({ snapshots: [], current: null, previous: null, diff: null, narrative: [] });

  const scanB = req.query.scan_b ? Number(req.query.scan_b) : null;
  const scanA = req.query.scan_a ? Number(req.query.scan_a) : null;

  let current, previous;
  if (scanB) {
    current = snapshots.find(s => s.scan_id === scanB) || snapshots[snapshots.length - 1];
  } else {
    current = snapshots[snapshots.length - 1];
  }
  if (scanA) {
    previous = snapshots.find(s => s.scan_id === scanA) || null;
  } else if (!scanB) {
    previous = snapshots.length > 1 ? snapshots[snapshots.length - 2] : null;
  } else {
    const idx = snapshots.findIndex(s => s.scan_id === current.scan_id);
    previous = idx > 0 ? snapshots[idx - 1] : null;
  }

  let diff = null;
  if (previous) {
    const older = Math.min(previous.scan_id, current.scan_id);
    const newer = Math.max(previous.scan_id, current.scan_id);
    const d = conn.prepare('SELECT * FROM scan_diffs WHERE scan_id_old=? AND scan_id_new=?').get(older, newer);
    if (d) {
      diff = {
        new_cves_count: d.new_cves_count, removed_cves_count: d.removed_cves_count,
        changed_cves_count: d.changed_cves_count,
        new_kev_count: d.new_kev_count, removed_kev_count: d.removed_kev_count,
        severity_summary: d.severity_summary ? JSON.parse(d.severity_summary) : {},
      };
    }
  }

  const tenant = resolveTenantSlug(req);
  const tenants = loadTenants();
  const tName = (tenants.find(t => t.slug === tenant) || {}).name || tenant;

  const narrative = [];
  narrative.push('This report represents a vulnerability assessment for ' + tName + '. The scan from ' + current.run_date + ' is shown' + (previous ? ', compared against the scan from ' + previous.run_date : '') + '.');

  narrative.push('There were ' + num(current.total_cves) + ' vulnerabilities found during this scan. Of these, ' + num(current.critical_count) + ' were critical, ' + num(current.high_count) + ' were high, ' + num(current.medium_count) + ' were medium, and ' + num(current.low_count) + ' were low severity.');

  if (current.total_kev > 0) {
    narrative.push('There are ' + num(current.total_kev) + ' known exploited vulnerabilities (KEV) that require immediate attention.');
  }

  if (previous) {
    const cveDelta = current.total_cves - previous.total_cves;
    const dir = cveDelta > 0 ? 'increased' : cveDelta < 0 ? 'decreased' : 'remained unchanged';
    narrative.push('The overall number of vulnerabilities ' + dir + ' from ' + num(previous.total_cves) + ' to ' + num(current.total_cves) + (cveDelta !== 0 ? ' (' + (cveDelta > 0 ? '+' : '') + num(cveDelta) + ')' : '') + '.');

    const critDelta = current.critical_count - previous.critical_count;
    if (critDelta > 0) {
      narrative.push('The number of critical vulnerabilities increased from ' + num(previous.critical_count) + ' to ' + num(current.critical_count) + ' (+' + num(critDelta) + '). Critical vulnerabilities require immediate attention as they may provide attackers full control of affected systems.');
    } else if (critDelta < 0) {
      narrative.push('The number of critical vulnerabilities decreased from ' + num(previous.critical_count) + ' to ' + num(current.critical_count) + ' (' + num(critDelta) + '). This represents progress in addressing the most severe vulnerabilities.');
    }

    if (diff) {
      if (diff.new_cves_count > 0) narrative.push(num(diff.new_cves_count) + ' new vulnerabilities were discovered since the previous scan.');
      if (diff.removed_cves_count > 0) narrative.push(num(diff.removed_cves_count) + ' vulnerabilities were resolved or are no longer detected.');
      if (diff.changed_cves_count > 0) narrative.push(num(diff.changed_cves_count) + ' existing vulnerabilities had their attributes updated (severity, fix status, or CVSS score changes).');
    }

    const fixedDelta = current.total_fixed - previous.total_fixed;
    if (fixedDelta > 0) {
      narrative.push(num(fixedDelta) + ' additional vulnerabilities now have fixes available compared to the previous scan.');
    }
  }

  if (current.total_fixed > 0) {
    const fixPct = ((current.total_fixed / current.total_cves) * 100).toFixed(1);
    narrative.push('Currently, ' + num(current.total_fixed) + ' of ' + num(current.total_cves) + ' vulnerabilities (' + fixPct + '%) have fixes available. It is important to address reported vulnerabilities as quickly as possible.');
  }

  res.json({ snapshots, current, previous, diff, narrative, tenant: tName });
});

function num(n) { return Number(n || 0).toLocaleString(); }

// Executive Export
app.post('/api/executive/export', async (req, res) => {
  const { format, scan_a, scan_b } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });

  const snapshots = conn.prepare('SELECT * FROM scan_snapshots ORDER BY scan_id ASC').all();
  if (!snapshots.length) return res.status(400).json({ error: 'No snapshot data' });

  let current, previous;
  if (scan_b) {
    current = snapshots.find(s => s.scan_id === Number(scan_b)) || snapshots[snapshots.length - 1];
  } else {
    current = snapshots[snapshots.length - 1];
  }
  if (scan_a) {
    previous = snapshots.find(s => s.scan_id === Number(scan_a)) || null;
  } else if (!scan_b) {
    previous = snapshots.length > 1 ? snapshots[snapshots.length - 2] : null;
  } else {
    const idx = snapshots.findIndex(s => s.scan_id === current.scan_id);
    previous = idx > 0 ? snapshots[idx - 1] : null;
  }

  let diff = null;
  if (previous) {
    const older = Math.min(previous.scan_id, current.scan_id);
    const newer = Math.max(previous.scan_id, current.scan_id);
    const d = conn.prepare('SELECT * FROM scan_diffs WHERE scan_id_old=? AND scan_id_new=?').get(older, newer);
    if (d) diff = { new_cves_count: d.new_cves_count, removed_cves_count: d.removed_cves_count, changed_cves_count: d.changed_cves_count };
  }
  const slug = resolveTenantSlug(req);
  const tenants = loadTenants();
  const tName = (tenants.find(t => t.slug === slug) || {}).name || slug;

  try {
    if (format === 'csv') {
      const ts = Date.now();
      const fp = path.join(REPORTS_DIR, 'executive_' + ts + '.csv');
      const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
      const lines = ['Metric,Current' + (previous ? ',Previous,Delta' : '')];
      const push = (label, cur, prev) => {
        let row = csvEnc(label) + ',' + csvEnc(cur);
        if (previous) { row += ',' + csvEnc(prev != null ? prev : '') + ',' + csvEnc(prev != null ? cur - prev : ''); }
        lines.push(row);
      };
      push('Total CVEs', current.total_cves, previous ? previous.total_cves : null);
      push('KEV', current.total_kev, previous ? previous.total_kev : null);
      push('Critical', current.critical_count, previous ? previous.critical_count : null);
      push('High', current.high_count, previous ? previous.high_count : null);
      push('Medium', current.medium_count, previous ? previous.medium_count : null);
      push('Low', current.low_count, previous ? previous.low_count : null);
      push('Packages', current.total_packages, previous ? previous.total_packages : null);
      push('Resources', current.total_resources, previous ? previous.total_resources : null);
      push('Avg CVSS', current.avg_cvss, previous ? previous.avg_cvss : null);
      push('Max CVSS', current.max_cvss, previous ? previous.max_cvss : null);
      if (diff) {
        lines.push(''); lines.push('Diff Metric,Count');
        lines.push(csvEnc('New CVEs') + ',' + (diff.new_cves_count || 0));
        lines.push(csvEnc('Removed CVEs') + ',' + (diff.removed_cves_count || 0));
        lines.push(csvEnc('Changed CVEs') + ',' + (diff.changed_cves_count || 0));
      }
      fs.writeFileSync(fp, lines.join('\n'));
      return res.json({ ok: true, file: path.basename(fp), format: 'csv' });
    }
    const html = renderExecutiveHtml(snapshots, current, previous, diff, tName);
    const ts = Date.now();
    if (format === 'html') {
      const fp = path.join(REPORTS_DIR, 'executive_' + ts + '.html');
      fs.writeFileSync(fp, html);
      return res.json({ ok: true, file: path.basename(fp), format: 'html' });
    }
    const fp = path.join(REPORTS_DIR, 'executive_' + ts + '.pdf');
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    await page.pdf({ path: fp, format: 'A4', landscape: true, margin: { top: '16px', bottom: '16px', left: '16px', right: '16px' } });
    await browser.close();
    res.json({ ok: true, file: path.basename(fp), format: 'pdf' });
  } catch (err) {
    console.error('Executive export error:', err);
    res.status(500).json({ error: err.message });
  }
});

function renderExecutiveHtml(snapshots, current, previous, diff, tenantName) {
  const esc = s => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const n = v => Number(v || 0).toLocaleString();
  const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  function deltaRow(label, curVal, prevVal, dec) {
    const fmt = dec != null ? (v => Number(v).toFixed(dec)) : n;
    let html = '<tr><td>' + esc(label) + '</td><td style="font-family:monospace">' + fmt(curVal) + '</td>';
    if (prevVal != null) {
      const d = curVal - prevVal;
      const pct = prevVal ? ((d / prevVal) * 100).toFixed(1) : '0';
      const color = d > 0 ? '#ef4444' : d < 0 ? '#22c55e' : '#94a3b8';
      html += '<td style="font-family:monospace">' + fmt(prevVal) + '</td>';
      html += '<td style="color:' + color + ';font-weight:600">' + (d > 0 ? '+' : '') + fmt(d) + ' (' + (d > 0 ? '+' : '') + pct + '%)</td>';
    }
    return html + '</tr>';
  }

  function sevBarSvg(label, data, prevData) {
    const sevs = ['critical', 'high', 'medium', 'low'];
    const W = 320, H = 180, pL = 40, pR = 10, pT = 10, pB = 30;
    const pW = W - pL - pR, pH = H - pT - pB;
    const vals = sevs.map(s => data[s + '_count'] || 0);
    const maxV = Math.max(...vals, 1);
    const group = pW / sevs.length;
    let svg = '<svg width="' + W + '" height="' + H + '">';
    for (let i = 0; i < sevs.length; i++) {
      const cx = pL + group * i + group / 2;
      const h = (vals[i] / maxV) * pH;
      const y = pT + pH - h;
      const bw = group * 0.5;
      svg += '<rect x="' + (cx - bw / 2) + '" y="' + y + '" width="' + bw + '" height="' + h + '" fill="' + SEV_COLORS[sevs[i]] + '" rx="3"/>';
      svg += '<text x="' + cx + '" y="' + (y - 4) + '" text-anchor="middle" fill="#0f172a" font-size="10" font-weight="700" font-family="monospace">' + n(vals[i]) + '</text>';
      svg += '<text x="' + cx + '" y="' + (H - 6) + '" text-anchor="middle" fill="#94a3b8" font-size="9">' + sevs[i].charAt(0).toUpperCase() + sevs[i].slice(1) + '</text>';
    }
    svg += '</svg>';
    return svg;
  }

  function sevTrendSvg(current, previous) {
    if (!previous) return '<p style="color:#94a3b8;text-align:center">Need previous scan for comparison</p>';
    const sevs = ['critical', 'high', 'medium', 'low'];
    const W = 320, H = 200, pL = 40, pR = 10, pT = 10, pB = 50;
    const pW = W - pL - pR, pH = H - pT - pB;
    const allVals = sevs.flatMap(s => [current[s + '_count'] || 0, previous[s + '_count'] || 0]);
    const maxV = Math.max(...allVals, 1);
    const group = pW / sevs.length;
    const bw = group * 0.28;
    let svg = '<svg width="' + W + '" height="' + H + '">';
    for (let i = 0; i < sevs.length; i++) {
      const cx = pL + group * i + group / 2;
      const pv = previous[sevs[i] + '_count'] || 0;
      const cv = current[sevs[i] + '_count'] || 0;
      const hP = (pv / maxV) * pH, hC = (cv / maxV) * pH;
      svg += '<rect x="' + (cx - bw - 1) + '" y="' + (pT + pH - hP) + '" width="' + bw + '" height="' + hP + '" fill="#94a3b8" opacity="0.4" rx="2"/>';
      svg += '<rect x="' + (cx + 1) + '" y="' + (pT + pH - hC) + '" width="' + bw + '" height="' + hC + '" fill="' + SEV_COLORS[sevs[i]] + '" rx="2"/>';
      svg += '<text x="' + cx + '" y="' + (H - 30) + '" text-anchor="middle" fill="#94a3b8" font-size="9">' + sevs[i].charAt(0).toUpperCase() + sevs[i].slice(1) + '</text>';
    }
    svg += '<rect x="' + pL + '" y="' + (H - 16) + '" width="10" height="8" fill="#94a3b8" opacity="0.4" rx="2"/>';
    svg += '<text x="' + (pL + 14) + '" y="' + (H - 9) + '" fill="#94a3b8" font-size="8">Previous</text>';
    svg += '<rect x="' + (pL + 70) + '" y="' + (H - 16) + '" width="10" height="8" fill="#0ea5e9" rx="2"/>';
    svg += '<text x="' + (pL + 84) + '" y="' + (H - 9) + '" fill="#94a3b8" font-size="8">Current</text>';
    svg += '</svg>';
    return svg;
  }

  const narrative = [];
  narrative.push('This report represents a vulnerability assessment for ' + esc(tenantName) + '. The most recent scan was performed on ' + esc(current.run_date) + '.');
  narrative.push('There were ' + n(current.total_cves) + ' vulnerabilities found. Of these, ' + n(current.critical_count) + ' were critical, ' + n(current.high_count) + ' high, ' + n(current.medium_count) + ' medium, and ' + n(current.low_count) + ' low severity.');
  if (current.total_kev > 0) narrative.push(n(current.total_kev) + ' known exploited vulnerabilities (KEV) require immediate attention.');
  if (previous) {
    const cveDelta = current.total_cves - previous.total_cves;
    narrative.push('Compared to the previous scan (' + esc(previous.run_date) + '), total vulnerabilities ' + (cveDelta > 0 ? 'increased' : cveDelta < 0 ? 'decreased' : 'remained unchanged') + (cveDelta ? ' by ' + Math.abs(cveDelta).toLocaleString() : '') + '.');
    if (diff) {
      if (diff.new_cves_count) narrative.push(n(diff.new_cves_count) + ' new vulnerabilities were discovered.');
      if (diff.removed_cves_count) narrative.push(n(diff.removed_cves_count) + ' vulnerabilities were resolved.');
      if (diff.changed_cves_count) narrative.push(n(diff.changed_cves_count) + ' vulnerabilities had attribute changes.');
    }
  }
  if (current.total_fixed > 0) {
    const pct = ((current.total_fixed / current.total_cves) * 100).toFixed(1);
    narrative.push(n(current.total_fixed) + ' of ' + n(current.total_cves) + ' vulnerabilities (' + pct + '%) have fixes available.');
  }

  const css = `body{font-family:"Plus Jakarta Sans",system-ui,sans-serif;font-size:11px;color:#0f172a;margin:24px;line-height:1.5}
h1{font-size:22px;font-weight:800;margin:0 0 4px}
h2{font-size:15px;font-weight:700;margin:24px 0 10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
.meta{font-size:11px;color:#94a3b8;margin-bottom:20px}
table{width:100%;border-collapse:collapse;margin-bottom:16px}
th{text-align:left;padding:5px 8px;font-size:9px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;background:#f8fafc}
td{padding:5px 8px;border-bottom:1px solid #f1f5f9}
.chart-row{display:flex;gap:24px;margin-bottom:16px}
.chart-col{flex:1}
.chart-label{font-size:11px;font-weight:700;color:#374151;margin-bottom:8px}
.narrative p{margin:0 0 10px;line-height:1.7;font-size:11px;color:#374151}
.narrative p:last-child{margin:0}`;

  let html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Executive Summary — ' + esc(tenantName) + '</title><style>' + css + '</style></head><body>';
  html += '<h1>Executive Summary</h1>';
  html += '<div class="meta">' + esc(tenantName) + ' — Scan: ' + esc(current.run_date) + (previous ? ' | Compared to: ' + esc(previous.run_date) : '') + '</div>';

  html += '<h2>Assets Summary</h2>';
  html += '<table><thead><tr><th>Metric</th><th>Current</th>' + (previous ? '<th>Previous</th><th>Change</th>' : '') + '</tr></thead><tbody>';
  html += deltaRow('Total CVEs', current.total_cves, previous ? previous.total_cves : null);
  html += deltaRow('Critical', current.critical_count, previous ? previous.critical_count : null);
  html += deltaRow('High', current.high_count, previous ? previous.high_count : null);
  html += deltaRow('Medium', current.medium_count, previous ? previous.medium_count : null);
  html += deltaRow('Low', current.low_count, previous ? previous.low_count : null);
  html += deltaRow('KEV', current.total_kev, previous ? previous.total_kev : null);
  html += deltaRow('Packages', current.total_packages, previous ? previous.total_packages : null);
  html += deltaRow('Resources', current.total_resources, previous ? previous.total_resources : null);
  html += deltaRow('Avg CVSS', current.avg_cvss, previous ? previous.avg_cvss : null, 1);
  html += deltaRow('Max CVSS', current.max_cvss, previous ? previous.max_cvss : null, 1);
  html += '</tbody></table>';

  html += '<div class="chart-row">';
  html += '<div class="chart-col"><div class="chart-label">Vulnerabilities by Severity</div>' + sevBarSvg('Current', current) + '</div>';
  html += '<div class="chart-col"><div class="chart-label">Severity Trend</div>' + sevTrendSvg(current, previous) + '</div>';
  html += '</div>';

  html += '<h2>Analysis</h2>';
  html += '<div class="narrative">' + narrative.map(p => '<p>' + p + '</p>').join('') + '</div>';

  html += '<div style="margin-top:20px;font-size:9px;color:#94a3b8;text-align:center">Generated ' + new Date().toISOString().slice(0, 19).replace('T', ' ') + '</div>';
  html += '</body></html>';
  return html;
}

// Explorer API
app.get('/api/explorer', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ rows: [], total: 0, page: 1, pageSize: 50 });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json({ rows: [], total: 0, page: 1, pageSize: 50 });
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(200, Math.max(10, parseInt(req.query.pageSize) || 50));
  const sortBy = req.query.sort_by || 'cvss';
  const sortDir = req.query.sort_dir === 'ASC' ? 'ASC' : 'DESC';
  const search = (req.query.q || '').trim();
  const filters = req.query.filters ? JSON.parse(req.query.filters) : {};
  let where = ['c.scan_id=?'], params = [scanId], joins = '';
  if (filters.severity && filters.severity.length) { where.push('c.severity IN (' + filters.severity.map(()=>'?').join(',') + ')'); params.push(...filters.severity); }
  if (filters.fix_status && filters.fix_status.length) { where.push('c.fix_status IN (' + filters.fix_status.map(()=>'?').join(',') + ')'); params.push(...filters.fix_status); }
  if (filters.is_kev === true || filters.is_kev === 'true') { where.push('c.is_kev=1'); }
  if (filters.os && filters.os.length) {
    const allOsRaw = conn.prepare('SELECT DISTINCT os_label FROM cve_os_labels WHERE scan_id=?').all(scanId).map(r => r.os_label);
    const resolved = allOsRaw.filter(l => filters.os.includes(normalizeOs(l)));
    if (resolved.length) { joins += ' JOIN cve_os_labels ol ON ol.cve_id=c.cve_id AND ol.scan_id=c.scan_id'; where.push('ol.os_label IN (' + resolved.map(()=>'?').join(',') + ')'); params.push(...resolved); }
  }
  if (filters.risk_factor && filters.risk_factor.length) { joins += ' JOIN cve_risk_factors rf ON rf.cve_id=c.cve_id AND rf.scan_id=c.scan_id'; where.push('rf.risk_factor IN (' + filters.risk_factor.map(()=>'?').join(',') + ')'); params.push(...filters.risk_factor); }
  if (filters.collection && filters.collection.length) { joins += ' JOIN cve_collections cc ON cc.cve_id=c.cve_id AND cc.scan_id=c.scan_id'; where.push('cc.collection IN (' + filters.collection.map(()=>'?').join(',') + ')'); params.push(...filters.collection); }
  if (filters.repo && filters.repo.length) { joins += ' JOIN cve_repos cr ON cr.cve_id=c.cve_id AND cr.scan_id=c.scan_id'; where.push('cr.repo IN (' + filters.repo.map(()=>'?').join(',') + ')'); params.push(...filters.repo); }
  if (filters.resource_type && filters.resource_type.length) { joins += ' JOIN cve_resources rtr ON rtr.cve_id=c.cve_id AND rtr.scan_id=c.scan_id'; where.push('rtr.resource_type IN (' + filters.resource_type.map(()=>'?').join(',') + ')'); params.push(...filters.resource_type); }
  if (search) {
    joins += ' LEFT JOIN cve_packages sp ON sp.cve_id=c.cve_id AND sp.scan_id=c.scan_id';
    joins += ' LEFT JOIN cve_resources sr ON sr.cve_id=c.cve_id AND sr.scan_id=c.scan_id';
    where.push('(c.cve_id LIKE ? OR c.description LIKE ? OR c.fix_status LIKE ? OR sp.package_name LIKE ? OR sr.resource_name LIKE ?)');
    const q = '%' + search + '%';
    params.push(q, q, q, q, q);
  }
  const allowed = ['cvss','cve_id','severity','fix_status','is_kev'];
  const rs = allowed.includes(sortBy) ? sortBy : 'cvss';
  const order = rs === 'severity' ? "ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END " + sortDir : 'ORDER BY c.' + rs + ' ' + sortDir;
  const baseSql = 'FROM cves c' + joins + ' WHERE ' + where.join(' AND ');
  const countRow = conn.prepare('SELECT COUNT(DISTINCT c.cve_id) as cnt ' + baseSql).get(...params);
  const total = countRow ? countRow.cnt : 0;
  const offset = (page - 1) * pageSize;
  const dataParams = [...params, pageSize, offset];
  const rows = conn.prepare('SELECT DISTINCT c.* ' + baseSql + ' ' + order + ' LIMIT ? OFFSET ?').all(...dataParams);
  const ALL_COLS = ['cve_id','severity','cvss','description','fix_status','is_kev','packages','resources','risk_factors','os_labels','repos','collections','link'];
  const enriched = rows.map(c => { const e = enrichCve(conn, c, scanId, true); const out = {}; for (const col of ALL_COLS) out[col] = e[col]; return out; });
  res.json({ rows: enriched, total, page, pageSize });
});

app.post('/api/explorer/export', async (req, res) => {
  const { format, filters: clientFilters, q, sort_by, sort_dir, columns: clientCols, group_by } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const ALL_COLS = ['cve_id','severity','cvss','description','fix_status','is_kev','packages','resources','risk_factors','os_labels','repos','collections','link'];
  const useCols = (Array.isArray(clientCols) && clientCols.length) ? clientCols.filter(c => ALL_COLS.includes(c)) : ALL_COLS;
  const config = {
    data_source: 'all',
    filters: clientFilters || {},
    columns: ALL_COLS,
    sort_by: sort_by || 'cvss',
    sort_dir: sort_dir || 'DESC',
    limit: 5000,
  };
  if (clientFilters && clientFilters.is_kev) { config.data_source = 'kev'; delete config.filters.is_kev; }
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database available for this tenant' });
  try {
    let rows = executeReportQuery(config, conn);
    if (q && q.trim()) {
      const s = q.trim().toLowerCase();
      rows = rows.filter(r => {
        if (r.cve_id && r.cve_id.toLowerCase().includes(s)) return true;
        if (r.description && r.description.toLowerCase().includes(s)) return true;
        if (r.fix_status && r.fix_status.toLowerCase().includes(s)) return true;
        if (r.packages && typeof r.packages === 'object') { for (const k of Object.keys(r.packages)) { if (k.toLowerCase().includes(s)) return true; } }
        if (r.resources && typeof r.resources === 'object') { for (const list of Object.values(r.resources)) { if (Array.isArray(list)) { for (const res of list) { if (res.name && res.name.toLowerCase().includes(s)) return true; } } } }
        return false;
      });
    }
    const title = 'Explorer Export';
    const ts = Date.now();
    if (format === 'csv') {
      const { headers, headerLabels, flatRows, sourceIndices } = flattenForCsv(rows, useCols);
      const fp = path.join(REPORTS_DIR, 'explorer_' + ts + '.csv');
      const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
      function csvVal(h, v) {
        if (h === 'is_kev') return v ? 'Yes' : 'No';
        return v;
      }
      const GB_LABELS = { severity:'Severity', fix_status:'Fix Status', resource_type:'Resource Type', collection:'Collection', os:'OS', risk_factor:'Risk Factor' };
      const gbField = group_by || '';
      const RT_MAP_CSV = { host:'Hosts', image:'Images', registryImage:'Registry' };
      function csvGroupVal(r, field) {
        if (field === 'severity') return r.severity || '';
        if (field === 'fix_status') return r.fix_status || '';
        if (field === 'resource_type') { if (!r.resources || typeof r.resources !== 'object') return ''; const t = Object.keys(r.resources).filter(k => (r.resources[k]||[]).length); return t.map(k => RT_MAP_CSV[k]||k).join('; '); }
        if (field === 'collection') return (Array.isArray(r.collections) ? r.collections : []).join('; ');
        if (field === 'os') return (Array.isArray(r.os_labels) ? r.os_labels : []).join('; ');
        if (field === 'risk_factor') return (Array.isArray(r.risk_factors) ? r.risk_factors : []).join('; ');
        return '';
      }
      const csvHeaders = gbField ? [GB_LABELS[gbField] || gbField, ...headerLabels] : headerLabels;
      const lines = [csvHeaders.map(csvEnc).join(',')];
      for (let i = 0; i < flatRows.length; i++) {
        const row = flatRows[i];
        const origRow = rows[sourceIndices[i]];
        if (gbField) {
          const gv = csvGroupVal(origRow, gbField);
          lines.push([csvEnc(gv), ...headers.map(h => csvEnc(csvVal(h, row[h])))].join(','));
        } else {
          lines.push(headers.map(h => csvEnc(csvVal(h, row[h]))).join(','));
        }
      }
      fs.writeFileSync(fp, lines.join('\n'));
      const tenant = resolveTenantSlug(req);
      return res.json({ ok: true, file: path.basename(fp), count: rows.length, tenant });
    }
    const result = await generateReportFromRows(rows, useCols, title, format, group_by || '');
    const tenant = resolveTenantSlug(req);
    res.json({ ok: true, file: path.basename(result.file), format: result.format, count: rows.length, tenant });
  } catch (err) { console.error('Explorer export error:', err); res.status(500).json({ error: err.message }); }
});

app.get('/api/explorer/fix-statuses', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json([]);
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json([]);
  const rows = conn.prepare('SELECT DISTINCT fix_status FROM cves WHERE scan_id=? AND fix_status IS NOT NULL ORDER BY fix_status').all(scanId);
  res.json(rows.map(r => r.fix_status));
});

// ── Host Report ──

app.get('/api/hosts', (req, res) => {
  const conn = getDb(req);
  if (!conn) return res.json({ hosts: [], summary: {}, total: 0 });
  const scanId = resolveScanId(req, conn);
  if (!scanId) return res.json({ hosts: [], summary: {}, total: 0 });

  const hostNames = conn.prepare("SELECT DISTINCT resource_name, os_label FROM cve_resources WHERE scan_id=? AND resource_type='host'").all(scanId);
  if (!hostNames.length) return res.json({ hosts: [], summary: { total_hosts: 0, total_cves: 0 }, total: 0 });

  const cveIds = conn.prepare("SELECT DISTINCT cve_id FROM cve_resources WHERE scan_id=? AND resource_type='host'").all(scanId).map(r => r.cve_id);
  if (!cveIds.length) return res.json({ hosts: [], summary: { total_hosts: hostNames.length, total_cves: 0 }, total: 0 });

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(200, Math.max(10, parseInt(req.query.pageSize) || 50));
  const sortBy = req.query.sort_by || 'cvss';
  const sortDir = req.query.sort_dir === 'ASC' ? 'ASC' : 'DESC';
  const search = (req.query.q || '').trim();
  const sevFilter = req.query.severity ? req.query.severity.split(',') : null;

  let where = ['c.scan_id=?', 'c.cve_id IN (' + cveIds.map(() => '?').join(',') + ')'];
  let params = [scanId, ...cveIds];
  if (sevFilter && sevFilter.length) {
    where.push('c.severity IN (' + sevFilter.map(() => '?').join(',') + ')');
    params.push(...sevFilter);
  }
  if (search) {
    where.push('(c.cve_id LIKE ? OR c.description LIKE ?)');
    params.push('%' + search + '%', '%' + search + '%');
  }

  const allowed = ['cvss','cve_id','severity','fix_status','is_kev'];
  const rs = allowed.includes(sortBy) ? sortBy : 'cvss';
  const order = rs === 'severity' ? "ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END " + sortDir : 'ORDER BY c.' + rs + ' ' + sortDir;

  const countRow = conn.prepare('SELECT COUNT(*) as cnt FROM cves c WHERE ' + where.join(' AND ')).get(...params);
  const total = countRow ? countRow.cnt : 0;
  const offset = (page - 1) * pageSize;
  const rows = conn.prepare('SELECT c.* FROM cves c WHERE ' + where.join(' AND ') + ' ' + order + ' LIMIT ? OFFSET ?').all(...params, pageSize, offset);
  const enriched = rows.map(c => enrichCve(conn, c, scanId, true));

  const sevCounts = {};
  const allCvesPh = cveIds.map(() => '?').join(',');
  for (const r of conn.prepare('SELECT severity, COUNT(*) as cnt FROM cves WHERE scan_id=? AND cve_id IN (' + allCvesPh + ') GROUP BY severity').all(scanId, ...cveIds)) sevCounts[r.severity] = r.cnt;
  const totalCves = Object.values(sevCounts).reduce((a, b) => a + b, 0);
  const kevCount = conn.prepare('SELECT COUNT(*) as cnt FROM cves WHERE scan_id=? AND is_kev=1 AND cve_id IN (' + allCvesPh + ')').get(scanId, ...cveIds).cnt || 0;

  const osMap = {};
  for (const h of hostNames) { const os = normalizeOs(h.os_label); osMap[os] = (osMap[os] || 0) + 1; }

  res.json({
    rows: enriched, total, page, pageSize,
    summary: { total_hosts: hostNames.length, total_cves: totalCves, kev: kevCount, severity: sevCounts, os_breakdown: osMap },
  });
});

app.post('/api/hosts/export', async (req, res) => {
  const { format, severity, q } = req.body;
  if (!format) return res.status(400).json({ error: 'format required' });
  const conn = getDb(req);
  if (!conn) return res.status(400).json({ error: 'No database' });
  const scanId = (() => { const r = conn.prepare('SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1').get(); return r ? r.id : null; })();
  if (!scanId) return res.status(400).json({ error: 'No scan data' });

  const cveIds = conn.prepare("SELECT DISTINCT cve_id FROM cve_resources WHERE scan_id=? AND resource_type='host'").all(scanId).map(r => r.cve_id);
  if (!cveIds.length) return res.status(400).json({ error: 'No host CVEs' });

  let where = ['c.scan_id=?', 'c.cve_id IN (' + cveIds.map(() => '?').join(',') + ')'];
  let params = [scanId, ...cveIds];
  if (severity && severity.length) { where.push('c.severity IN (' + severity.map(() => '?').join(',') + ')'); params.push(...severity); }
  if (q && q.trim()) { where.push('(c.cve_id LIKE ? OR c.description LIKE ?)'); params.push('%' + q.trim() + '%', '%' + q.trim() + '%'); }

  const rows = conn.prepare("SELECT c.* FROM cves c WHERE " + where.join(' AND ') + " ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, c.cvss DESC LIMIT 5000").all(...params);
  const ALL_COLS = ['cve_id','severity','cvss','description','fix_status','is_kev','packages','resources','risk_factors','os_labels','repos','collections','link'];
  const enriched = rows.map(c => { const e = enrichCve(conn, c, scanId, true); const out = {}; for (const col of ALL_COLS) out[col] = e[col]; return out; });

  try {
    const title = 'Host Vulnerability Report';
    const ts = Date.now();
    if (format === 'csv') {
      const { headers, headerLabels, flatRows } = flattenForCsv(enriched, ALL_COLS);
      const fp = path.join(REPORTS_DIR, 'hosts_' + ts + '.csv');
      const csvEnc = v => { if (v == null) return ''; return '"' + String(v).replace(/"/g, '""') + '"'; };
      function csvVal(h, v) { if (h === 'is_kev') return v ? 'Yes' : 'No'; return v; }
      const lines = [headerLabels.map(csvEnc).join(',')];
      for (const row of flatRows) lines.push(headers.map(h => csvEnc(csvVal(h, row[h]))).join(','));
      fs.writeFileSync(fp, lines.join('\n'));
      return res.json({ ok: true, file: path.basename(fp), count: enriched.length, tenant: resolveTenantSlug(req) });
    }
    const result = await generateReportFromRows(enriched, ALL_COLS, title, format, '');
    res.json({ ok: true, file: path.basename(result.file), format: result.format, count: enriched.length, tenant: resolveTenantSlug(req) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => {
  const ts = loadTenants();
  console.log('Vulnerability Report Server');
  console.log('  Tenants:  ' + ts.map(t => t.name + ' (' + t.slug + ')').join(', '));
  console.log('  URL:      http://localhost:' + PORT);
  loadScheduledJobs();
});
