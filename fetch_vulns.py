#!/usr/bin/env python3
"""
Fetch vulnerability data from Prisma Cloud (Twistlock) CWP API
using the PCPI module, then store results in per-tenant SQLite databases.

Reads tenants.json to determine which tenants to fetch and where to write.

Endpoints:
  - /api/v1/images    (deployed container images)
  - /api/v1/registry  (registry images)
  - /api/v1/hosts     (hosts)

Usage:
  pip install pcpi
  python3 fetch_vulns.py                          # fetch all tenants
  python3 fetch_vulns.py --tenant pcs_cloud_cwp   # single tenant
  python3 fetch_vulns.py --json-cache raw.json     # dev: skip API calls (single tenant only)

On first run, PCPI will prompt for console URL, access key, and secret key.
Credentials are cached at ~/.prismacloud/credentials.json for subsequent runs.
"""

import json
import sys
import re
import time
import argparse
import datetime
import sqlite3
import os
from collections import defaultdict

HAS_PCPI = False
try:
    from pcpi import session_loader
    HAS_PCPI = True
except ImportError:
    pass

API_VERSION = "v1"
ENDPOINTS = {
    "image":         f"/api/{API_VERSION}/images",
    "registryImage": f"/api/{API_VERSION}/registry",
    "host":          f"/api/{API_VERSION}/hosts",
}
PAGE_LIMIT = 50
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


# ── Tenant config ─────────────────────────────────────────────

TENANTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tenants.json")
CRED_FILE = os.path.expanduser("~/.prismacloud/credentials.json")

def generate_tenants_from_creds():
    try:
        with open(CRED_FILE) as f:
            creds = json.load(f)
        if not isinstance(creds, list) or not creds:
            return None
        tenants = []
        for i, c in enumerate(creds):
            name = c.get("name") or c.get("url") or f"Tenant {i + 1}"
            slug = re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_') or f"tenant_{i}"
            tenants.append({
                "slug": slug,
                "name": name,
                "db_file": f"/app/data/vuln_data_{slug}.db",
                "cred_index": i
            })
        with open(TENANTS_FILE, 'w') as f:
            json.dump(tenants, f, indent=2)
            f.write('\n')
        print(f"Auto-generated tenants.json with {len(tenants)} tenant(s) from credentials")
        return tenants
    except Exception as e:
        print(f"Could not auto-generate tenants.json: {e}")
        return None

def load_tenants():
    try:
        with open(TENANTS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: Could not load {TENANTS_FILE}: {e}")
        generated = generate_tenants_from_creds()
        if generated:
            return generated
        default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_data.db")
        return [{"slug": "default", "name": "Default", "db_file": default_db, "cred_index": 0}]


# ── Authentication ─────────────────────────────────────────────

def get_cwp_session(cred_path=None):
    if not HAS_PCPI:
        print("ERROR: pcpi is not installed. Run: pip install pcpi")
        sys.exit(1)
    if cred_path:
        managers = session_loader.load_config(file_path=cred_path)
    else:
        managers = session_loader.load_config()
    return managers


def get_session_for_tenant(managers, cred_index):
    if cred_index >= len(managers):
        print(f"  WARNING: cred_index {cred_index} out of range ({len(managers)} credentials available)")
        return None
    return managers[cred_index].create_cwp_session()


# ── Paginated API fetch ───────────────────────────────────────

def fetch_all_pages(session, endpoint, params=None):
    if params is None:
        params = {}
    all_data = []
    offset = 0
    while True:
        p = {**params, "limit": PAGE_LIMIT, "offset": offset}
        resp = session.request("GET", endpoint, params=p)
        if resp.status_code != 200:
            print(f"  WARNING: {endpoint} returned {resp.status_code} at offset {offset}")
            break
        page = resp.json()
        if not page:
            break
        all_data.extend(page)
        print(f"  {endpoint}: fetched {len(all_data)} resources ...", end="\r")
        if len(page) < PAGE_LIMIT:
            break
        offset += PAGE_LIMIT
        time.sleep(0.3)
    print(f"  {endpoint}: {len(all_data)} total resources")
    return all_data


# ── Data extraction helpers ───────────────────────────────────

def extract_distro(resource):
    distro = (resource.get("osDistro") or resource.get("distro") or "").strip()
    if not distro:
        return "Unknown"
    return _normalize_os(distro)


def _normalize_os(distro):
    """Return distro family without version numbers.

    Windows is kept as-is (e.g. Windows Server 2019, Windows 10).
    Linux/other distros have version numbers stripped:
      Ubuntu 22.04 → Ubuntu, Debian 11 → Debian, Alpine 3.18.4 → Alpine
    """
    d = distro.strip()
    if d.lower().startswith("windows"):
        return d

    cleaned = re.sub(r"\s+[\d][\d.]*.*$", "", d)
    return cleaned if cleaned else d


def extract_resource_name(resource, rtype):
    if rtype == "host":
        return resource.get("hostname", resource.get("_id", "unknown-host"))
    tags = resource.get("repoTag", resource.get("repoTags"))
    if tags:
        if isinstance(tags, list) and tags:
            tag = tags[0]
        elif isinstance(tags, dict):
            tag = tags
        else:
            tag = {}
        repo = tag.get("repo", "")
        t = tag.get("tag", "latest")
        reg = tag.get("registry", "")
        if reg and repo:
            return f"{reg}/{repo}:{t}"
        if repo:
            return f"{repo}:{t}"
    return resource.get("_id", "unknown-image")[:80]


def extract_namespaces(resource):
    ns = set()
    for n in resource.get("namespaces", []):
        if n:
            ns.add(n)
    for c in resource.get("clusters", []):
        if c:
            ns.add(c)
    return ns


def extract_collections(resource):
    raw = resource.get("collections", []) or []
    return {c for c in raw if "Access Group (RBAC)" not in c}


def extract_repos(resource):
    repos = set()
    tags = resource.get("repoTag", resource.get("repoTags"))
    if tags:
        if isinstance(tags, list):
            for t in tags:
                if isinstance(t, dict) and t.get("repo"):
                    repos.add(t["repo"])
        elif isinstance(tags, dict) and tags.get("repo"):
            repos.add(tags["repo"])
    return repos


def extract_risk_factors(vuln):
    rfs = set()
    for rf in vuln.get("riskFactors", {}) or {}:
        if rf:
            rfs.add(rf)
    return rfs


def process_resource(resource, rtype, cve_map, comp_map=None, res_collections=None):
    resource_name = extract_resource_name(resource, rtype)
    os_label = extract_distro(resource)
    namespaces = extract_namespaces(resource)
    collections = extract_collections(resource)
    repos = extract_repos(resource)

    if res_collections is not None and collections:
        key = (resource_name, rtype)
        if key not in res_collections:
            res_collections[key] = set()
        res_collections[key].update(collections)

    vulns = resource.get("vulnerabilities") or []
    for v in vulns:
        cve_id = v.get("cve", "")
        if not cve_id:
            continue
        severity = (v.get("severity", "") or "").lower()
        if severity not in SEVERITY_ORDER:
            continue

        pkg_name = v.get("packageName", "")
        pkg_version = v.get("packageVersion", "")
        cvss = v.get("cvss", 0) or 0
        link = v.get("link", "")
        description = v.get("description", "")
        fix_status = v.get("status", "")
        is_kev = 1 if v.get("cisa", False) or v.get("knownExploit", False) else 0
        risk_factors = extract_risk_factors(v)
        if "Exploit exists - in the wild" in risk_factors:
            is_kev = 1

        if cve_id not in cve_map:
            cve_map[cve_id] = {
                "severity": severity,
                "description": description,
                "link": link,
                "cvss": cvss,
                "fix_status": fix_status,
                "is_kev": is_kev,
                "packages": {},
                "resources": {},
                "os_labels": set(),
                "risk_factors": set(),
                "repos": set(),
            }

        entry = cve_map[cve_id]
        if cvss and cvss > entry["cvss"]:
            entry["cvss"] = cvss
        if is_kev:
            entry["is_kev"] = 1

        if pkg_name:
            if pkg_name not in entry["packages"]:
                entry["packages"][pkg_name] = set()
            if pkg_version:
                entry["packages"][pkg_name].add(pkg_version)

        if rtype not in entry["resources"]:
            entry["resources"][rtype] = {}
        rt = entry["resources"][rtype]
        if resource_name not in rt:
            rt[resource_name] = {"os": os_label, "namespaces": set()}
        rt[resource_name]["namespaces"].update(namespaces)

        entry["os_labels"].add(os_label)
        entry["risk_factors"].update(risk_factors)
        entry["repos"].update(repos)

    if comp_map is not None:
        for ci in resource.get("complianceIssues") or []:
            cid = ci.get("id")
            if not cid:
                continue
            severity = (ci.get("severity", "") or "").lower()
            if severity not in SEVERITY_ORDER:
                severity = "low"
            if cid not in comp_map:
                comp_map[cid] = {
                    "severity": severity,
                    "title": ci.get("title", ""),
                    "description": ci.get("description", ""),
                    "cause": ci.get("cause", ""),
                    "comp_type": ci.get("type", ""),
                    "templates": list(ci.get("templates") or []),
                    "resources": {},
                }
            entry_c = comp_map[cid]
            if rtype not in entry_c["resources"]:
                entry_c["resources"][rtype] = {}
            entry_c["resources"][rtype][resource_name] = os_label


# ── SQLite schema ─────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date TEXT NOT NULL,
    total_cves INTEGER DEFAULT 0,
    total_kev INTEGER DEFAULT 0,
    total_packages INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    link TEXT,
    cvss REAL DEFAULT 0,
    fix_status TEXT,
    is_kev INTEGER DEFAULT 0,
    PRIMARY KEY (cve_id, scan_id),
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cve_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cve_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    resource_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    os_label TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cve_resource_namespaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    namespace TEXT NOT NULL,
    FOREIGN KEY (resource_id) REFERENCES cve_resources(id)
);

CREATE TABLE IF NOT EXISTS cve_risk_factors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    risk_factor TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cve_os_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    os_label TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS cve_repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    repo TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS resource_collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    scan_id INTEGER NOT NULL,
    collection TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_cves_scan_sev ON cves(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_cves_scan_kev ON cves(scan_id, is_kev);
CREATE INDEX IF NOT EXISTS idx_pkg_cve ON cve_packages(cve_id, scan_id);
CREATE INDEX IF NOT EXISTS idx_res_cve ON cve_resources(cve_id, scan_id);
CREATE INDEX IF NOT EXISTS idx_ns_res ON cve_resource_namespaces(resource_id);
CREATE INDEX IF NOT EXISTS idx_rf_cve ON cve_risk_factors(cve_id, scan_id);
CREATE INDEX IF NOT EXISTS idx_os_cve ON cve_os_labels(cve_id, scan_id);
CREATE INDEX IF NOT EXISTS idx_repo_cve ON cve_repos(cve_id, scan_id);
CREATE INDEX IF NOT EXISTS idx_rescol_res ON resource_collections(resource_name, scan_id);
CREATE INDEX IF NOT EXISTS idx_rescol_col ON resource_collections(collection, scan_id);

CREATE TABLE IF NOT EXISTS compliance_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comp_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    title TEXT,
    description TEXT,
    cause TEXT,
    comp_type TEXT,
    templates TEXT,
    UNIQUE(comp_id, scan_id)
);

CREATE TABLE IF NOT EXISTS compliance_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comp_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    resource_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    os_label TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_comp_scan_sev ON compliance_issues(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_compres_scan ON compliance_resources(comp_id, scan_id);

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
    scan_id_old INTEGER NOT NULL,
    scan_id_new INTEGER NOT NULL,
    computed_at TEXT DEFAULT (datetime('now')),
    new_cves_count INTEGER DEFAULT 0, removed_cves_count INTEGER DEFAULT 0,
    changed_cves_count INTEGER DEFAULT 0,
    new_kev_count INTEGER DEFAULT 0, removed_kev_count INTEGER DEFAULT 0,
    severity_summary TEXT,
    diff_detail TEXT,
    UNIQUE(scan_id_old, scan_id_new)
);
"""


def write_to_sqlite(db_path, cve_map, comp_map=None, res_collections=None):
    print(f"\nWriting to {db_path} ...")
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    # Migrate: if compliance_issues exists but lacks comp_id column, recreate it
    try:
        conn.execute("SELECT comp_id FROM compliance_issues LIMIT 1")
    except sqlite3.OperationalError:
        conn.executescript("""
            DROP TABLE IF EXISTS compliance_issues;
            DROP TABLE IF EXISTS compliance_resources;
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
        """)

    run_date = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    total_cves = len(cve_map)
    total_kev = sum(1 for d in cve_map.values() if d["is_kev"])
    total_pkgs = len({pkg for d in cve_map.values() for pkg in d["packages"]})

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scan_runs (run_date, total_cves, total_kev, total_packages) VALUES (?,?,?,?)",
        (run_date, total_cves, total_kev, total_pkgs),
    )
    scan_id = cur.lastrowid
    print(f"  Scan ID: {scan_id}")

    cve_rows = []
    pkg_rows = []
    res_pending = []
    rf_rows = []
    os_rows = []
    repo_rows = []

    for cve_id, data in cve_map.items():
        cve_rows.append((
            cve_id, scan_id, data["severity"], data.get("description", ""),
            data.get("link", ""), data.get("cvss", 0), data.get("fix_status", ""),
            data.get("is_kev", 0),
        ))

        for pkg_name, versions in data["packages"].items():
            if versions:
                for ver in versions:
                    pkg_rows.append((cve_id, scan_id, pkg_name, ver))
            else:
                pkg_rows.append((cve_id, scan_id, pkg_name, None))

        for rtype, resources in data["resources"].items():
            for rname, rinfo in resources.items():
                res_pending.append((
                    cve_id, scan_id, rname, rtype,
                    rinfo.get("os", ""),
                    list(rinfo.get("namespaces", set())),
                ))

        for rf in data.get("risk_factors", set()):
            rf_rows.append((cve_id, scan_id, rf))

        for ol in data.get("os_labels", set()):
            os_rows.append((cve_id, scan_id, ol))

        for repo in data.get("repos", set()):
            repo_rows.append((cve_id, scan_id, repo))

    print(f"  CVEs: {len(cve_rows)}")
    cur.executemany(
        "INSERT OR REPLACE INTO cves (cve_id,scan_id,severity,description,link,cvss,fix_status,is_kev) VALUES (?,?,?,?,?,?,?,?)",
        cve_rows,
    )

    print(f"  Packages: {len(pkg_rows)}")
    cur.executemany(
        "INSERT INTO cve_packages (cve_id,scan_id,package_name,package_version) VALUES (?,?,?,?)",
        pkg_rows,
    )

    print(f"  Resources: {len(res_pending)}")
    ns_rows = []
    for cve_id, sid, rname, rtype, os_label, namespaces in res_pending:
        cur.execute(
            "INSERT INTO cve_resources (cve_id,scan_id,resource_name,resource_type,os_label) VALUES (?,?,?,?,?)",
            (cve_id, sid, rname, rtype, os_label),
        )
        res_id = cur.lastrowid
        for ns in namespaces:
            ns_rows.append((res_id, ns))
    print(f"  Namespaces: {len(ns_rows)}")
    cur.executemany(
        "INSERT INTO cve_resource_namespaces (resource_id,namespace) VALUES (?,?)",
        ns_rows,
    )

    print(f"  Risk factors: {len(rf_rows)}")
    cur.executemany(
        "INSERT INTO cve_risk_factors (cve_id,scan_id,risk_factor) VALUES (?,?,?)",
        rf_rows,
    )

    print(f"  OS labels: {len(os_rows)}")
    cur.executemany(
        "INSERT INTO cve_os_labels (cve_id,scan_id,os_label) VALUES (?,?,?)",
        os_rows,
    )

    print(f"  Repos: {len(repo_rows)}")
    cur.executemany(
        "INSERT INTO cve_repos (cve_id,scan_id,repo) VALUES (?,?,?)",
        repo_rows,
    )

    col_rows = []
    if res_collections:
        for (rname, rtype), cols in res_collections.items():
            for col in cols:
                col_rows.append((rname, rtype, scan_id, col))
    print(f"  Resource collections: {len(col_rows)}")
    cur.executemany(
        "INSERT INTO resource_collections (resource_name,resource_type,scan_id,collection) VALUES (?,?,?,?)",
        col_rows,
    )

    if comp_map:
        comp_issue_rows = []
        comp_res_rows = []
        for comp_id, data in comp_map.items():
            comp_issue_rows.append((
                comp_id, scan_id, data["severity"],
                data.get("title", ""), data.get("description", ""),
                data.get("cause", ""), data.get("comp_type", ""),
                json.dumps(data.get("templates", [])),
            ))
            for rtype, resources in data["resources"].items():
                for rname, os_lbl in resources.items():
                    comp_res_rows.append((comp_id, scan_id, rname, rtype, os_lbl))

        print(f"  Compliance issues: {len(comp_issue_rows)}")
        cur.executemany(
            "INSERT OR REPLACE INTO compliance_issues (comp_id,scan_id,severity,title,description,cause,comp_type,templates) VALUES (?,?,?,?,?,?,?,?)",
            comp_issue_rows,
        )
        print(f"  Compliance resources: {len(comp_res_rows)}")
        cur.executemany(
            "INSERT INTO compliance_resources (comp_id,scan_id,resource_name,resource_type,os_label) VALUES (?,?,?,?,?)",
            comp_res_rows,
        )

    conn.commit()
    conn.close()
    print(f"  Done — scan {scan_id} written successfully.")
    return scan_id, db_path


def compute_snapshot(db_path, scan_id):
    """Compute and store aggregate snapshot for a scan."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    run_date = cur.execute("SELECT run_date FROM scan_runs WHERE id=?", (scan_id,)).fetchone()[0]

    sev_counts = {}
    for row in cur.execute("SELECT severity, COUNT(*) FROM cves WHERE scan_id=? GROUP BY severity", (scan_id,)):
        sev_counts[row[0]] = row[1]
    sev_kev = {}
    for row in cur.execute("SELECT severity, COUNT(*) FROM cves WHERE scan_id=? AND is_kev=1 GROUP BY severity", (scan_id,)):
        sev_kev[row[0]] = row[1]

    agg = cur.execute(
        "SELECT COUNT(*), SUM(is_kev), AVG(cvss), MAX(cvss), SUM(CASE WHEN fix_status='fixed' THEN 1 ELSE 0 END) FROM cves WHERE scan_id=?",
        (scan_id,)
    ).fetchone()
    pkg_count = cur.execute("SELECT COUNT(DISTINCT package_name) FROM cve_packages WHERE scan_id=?", (scan_id,)).fetchone()[0]

    res_counts = {}
    for row in cur.execute("SELECT resource_type, COUNT(*) FROM cve_resources WHERE scan_id=? GROUP BY resource_type", (scan_id,)):
        res_counts[row[0]] = row[1]
    total_res = sum(res_counts.values())

    c = sev_counts.get("critical", 0)
    h = sev_counts.get("high", 0)
    m = sev_counts.get("medium", 0)
    lo = sev_counts.get("low", 0)
    risk = c * 10 + h * 5 + m * 2 + lo

    cur.execute(
        "INSERT OR REPLACE INTO scan_snapshots "
        "(scan_id,run_date,total_cves,total_kev,total_packages,total_resources,total_fixed,"
        "critical_count,high_count,medium_count,low_count,"
        "critical_kev,high_kev,medium_kev,low_kev,"
        "avg_cvss,max_cvss,resource_hosts,resource_images,resource_registry,risk_score) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, run_date, agg[0] or 0, agg[1] or 0, pkg_count or 0, total_res, agg[4] or 0,
         c, h, m, lo,
         sev_kev.get("critical", 0), sev_kev.get("high", 0), sev_kev.get("medium", 0), sev_kev.get("low", 0),
         agg[2] or 0, agg[3] or 0,
         res_counts.get("host", 0), res_counts.get("image", 0), res_counts.get("registryImage", 0), risk)
    )
    conn.commit()
    conn.close()
    print(f"  Snapshot saved for scan {scan_id} (risk_score={risk:,})")


def compute_diff(db_path, new_scan_id):
    """Compute and store diff between the new scan and the previous one."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    prev = cur.execute("SELECT id FROM scan_runs WHERE id < ? ORDER BY id DESC LIMIT 1", (new_scan_id,)).fetchone()
    if not prev:
        conn.close()
        print("  No previous scan — skipping diff.")
        return
    old_id = prev[0]

    already = cur.execute("SELECT id FROM scan_diffs WHERE scan_id_old=? AND scan_id_new=?", (old_id, new_scan_id)).fetchone()
    if already:
        conn.close()
        return

    old_cves = {r[0]: r for r in cur.execute(
        "SELECT cve_id, severity, cvss, fix_status, is_kev, description FROM cves WHERE scan_id=?", (old_id,)
    ).fetchall()}
    new_cves = {r[0]: r for r in cur.execute(
        "SELECT cve_id, severity, cvss, fix_status, is_kev, description FROM cves WHERE scan_id=?", (new_scan_id,)
    ).fetchall()}

    old_pkgs = defaultdict(list)
    for r in cur.execute("SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?", (old_id,)):
        old_pkgs[r[0]].append(r[1])
    new_pkgs = defaultdict(list)
    for r in cur.execute("SELECT cve_id, package_name FROM cve_packages WHERE scan_id=?", (new_scan_id,)):
        new_pkgs[r[0]].append(r[1])

    old_ids = set(old_cves.keys())
    new_ids = set(new_cves.keys())

    added_ids = new_ids - old_ids
    removed_ids = old_ids - new_ids
    common_ids = old_ids & new_ids

    new_list = []
    for cid in sorted(added_ids):
        r = new_cves[cid]
        new_list.append({"cve_id": cid, "severity": r[1], "cvss": r[2], "fix_status": r[3],
                         "is_kev": bool(r[4]), "packages": list(set(new_pkgs.get(cid, [])))[:10]})

    removed_list = []
    for cid in sorted(removed_ids):
        r = old_cves[cid]
        removed_list.append({"cve_id": cid, "severity": r[1], "cvss": r[2], "fix_status": r[3],
                             "is_kev": bool(r[4]), "packages": list(set(old_pkgs.get(cid, [])))[:10]})

    changed_list = []
    for cid in sorted(common_ids):
        o = old_cves[cid]
        n = new_cves[cid]
        changes = []
        if o[1] != n[1]:
            changes.append({"field": "severity", "old": o[1], "new": n[1]})
        if abs((o[2] or 0) - (n[2] or 0)) > 0.01:
            changes.append({"field": "cvss", "old": o[2], "new": n[2]})
        if o[3] != n[3]:
            changes.append({"field": "fix_status", "old": o[3], "new": n[3]})
        if o[4] != n[4]:
            changes.append({"field": "is_kev", "old": bool(o[4]), "new": bool(n[4])})
        if changes:
            changed_list.append({"cve_id": cid, "severity": n[1], "cvss": n[2], "changes": changes})

    sev_summary = {}
    for sev in SEVERITY_ORDER:
        s_new = [x for x in new_list if x["severity"] == sev]
        s_rem = [x for x in removed_list if x["severity"] == sev]
        sev_summary[sev] = {"new": len(s_new), "removed": len(s_rem)}

    new_kev = sum(1 for x in new_list if x.get("is_kev"))
    rem_kev = sum(1 for x in removed_list if x.get("is_kev"))

    diff_detail = json.dumps({"new": new_list, "removed": removed_list, "changed": changed_list}, default=str)
    sev_json = json.dumps(sev_summary)

    cur.execute(
        "INSERT OR IGNORE INTO scan_diffs "
        "(scan_id_old,scan_id_new,new_cves_count,removed_cves_count,changed_cves_count,"
        "new_kev_count,removed_kev_count,severity_summary,diff_detail) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (old_id, new_scan_id, len(new_list), len(removed_list), len(changed_list),
         new_kev, rem_kev, sev_json, diff_detail)
    )
    conn.commit()
    conn.close()
    print(f"  Diff: +{len(new_list)} new, -{len(removed_list)} removed, ~{len(changed_list)} changed (scan {old_id}→{new_scan_id})")


def purge_old_scans(db_path, keep=2):
    """Delete full row-level data for scans older than the most recent `keep` scans."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    scans = [r[0] for r in cur.execute("SELECT id FROM scan_runs ORDER BY id DESC").fetchall()]
    if len(scans) <= keep:
        conn.close()
        return

    to_purge = scans[keep:]
    print(f"  Purging full data for {len(to_purge)} old scan(s): {to_purge}")
    for sid in to_purge:
        has_data = cur.execute("SELECT COUNT(*) FROM cves WHERE scan_id=?", (sid,)).fetchone()[0]
        if not has_data:
            continue
        res_ids = [r[0] for r in cur.execute("SELECT id FROM cve_resources WHERE scan_id=?", (sid,)).fetchall()]
        if res_ids:
            for i in range(0, len(res_ids), 500):
                batch = res_ids[i:i+500]
                ph = ",".join("?" * len(batch))
                cur.execute(f"DELETE FROM cve_resource_namespaces WHERE resource_id IN ({ph})", batch)
        cur.execute("DELETE FROM cves WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM cve_packages WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM cve_resources WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM cve_risk_factors WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM cve_os_labels WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM cve_repos WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM resource_collections WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM compliance_issues WHERE scan_id=?", (sid,))
        cur.execute("DELETE FROM compliance_resources WHERE scan_id=?", (sid,))
    conn.commit()
    print("  Running VACUUM…")
    conn.execute("VACUUM")
    conn.close()
    print("  Purge complete.")


# ── Main ──────────────────────────────────────────────────────

def fetch_tenant_data(session, json_cache=None):
    """Fetch vuln data for a single tenant session. Returns (cve_map, comp_map, res_collections)."""
    cve_map = {}
    comp_map = {}
    res_collections = {}

    if json_cache and os.path.exists(json_cache):
        try:
            with open(json_cache) as f:
                cached = json.load(f)
            print(f"  Loaded cached data from {json_cache}")
            for rtype, resources in cached.items():
                print(f"    Processing {len(resources)} {rtype} resources ...")
                for res in resources:
                    process_resource(res, rtype, cve_map, comp_map, res_collections)
            return cve_map, comp_map, res_collections
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"  Cache load error: {e}")

    raw_data = {}
    for rtype, endpoint in ENDPOINTS.items():
        print(f"  Fetching {rtype} data ...")
        resources = fetch_all_pages(session, endpoint)
        raw_data[rtype] = resources
        for res in resources:
            process_resource(res, rtype, cve_map, comp_map, res_collections)

    if json_cache:
        with open(json_cache, "w") as f:
            json.dump(raw_data, f, default=str)
        print(f"  Cached raw data to {json_cache}")

    return cve_map, comp_map, res_collections


def main():
    parser = argparse.ArgumentParser(description="Fetch Prisma Cloud vulnerabilities and store in per-tenant SQLite databases")
    parser.add_argument("--cred-path", default=None, help="Path to PCPI credentials JSON file")
    parser.add_argument("--tenant", default=None, help="Slug of a single tenant to fetch (default: all)")
    parser.add_argument("--json-cache", default=None, help="Path to save/load raw API data as JSON (dev mode, single tenant only)")
    args = parser.parse_args()

    tenants = load_tenants()
    if args.tenant:
        tenants = [t for t in tenants if t["slug"] == args.tenant]
        if not tenants:
            print(f"ERROR: Tenant '{args.tenant}' not found in {TENANTS_FILE}")
            sys.exit(1)

    print(f"Tenants to process: {', '.join(t['name'] + ' (' + t['slug'] + ')' for t in tenants)}\n")

    managers = None
    use_cache = args.json_cache and os.path.exists(args.json_cache)

    if not use_cache:
        print("Authenticating with Prisma Cloud ...")
        managers = get_cwp_session(args.cred_path)
        print(f"Loaded {len(managers)} credential(s).\n")

    for tenant in tenants:
        slug = tenant["slug"]
        db_file = tenant["db_file"]
        cred_idx = tenant.get("cred_index", 0)

        print(f"{'='*60}")
        print(f"Tenant: {tenant['name']} ({slug})")
        print(f"  DB:   {db_file}")
        print(f"{'='*60}")

        if use_cache:
            cve_map, comp_map, res_collections = fetch_tenant_data(None, json_cache=args.json_cache)
        else:
            session = get_session_for_tenant(managers, cred_idx)
            if session is None:
                print(f"  SKIPPING — no credential at index {cred_idx}\n")
                continue
            cve_map, comp_map, res_collections = fetch_tenant_data(session)

        print(f"\n  Processed {len(cve_map):,} unique CVEs, {len(comp_map):,} compliance issues")
        for s in SEVERITY_ORDER:
            count = sum(1 for d in cve_map.values() if d["severity"] == s)
            print(f"    {s.capitalize():>8}: {count:,}")

        scan_id, db_path = write_to_sqlite(db_file, cve_map, comp_map, res_collections)
        compute_snapshot(db_path, scan_id)
        compute_diff(db_path, scan_id)
        purge_old_scans(db_path)
        print()

    print("All tenants complete.")


if __name__ == "__main__":
    main()
