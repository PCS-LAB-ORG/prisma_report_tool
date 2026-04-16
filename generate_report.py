import csv
from html import escape
from collections import defaultdict
import datetime

CSV_PATH = "twistlock_system-vulnerability_3_27_26_12_15_45.csv"
OUTPUT_PATH = "vulnerability_report.html"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_META = {
    "critical": {"color": "#ef4444", "light": "#fef2f2", "mid": "#fecaca", "icon": "&#9888;"},
    "high":     {"color": "#f97316", "light": "#fff7ed", "mid": "#fed7aa", "icon": "&#9650;"},
    "medium":   {"color": "#eab308", "light": "#fefce8", "mid": "#fef08a", "icon": "&#9644;"},
    "low":      {"color": "#22c55e", "light": "#f0fdf4", "mid": "#bbf7d0", "icon": "&#9660;"},
}

RT_LABELS = {
    "host": "Hosts",
    "image": "Container Images",
    "registryImage": "Registry Images",
    "function": "Functions",
}
RT_ICONS = {
    "host": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>',
    "image": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 002 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0022 16z"/></svg>',
    "registryImage": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7"/><ellipse cx="12" cy="7" rx="8" ry="4"/></svg>',
    "function": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>',
}

def extract_distro(version):
    v = version.lower()
    if ".azl3" in v or "-azl3" in v: return "Azure Linux 3"
    if ".azl" in v or "-azl" in v: return "Azure Linux"
    if ".cm2" in v or "-cm2" in v: return "CBL-Mariner 2"
    if ".cm1" in v or "-cm1" in v: return "CBL-Mariner"
    if ".amzn2023" in v or "-amzn2023" in v: return "Amazon Linux 2023"
    if ".amzn2" in v or "-amzn2" in v: return "Amazon Linux 2"
    if ".amzn1" in v or "-amzn1" in v: return "Amazon Linux"
    if ".el9" in v or "-el9" in v: return "RHEL 9"
    if ".el8" in v or "-el8" in v: return "RHEL 8"
    if ".el7" in v or "-el7" in v: return "RHEL 7"
    if "ubuntu" in v: return "Ubuntu"
    if ".deb" in v or "debian" in v: return "Debian"
    if ".fc" in v: return "Fedora"
    if ".alpine" in v: return "Alpine"
    return "Other"

def detect_ecosystem(name):
    n = name.lower()
    if n.startswith("google.golang.org/") or n.startswith("go.opentelemetry.io/"):
        return "go"
    if "/" in n and ("golang" in n or n.startswith("crypto/") or n.startswith("net/")
                     or n.startswith("html/") or n.startswith("os") or n.startswith("mime/")
                     or n.startswith("encoding/") or n.startswith("go.")
                     or n.startswith("github.com/") or n.startswith("k8s.io/")):
        return "go"
    if n.startswith("com.") or n.startswith("org.") or n.startswith("io."):
        return "java"
    if n in ("pip","setuptools","certifi","urllib3","aiohttp","pillow","cryptography",
             "flask","werkzeug","black","requests","protobuf","azure-core","boto3",
             "botocore","numpy","pandas","pyyaml","jinja2","markupsafe","idna",
             "charset-normalizer","pyopenssl","paramiko","twisted","django","celery",
             "pyspark") or n.startswith("python"):
        return "python"
    if n in ("node-serialize","node-forge","forge","express","lodash","axios",
             "minimist","semver","tar","glob-parent") or n.startswith("@"):
        return "node"
    return "system"

# ── Parse CSV ──────────────────────────────────────────────────
cves = {}
with open(CSV_PATH) as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        cve_id = row[0]
        severity = row[8].strip().lower() if len(row) > 8 else "unknown"
        raw_pkgs = [p.strip() for p in row[3].split(",") if p.strip()] if row[3] else []
        resource_type = row[10].strip() if len(row) > 10 else ""
        cvss = row[9].strip() if len(row) > 9 else ""
        link = row[5].strip() if len(row) > 5 else ""
        risk_score = row[2].strip() if len(row) > 2 else ""
        description = row[1].strip() if len(row) > 1 else ""
        env_factors = row[7].strip() if len(row) > 7 else ""

        if cve_id not in cves:
            cves[cve_id] = {
                "severity": severity,
                "consolidated_pkgs": {},  # name -> set of versions
                "by_resource_type": {},   # rt -> {name -> set of versions}
                "by_rt_distro": {},       # rt -> distro -> set of pkg strings
                "resource_types": set(),
                "cvss": cvss, "link": link, "risk_score": risk_score,
                "description": description, "env_factors": set(),
            }

        entry = cves[cve_id]
        if resource_type:
            entry["resource_types"].add(resource_type)
        if env_factors:
            for ef in env_factors.split(","):
                entry["env_factors"].add(ef.strip())

        if resource_type not in entry["by_resource_type"]:
            entry["by_resource_type"][resource_type] = {}
        if resource_type not in entry["by_rt_distro"]:
            entry["by_rt_distro"][resource_type] = defaultdict(set)

        for pkg_str in raw_pkgs:
            if ":" in pkg_str:
                name, ver = pkg_str.rsplit(":", 1)
            else:
                name, ver = pkg_str, ""

            # Consolidated (unique package names)
            if name not in entry["consolidated_pkgs"]:
                entry["consolidated_pkgs"][name] = set()
            entry["consolidated_pkgs"][name].add(ver)

            # Per resource type
            rt_map = entry["by_resource_type"][resource_type]
            if name not in rt_map:
                rt_map[name] = set()
            rt_map[name].add(ver)

            # Distro grouping
            distro = extract_distro(ver)
            entry["by_rt_distro"][resource_type][distro].add(name)

# ── Group by severity ──────────────────────────────────────────
all_grouped = {s: [] for s in SEVERITY_ORDER}
for cve_id, data in cves.items():
    sev = data["severity"]
    if sev in all_grouped:
        all_grouped[sev].append((cve_id, data))

total_counts = {s: len(all_grouped[s]) for s in SEVERITY_ORDER}

TOP_N = 10
grouped = {}
for sev in SEVERITY_ORDER:
    all_grouped[sev].sort(key=lambda x: len(x[1]["consolidated_pkgs"]), reverse=True)
    grouped[sev] = all_grouped[sev][:TOP_N]

total_cves = len(cves)
total_packages = len({name for d in cves.values() for name in d["consolidated_pkgs"]})

global_max_vulns = max(
    len(data["consolidated_pkgs"])
    for entries in grouped.values()
    for _, data in entries
) if any(grouped.values()) else 1


# ── HTML builder helpers ───────────────────────────────────────

def build_consolidated_pills(consolidated_pkgs):
    pills = []
    for name in sorted(consolidated_pkgs.keys()):
        versions = sorted(consolidated_pkgs[name])
        name_esc = escape(name)
        ver_count = len(versions)
        if ver_count == 1 and versions[0]:
            pills.append(
                f'<span class="pkg-pill">'
                f'<span class="pkg-name">{name_esc}</span>'
                f'<span class="pkg-ver">{escape(versions[0])}</span>'
                f'</span>'
            )
        elif ver_count > 1:
            pills.append(
                f'<span class="pkg-pill">'
                f'<span class="pkg-name">{name_esc}</span>'
                f'<span class="pkg-ver">{ver_count} versions</span>'
                f'</span>'
            )
        else:
            pills.append(f'<span class="pkg-pill"><span class="pkg-name">{name_esc}</span></span>')
    return "\n                    ".join(pills)


def build_resource_breakdown(data, color):
    html_parts = []
    for rt in ["host", "image", "registryImage", "function"]:
        if rt not in data["by_resource_type"] or not data["by_resource_type"][rt]:
            continue
        rt_pkgs = data["by_resource_type"][rt]
        pkg_count = len(rt_pkgs)
        label = RT_LABELS.get(rt, rt)
        icon = RT_ICONS.get(rt, "")
        distro_groups = data["by_rt_distro"].get(rt, {})
        distro_html = ""
        if distro_groups and len(distro_groups) > 1 or (len(distro_groups) == 1 and "Other" not in distro_groups):
            dg_parts = []
            for distro_name in sorted(distro_groups.keys()):
                pkg_names = sorted(distro_groups[distro_name])
                count = len(pkg_names)
                sample = ", ".join(escape(p) for p in pkg_names[:5])
                more = f" +{count - 5} more" if count > 5 else ""
                dg_parts.append(
                    f'<div class="distro-group">'
                    f'<span class="distro-label">{escape(distro_name)}</span>'
                    f'<span class="distro-count">{count} pkg{"s" if count != 1 else ""}</span>'
                    f'<span class="distro-pkgs">{sample}{more}</span>'
                    f'</div>'
                )
            distro_html = f'<div class="distro-list">{"".join(dg_parts)}</div>'

        html_parts.append(
            f'<div class="rt-block">'
            f'<div class="rt-header">'
            f'<span class="rt-icon">{icon}</span>'
            f'<span class="rt-label">{label}</span>'
            f'<span class="rt-badge" style="background:{color}22;color:{color}">{pkg_count} pkg{"s" if pkg_count != 1 else ""}</span>'
            f'</div>'
            f'{distro_html}'
            f'</div>'
        )
    return "\n".join(html_parts)


def build_patch_steps(consolidated_pkgs, cve_id):
    eco = {"system": set(), "python": set(), "node": set(), "go": set(), "java": set()}
    for name in consolidated_pkgs:
        e = detect_ecosystem(name)
        eco[e].add(name)
    groups = {k: sorted(v) for k, v in eco.items() if v}

    linux_lines, win_lines = [], []
    if "system" in groups:
        names = " ".join(groups["system"])
        linux_lines += ["# RHEL / Amazon Linux", f"sudo yum update -y {names}",
                        "# Ubuntu / Debian", f"sudo apt update && sudo apt upgrade -y {names}"]
        win_lines += ["# Update via Chocolatey", f"choco upgrade -y {names}"]
    if "python" in groups:
        cmd = f"pip install --upgrade {' '.join(groups['python'])}"
        linux_lines += ["", "# Python packages", cmd]
        win_lines += ["", "# Python packages", cmd]
    if "node" in groups:
        names = " ".join(groups["node"])
        linux_lines += ["", "# Node.js packages", f"npm update {names}"]
        win_lines += ["", "# Node.js packages", f"npm update {names}"]
    if "go" in groups:
        linux_lines += ["", "# Go modules", "go get -u ./...", "go mod tidy"]
        win_lines += ["", "# Go modules", "go get -u ./...", "go mod tidy"]
    if "java" in groups:
        linux_lines += ["", "# Java (Maven)", "mvn versions:use-latest-releases"]
        win_lines += ["", "# Java (Maven)", "mvn versions:use-latest-releases"]
    if not linux_lines:
        linux_lines.append(f"# Review {cve_id} advisory for specific patch instructions")
    if not win_lines:
        win_lines.append(f"# Review {cve_id} advisory for specific patch instructions")
    return "\n".join(linux_lines), "\n".join(win_lines)


def build_table_rows(entries, severity):
    meta = SEVERITY_META[severity]
    rows = []
    for rank, (cve_id, data) in enumerate(entries, 1):
        link = escape(data["link"])
        rts = sorted(data["resource_types"])
        rt_icons_html = " ".join(
            f'<span class="rt-tiny" title="{RT_LABELS.get(r,r)}">{RT_ICONS.get(r,"")}</span>'
            for r in rts
        )
        n_pkgs = len(data["consolidated_pkgs"])
        n_rts = len(rts)
        cvss = data["cvss"]
        risk = data["risk_score"]
        cve_escaped = escape(cve_id)
        bar_pct = (n_pkgs / global_max_vulns) * 100 if global_max_vulns else 0
        row_id = f"{severity}-{rank}"

        pkg_pills = build_consolidated_pills(data["consolidated_pkgs"])
        resource_html = build_resource_breakdown(data, meta["color"])
        linux_cmds, win_cmds = build_patch_steps(data["consolidated_pkgs"], cve_id)
        linux_html = escape(linux_cmds)
        win_html = escape(win_cmds)

        desc_short = escape(data["description"][:180])
        if len(data["description"]) > 180:
            desc_short += "..."

        env_html = ""
        if data["env_factors"]:
            ef_tags = " ".join(
                f'<span class="ef-tag">{escape(ef)}</span>'
                for ef in sorted(data["env_factors"])
            )
            env_html = f'<div class="ef-row">{ef_tags}</div>'

        rows.append(
            f"""            <tr class="data-row" onclick="togglePkgs('{row_id}')">
              <td class="rank-cell">{rank}</td>
              <td class="cve-cell">
                <a href="{link}" target="_blank" rel="noopener" onclick="event.stopPropagation()">{cve_escaped}</a>
                <div class="cve-desc">{desc_short}</div>
              </td>
              <td class="rt-cell">{rt_icons_html}<span class="rt-count">{n_rts}</span></td>
              <td class="bar-cell">
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:{bar_pct:.1f}%;background:{meta['color']}"></div>
                  <span class="bar-label">{n_pkgs}</span>
                </div>
              </td>
              <td class="num cvss-cell">{cvss}</td>
              <td class="num">{risk}</td>
              <td class="expand-cell"><span class="expand-icon" id="exp-{row_id}">
                <svg width="14" height="14" viewBox="0 0 14 14"><path d="M5.25 3.5L8.75 7L5.25 10.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>
              </span></td>
            </tr>
            <tr class="pkg-row hidden" id="pkgs-{row_id}">
              <td colspan="7">
                <div class="pkg-detail" style="border-left-color:{meta['color']}">
                  <div class="pkg-header">
                    <svg width="14" height="14" viewBox="0 0 14 14" style="flex-shrink:0"><path d="M7 1.75L12.25 4.375V9.625L7 12.25L1.75 9.625V4.375L7 1.75Z" stroke="{meta['color']}" stroke-width="1.2" fill="none"/><path d="M1.75 4.375L7 7M7 7L12.25 4.375M7 7V12.25" stroke="{meta['color']}" stroke-width="1.2" fill="none"/></svg>
                    <span class="pkg-title">Consolidated Packages ({n_pkgs})</span>
                  </div>
                  <div class="pkg-list">{pkg_pills}</div>
                  {env_html}
                  <div class="resource-section">
                    <div class="rs-label">Resource Breakdown</div>
                    {resource_html}
                  </div>
                  <div class="patch-section">
                    <div class="patch-label">Patch Steps</div>
                    <div class="os-tabs">
                      <button class="os-tab active" onclick="event.stopPropagation();switchTab('{row_id}','linux');" id="tab-linux-{row_id}">Linux</button>
                      <button class="os-tab" onclick="event.stopPropagation();switchTab('{row_id}','windows');" id="tab-windows-{row_id}">Windows</button>
                    </div>
                    <div class="os-panel" id="panel-linux-{row_id}"><pre><code>{linux_html}</code></pre></div>
                    <div class="os-panel hidden" id="panel-windows-{row_id}"><pre><code>{win_html}</code></pre></div>
                  </div>
                </div>
              </td>
            </tr>""")
    return "\n".join(rows)


def build_section(severity, entries):
    meta = SEVERITY_META[severity]
    count = len(entries)
    total = total_counts[severity]
    table_rows = build_table_rows(entries, severity)
    sid = severity
    return f"""
    <section class="severity-section" id="{sid}">
      <div class="section-header" onclick="toggleSection('{sid}')">
        <div class="sev-indicator" style="background:{meta['color']}"></div>
        <span class="sev-icon" style="color:{meta['color']}">{meta['icon']}</span>
        <span class="sev-label">{severity.capitalize()}</span>
        <span class="sev-badge" style="background:{meta['light']};color:{meta['color']}">Top {count} of {total:,}</span>
        <span class="chevron" id="chevron-{sid}">
          <svg width="12" height="12" viewBox="0 0 12 12"><path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>
        </span>
      </div>
      <div class="section-body" id="body-{sid}">
        <table>
          <thead>
            <tr>
              <th class="rank-col">#</th>
              <th>Remediation (CVE)</th>
              <th class="rt-col">Resources</th>
              <th>Packages</th>
              <th class="num">CVSS</th>
              <th class="num">Risk</th>
              <th class="expand-col"></th>
            </tr>
          </thead>
          <tbody>
{table_rows}
          </tbody>
        </table>
      </div>
    </section>"""


sections_html = "\n".join(build_section(s, grouped[s]) for s in SEVERITY_ORDER)

CSS = """
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
  :root {
    --font: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155; --border: #334155;
    --text: #f1f5f9; --text-dim: #94a3b8; --text-muted: #64748b; --accent: #3b82f6;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:var(--font); background:var(--bg); color:var(--text); line-height:1.6; min-height:100vh; }
  .page-header { background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%); border-bottom:1px solid var(--border); padding:2.5rem 2rem 2rem; }
  .page-header .inner { max-width:1320px; margin:0 auto; }
  .page-header h1 { font-size:1.5rem; font-weight:800; letter-spacing:-0.025em; margin-bottom:0.25rem; }
  .page-header .subtitle { color:var(--text-dim); font-size:0.8rem; }
  .container { max-width:1320px; margin:0 auto; padding:1.75rem 2rem 3rem; }

  .summary { display:grid; grid-template-columns:repeat(5,1fr); gap:0.875rem; margin-bottom:2rem; }
  @media(max-width:900px){ .summary{grid-template-columns:repeat(3,1fr);} }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:0.75rem; padding:1.25rem; position:relative; overflow:hidden; transition:transform .15s,box-shadow .15s; }
  .card:hover { transform:translateY(-2px); box-shadow:0 8px 24px rgba(0,0,0,.25); }
  .card .stripe { position:absolute; top:0;left:0;right:0; height:3px; }
  .card .card-label { font-size:0.65rem; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; color:var(--text-muted); margin-bottom:0.5rem; }
  .card .card-value { font-size:2rem; font-weight:800; letter-spacing:-0.03em; line-height:1; }
  .card .card-sub { font-size:0.7rem; color:var(--text-muted); margin-top:0.35rem; }

  .severity-section { margin-bottom:1.25rem; }
  .section-header { display:flex; align-items:center; gap:0.625rem; padding:0.875rem 1.25rem; background:var(--surface); border:1px solid var(--border); border-radius:0.625rem 0.625rem 0 0; cursor:pointer; user-select:none; transition:background .15s; }
  .section-header:hover { background:var(--surface2); }
  .sev-indicator { width:4px; height:28px; border-radius:2px; flex-shrink:0; }
  .sev-icon { font-size:0.875rem; flex-shrink:0; line-height:1; }
  .sev-label { font-weight:700; font-size:0.9375rem; }
  .sev-badge { font-size:0.7rem; font-weight:700; padding:0.2rem 0.625rem; border-radius:999px; }
  .chevron { margin-left:auto; color:var(--text-muted); transition:transform .2s; display:flex; align-items:center; }
  .chevron.collapsed { transform:rotate(-90deg); }
  .section-body { background:var(--surface); border:1px solid var(--border); border-top:none; border-radius:0 0 0.625rem 0.625rem; overflow:hidden; }
  .section-body.hidden { display:none; }

  table { width:100%; border-collapse:collapse; font-size:0.8125rem; }
  thead th { background:rgba(15,23,42,.6); padding:0.625rem 1rem; text-align:left; font-weight:600; font-size:0.6875rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--text-muted); border-bottom:1px solid var(--border); position:sticky; top:0; z-index:1; }
  th.num { text-align:right; }
  th.rank-col { width:40px; text-align:center; }
  th.rt-col { width:100px; text-align:center; }
  tbody tr { border-bottom:1px solid rgba(51,65,85,.5); transition:background .1s; }
  tbody tr:last-child { border-bottom:none; }
  td { padding:0.625rem 1rem; vertical-align:middle; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }
  td.rank-cell { text-align:center; font-weight:700; color:var(--text-muted); font-size:0.75rem; width:40px; }
  td.cve-cell a { color:var(--accent); text-decoration:none; font-weight:600; font-size:0.8125rem; }
  td.cve-cell a:hover { color:#60a5fa; text-decoration:underline; }
  .cve-desc { font-size:0.675rem; color:var(--text-muted); margin-top:0.2rem; line-height:1.4; max-width:400px; }
  td.cvss-cell { font-weight:600; }
  td.rt-cell { text-align:center; }
  .rt-tiny { display:inline-flex; align-items:center; margin:0 2px; color:var(--text-dim); }
  .rt-count { font-size:0.65rem; color:var(--text-muted); margin-left:4px; }

  .bar-cell { width:220px; }
  .bar-wrap { display:flex; align-items:center; gap:0.5rem; }
  .bar-fill { height:18px; border-radius:3px; min-width:2px; opacity:0.8; transition:width .3s ease; }
  .bar-label { font-weight:700; font-size:0.8125rem; font-variant-numeric:tabular-nums; white-space:nowrap; }

  .data-row { cursor:pointer; }
  .data-row:hover { background:rgba(51,65,85,.35); }
  .expand-col { width:36px; }
  .expand-cell { width:36px; text-align:center; color:var(--text-muted); }
  .expand-icon { display:inline-flex; align-items:center; justify-content:center; transition:transform .2s; }
  .expand-icon.open { transform:rotate(90deg); }
  .pkg-row td { padding:0 !important; }
  .pkg-row.hidden { display:none; }
"""

CSS2 = """
  .pkg-detail { margin:0 1rem 0.75rem; padding:1rem 1.25rem; background:rgba(15,23,42,.5); border-radius:0.5rem; border-left:3px solid; }
  .pkg-header { display:flex; align-items:center; gap:0.5rem; margin-bottom:0.75rem; }
  .pkg-title { font-weight:700; font-size:0.75rem; }
  .pkg-list { display:flex; flex-wrap:wrap; gap:0.375rem; }
  .pkg-pill { display:inline-flex; align-items:center; background:var(--surface2); border:1px solid rgba(148,163,184,.15); border-radius:0.375rem; font-size:0.7rem; overflow:hidden; }
  .pkg-name { padding:0.2rem 0.5rem; font-weight:600; }
  .pkg-ver { padding:0.2rem 0.5rem; background:rgba(0,0,0,.2); color:var(--text-dim); font-family:'SF Mono','Fira Code',monospace; font-size:0.65rem; border-left:1px solid rgba(148,163,184,.1); }

  .ef-row { display:flex; flex-wrap:wrap; gap:0.3rem; margin-top:0.75rem; }
  .ef-tag { font-size:0.6rem; padding:0.15rem 0.5rem; border-radius:999px; background:rgba(239,68,68,.12); color:#fca5a5; border:1px solid rgba(239,68,68,.2); font-weight:500; }

  .resource-section { margin-top:1rem; border-top:1px solid rgba(148,163,184,.1); padding-top:0.875rem; }
  .rs-label { font-weight:700; font-size:0.75rem; margin-bottom:0.625rem; }
  .rt-block { margin-bottom:0.625rem; background:rgba(0,0,0,.15); border-radius:0.375rem; padding:0.625rem 0.875rem; border:1px solid rgba(148,163,184,.08); }
  .rt-header { display:flex; align-items:center; gap:0.5rem; }
  .rt-icon { display:inline-flex; color:var(--text-dim); flex-shrink:0; }
  .rt-label { font-weight:600; font-size:0.725rem; }
  .rt-badge { font-size:0.6rem; font-weight:700; padding:0.1rem 0.5rem; border-radius:999px; }
  .distro-list { margin-top:0.5rem; padding-top:0.5rem; border-top:1px solid rgba(148,163,184,.08); }
  .distro-group { display:flex; align-items:baseline; gap:0.5rem; padding:0.2rem 0; font-size:0.675rem; }
  .distro-label { font-weight:600; color:var(--text-dim); min-width:130px; flex-shrink:0; }
  .distro-count { font-weight:700; color:var(--text-muted); font-size:0.6rem; min-width:55px; }
  .distro-pkgs { color:var(--text-muted); font-size:0.625rem; font-family:'SF Mono','Fira Code',monospace; }

  .patch-section { margin-top:1rem; border-top:1px solid rgba(148,163,184,.1); padding-top:0.875rem; }
  .patch-label { font-weight:700; font-size:0.75rem; margin-bottom:0.5rem; }
  .os-tabs { display:flex; gap:0; }
  .os-tab { display:inline-flex; align-items:center; gap:0.375rem; padding:0.4rem 1rem; font-family:var(--font); font-size:0.7rem; font-weight:600; border:1px solid var(--border); border-bottom:none; border-radius:0.375rem 0.375rem 0 0; background:transparent; color:var(--text-muted); cursor:pointer; transition:background .15s,color .15s; }
  .os-tab:hover { color:var(--text-dim); }
  .os-tab.active { background:rgba(0,0,0,.35); color:var(--text); }
  .os-panel { background:rgba(0,0,0,.35); border:1px solid var(--border); border-radius:0 0.375rem 0.375rem 0.375rem; overflow-x:auto; }
  .os-panel.hidden { display:none; }
  .os-panel pre { margin:0; padding:0.875rem 1rem; overflow-x:auto; }
  .os-panel code { font-family:'SF Mono','Fira Code','Cascadia Code',monospace; font-size:0.7rem; line-height:1.65; color:var(--text-dim); white-space:pre; }
  .footer { margin-top:2.5rem; padding-top:1.25rem; border-top:1px solid var(--border); text-align:center; color:var(--text-muted); font-size:0.7rem; }
"""

JS = """
function toggleSection(id) {
  document.getElementById('body-' + id).classList.toggle('hidden');
  document.getElementById('chevron-' + id).classList.toggle('collapsed');
}
function togglePkgs(id) {
  document.getElementById('pkgs-' + id).classList.toggle('hidden');
  document.getElementById('exp-' + id).classList.toggle('open');
}
function switchTab(rowId, os) {
  var lp = document.getElementById('panel-linux-' + rowId);
  var wp = document.getElementById('panel-windows-' + rowId);
  var lt = document.getElementById('tab-linux-' + rowId);
  var wt = document.getElementById('tab-windows-' + rowId);
  if (os === 'linux') {
    lp.classList.remove('hidden'); wp.classList.add('hidden');
    lt.classList.add('active'); wt.classList.remove('active');
  } else {
    wp.classList.remove('hidden'); lp.classList.add('hidden');
    wt.classList.add('active'); lt.classList.remove('active');
  }
}
"""

today = datetime.date.today().strftime("%B %d, %Y")

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Remediation Report</title>
<style>{CSS}{CSS2}</style>
</head>
<body>
<div class="page-header">
  <div class="inner">
    <h1>Vulnerability Remediation Report</h1>
    <p class="subtitle">Prisma Cloud (Twistlock) &mdash; Top {TOP_N} per severity by unique package count &mdash; {total_cves:,} CVEs &middot; {total_packages:,} unique packages</p>
  </div>
</div>
<div class="container">
  <div class="summary">
    <div class="card">
      <div class="stripe" style="background:var(--accent)"></div>
      <div class="card-label">Total CVEs</div>
      <div class="card-value" style="color:var(--accent)">{total_cves:,}</div>
      <div class="card-sub">{total_packages:,} unique packages</div>
    </div>
    <div class="card">
      <div class="stripe" style="background:#ef4444"></div>
      <div class="card-label">Critical</div>
      <div class="card-value" style="color:#ef4444">{total_counts['critical']:,}</div>
      <div class="card-sub">{total_counts['critical']/total_cves*100:.1f}% of total</div>
    </div>
    <div class="card">
      <div class="stripe" style="background:#f97316"></div>
      <div class="card-label">High</div>
      <div class="card-value" style="color:#f97316">{total_counts['high']:,}</div>
      <div class="card-sub">{total_counts['high']/total_cves*100:.1f}% of total</div>
    </div>
    <div class="card">
      <div class="stripe" style="background:#eab308"></div>
      <div class="card-label">Medium</div>
      <div class="card-value" style="color:#eab308">{total_counts['medium']:,}</div>
      <div class="card-sub">{total_counts['medium']/total_cves*100:.1f}% of total</div>
    </div>
    <div class="card">
      <div class="stripe" style="background:#22c55e"></div>
      <div class="card-label">Low</div>
      <div class="card-value" style="color:#22c55e">{total_counts['low']:,}</div>
      <div class="card-sub">{total_counts['low']/total_cves*100:.1f}% of total</div>
    </div>
  </div>
{sections_html}
  <p class="footer">Source: twistlock_system-vulnerability_3_27_26_12_15_45.csv &middot; Generated {today}</p>
</div>
<script>{JS}</script>
</body>
</html>"""

with open(OUTPUT_PATH, "w") as f:
    f.write(html)

print(f"Report written to {OUTPUT_PATH}")
for s in SEVERITY_ORDER:
    print(f"  {s.capitalize():>8}: top {len(grouped[s])} of {total_counts[s]:,}")
print(f"  {'Total':>8}: {total_cves:,} CVEs, {total_packages:,} unique packages")
