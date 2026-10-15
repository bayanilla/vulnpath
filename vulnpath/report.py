"""Write the results package: HTML report, SVG, CSV and JSON."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def ts(v) -> str:
    if v is None or v in (float("inf"), float("-inf")):
        return ""
    return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _iso(obj):
    """JSON-friendly copy with readable timestamps."""
    if isinstance(obj, dict):
        return {k: (ts(v) if k in ("first_seen", "last_seen") else _iso(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_iso(x) for x in obj]
    return obj


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(_iso(data), indent=2, sort_keys=False), encoding="utf-8")


def _safe(row):
    """Neutralise spreadsheet formula injection from untrusted log content."""
    return [("'" + c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in row]


def write_csv(path: Path, findings: list[dict]) -> None:
    cols = ["id", "priority_score", "target_ip", "target_hostname", "port", "protocol", "top_severity", "cves",
            "exploit_available", "behaviours", "possible_login_success", "outcome", "hostile_sources",
            "external_sources", "first_seen", "last_seen", "chains", "scan_stale", "assessment", "score_reasons",
            "evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for x in findings:
            vs = x["vulnerabilities"]
            cves = sorted({c for v in vs for c in v["cves"]})
            row = [x["id"], x["priority_score"], x["target_ip"], x["target_hostname"], x["port"], x["protocol"],
                   vs[0]["severity"] if vs else "", " ".join(cves), any(v["exploit_available"] for v in vs),
                   " ".join(x["kinds"]), x["possible_login_success"], x["outcome"], " ".join(x["hostile_sources"]),
                   x["external_sources"], ts(x["first_seen"]), ts(x["last_seen"]), " | ".join(x["chains"]),
                   x["scan_stale"], x["assessment"], " | ".join(x["score_reasons"]), " | ".join(x["evidence"])]
            w.writerow(_safe(row))


def write_sources_csv(path: Path, sources: list[dict]) -> None:
    cols = ["source_ip", "external", "behaviours", "routine_only", "possible_login_success", "targets_contacted",
            "vulnerable_targets", "finding_ids", "first_seen", "last_seen", "details"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for x in sources:
            row = [x["source_ip"], x["external"], " ".join(x["kinds"]), x["routine_only"],
                   x["possible_login_success"], x["targets_contacted"], x["vulnerable_targets"],
                   " ".join(x["finding_ids"]), ts(x["first_seen"]), ts(x["last_seen"]),
                   " | ".join(d["detail"] for d in x["detections"])]
            w.writerow(_safe(row))


CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:var(--text);background:var(--bg);max-width:1200px;margin:24px auto;padding:0 16px;line-height:1.45}
h1{font-size:24px;margin-bottom:4px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid var(--border);padding-bottom:4px}
a{color:var(--accent)}
.muted{color:var(--muted)}.box{border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin:10px 0}
.warn{background:var(--warn-bg);border-color:var(--warn-border)}.kpi{display:inline-block;margin:0 24px 8px 0}.kpi b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--border);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--surface)}code{font-size:12px;background:var(--raised);padding:1px 4px;border-radius:4px;word-break:break-all}
.sev-Critical{color:var(--sev-crit);font-weight:600}.sev-High{color:var(--sev-high);font-weight:600}.sev-Medium{color:var(--sev-med)}.sev-Low{color:var(--sev-low)}
.tag{display:inline-block;font-size:11px;padding:1px 8px;border-radius:9px;background:var(--tag-bg);color:var(--tag-fg);margin-right:4px}
.tag.hot{background:var(--hot-bg);color:var(--hot-fg)}.tag.cred{background:var(--cred-bg);color:var(--cred-fg)}.tag.scan{background:var(--scan-bg);color:var(--scan-fg)}
.svgwrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px}details{margin:4px 0}
"""

# Report themes. "classic" is the original light report; the rest are the Múcaro themes used by
# Pathfinder and the BGP Routing Exposure Lookup, so the tools look alike side by side.
CLASSIC = {"scheme": "light", "bg": "#ffffff", "surface": "#f9fafb", "raised": "#f3f4f6", "hover": "#f9fafb",
           "border": "#e5e7eb", "border-strong": "#d1d5db", "text": "#111827", "text-2": "#4b5563",
           "muted": "#6b7280", "accent": "#7c3aed", "sel": "#f5f3ff", "focus-ring": "#ddd6fe",
           "warn-bg": "#fff7ed", "warn-border": "#fdba74", "chip-bg": "#ede9fe", "chip-fg": "#5b21b6",
           "tag-bg": "#eef2ff", "tag-fg": "#3730a3", "hot-bg": "#fee2e2", "hot-fg": "#991b1b",
           "cred-bg": "#ffedd5", "cred-fg": "#9a3412", "scan-bg": "#f3f4f6", "scan-fg": "#374151",
           "node": "#ffffff", "node-src": "#f1f5f9", "sev-crit": "#b91c1c", "sev-high": "#ea580c",
           "sev-med": "#ca8a04", "sev-low": "#2563eb", "sev-none": "#475569"}
_DARK_SEV = {"sev-high": "#ff9f5a", "sev-low": "#8ab4f8"}
# id, label, scheme, bg, surface, raised, hover, border, border-strong, text, muted, accent, warning, danger, extra
MUCARO = [
    ("soc", "SOC Dark", "dark", "#101415", "#141a1c", "#252e30", "#354246", "#333c3e", "#435053", "#e9eeee",
     "#9eafb1", "#b8c4c7", "#efd384", "#ffb7ae", _DARK_SEV),
    ("nord", "Nord Calm", "dark", "#2e3440", "#3b4252", "#434c5e", "#4c566a", "#4c566a", "#5b667a", "#eceff4",
     "#b4bfce", "#88c0d0", "#ebcb8b", "#e0868e", _DARK_SEV),
    ("contrast", "High Contrast", "dark", "#000000", "#080808", "#171717", "#303030", "#777777", "#aaaaaa",
     "#ffffff", "#d0d0d0", "#62bfb0", "#ffdf00", "#ff8f8f", {"sev-high": "#ffb070", "sev-low": "#9cc8ff"}),
    ("matrix", "Matrix", "dark", "#030805", "#07120a", "#0d1f11", "#15351c", "#24532d", "#347a40", "#d9ffe0",
     "#83b98c", "#24f06b", "#c7ff47", "#ff8270", _DARK_SEV),
    ("mucaro", "Mucaro Dusk", "dark", "#102333", "#142d3e", "#1c3a4d", "#294c60", "#36596c", "#4c7183", "#f1f5ef",
     "#9fbab3", "#42d6bd", "#f4bd61", "#f18a7b", _DARK_SEV),
    ("notebook", "Field Notebook", "light", "#f3eee3", "#fffaf0", "#ebe1cc", "#dfd0b6", "#9a8b72", "#766850",
     "#1f2b30", "#68797a", "#006d77", "#a15c00", "#9b302a", {"sev-high": "#c2410c", "sev-med": "#8a6a00",
                                                           "sev-low": "#1d4ed8"}),
    ("amber", "Terminal Amber", "dark", "#0d0a04", "#151006", "#241b0a", "#382a0c", "#664a14", "#8f681d", "#ffe9b0",
     "#bda265", "#ffb000", "#ffe075", "#ff9370", _DARK_SEV),
]


def _mucaro_vars(scheme, bg, surface, raised, hover, border, strong, text, muted, accent, warning, danger, extra):
    v = {"scheme": scheme, "bg": bg, "surface": surface, "raised": raised, "hover": hover, "border": border,
         "border-strong": strong, "text": text, "text-2": muted, "muted": muted, "accent": accent, "sel": hover,
         "focus-ring": accent, "warn-bg": raised, "warn-border": warning, "chip-bg": raised, "chip-fg": accent,
         "tag-bg": raised, "tag-fg": text, "hot-bg": raised, "hot-fg": danger, "cred-bg": raised,
         "cred-fg": warning, "scan-bg": raised, "scan-fg": muted, "node": surface, "node-src": raised,
         "sev-crit": danger, "sev-med": warning, "sev-none": muted}
    v.update(extra)
    return v


THEMES = [("classic", "Classic Light", CLASSIC)] + [(t[0], t[1], _mucaro_vars(*t[2:])) for t in MUCARO]


def _theme_css() -> str:
    def block(sel, v):
        body = ";".join(f"--{k}:{val}" for k, val in v.items() if k != "scheme")
        return f"{sel}{{color-scheme:{v['scheme']};{body}}}"
    out = [block(":root", CLASSIC)]
    out += [block(f":root[data-theme='{tid}']", v) for tid, _, v in THEMES[1:]]
    # Printed reports always use the light layout.
    out.append("@media print{" + block(":root[data-theme]", CLASSIC) + "}")
    return "\n".join(out) + "\n"


THEME_IDS = [t[0] for t in THEMES]
THEME_KEY = "vulnpath-report-theme"
# Múcaro M mark (same as Pathfinder and the BGP lookup), inlined so the report stays one file.
FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E"
           "%3Crect width='64' height='64' rx='14' fill='%23141a1c'/%3E%3Cpath fill='%23c9dddd' "
           "d='M12 48V16h10l10 16 10-16h10v32H42V31l-7 12h-6l-7-12v17H12z'/%3E%3C/svg%3E")

# The same mark drawn inline for the report header. The fixed dark tile is the brand mark itself;
# the outline in UI_CSS keeps it visible on the dark themes.
MARK_SVG = ("<svg class='mark' viewBox='0 0 64 64' width='36' height='36' aria-hidden='true'>"
            "<rect width='64' height='64' rx='14' fill='#141a1c'/><path fill='#c9dddd' "
            "d='M12 48V16h10l10 16 10-16h10v32H42V31l-7 12h-6l-7-12v17H12z'/></svg>")

# Runs in <head> so a saved theme applies before the page is painted.
THEME_BOOT = ("(function(){try{var t=localStorage.getItem('%s');if(%s.indexOf(t)>0)"
              "document.documentElement.setAttribute('data-theme',t)}catch(e){}})();"
              % (THEME_KEY, json.dumps(THEME_IDS)))


def _theme_picker() -> str:
    mucaro = "".join(f"<option value='{tid}'>{escape(label)}</option>" for tid, label, _ in THEMES[1:])
    return ("<label class='theme-picker js-only' for='theme'>Theme <select id='theme' "
            "title='Saved only in this browser'><option value='classic'>Classic Light</option>"
            f"<optgroup label='Múcaro'>{mucaro}</optgroup></select></label>")


MAX_HTML_FINDINGS = 1000
MAX_HTML_SOURCES = 500
KIND_TAG = {"ips-exploit": ("IPS exploit", "hot"), "auth-brute-force": ("failed logins", "cred"),
            "ips-brute-force": ("IPS brute force", "cred"), "brute-force": ("brute force", "cred"),
            "vertical-scan": ("port scan", "scan"), "horizontal-scan": ("sweep", "scan"),
            "ips-scan": ("firewall scan", "scan")}


def _tags(kinds, success=False) -> str:
    out = "".join(f"<span class='tag {KIND_TAG[k][1]}'>{escape(KIND_TAG[k][0])}</span>" for k in kinds)
    if success:
        out += "<span class='tag hot'>possible login success</span>"
    return out


def write_html(path: Path, ctx: dict, svg: str) -> None:
    e = escape
    F, S, P, C = ctx["findings"], ctx["hostile_sources"], ctx["paths"], ctx["chains"]
    live_src = [x for x in S if not x["routine_only"]]
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>VulnPath Report</title>"
         f"<link rel='icon' type='image/svg+xml' href=\"{FAVICON}\">"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'><script>{THEME_BOOT}</script>"
         f"<style>{_theme_css()}{CSS}{UI_CSS}</style></head><body>",
         "<div class='titlebar'><div><div class='brand'>" + MARK_SVG + "<span><strong>Múcaro</strong>"
         "<span class='brand-divider'> | </span>VulnPath</span></div>"
         "<h1>VulnPath report: which vulnerable services are being targeted</h1></div>"
         + _theme_picker() + "</div>",
         f"<div class='muted'>Case folder: <code>{e(ctx['case'])}</code> · generated {e(ctx['generated'])} · "
         f"VulnPath {e(ctx['version'])}</div>",
         "<div class='box warn'><b>How to read this report.</b> VulnPath first looks for hostile behaviour in the "
         "traffic (scanning, brute force, firewall IPS detections), then checks which of the targets the Nessus "
         "scan reports as vulnerable. Ordinary use of a vulnerable service is not a finding. Detections are leads "
         "for an analyst; nothing here confirms that a vulnerability was exploited.</div>",
         "<h2>Summary</h2><div>"]
    for label, val in [("Vulnerable services targeted", sum(1 for f in F if f["vulnerabilities"])),
                       ("Login attacks on scanned hosts", sum(1 for f in F if not f["vulnerabilities"])),
                       ("Possible login successes", sum(1 for f in F if f["possible_login_success"])),
                       ("Unblocked IPS exploit detections", sum(1 for f in F for b in f["behaviours"]
                                                                if b["kind"] == "ips-exploit" and b["not_blocked"])),
                       ("Hostile sources", len(live_src)),
                       ("Candidate attack paths", len(P)), ("Same-host chains", len(C)),
                       ("Connections analysed", ctx["traffic_total"]),
                       ("Login records analysed", ctx["auth_total"])]:
        h.append(f"<div class='kpi'><b>{val:,}</b>{e(label)}</div>")
    h.append("</div>")
    h.append(f"<p>Sources analysed: {', '.join(e(s) for s in ctx['sources']) or 'none'}. "
             f"Traffic window: {e(ctx['traffic_window'])}.</p>")
    for msg in ctx["notices"]:
        h.append(f"<div class='box warn'>{e(msg)}</div>")

    h.append("<h2>Hostile activity diagram</h2><p class='muted js-only'>Click a host to focus the report on it. "
             "Click a finding, path or chain below to highlight it here.</p><div class='svgwrap' id='diagram'>"
             + svg + "</div>")

    # ---- Findings: targeted services, ranked for remediation ----
    h.append("<h2>Remediation priorities: targeted services</h2>"
             "<p class='muted'>One row per service that drew hostile behaviour, ranked by how strong the behaviour "
             "is and how serious the vulnerability is. Expand <b>why / evidence</b> for the scoring and log lines.</p>")
    kinds_present = [k for k in KIND_TAG if any(k in f["kinds"] for f in F)]
    h.append("<div class='toolbar js-only' id='toolbar'>"
             "<input type='search' id='q' placeholder='Search IP, host, CVE, behaviour…'>"
             + _select("f-sev", "Severity", ["Critical", "High", "Medium", "Low", "none"])
             + _select("f-kind", "Behaviour", kinds_present)
             + _select("f-out", "Contact", ["contact", "no-contact"])
             + "<label><input type='checkbox' id='f-ext'> External sources only</label>"
             "<label><input type='checkbox' id='f-ok'> Possible login success</label>"
             "<span id='hostchip' class='chip' hidden></span>"
             "<button id='reset'>Reset</button><button id='dl'>Download CSV (filtered)</button>"
             "<span id='count' class='muted'></span></div>")
    if len(F) > MAX_HTML_FINDINGS:
        h.append(f"<div class='box warn'>Showing the top {MAX_HTML_FINDINGS:,} of {len(F):,} findings. "
                 "All of them are in findings.csv and findings.json.</div>")
    h.append("<table id='findings'><thead><tr><th data-k='id'>ID</th><th data-k='score' data-num='1'>Score</th>"
             "<th data-k='dst'>Target</th><th data-k='port' data-num='1'>Service</th>"
             "<th data-k='sevrank' data-num='1'>Vulnerabilities</th><th>Hostile behaviour</th><th>Assessment</th>"
             "</tr></thead><tbody>")
    for f in F[:MAX_HTML_FINDINGS]:
        vs = f["vulnerabilities"]
        vtxt = "<br>".join(f"<span class='sev-{e(v['severity'])}'>{e(v['severity'])}</span> "
                           f"{e(', '.join(v['cves']) or v['name'])}" + (" · exploit public" if v["exploit_available"] else "")
                           for v in vs[:4]) or "<span class='muted'>none on this port</span>"
        if f["other_vulnerabilities_on_host"]:
            vtxt += f"<br><span class='muted'>+{f['other_vulnerabilities_on_host']} on other ports or host-level</span>"
        btxt = _tags(f["kinds"], f["possible_login_success"]) + "".join(
            f"<div>{e(b['source_ip'])}{' (external)' if b['external'] else ''}: {e(b['detail'])}"
            + (f" <b>{e(b['success_detail'])}</b>" if b["possible_success"] else "") + "</div>"
            for b in f["behaviours"][:4])
        more = len(f["behaviours"]) - 4 + f["behaviours_not_shown"]
        if more > 0:
            btxt += f"<div class='muted'>+{more} more in why / evidence</div>"
        st = f["service_traffic"]
        if st:
            btxt += (f"<div class='muted'>All traffic to this service: {st['established']:,} established from "
                     f"{st['distinct_sources']:,}{'+' if st['distinct_sources_capped'] else ''} source(s)</div>")
        if f["pre_nat_destinations"]:
            btxt += f"<div class='muted'>via NAT {e(', '.join(f['pre_nat_destinations']))}</div>"
        cves = " ".join(sorted({c for v in vs for c in v["cves"]}))
        sev = vs[0]["severity"] if vs else "none"
        attrs = {
            "id": f["id"], "score": f["priority_score"], "dst": f["target_ip"], "port": f["port"],
            "proto": f["protocol"], "host": f["target_hostname"], "sev": sev,
            "sevrank": {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(sev, 0),
            "kinds": " ".join(f["kinds"]), "outcome": f["outcome"], "ext": int(f["external_sources"] > 0),
            "ok": int(f["possible_login_success"]), "src": " ".join(f["hostile_sources"][:50]), "cves": cves,
            "assess": f["assessment"], "first": ts(f["first_seen"]),
        }
        data = " ".join(f"data-{k}='{e(str(v), quote=True)}'" for k, v in attrs.items())
        h.append(f"<tr class='frow' {data}><td>{e(f['id'])}</td><td>{f['priority_score']}</td>"
                 f"<td><b>{e(f['target_ip'])}</b><br><span class='muted'>{e(f['target_hostname'])}</span></td>"
                 f"<td>{e(f['protocol'])}/{f['port']}</td><td>{vtxt}</td><td>{btxt}"
                 f"<div class='muted'>{e(ts(f['first_seen']))} to {e(ts(f['last_seen']))}</div></td>"
                 f"<td>{e(f['assessment'])}"
                 + (f"<br><b>Chain:</b> {e(', '.join(f['chains']))}" if f["chains"] else "")
                 + ("<br><b>Scan may be stale.</b>" if f["scan_stale"] else "")
                 + "<details><summary class='muted'>why / evidence</summary>"
                 + "".join(f"<div>• {e(r)}</div>" for r in f["score_reasons"])
                 + "".join(f"<div>{e(b['source_ip'])}: {e(b['label'])}: {e(b['detail'])}</div>"
                           + "".join(f"<div>Signature: {e(sg)}</div>" for sg in b["signatures"])
                           for b in f["behaviours"][4:])
                 + "".join(f"<div><code>{e(r)}</code></div>" for r in f["evidence"]) + "</details></td></tr>")
    h.append("</tbody></table><p id='nomatch' class='muted' hidden>No findings match the current filters.</p>")

    # ---- Hostile sources ----
    h.append("<h2>Hostile sources</h2><p class='muted'>Every source with at least one detection, including those "
             "that only touched hosts without vulnerability data. Sources marked <i>routine</i> matched the "
             "brute-force pattern but behave like many internal peers, so they produce no finding.</p>")
    if not S:
        h.append("<p class='muted'>No scanning, brute force or IPS detections were found.</p>")
    else:
        if len(S) > MAX_HTML_SOURCES:
            h.append(f"<div class='box warn'>Showing {MAX_HTML_SOURCES:,} of {len(S):,} sources. "
                     "All of them are in sources.csv.</div>")
        h.append("<table id='sources'><thead><tr><th>Source</th><th>Behaviour</th><th>Targets</th>"
                 "<th>Findings</th><th>Seen</th></tr></thead><tbody>")
        for x in S[:MAX_HTML_SOURCES]:
            kinds = _tags(x["kinds"], x["possible_login_success"]) or "<span class='tag scan'>routine</span>"
            det = "".join(f"<div>{e(d['detail'])}" + (f" <i>({e(d['routine_reason'])})</i>" if d["routine"] else "")
                          + "</div>" for d in x["detections"][:4])
            h.append(f"<tr class='srow' data-src='{e(x['source_ip'], quote=True)}'><td><b>{e(x['source_ip'])}</b>"
                     f"{'<br><span class=muted>external</span>' if x['external'] else ''}</td><td>{kinds}{det}</td>"
                     f"<td>{x['targets_contacted']:,} contacted<br>{x['vulnerable_targets']} vulnerable</td>"
                     f"<td>{e(' '.join(x['finding_ids'][:10]))}{' …' if len(x['finding_ids']) > 10 else ''}</td>"
                     f"<td>{e(ts(x['first_seen']))}<br>{e(ts(x['last_seen']))}</td></tr>")
        h.append("</tbody></table>")

    # ---- Attack paths ----
    h.append("<h2>Candidate attack paths</h2><p class='muted'>A path starts at a hostile source that got through "
             "(a login after failures, an unblocked IPS detection or an established session) and follows that "
             "host's later connections to other vulnerable services.</p>")
    if not P:
        h.append("<p class='muted'>No hostile source got through to a host that then connected onward to another "
                 "vulnerable service.</p>")
    for p in P:
        edges = " ".join(f"{hp['from']}>{hp['to']}" for hp in p["hops"])
        h.append(f"<div class='box pathbox' data-hosts='{e(' '.join(p['hosts']), quote=True)}' "
                 f"data-edges='{e(edges, quote=True)}'><b>{e(p['id'])}</b> · {p['hop_count']} hop(s) · max severity "
                 f"<span class='sev-{e(p['max_severity'])}'>{e(p['max_severity'])}</span> · "
                 f"<span class='tag'>{e(p['status'])}</span><br><code>{' → '.join(e(x) for x in p['hosts'])}</code><ol>")
        for hop in p["hops"]:
            vtxt = "; ".join(f"{', '.join(v['cves']) or v['name']} ({v['severity']}, {v['stage']})"
                             for v in hop["vulnerabilities_at_target"])
            ch = (" · same-host chain: " + e(", ".join(hop["same_host_chains_at_target"]))) \
                if hop["same_host_chains_at_target"] else ""
            h.append(f"<li>{e(hop['from'])} → <b>{e(hop['to'])}</b> {e(hop['to_hostname'])}: observed "
                     f"{e(hop['observed'])} ({e(ts(hop['first_seen']))} to {e(ts(hop['last_seen']))}). "
                     f"Vulnerable: {e(vtxt)}{ch}"
                     f"<details><summary class='muted'>evidence</summary>"
                     + "".join(f"<div><code>{e(r)}</code></div>" for r in hop["evidence"]) + "</details></li>")
        h.append("</ol><div class='muted'>Missing evidence: " + e(" ".join(p["missing_evidence"])) + "</div></div>")

    # ---- Same-host chains ----
    h.append("<h2>Same-host vulnerability chains</h2>")
    if not C:
        h.append("<p class='muted'>No targeted host matched a published or inferred chain.</p>")
    for c in C:
        tag = "Published chain" if c["type"] == "documented" else "Inferred chain"
        reached = "Hostile activity reached this host." if c["entry_targeted"] else \
            "No hostile activity against this host was observed."
        h.append(f"<div class='box chainbox' data-hosts='{e(c['host'], quote=True)}' data-edges=''>"
                 f"<b>{e(c['host'])}</b> {e(c['hostname'])} · <span class='tag'>{tag}</span>"
                 f"<b>{e(c['name'])}</b><br>{e(c['description'])}<ol>")
        for st in c["steps"]:
            frm = f" · targeted by {', '.join(st['targeted_by'])}" if st["targeted_by"] else ""
            port = f"{st['protocol']}/{st['port']}" if st["port"] else "host-level"
            h.append(f"<li>{e(', '.join(st['cves']) or st['name'])} <span class='sev-{e(st['severity'])}'>"
                     f"{e(st['severity'])}</span> · {e(port)} · {e(st['stage_label'])}{e(frm)}</li>")
        h.append("</ol>")
        if c["missing_cves"]:
            h.append(f"<div class='muted'>Chain CVEs not found on this host: {e(', '.join(c['missing_cves']))}</div>")
        if c["reference"]:
            h.append(f"<div class='muted'>Reference: {e(c['reference'])}</div>")
        h.append(f"<div><b>{e(reached)}</b> <span class='muted'>{e(c['caveat'])}</span></div></div>")

    h.append("<h2>Coverage and data quality</h2><ul>")
    for line in ctx["coverage"]:
        h.append(f"<li>{e(line)}</li>")
    h.append("</ul><h2>Evidence manifest</h2><table><tr><th>File</th><th>Type</th><th>SHA-256</th>"
             "<th>Parsed</th><th>Skipped</th></tr>")
    for m in ctx["manifest"]:
        h.append(f"<tr><td>{e(m['path'])}</td><td>{e(m['source_type'])}</td><td><code>{e(m['sha256'])}</code></td>"
                 f"<td>{m['records_parsed']}</td><td>{m['records_skipped']}</td></tr>")
    h.append("</table><p class='muted'>" + e(ctx["integrity"]) + "</p>")
    h.append("<h2>Limitations</h2><ul>"
             "<li>Asset matching is by IP address. Palo Alto inbound NAT is resolved to the internal address; DHCP "
             "changes and overlapping address ranges are not.</li>"
             "<li>Palo Alto timestamps carry no time zone and are read with the configured offset.</li>"
             "<li>Behaviour is counted in fixed time windows; a slow scan spread over many windows can stay under "
             "the thresholds.</li>"
             "<li>Brute force from conn.log is a pattern. Zeek ssh.log, ntlm.log and kerberos.log, or a firewall "
             "signature, are needed for login results.</li>"
             "<li>Chain detection uses CVSS access requirements and the known-chain list. It does not verify "
             "that one flaw provides the access the next one needs.</li>"
             "<li>Host-level vulnerabilities (port 0) are used only for chaining, never matched to traffic.</li>"
             "</ul>")
    h.append(f"<script>{UI_JS.replace('%THEME_KEY%', THEME_KEY)}</script></body></html>")
    path.write_text("\n".join(h), encoding="utf-8")


def _select(id_, label, options) -> str:
    opts = "".join(f"<option value='{escape(o, quote=True)}'>{escape(o)}</option>" for o in options)
    return f"<select id='{id_}' aria-label='{label}'><option value=''>{label}: all</option>{opts}</select>"


UI_CSS = """
.js-only{display:none}.js .js-only{display:block}.js .toolbar.js-only{display:flex}
.js .theme-picker.js-only{display:flex}
.titlebar{display:flex;gap:16px;align-items:flex-start;justify-content:space-between}
.titlebar h1{margin-top:0}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:18px;color:var(--muted)}
.brand strong{color:var(--text)}.brand-divider{padding:0 4px}
.brand .mark{flex:none;border-radius:8px;box-shadow:0 0 0 1px var(--border-strong)}
.theme-picker{flex:none;margin-left:auto;gap:6px;align-items:center;font-size:13px;color:var(--muted)}
.toolbar{position:sticky;top:0;z-index:5;background:var(--bg);flex-wrap:wrap;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.toolbar input[type=search]{flex:1 1 240px;padding:6px 8px;border:1px solid var(--border-strong);border-radius:6px;background:var(--surface);color:var(--text)}
.toolbar select,.toolbar button,.theme-picker select{padding:5px 8px;border:1px solid var(--border-strong);border-radius:6px;background:var(--surface);color:var(--text);font:inherit;font-size:13px}
.toolbar button{cursor:pointer}.toolbar label{font-size:13px}
.chip{background:var(--chip-bg);color:var(--chip-fg);border-radius:12px;padding:3px 10px;font-size:13px;cursor:pointer}
th[data-k]{cursor:pointer;user-select:none}th[data-k]:after{content:' \\2195';color:var(--muted);font-size:11px}
th.asc:after{content:' \\2191';color:var(--text)}th.desc:after{content:' \\2193';color:var(--text)}
tr.frow{cursor:pointer}tr.frow:hover{background:var(--hover)}tr.sel{background:var(--sel)!important}
.pathbox,.chainbox{cursor:pointer}.pathbox.sel,.chainbox.sel{border-color:var(--accent);box-shadow:0 0 0 2px var(--focus-ring)}
#diagram .bg{fill:var(--bg)}#diagram .ink{fill:var(--text)}#diagram .ink2{fill:var(--text-2)}#diagram .ink3{fill:var(--muted)}
#diagram path.ink,#diagram line.ink{fill:none;stroke:var(--text)}#diagram .halo{stroke:var(--bg)}
#diagram .box{fill:var(--node)}#diagram .box.src{fill:var(--node-src);stroke:var(--sev-none)}
#diagram [data-sev=Critical] .box,#diagram .sev-Critical{stroke:var(--sev-crit)}#diagram [data-sev=Critical] .sevtx{fill:var(--sev-crit)}
#diagram [data-sev=High] .box,#diagram .sev-High{stroke:var(--sev-high)}#diagram [data-sev=High] .sevtx{fill:var(--sev-high)}
#diagram [data-sev=Medium] .box,#diagram .sev-Medium{stroke:var(--sev-med)}#diagram [data-sev=Medium] .sevtx{fill:var(--sev-med)}
#diagram [data-sev=Low] .box,#diagram .sev-Low{stroke:var(--sev-low)}#diagram [data-sev=Low] .sevtx{fill:var(--sev-low)}
.dimbox{opacity:.35}
#diagram .node{cursor:pointer}#diagram .dim{opacity:.12}#diagram .hl rect:first-of-type{stroke-width:4}
@media print{.toolbar,.js-only{display:none!important}.dimbox{opacity:1}#diagram .dim{opacity:1}}
"""

UI_JS = r"""
(function(){
document.documentElement.classList.add('js');
var $=function(s){return document.querySelector(s)}, $$=function(s){return Array.prototype.slice.call(document.querySelectorAll(s))};
var rows=$$('tr.frow'), state={host:null};
// theme picker: remembered per browser, ignored if storage is blocked
var theme=$('#theme'), root=document.documentElement;
theme.value=root.getAttribute('data-theme')||'classic';
theme.addEventListener('change',function(){
  if(theme.value==='classic')root.removeAttribute('data-theme'); else root.setAttribute('data-theme',theme.value);
  try{localStorage.setItem('%THEME_KEY%',theme.value)}catch(e){}
});
function txt(r){return Object.keys(r.dataset).map(function(k){return r.dataset[k]}).join(' ').toLowerCase()}
function apply(){
  var q=$('#q').value.trim().toLowerCase(), sev=$('#f-sev').value, kind=$('#f-kind').value,
      out=$('#f-out').value, ok=$('#f-ok').checked, ext=$('#f-ext').checked, n=0;
  rows.forEach(function(r){
    var d=r.dataset, show=(!q||txt(r).indexOf(q)>=0)&&(!sev||d.sev===sev)&&
      (!kind||d.kinds.split(' ').indexOf(kind)>=0)&&(!out||d.outcome===out)&&(!ok||d.ok==='1')&&
      (!ext||d.ext==='1')&&(!state.host||d.src.split(' ').indexOf(state.host)>=0||d.dst===state.host);
    r.hidden=!show; if(show)n++;
  });
  $('#count').textContent='Showing '+n+' of '+rows.length;
  $('#nomatch').hidden=n>0;
  var chip=$('#hostchip');
  if(state.host){chip.hidden=false;chip.textContent='Host: '+state.host+'  ✕';}else chip.hidden=true;
  $$('tr.srow').forEach(function(r){r.classList.toggle('dimbox',!!state.host&&r.dataset.src!==state.host);});
  $$('.pathbox,.chainbox').forEach(function(b){
    b.classList.toggle('dimbox',!!state.host&&b.dataset.hosts.split(' ').indexOf(state.host)<0);});
}
function highlight(hosts,edges){
  var on=hosts&&hosts.length;
  $$('#diagram .node').forEach(function(g){
    var hit=on&&hosts.indexOf(g.dataset.host)>=0; g.classList.toggle('dim',on&&!hit); g.classList.toggle('hl',!!hit);});
  $$('#diagram .edge').forEach(function(g){
    var k=g.dataset.src+'>'+g.dataset.dst;
    var hit=on&&(edges?edges.indexOf(k)>=0:(hosts.indexOf(g.dataset.src)>=0||hosts.indexOf(g.dataset.dst)>=0));
    g.classList.toggle('dim',on&&!hit);});
}
function clearSel(){$$('.sel').forEach(function(x){x.classList.remove('sel')})}
function focusHost(h){
  state.host=(state.host===h)?null:h; clearSel();
  if(state.host){
    var nb=[state.host];
    $$('#diagram .edge').forEach(function(g){
      if(g.dataset.src===state.host)nb.push(g.dataset.dst); if(g.dataset.dst===state.host)nb.push(g.dataset.src);});
    highlight(nb,null);
  } else highlight(null);
  apply();
}
$$('#diagram .node').forEach(function(g){g.addEventListener('click',function(){focusHost(g.dataset.host)})});
$('#hostchip').addEventListener('click',function(){focusHost(state.host)});
$$('.pathbox,.chainbox').forEach(function(b){b.addEventListener('click',function(ev){
  if(ev.target.closest('summary'))return;
  var was=b.classList.contains('sel'); clearSel();
  if(was){highlight(null);return;}
  b.classList.add('sel');
  var ed=b.dataset.edges?b.dataset.edges.split(' '):null;
  highlight(b.dataset.hosts.split(' '),ed);
  $('#diagram').scrollIntoView({behavior:'smooth',block:'nearest'});
});});
rows.forEach(function(r){r.addEventListener('click',function(ev){
  if(ev.target.closest('details'))return;
  var was=r.classList.contains('sel'); clearSel();
  if(was){highlight(null);return;}
  r.classList.add('sel');
  var srcs=r.dataset.src?r.dataset.src.split(' '):[];
  highlight(srcs.concat([r.dataset.dst]),srcs.map(function(s){return s+'>'+r.dataset.dst}));
});});
['#q','#f-sev','#f-kind','#f-out','#f-ok','#f-ext'].forEach(function(s){$(s).addEventListener('input',apply)});
$('#reset').addEventListener('click',function(){
  $('#q').value='';['#f-sev','#f-kind','#f-out'].forEach(function(s){$(s).value=''});
  $('#f-ext').checked=false; $('#f-ok').checked=false; state.host=null; clearSel(); highlight(null);
  rows.sort(function(a,b){return a.dataset.id<b.dataset.id?-1:1}); rows.forEach(function(r){tbody.appendChild(r)});
  $$('#findings th').forEach(function(x){x.classList.remove('asc','desc')}); apply();});
// sorting
var tbody=$('#findings tbody');
$$('#findings th[data-k]').forEach(function(th){th.addEventListener('click',function(){
  var k=th.dataset.k, num=!!th.dataset.num, asc=!th.classList.contains('asc');
  $$('#findings th').forEach(function(x){x.classList.remove('asc','desc')}); th.classList.add(asc?'asc':'desc');
  rows.sort(function(a,b){var x=a.dataset[k],y=b.dataset[k];
    if(num){x=+x;y=+y;} var c=x<y?-1:x>y?1:0; return asc?c:-c;});
  rows.forEach(function(r){tbody.appendChild(r)});
});});
// CSV of the visible rows
$('#dl').addEventListener('click',function(){
  var cols=['id','score','dst','host','proto','port','sev','cves','kinds','ok','outcome','src','first','assess'];
  var esc=function(v){v=String(v==null?'':v); if(/^[=+\-@]/.test(v))v="'"+v; return '"'+v.replace(/"/g,'""')+'"'};
  var lines=[cols.join(',')];
  rows.filter(function(r){return !r.hidden}).forEach(function(r){lines.push(cols.map(function(c){return esc(r.dataset[c])}).join(','))});
  var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lines.join('\r\n')],{type:'text/csv'}));
  a.download='findings_filtered.csv'; document.body.appendChild(a); a.click(); a.remove();
});
apply();
})();
"""
