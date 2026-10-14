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


def write_csv(path: Path, findings: list[dict]) -> None:
    cols = ["id", "priority_score", "activity", "outcome", "direction", "source_ip", "target_ip",
            "target_hostname", "port", "protocol", "top_severity", "cves", "exploit_available",
            "established", "attempts", "denied", "ips_not_blocked", "ips_blocked", "ips_signatures",
            "ips_cves_matched", "pre_nat_destinations", "first_seen", "last_seen", "scan_stale", "assessment",
            "evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for x in findings:
            vs = x["vulnerabilities"]
            cves = sorted({c for v in vs for c in v["cves"]})
            row = [x["id"], x["priority_score"], x["activity"], x["outcome"], x["direction"], x["source_ip"],
                   x["target_ip"], x["target_hostname"], x["port"], x["protocol"], vs[0]["severity"],
                   " ".join(cves), any(v["exploit_available"] for v in vs), x["traffic"]["established"],
                   x["traffic"]["attempts"], x["traffic"]["denied"], x["ips"]["not_blocked"], x["ips"]["blocked"],
                   " | ".join(x["ips"]["signatures"]), " ".join(x["ips"]["cves_matched"]),
                   " ".join(x["traffic"]["pre_nat_destinations"]), ts(x["traffic"]["first_seen"]),
                   ts(x["traffic"]["last_seen"]), x["scan_stale"], x["assessment"], " | ".join(x["evidence"])]
            # Neutralise spreadsheet formula injection from untrusted log content.
            w.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in row])


CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#111827;max-width:1200px;margin:24px auto;padding:0 16px;line-height:1.45}
h1{font-size:24px;margin-bottom:4px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
.muted{color:#6b7280}.box{border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin:10px 0}
.warn{background:#fff7ed;border-color:#fdba74}.kpi{display:inline-block;margin:0 24px 8px 0}.kpi b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f9fafb}code{font-size:12px;background:#f3f4f6;padding:1px 4px;border-radius:4px;word-break:break-all}
.sev-Critical{color:#b91c1c;font-weight:600}.sev-High{color:#ea580c;font-weight:600}.sev-Medium{color:#ca8a04}.sev-Low{color:#2563eb}
.tag{display:inline-block;font-size:11px;padding:1px 8px;border-radius:9px;background:#eef2ff;color:#3730a3;margin-right:4px}
.svgwrap{overflow-x:auto;border:1px solid #e5e7eb;border-radius:8px}details{margin:4px 0}
"""


def write_html(path: Path, ctx: dict, svg: str) -> None:
    e = escape
    F, P, C = ctx["findings"], ctx["paths"], ctx["chains"]
    est = [f for f in F if f["outcome"] == "established"]
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Investigation Report</title>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}{UI_CSS}</style></head><body>",
         f"<h1>Vulnerability and traffic correlation report</h1>",
         f"<div class='muted'>Case folder: <code>{e(ctx['case'])}</code> · generated {e(ctx['generated'])} · "
         f"workbench {e(ctx['version'])}</div>",
         "<div class='box warn'><b>How to read this report.</b> Findings show traffic that reached services a "
         "Nessus scan reported as vulnerable. Attack paths and chains are <b>hypotheses</b> for an analyst to "
         "check. Nothing here confirms that a vulnerability was exploited.</div>",
         "<h2>Summary</h2><div>"]
    for label, val in [("Findings", len(F)), ("Established to vulnerable service", len(est)),
                       ("IPS exploit detections not blocked", sum(1 for f in F if f["ips"]["not_blocked"])),
                       ("Candidate attack paths", len(P)), ("Same-host chains", len(C)),
                       ("Connections analysed", ctx["traffic_total"]), ("Vulnerable services in scan", ctx["vuln_services"])]:
        h.append(f"<div class='kpi'><b>{val:,}</b>{e(label)}</div>")
    h.append("</div>")
    h.append(f"<p>Sources analysed: {', '.join(e(s) for s in ctx['sources']) or 'none'}. "
             f"Traffic window: {e(ctx['traffic_window'])}.</p>")
    for msg in ctx["notices"]:
        h.append(f"<div class='box warn'>{e(msg)}</div>")

    h.append("<h2>Attack-path diagram</h2><p class='muted js-only'>Click a host to focus the report on it. "
             "Click a path or finding below to highlight it here.</p><div class='svgwrap' id='diagram'>" + svg + "</div>")

    # ---- Findings (interactive table) ----
    sources = sorted({s for f in F for s in f["traffic"]["telemetry_sources"]})
    h.append("<h2>Findings</h2>")
    h.append("<div class='toolbar js-only' id='toolbar'>"
             "<input type='search' id='q' placeholder='Search IP, host, CVE, signature…'>"
             + _select("f-sev", "Severity", ["Critical", "High", "Medium", "Low"])
             + _select("f-act", "Activity", ["exploit-attempt", "targeting", "probing"])
             + _select("f-out", "Outcome", ["established", "attempted", "denied", "ips-only"])
             + _select("f-src", "Telemetry", sources)
             + "<label><input type='checkbox' id='f-ext'> External sources only</label>"
             "<span id='hostchip' class='chip' hidden></span>"
             "<button id='reset'>Reset</button><button id='dl'>Download CSV (filtered)</button>"
             "<span id='count' class='muted'></span></div>")
    h.append("<table id='findings'><thead><tr><th data-k='id'>ID</th><th data-k='score' data-num='1'>Score</th>"
             "<th data-k='activity'>Activity</th><th data-k='src'>Source → target</th><th data-k='port' data-num='1'>"
             "Service</th><th data-k='sevrank' data-num='1'>Vulnerabilities</th><th>Traffic</th><th>Assessment</th>"
             "</tr></thead><tbody>")
    for f in F:
        vs = f["vulnerabilities"]
        vtxt = "<br>".join(f"<span class='sev-{e(v['severity'])}'>{e(v['severity'])}</span> "
                           f"{e(', '.join(v['cves']) or v['name'])}" + (" · exploit public" if v["exploit_available"] else "")
                           for v in vs[:4])
        t = f["traffic"]
        ips = f["ips"]
        ips_txt = ""
        if ips["exploit_detections"]:
            ips_txt = (f"<br><b style='color:#dc2626'>IPS: {ips['not_blocked']} not blocked · {ips['blocked']} blocked"
                       f"</b>")
        nat_txt = f"<br><span class='muted'>via NAT {e(', '.join(t['pre_nat_destinations']))}</span>" \
            if t["pre_nat_destinations"] else ""
        cves = " ".join(sorted({c for v in vs for c in v["cves"]}))
        attrs = {
            "id": f["id"], "score": f["priority_score"], "activity": f["activity"], "outcome": f["outcome"],
            "src": f["source_ip"], "dst": f["target_ip"], "port": f["port"], "sev": vs[0]["severity"],
            "sevrank": {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(vs[0]["severity"], 0),
            "ext": int(f["direction"] == "inbound-external"), "tele": " ".join(t["telemetry_sources"]),
            "proto": f["protocol"], "host": f["target_hostname"], "cves": cves,
            "assess": f["assessment"], "sig": " | ".join(ips["signatures"]),
            "ipsn": ips["not_blocked"], "ipsb": ips["blocked"],
            "est": t["established"], "att": t["attempts"], "den": t["denied"], "first": ts(t["first_seen"]),
        }
        data = " ".join(f"data-{k}='{e(str(v), quote=True)}'" for k, v in attrs.items())
        h.append(f"<tr class='frow' {data}><td>{e(f['id'])}</td><td>{f['priority_score']}</td><td>{e(f['activity'])}<br>"
                 f"<span class='muted'>{e(f['outcome'])}</span></td><td>{e(f['source_ip'])} → <b>{e(f['target_ip'])}</b>"
                 f"<br><span class='muted'>{e(f['target_hostname'])}</span></td><td>{e(f['protocol'])}/{f['port']}</td>"
                 f"<td>{vtxt}</td><td>{t['established']} est · {t['attempts']} att · {t['denied']} denied{ips_txt}{nat_txt}"
                 f"{_by_source(t)}<br>"
                 f"<span class='muted'>{e(ts(t['first_seen']))}</span></td><td>{e(f['assessment'])}"
                 + ("<br><b>Scan may be stale.</b>" if f["scan_stale"] else "")
                 + "<details><summary class='muted'>why / evidence</summary>"
                 + "".join(f"<div>• {e(r)}</div>" for r in f["score_reasons"])
                 + "".join(f"<div>Signature: {e(sg)}</div>" for sg in ips["signatures"])
                 + "".join(f"<div><code>{e(r)}</code></div>" for r in f["evidence"]) + "</details></td></tr>")
    h.append("</tbody></table><p id='nomatch' class='muted' hidden>No findings match the current filters.</p>")

    # ---- Attack paths ----
    h.append("<h2>Candidate attack paths</h2>")
    if not P:
        h.append("<p class='muted'>No multi-step paths were found in observed, established traffic.</p>")
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
        h.append("<p class='muted'>No hosts matched a documented or generic chain.</p>")
    for c in C:
        tag = "Documented chain" if c["type"] == "documented" else "Generic chain (inferred)"
        reached = "Entry point received established traffic." if c["entry_reached"] else \
            "No established traffic to the entry point was observed."
        h.append(f"<div class='box chainbox' data-hosts='{e(c['host'], quote=True)}' data-edges=''>"
                 f"<b>{e(c['host'])}</b> {e(c['hostname'])} · <span class='tag'>{tag}</span>"
                 f"<b>{e(c['name'])}</b><br>{e(c['description'])}<ol>")
        for st in c["steps"]:
            frm = f" · reached from {', '.join(st['reached_from'])}" if st["reached_from"] else ""
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
             "<li>Chain detection uses CVSS access requirements and the known-chain list. It does not verify "
             "that one flaw provides the access the next one needs.</li>"
             "<li>A connection to a vulnerable port shows reachability only. It does not show exploitation.</li>"
             "<li>Host-level vulnerabilities (port 0) are used only for chaining, never matched to traffic.</li>"
             "</ul>")
    h.append(f"<script>{UI_JS}</script></body></html>")
    path.write_text("\n".join(h), encoding="utf-8")


def _by_source(t: dict) -> str:
    """Per-sensor counts when more than one sensor saw the traffic (combined figure is the max, not the sum)."""
    bs = t.get("by_source", {})
    if len(bs) < 2:
        return ""
    parts = [f"{escape(k)} {v['established']}/{v['attempts']}/{v['denied']}" for k, v in bs.items()]
    return f"<br><span class='muted' title='established/attempted/denied per sensor'>{' · '.join(parts)}</span>"


def _select(id_, label, options) -> str:
    opts = "".join(f"<option value='{escape(o, quote=True)}'>{escape(o)}</option>" for o in options)
    return f"<select id='{id_}' aria-label='{label}'><option value=''>{label}: all</option>{opts}</select>"


UI_CSS = """
.js-only{display:none}.js .js-only{display:block}.js .toolbar.js-only{display:flex}
.toolbar{position:sticky;top:0;z-index:5;background:#fff;flex-wrap:wrap;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid #e5e7eb}
.toolbar input[type=search]{flex:1 1 240px;padding:6px 8px;border:1px solid #d1d5db;border-radius:6px}
.toolbar select,.toolbar button{padding:5px 8px;border:1px solid #d1d5db;border-radius:6px;background:#fff;font:inherit;font-size:13px}
.toolbar button{cursor:pointer}.toolbar label{font-size:13px}
.chip{background:#ede9fe;color:#5b21b6;border-radius:12px;padding:3px 10px;font-size:13px;cursor:pointer}
th[data-k]{cursor:pointer;user-select:none}th[data-k]:after{content:' \\2195';color:#9ca3af;font-size:11px}
th.asc:after{content:' \\2191';color:#111827}th.desc:after{content:' \\2193';color:#111827}
tr.frow{cursor:pointer}tr.frow:hover{background:#f9fafb}tr.sel{background:#f5f3ff!important}
.pathbox,.chainbox{cursor:pointer}.pathbox.sel,.chainbox.sel{border-color:#7c3aed;box-shadow:0 0 0 2px #ddd6fe}
.dimbox{opacity:.35}
#diagram .node{cursor:pointer}#diagram .dim{opacity:.12}#diagram .hl rect:first-of-type{stroke-width:4}
@media print{.toolbar,.js-only{display:none!important}.dimbox{opacity:1}#diagram .dim{opacity:1}}
"""

UI_JS = r"""
(function(){
document.documentElement.classList.add('js');
var $=function(s){return document.querySelector(s)}, $$=function(s){return Array.prototype.slice.call(document.querySelectorAll(s))};
var rows=$$('tr.frow'), state={host:null};
function txt(r){return Object.keys(r.dataset).map(function(k){return r.dataset[k]}).join(' ').toLowerCase()}
function apply(){
  var q=$('#q').value.trim().toLowerCase(), sev=$('#f-sev').value, act=$('#f-act').value,
      out=$('#f-out').value, src=$('#f-src').value, ext=$('#f-ext').checked, n=0;
  rows.forEach(function(r){
    var d=r.dataset, ok=(!q||txt(r).indexOf(q)>=0)&&(!sev||d.sev===sev)&&(!act||d.activity===act)&&
      (!out||d.outcome===out)&&(!src||d.tele.split(' ').indexOf(src)>=0)&&(!ext||d.ext==='1')&&
      (!state.host||d.src===state.host||d.dst===state.host);
    r.hidden=!ok; if(ok)n++;
  });
  $('#count').textContent='Showing '+n+' of '+rows.length;
  $('#nomatch').hidden=n>0;
  var chip=$('#hostchip');
  if(state.host){chip.hidden=false;chip.textContent='Host: '+state.host+'  ✕';}else chip.hidden=true;
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
  r.classList.add('sel'); highlight([r.dataset.src,r.dataset.dst],[r.dataset.src+'>'+r.dataset.dst]);
});});
['#q','#f-sev','#f-act','#f-out','#f-src','#f-ext'].forEach(function(s){$(s).addEventListener('input',apply)});
$('#reset').addEventListener('click',function(){
  $('#q').value='';['#f-sev','#f-act','#f-out','#f-src'].forEach(function(s){$(s).value=''});
  $('#f-ext').checked=false; state.host=null; clearSel(); highlight(null);
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
  var cols=['id','score','activity','outcome','src','dst','host','proto','port','sev','cves','ipsn','ipsb','sig','est','att','den','first','tele','assess'];
  var esc=function(v){v=String(v==null?'':v); if(/^[=+\-@]/.test(v))v="'"+v; return '"'+v.replace(/"/g,'""')+'"'};
  var lines=[cols.join(',')];
  rows.filter(function(r){return !r.hidden}).forEach(function(r){lines.push(cols.map(function(c){return esc(r.dataset[c])}).join(','))});
  var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lines.join('\r\n')],{type:'text/csv'}));
  a.download='findings_filtered.csv'; document.body.appendChild(a); a.click(); a.remove();
});
apply();
})();
"""
