"""Pure-Python SVG attack-path diagram (no Graphviz binary, works offline)."""
from __future__ import annotations

from html import escape

SEV_COLOR = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", None: "#475569"}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
NODE_W, NODE_H, COL_GAP, ROW_GAP, MARGIN = 230, 70, 410, 34, 30
MAX_NODES = 40


def render(findings: list[dict], paths: list[dict], chains: list[dict]) -> str:
    edges: dict[tuple, dict] = {}
    node_sev: dict[str, str | None] = {}
    node_name: dict[str, str] = {}
    node_vuln: dict[str, str] = {}
    external: dict[str, bool] = {}

    for f in findings:
        key = (f["source_ip"], f["target_ip"], f["port"], f["protocol"])
        style = {"established": "observed", "attempted": "attempt", "denied": "denied",
                 "ips-only": "attempt"}[f["outcome"]]
        if f["activity"] == "probing" and style != "observed":
            style = "probe"
        n = f["traffic"]["established"] or f["traffic"]["attempts"] or f["traffic"]["denied"]
        label = f"{f['protocol']}/{f['port']} ×{n}" if n else f"{f['protocol']}/{f['port']}"
        ips = f["ips"]
        if ips["not_blocked"]:
            style, label = "exploit", f"{f['protocol']}/{f['port']} · IPS alert ×{ips['not_blocked']}"
        elif ips["exploit_detections"]:
            style, label = "exploit-blocked", f"{f['protocol']}/{f['port']} · IPS blocked ×{ips['blocked']}"
        edges[key] = {"style": style, "label": label,
                      "score": f["priority_score"]}
        sev = f["vulnerabilities"][0]["severity"]
        if SEV_RANK[sev] > SEV_RANK.get(node_sev.get(f["target_ip"])):
            node_sev[f["target_ip"]] = sev
            v = f["vulnerabilities"][0]
            node_vuln[f["target_ip"]] = (v["cves"][0] if v["cves"] else v["name"])[:34]
        node_sev.setdefault(f["source_ip"], node_sev.get(f["source_ip"]))
        node_name[f["target_ip"]] = f["target_hostname"]
        external[f["source_ip"]] = f["direction"] == "inbound-external"

    chained = {c["host"] for c in chains}
    for c in chains:
        if c["host"] in node_sev and c["host"] not in node_vuln:
            node_vuln[c["host"]] = c["name"][:34]

    # Keep the diagram readable: nodes on attack paths first, then by finding priority.
    keep: list[str] = []
    for p in paths:
        for h in p["hosts"]:
            if h not in keep:
                keep.append(h)
    for f in findings:
        for h in (f["source_ip"], f["target_ip"]):
            if h not in keep:
                keep.append(h)
    keep = keep[:MAX_NODES]
    kept = set(keep)
    edges = {k: e for k, e in edges.items() if k[0] in kept and k[1] in kept}

    # Columns: depth from sources along edges (sources with no inbound edge are column 0).
    inbound = {k[1] for k in edges}
    depth = {n: 0 for n in keep if n not in inbound}
    changed = True
    while changed:
        changed = False
        for (s, d, *_), e in sorted(edges.items()):
            if s in depth and depth[s] + 1 > depth.get(d, -1) and depth[s] + 1 <= 6:
                if d not in depth or (e["style"] == "observed" and depth[d] < depth[s] + 1):
                    depth[d] = depth[s] + 1
                    changed = True
    for n in keep:
        depth.setdefault(n, 1)

    cols: dict[int, list[str]] = {}
    for n in keep:
        cols.setdefault(depth[n], []).append(n)
    pos = {}
    for c, nodes in cols.items():
        for r, n in enumerate(nodes):
            pos[n] = (MARGIN + c * COL_GAP, MARGIN + 40 + r * (NODE_H + ROW_GAP))

    width = MARGIN * 2 + (max(cols) + 1) * COL_GAP - (COL_GAP - NODE_W) if cols else 400
    height = max((y for _, y in pos.values()), default=0) + NODE_H + MARGIN + 185
    width = max(width, 760)

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="12">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
           'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker></defs>',
           f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
           f'<text x="{MARGIN}" y="{MARGIN + 6}" font-size="15" font-weight="600" fill="#111827">'
           'Candidate attack paths (observed traffic into vulnerable services)</text>']

    path_edges = {(h["from"], h["to"]) for p in paths for h in p["hops"]}
    styles = {
        "observed": ("#111827", "", 2.0),
        "attempt": ("#6b7280", "6 4", 1.4),
        "probe": ("#9ca3af", "2 4", 1.2),
        "denied": ("#16a34a", "1 3", 1.2),
        "exploit": ("#dc2626", "", 2.6),
        "exploit-blocked": ("#dc2626", "3 3", 1.6),
    }
    for (s, d, port, proto), e in sorted(edges.items(), key=lambda kv: kv[1]["style"] in ("observed", "exploit")):
        x1, y1 = pos[s][0] + NODE_W, pos[s][1] + NODE_H / 2
        x2, y2 = pos[d][0], pos[d][1] + NODE_H / 2
        color, dash, w = styles[e["style"]]
        if (s, d) in path_edges and e["style"] == "observed":
            color, w = "#7c3aed", 2.6
        dx = max(60, abs(x2 - x1) / 2)
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        out.append(f'<g class="edge" data-src="{escape(s)}" data-dst="{escape(d)}" data-port="{port}">')
        out.append(f'<path d="M{x1},{y1} C{x1 + dx},{y1} {x2 - dx},{y2} {x2},{y2}" fill="none" '
                   f'stroke="{color}" stroke-width="{w}"{dash_attr} marker-end="url(#arr)"/>')
        if e["style"] != "probe":  # probe edges are summarised on the source node to avoid clutter
            mx, my = x1 + (x2 - x1) * 0.5, y1 + (y2 - y1) * 0.5 - 6
            out.append(f'<text x="{mx}" y="{my}" text-anchor="middle" fill="{color}" font-size="11" '
                       f'paint-order="stroke" stroke="#fff" stroke-width="3">{escape(e["label"])}</text>')
        out.append('</g>')

    for n in keep:
        x, y = pos[n]
        sev = node_sev.get(n)
        color = SEV_COLOR[sev]
        is_src = sev is None
        fill = "#f1f5f9" if is_src else "#ffffff"
        out.append(f'<g class="node" data-host="{escape(n)}"><title>{escape(n)}: click to focus</title>')
        out.append(f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="8" fill="{fill}" '
                   f'stroke="{color}" stroke-width="{3 if n in chained else 2}"/>')
        title = n + ("  (external)" if external.get(n) else "")
        out.append(f'<text x="{x + 10}" y="{y + 20}" font-weight="600" fill="#111827">{escape(title)}</text>')
        probes = sum(1 for k, ed in edges.items() if k[0] == n and ed["style"] == "probe")
        sub = node_name.get(n) or (f"scanner: probed {probes} vuln. services" if probes
                                   else "traffic source" if is_src else "")
        out.append(f'<text x="{x + 10}" y="{y + 37}" fill="#4b5563">{escape(sub[:36])}</text>')
        if not is_src:
            out.append(f'<text x="{x + 10}" y="{y + 55}" fill="{color}">{escape(sev)}: '
                       f'{escape(node_vuln.get(n, ""))}</text>')
        if n in chained:
            out.append(f'<rect x="{x + NODE_W - 58}" y="{y - 9}" width="54" height="18" rx="9" fill="#b91c1c"/>'
                       f'<text x="{x + NODE_W - 31}" y="{y + 4}" text-anchor="middle" fill="#fff" '
                       f'font-size="10" font-weight="600">CHAIN</text>')
        out.append('</g>')

    # Legend
    ly = height - 150
    out.append(f'<text x="{MARGIN}" y="{ly}" font-weight="600" fill="#111827">Legend</text>')
    items = [("#7c3aed", "", 2.6, "Observed connection on a candidate attack path"),
             ("#111827", "", 2.0, "Observed established connection to a vulnerable service"),
             ("#6b7280", "6 4", 1.4, "Connection attempts only (no session established)"),
             ("#9ca3af", "2 4", 1.2, "Scan-like probing"),
             ("#16a34a", "1 3", 1.2, "Denied by firewall"),
             ("#dc2626", "", 2.6, "IPS exploit detection NOT blocked (alert only)"),
             ("#dc2626", "3 3", 1.6, "IPS exploit detection blocked")]
    for i, (c, dash, w, label) in enumerate(items):
        yy = ly + 18 + i * 18
        d = f' stroke-dasharray="{dash}"' if dash else ""
        out.append(f'<line x1="{MARGIN}" y1="{yy - 4}" x2="{MARGIN + 40}" y2="{yy - 4}" stroke="{c}" '
                   f'stroke-width="{w}"{d}/><text x="{MARGIN + 50}" y="{yy}" fill="#374151">{escape(label)}</text>')
    lx = MARGIN + 420
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"]):
        out.append(f'<rect x="{lx}" y="{ly + 6 + i * 18}" width="14" height="12" fill="none" '
                   f'stroke="{SEV_COLOR[sev]}" stroke-width="2"/><text x="{lx + 22}" y="{ly + 16 + i * 18}" '
                   f'fill="#374151">{sev} vulnerability on target</text>')
    out.append(f'<rect x="{lx}" y="{ly + 78}" width="34" height="14" rx="7" fill="#b91c1c"/>'
               f'<text x="{lx + 42}" y="{ly + 89}" fill="#374151">Same-host vulnerability chain candidate</text>')
    out.append(f'<text x="{MARGIN}" y="{height - 8}" fill="#6b7280" font-size="11">'
               'Paths are hypotheses from scanner results plus observed reachability. They are not confirmed '
               'compromise.</text>')
    out.append("</svg>")
    return "\n".join(out)
