"""Pure-Python SVG diagram of hostile sources, the vulnerable services they targeted, and onward paths
(no Graphviz binary, works offline)."""
from __future__ import annotations

from html import escape

SEV_COLOR = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", None: "#475569"}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
NODE_W, NODE_H, COL_GAP, ROW_GAP, MARGIN = 230, 70, 410, 34, 30
MAX_NODES = 40

# style -> (colour, dash, width, rank). The strongest style wins when one edge carries several behaviours.
STYLES = {
    "success": ("#7c3aed", "", 3.0, 7),
    "ips": ("#dc2626", "", 2.6, 6),
    "brute": ("#ea580c", "", 2.0, 5),
    "onward": ("#111827", "", 2.0, 4),
    "ips-blocked": ("#dc2626", "3 3", 1.6, 3),
    "scan-contact": ("#6b7280", "6 4", 1.4, 2),
    "scan": ("#9ca3af", "2 4", 1.2, 1),
}
SOURCE_ROLE = {"ips-exploit": "exploit attempts", "auth-brute-force": "failed logins",
               "ips-brute-force": "brute force", "brute-force": "brute force", "vertical-scan": "port scan",
               "horizontal-scan": "sweep", "ips-scan": "scan"}


def _style(b: dict) -> str:
    k = b["kind"]
    if b["possible_success"]:
        return "success"
    if k in ("ips-exploit", "ips-brute-force"):
        return "ips" if b["not_blocked"] else "ips-blocked"
    if k in ("auth-brute-force", "brute-force"):
        return "brute"
    return "scan-contact" if b["attempts"] > b["failed"] else "scan"


def _label(b: dict, f: dict) -> str:
    svc = f"{f['protocol']}/{f['port']}"
    k = b["kind"]
    if k == "auth-brute-force":
        return f"{svc} · {b['failed']} failed logins" + (" · LOGIN OK" if b["possible_success"] else "")
    if k == "brute-force":
        return f"{svc} · brute force ×{b['attempts']}" + (" · long session" if b["possible_success"] else "")
    if k in ("ips-exploit", "ips-brute-force"):
        what = "IPS" if k == "ips-exploit" else "IPS brute force"
        return f"{svc} · {what} " + (f"NOT blocked ×{b['not_blocked']}" if b["not_blocked"] else f"blocked ×{b['blocked']}")
    return f"{svc} · {SOURCE_ROLE[k]}"


def render(findings: list[dict], paths: list[dict], chains: list[dict]) -> str:
    edges: dict[tuple, dict] = {}
    node_sev: dict[str, str | None] = {}
    node_name: dict[str, str] = {}
    node_vuln: dict[str, str] = {}
    src_roles: dict[str, set] = {}
    external: dict[str, bool] = {}
    order: dict[str, None] = {}          # insertion-ordered set of candidate nodes, most important first

    def put(e_key, style, label):
        cur = edges.get(e_key)
        if cur is None or STYLES[style][3] > STYLES[cur["style"]][3]:
            edges[e_key] = {"style": style, "label": label}

    for p in paths:
        for h in p["hosts"]:
            order.setdefault(h)
        for i, hop in enumerate(p["hops"]):
            if i:
                put((hop["from"], hop["to"], hop["port"], hop["protocol"]), "onward",
                    f"{hop['protocol']}/{hop['port']} onward")
            node_name.setdefault(hop["to"], hop["to_hostname"])
            vs = hop["vulnerabilities_at_target"]
            if vs and SEV_RANK[vs[0]["severity"]] > SEV_RANK.get(node_sev.get(hop["to"])):
                node_sev[hop["to"]] = vs[0]["severity"]
                node_vuln[hop["to"]] = ((vs[0]["cves"] or [vs[0]["name"]])[0])[:34]
    for f in findings:
        dst = f["target_ip"]
        order.setdefault(dst)
        node_name[dst] = f["target_hostname"]
        if f["vulnerabilities"]:
            v = f["vulnerabilities"][0]
            if SEV_RANK[v["severity"]] > SEV_RANK.get(node_sev.get(dst)):
                node_sev[dst] = v["severity"]
                node_vuln[dst] = ((v["cves"] or [v["name"]])[0])[:34]
        else:
            node_sev.setdefault(dst, "Low")
            node_vuln.setdefault(dst, f"login attack on {f['protocol']}/{f['port']}")
        for b in f["behaviours"]:
            s = b["source_ip"]
            order.setdefault(s)
            external[s] = b["external"]
            src_roles.setdefault(s, set()).add(SOURCE_ROLE[b["kind"]])
            put((s, dst, f["port"], f["protocol"]), _style(b), _label(b, f))

    keep = []
    for n in order:
        if len(keep) >= MAX_NODES:
            break
        keep.append(n)
    kept = set(keep)
    edges = {k: e for k, e in edges.items() if k[0] in kept and k[1] in kept}
    for n in keep:
        if n in src_roles and n not in node_sev:
            node_sev[n] = None

    chained = {c["host"] for c in chains}

    # Columns: depth from sources along edges (sources with no inbound edge are column 0).
    inbound = {k[1] for k in edges}
    depth = {n: 0 for n in keep if n not in inbound}
    changed = True
    while changed:
        changed = False
        for (s, d, *_), e in sorted(edges.items()):
            if s in depth and depth[s] + 1 > depth.get(d, -1) and depth[s] + 1 <= 6:
                if d not in depth or (e["style"] == "onward" and depth[d] < depth[s] + 1):
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
           f'<rect class="bg" width="{width}" height="{height}" fill="#ffffff"/>',
           f'<text x="{MARGIN}" y="{MARGIN + 6}" font-size="15" font-weight="600" fill="#111827" class="ink">'
           'Hostile activity against vulnerable services</text>']
    if not keep:
        out.append(f'<text x="{MARGIN}" y="{MARGIN + 40}" fill="#6b7280" class="ink3">'
                   'No hostile behaviour reached a scanned host.</text>')

    for (s, d, port, proto), e in sorted(edges.items(), key=lambda kv: STYLES[kv[1]["style"]][3]):
        x1, y1 = pos[s][0] + NODE_W, pos[s][1] + NODE_H / 2
        x2, y2 = pos[d][0], pos[d][1] + NODE_H / 2
        color, dash, w, _ = STYLES[e["style"]]
        dx = max(60, abs(x2 - x1) / 2)
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        ink = ' class="ink"' if e["style"] == "onward" else ""
        label_cls = "halo ink" if ink else "halo"
        out.append(f'<g class="edge" data-src="{escape(s)}" data-dst="{escape(d)}" data-port="{port}">')
        out.append(f'<path d="M{x1},{y1} C{x1 + dx},{y1} {x2 - dx},{y2} {x2},{y2}" fill="none" '
                   f'stroke="{color}" stroke-width="{w}"{dash_attr} marker-end="url(#arr)"{ink}/>')
        if e["style"] not in ("scan",):   # plain scan edges are summarised on the source node
            mx, my = x1 + (x2 - x1) * 0.5, y1 + (y2 - y1) * 0.5 - 6
            out.append(f'<text x="{mx}" y="{my}" text-anchor="middle" fill="{color}" font-size="11" '
                       f'paint-order="stroke" stroke="#fff" stroke-width="3" class="{label_cls}">'
                       f'{escape(e["label"])}</text>')
        out.append('</g>')

    for n in keep:
        x, y = pos[n]
        sev = node_sev.get(n)
        color = SEV_COLOR[sev]
        is_src = sev is None
        fill = "#f1f5f9" if is_src else "#ffffff"
        box_cls = "box src" if is_src else "box"
        out.append(f'<g class="node" data-host="{escape(n)}" data-sev="{sev or "none"}">'
                   f'<title>{escape(n)}: click to focus</title>')
        out.append(f'<rect class="{box_cls}" x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="8" fill="{fill}" '
                   f'stroke="{color}" stroke-width="{3 if n in chained else 2}"/>')
        title = n + ("  (external)" if external.get(n) else "")
        out.append(f'<text x="{x + 10}" y="{y + 20}" font-weight="600" fill="#111827" class="ink">{escape(title)}</text>')
        sub = node_name.get(n) or ("hostile source: " + ", ".join(sorted(src_roles.get(n, ()))) if is_src else "")
        out.append(f'<text x="{x + 10}" y="{y + 37}" fill="#4b5563" class="ink2">{escape(sub[:36])}</text>')
        if not is_src:
            out.append(f'<text x="{x + 10}" y="{y + 55}" fill="{color}" class="sevtx">{escape(sev)}: '
                       f'{escape(node_vuln.get(n, ""))}</text>')
        if n in chained:
            out.append(f'<rect x="{x + NODE_W - 58}" y="{y - 9}" width="54" height="18" rx="9" fill="#b91c1c"/>'
                       f'<text x="{x + NODE_W - 31}" y="{y + 4}" text-anchor="middle" fill="#fff" '
                       f'font-size="10" font-weight="600">CHAIN</text>')
        out.append('</g>')

    # Legend
    ly = height - 150
    out.append(f'<text x="{MARGIN}" y="{ly}" font-weight="600" fill="#111827" class="ink">Legend</text>')
    items = [("success", "Possible successful login after failures"),
             ("ips", "IPS detection NOT blocked (alert only)"),
             ("brute", "Brute force or failed logins"),
             ("onward", "Onward connection from a reached host (candidate path)"),
             ("ips-blocked", "IPS detection blocked"),
             ("scan-contact", "Scan that completed sessions"),
             ("scan", "Scan, no session completed")]
    for i, (st, label) in enumerate(items):
        c, dash, w, _ = STYLES[st]
        yy = ly + 18 + i * 18
        d = f' stroke-dasharray="{dash}"' if dash else ""
        ink = ' class="ink"' if st == "onward" else ""
        out.append(f'<line x1="{MARGIN}" y1="{yy - 4}" x2="{MARGIN + 40}" y2="{yy - 4}" stroke="{c}" '
                   f'stroke-width="{w}"{d}{ink}/><text x="{MARGIN + 50}" y="{yy}" fill="#374151" class="ink2">{escape(label)}</text>')
    lx = MARGIN + 420
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"]):
        out.append(f'<rect x="{lx}" y="{ly + 6 + i * 18}" width="14" height="12" fill="none" '
                   f'stroke="{SEV_COLOR[sev]}" stroke-width="2" class="sev-{sev}"/><text x="{lx + 22}" y="{ly + 16 + i * 18}" '
                   f'fill="#374151" class="ink2">{sev} vulnerability on target</text>')
    out.append(f'<rect x="{lx}" y="{ly + 78}" width="34" height="14" rx="7" fill="#b91c1c"/>'
               f'<text x="{lx + 42}" y="{ly + 89}" fill="#374151" class="ink2">Same-host vulnerability chain candidate</text>')
    out.append(f'<text x="{MARGIN}" y="{height - 8}" fill="#6b7280" font-size="11" class="ink3">'
               'Detected behaviour and candidate paths are leads, not confirmed compromise.</text>')
    out.append("</svg>")
    return "\n".join(out)
