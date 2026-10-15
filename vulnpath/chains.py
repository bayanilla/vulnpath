"""Same-host vulnerability chaining and multi-host candidate attack paths.

Everything here is a HYPOTHESIS built from scanner data, detected hostile behaviour and observed
connectivity. Nothing in this module confirms exploitation.
"""
from __future__ import annotations

import json
from pathlib import Path

from .correlate import Settings, Touch
from .model import Vulnerability

MAX_DEPTH = 4
MAX_PATHS = 50
MAX_ENUMERATED = 5000
SCAN_KINDS = {"horizontal-scan", "vertical-scan", "ips-scan"}

STAGE_LABEL = {
    "remote-unauth": "Remote, no credentials needed (possible initial access)",
    "remote-auth": "Remote, needs credentials or a foothold",
    "local": "Local access needed (possible privilege escalation)",
    "unknown": "Access requirements unknown (no CVSS vector)",
    "credentials": "Stolen or guessed credentials",
}


def _vector_parts(vector: str) -> dict:
    parts = {}
    for p in vector.split("/"):
        if ":" in p:
            k, val = p.split(":", 1)
            parts[k.split("#")[-1]] = val
    return parts


def stage(v: Vulnerability) -> str:
    """Classify what access a vulnerability needs, from its CVSS vector only."""
    if v.cvss3_vector:
        p = _vector_parts(v.cvss3_vector)
        av, pr = p.get("AV"), p.get("PR")
        if av in ("L", "P"):
            return "local"
        if av in ("N", "A"):
            return "remote-unauth" if pr == "N" else "remote-auth"
    if v.cvss2_vector:
        p = _vector_parts(v.cvss2_vector)
        av, au = p.get("AV"), p.get("Au")
        if av == "L":
            return "local"
        if av in ("N", "A"):
            return "remote-unauth" if au == "N" else "remote-auth"
    return "unknown"


def load_known_chains(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("chains", [])


ROLLUP_FAMILIES = {"windows : microsoft bulletins", "windows : microsoft bulletins (security updates)"}
ROLLUP_MIN_CVES = 10


def is_rollup(v: Vulnerability) -> bool:
    """Cumulative-update plugins carry the CVSS vector of their worst CVE and report on 445 for every
    unpatched Windows host, so they cannot stand in for a specific remote entry point."""
    return v.plugin_family.strip().lower() in ROLLUP_FAMILIES or len(v.cves) >= ROLLUP_MIN_CVES


def same_host_chains(vulns: list[Vulnerability], known: list[dict], targeted: dict[tuple, list]) -> list[dict]:
    """Chains on one host, gated by observed hostile behaviour.

    `targeted` maps (dst, port, proto) to the detections pointing at it (see correlate.targets_of).
    Published chains are always reported, with a flag saying whether the host was targeted. Inferred
    chains are reported only for hosts that were targeted, and only when the targeted service is the entry.
    """
    from .behavior import CREDENTIAL_KINDS

    by_host: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        by_host.setdefault(v.host, []).append(v)
    hit: dict[str, dict[tuple, list]] = {}
    for (dst, port, proto), dets in targeted.items():
        hit.setdefault(dst, {})[(port, proto)] = dets

    out = []
    for host in sorted(by_host):
        hv = by_host[host]
        host_cves = {c: v for v in hv for c in v.cves}
        host_hits = hit.get(host, {})

        # 1. Published chains from rules/known_chains.json (matched by CVE).
        documented = False
        for rule in known:
            matched = [c for c in rule["cves"] if c in host_cves]
            if len(matched) >= rule.get("min_match", len(rule["cves"])):
                documented = True
                steps = [_step(host_cves[c], host_hits) for c in rule["cves"] if c in host_cves]
                out.append({
                    "host": host, "hostname": hv[0].hostname, "type": "documented",
                    "name": rule["name"], "reference": rule.get("reference", ""),
                    "description": rule.get("description", ""),
                    "matched_cves": matched, "missing_cves": [c for c in rule["cves"] if c not in host_cves],
                    "steps": steps, "entries": [],
                    "entry_targeted": any(s["targeted_by"] for s in steps) or bool(host_hits),
                    "caveat": "A published chain matches this host's scan results. Exploitation is not confirmed.",
                })
        if documented or not host_hits:
            continue

        # 2. Inferred chain: a targeted way in, plus a High/Critical flaw that needs a foothold.
        follow = [v for v in hv if stage(v) in ("local", "remote-auth") and v.severity >= 3]
        if not follow:
            continue
        entries = []
        for v in hv:
            if (stage(v) == "remote-unauth" and v.port > 0 and v.severity >= 3 and not is_rollup(v)
                    and (v.port, v.proto) in host_hits):
                entries.append(_step(v, host_hits))
        for (port, proto), dets in sorted(host_hits.items()):
            cred = [d for d in dets if d.kind in CREDENTIAL_KINDS]
            if cred:
                srcs = sorted({d.src for d in cred})
                ok = any(d.success for d in cred)
                entries.append({"cves": [], "plugin_id": "", "name": "Login attack (" + (
                    "possible success" if ok else "attempts") + ")", "severity": "", "port": port,
                    "protocol": proto, "stage": "credentials", "stage_label": "Stolen or guessed credentials",
                    "targeted_by": srcs[:10]})
        if not entries:
            continue
        follow.sort(key=lambda v: (-v.severity, v.plugin_id))
        entries.sort(key=lambda e: (e["stage"] != "credentials", e["port"]))
        out.append({
            "host": host, "hostname": hv[0].hostname, "type": "inferred",
            "name": "Targeted entry + follow-on on the same host",
            "reference": "", "description":
                "Hostile activity reached a way into this host (a remotely exploitable flaw or a login service), "
                "and the host also has a High or Critical flaw that needs a foothold or local access. Together "
                "they could take an attacker from network access to deeper control.",
            "matched_cves": [], "missing_cves": [],
            "steps": entries[:3] + [_step(v, host_hits) for v in follow[:3]],
            "entries": [{"port": e["port"], "protocol": e["protocol"]} for e in entries],
            "entry_targeted": True,
            "caveat": "Inferred from CVSS access requirements only. Whether the first step really gives the "
                      "access the second needs has not been checked.",
        })
    out.sort(key=lambda c: (c["type"] != "documented", not c["entry_targeted"], c["host"]))
    return out


def _step(v: Vulnerability, host_hits: dict) -> dict:
    dets = host_hits.get((v.port, v.proto), []) if v.port > 0 else []
    return {
        "cves": v.cves, "plugin_id": v.plugin_id, "name": v.plugin_name,
        "severity": v.severity_label, "port": v.port, "protocol": v.proto,
        "stage": stage(v), "stage_label": STAGE_LABEL[stage(v)],
        "targeted_by": sorted({d.src for d in dets})[:10],
    }


def attack_paths(col, settings: Settings, chains: list[dict]) -> list[dict]:
    """Paths that START at a hostile source and then follow established connections between scanned hosts.

    The first hop needs evidence that the hostile source got through to the target: a successful login after
    failures, an unblocked IPS detection, or an established session during a brute-force or IPS-detected
    attack. A scan that merely found an open port does not start a path. Each onward hop X -> Y must have been
    seen at or after the time X was first reached, so connections that happened earlier do not create a
    path. All paths are enumerated (up to a hard cap), ranked, and only then trimmed to MAX_PATHS.
    """
    from .correlate import targets_of

    index, hosts, touches = col.index, col.hosts, col.touches
    first: dict[str, dict[tuple, dict]] = {}
    for d in col.detections:
        if d.routine:
            continue
        for t in targets_of(d, index, hosts):
            touch = touches.get((d.src,) + t)
            if d.success:
                when, how, rank = d.success_at, d.success_detail, 3
            elif d.not_blocked and d.kind in ("ips-exploit", "ips-brute-force"):
                when, how, rank = d.first, f"{d.not_blocked} unblocked IPS detection(s)", 3
            elif touch is not None and touch.established and d.kind not in SCAN_KINDS:
                when, how, rank = touch.first_est, f"{touch.established} established session(s)", 1
            else:
                continue
            cur = first.setdefault(d.src, {}).get(t)
            if cur is None or (rank, -when) > (cur["rank"], -cur["when"]):
                first[d.src][t] = {"src": d.src, "dst": t[0], "port": t[1], "proto": t[2], "when": when,
                                   "how": how, "rank": rank, "last": d.last,
                                   "evidence": [r.as_text() for r in (d.success_evidence + d.evidence)[:4]]}
    onward: dict[str, list[Touch]] = {}
    for t in touches.values():
        if t.established and t.src in hosts:
            onward.setdefault(t.src, []).append(t)
    for lst in onward.values():
        lst.sort(key=lambda t: (t.dst, t.port))

    chain_by_host: dict[str, list[str]] = {}
    for c in chains:
        chain_by_host.setdefault(c["host"], []).append(c["name"])

    raw: list[list[dict]] = []

    def walk(node: str, path: list[dict], seen: set[str], not_before: float):
        if len(raw) >= MAX_ENUMERATED:
            return
        nxt = [t for t in onward.get(node, []) if t.dst not in seen and t.last_ts >= not_before] \
            if len(path) < MAX_DEPTH else []
        if not nxt:
            if len(path) >= 2:
                raw.append(list(path))
            return
        for t in nxt:
            when = max(t.first_est, not_before)
            path.append({"src": t.src, "dst": t.dst, "port": t.port, "proto": t.proto, "when": when,
                         "last": t.last_ts, "how": f"{t.established} established session(s)", "rank": 1,
                         "evidence": [r.as_text() for r in t.samples]})
            walk(t.dst, path, seen | {t.dst}, when)
            path.pop()

    for src in sorted(first):
        for t, hop in sorted(first[src].items()):
            walk(hop["dst"], [hop], {src, hop["dst"]}, hop["when"])

    def max_sev(p):
        return max((v.severity for h in p for v in index.get((h["dst"], h["port"], h["proto"]), [])), default=0)

    raw.sort(key=lambda p: (-(not settings.is_internal(p[0]["src"])), -p[0]["rank"], -max_sev(p), -len(p),
                            [h["dst"] for h in p]))
    result = []
    for p in raw[:MAX_PATHS]:
        hops = []
        for h in p:
            vs = sorted(index.get((h["dst"], h["port"], h["proto"]), []), key=lambda v: -v.severity)
            hops.append({
                "from": h["src"], "to": h["dst"], "port": h["port"], "protocol": h["proto"],
                "to_hostname": hosts[h["dst"]].hostname if h["dst"] in hosts else "",
                "observed": f"{h['proto']}/{h['port']}: {h['how']}",
                "first_seen": h["when"], "last_seen": h["last"],
                "evidence": h["evidence"],
                "vulnerabilities_at_target": [{"cves": v.cves, "name": v.plugin_name,
                                               "severity": v.severity_label, "stage": stage(v)} for v in vs],
                "same_host_chains_at_target": chain_by_host.get(h["dst"], []),
            })
        sev = max_sev(p)
        result.append({
            "id": "",
            "start": p[0]["src"],
            "start_is_external": not settings.is_internal(p[0]["src"]),
            "hosts": [p[0]["src"]] + [h["dst"] for h in p],
            "hop_count": len(p),
            "max_severity": ["Info", "Low", "Medium", "High", "Critical"][sev],
            "hops": hops,
            "status": "candidate (hypothetical)",
            "missing_evidence": [
                "No evidence any vulnerability was exploited; only hostile activity, reachability and scanner "
                "findings are shown.",
                "Host logs from each hop are needed to confirm or rule out compromise.",
            ],
        })
    for i, r in enumerate(result, 1):
        r["id"] = f"P{i:03d}"
    return result
