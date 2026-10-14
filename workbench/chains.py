"""Same-host vulnerability chaining and multi-host candidate attack paths.

Everything here is a HYPOTHESIS built from scanner data and observed connectivity.
Nothing in this module confirms exploitation.
"""
from __future__ import annotations

import json
from pathlib import Path

from .correlate import Settings, Touch
from .model import HostInfo, Vulnerability

MAX_DEPTH = 4
MAX_PATHS = 50

STAGE_LABEL = {
    "remote-unauth": "Remote, no credentials needed (possible initial access)",
    "remote-auth": "Remote, needs credentials or a foothold",
    "local": "Local access needed (possible privilege escalation)",
    "unknown": "Access requirements unknown (no CVSS vector)",
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


def same_host_chains(vulns: list[Vulnerability], known: list[dict], touches: dict) -> list[dict]:
    by_host: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        by_host.setdefault(v.host, []).append(v)

    # Which vulnerable ports had established traffic, and from where.
    reached: dict[tuple, set] = {}
    for (src, dst, port, proto), t in touches.items():
        if t.established or t.exploit_unblocked:
            reached.setdefault((dst, port, proto), set()).add(src)

    out = []
    for host in sorted(by_host):
        hv = by_host[host]
        host_cves = {c: v for v in hv for c in v.cves}

        # 1. Documented chains from rules/known_chains.json (matched by CVE).
        for rule in known:
            hit = [c for c in rule["cves"] if c in host_cves]
            if len(hit) >= rule.get("min_match", len(rule["cves"])):
                steps = [_step(host_cves[c], reached) for c in rule["cves"] if c in host_cves]
                out.append({
                    "host": host, "hostname": hv[0].hostname, "type": "documented",
                    "name": rule["name"], "reference": rule.get("reference", ""),
                    "description": rule.get("description", ""),
                    "matched_cves": hit, "missing_cves": [c for c in rule["cves"] if c not in host_cves],
                    "steps": steps,
                    "entry_reached": any(s["reached_from"] for s in steps),
                    "caveat": "A published chain matches this host's scan results. "
                              "Exploitation is not confirmed.",
                })

        # 2. Generic chain: an unauthenticated remote entry point plus a follow-on that needs a foothold.
        #    Skipped when a documented chain already explains this host.
        if any(c["host"] == host and c["type"] == "documented" for c in out):
            continue
        entries = [v for v in hv if stage(v) == "remote-unauth" and v.port > 0 and v.severity >= 3]
        follow = [v for v in hv if stage(v) in ("local", "remote-auth") and v.severity >= 3]
        if entries and follow:
            entries.sort(key=lambda v: (-v.severity, v.port, v.plugin_id))
            follow.sort(key=lambda v: (-v.severity, v.plugin_id))
            steps = [_step(v, reached) for v in entries[:3]] + [_step(v, reached) for v in follow[:3]]
            out.append({
                "host": host, "hostname": hv[0].hostname, "type": "generic",
                "name": "Remote entry + follow-on on the same host",
                "reference": "", "description":
                    "This host has a remotely reachable vulnerability that needs no credentials, plus one "
                    "that needs a foothold or local access. Together they could take an attacker from "
                    "network access to deeper control.",
                "matched_cves": [], "missing_cves": [],
                "steps": steps,
                "entry_reached": any(s["reached_from"] for s in steps),
                "caveat": "Inferred from CVSS access requirements only. Whether the first flaw "
                          "really gives the access the second needs has not been checked.",
            })
    out.sort(key=lambda c: (c["type"] != "documented", not c["entry_reached"], c["host"]))
    return out


def _step(v: Vulnerability, reached: dict) -> dict:
    srcs = sorted(reached.get((v.host, v.port, v.proto), ())) if v.port > 0 else []
    return {
        "cves": v.cves, "plugin_id": v.plugin_id, "name": v.plugin_name,
        "severity": v.severity_label, "port": v.port, "protocol": v.proto,
        "stage": stage(v), "stage_label": STAGE_LABEL[stage(v)],
        "reached_from": srcs[:10],
    }


def attack_paths(touches: dict[tuple, Touch], index: dict, hosts: dict[str, HostInfo],
                 chains: list[dict], settings: Settings) -> list[dict]:
    """Paths that follow observed, established connections into vulnerable services.

    A hop X -> Y is only chained after hop W -> X if X -> Y was seen at or after
    the first time X was reached (time order is respected).
    """
    edges: dict[str, list[Touch]] = {}
    inbound: set[str] = set()
    for t in touches.values():
        if t.established or t.exploit_unblocked:
            edges.setdefault(t.src, []).append(t)
            inbound.add(t.dst)
    for lst in edges.values():
        lst.sort(key=lambda t: (t.dst, t.port))

    chain_by_host: dict[str, list[dict]] = {}
    for c in chains:
        chain_by_host.setdefault(c["host"], []).append(c)

    starts = sorted(s for s in edges if not settings.is_internal(s) or s not in inbound)
    paths: list[list[Touch]] = []

    def walk(node: str, path: list[Touch], seen: set[str], not_before: float):
        if len(paths) >= MAX_PATHS:
            return
        nxt = [t for t in edges.get(node, []) if t.dst not in seen and t.last_ts >= not_before]
        if not nxt or len(path) >= MAX_DEPTH:
            if path:
                paths.append(list(path))
            return
        for t in nxt:
            path.append(t)
            walk(t.dst, path, seen | {t.dst}, t.first_ts)
            path.pop()

    for s in starts:
        walk(s, [], {s}, float("-inf"))

    result = []
    for p in paths:
        hops = []
        for t in p:
            vs = sorted(index[(t.dst, t.port, t.proto)], key=lambda v: -v.severity)
            hops.append({
                "from": t.src, "to": t.dst, "port": t.port, "protocol": t.proto,
                "to_hostname": hosts[t.dst].hostname if t.dst in hosts else "",
                "observed": f"{t.proto}/{t.port}: {t.established} established connection(s)"
                            + (f", {t.exploit_unblocked} unblocked IPS detection(s)" if t.exploit_unblocked else ""),
                "first_seen": t.first_ts, "last_seen": t.last_ts,
                "telemetry_sources": sorted(t.sources),
                "evidence": [r.as_text() for r in t.samples + t.threat_samples],
                "vulnerabilities_at_target": [{"cves": v.cves, "name": v.plugin_name,
                                               "severity": v.severity_label, "stage": stage(v)} for v in vs],
                "same_host_chains_at_target": [c["name"] for c in chain_by_host.get(t.dst, [])],
            })
        max_sev = max(v.severity for t in p for v in index[(t.dst, t.port, t.proto)])
        result.append({
            "id": "",
            "start": p[0].src,
            "start_is_external": not settings.is_internal(p[0].src),
            "hosts": [p[0].src] + [t.dst for t in p],
            "hop_count": len(p),
            "max_severity": ["Info", "Low", "Medium", "High", "Critical"][max_sev],
            "hops": hops,
            "status": "candidate (hypothetical)",
            "missing_evidence": [
                "No evidence any vulnerability was exploited; only reachability and scanner findings are shown.",
                "Payload or host logs from each hop are needed to confirm or rule out compromise.",
            ],
        })
    result.sort(key=lambda r: (-r["hop_count"], not r["start_is_external"], r["hosts"]))
    for i, r in enumerate(result, 1):
        r["id"] = f"P{i:03d}"
    return result
