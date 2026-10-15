"""Stream the traffic once, detect hostile behaviour, then join it to the Nessus results and rank targets.

The order matters: behaviour is detected first, from the traffic alone, and the vulnerability data then
decides which of those behaviours point at something worth fixing. Ordinary use of a vulnerable service
(workstations talking to a domain controller) produces no finding.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .behavior import CREDENTIAL_KINDS, KIND_LABEL, Behaviour, Detection
from .model import Connection, HostInfo, Vulnerability

DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "127.0.0.0/8"]
DEFAULT_AUTH_PORTS = [21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986]
SEVERITY_POINTS = {4: 40, 3: 30, 2: 15, 1: 5}
MAX_SAMPLE_REFS = 5
DISTINCT_SOURCE_CAP = 10_000
MAX_BEHAVIOURS_PER_FINDING = 25


@dataclass
class Settings:
    internal_networks: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL))
    exclude_sources: list[str] = field(default_factory=list)   # known scanners, admin and monitoring hosts
    window_minutes: float = 15.0       # behaviour is counted in fixed windows of this length
    sweep_min_hosts: int = 20          # distinct hosts on one port in a window = sweep
    portscan_min_ports: int = 15       # distinct ports on one host in a window = port scan
    scan_min_failed: float = 0.5       # share of connections that must fail for a scan or brute-force pattern
    brute_min_attempts: int = 10       # short connections to one login service in a window
    auth_min_failures: int = 5         # failed logins in authentication logs in a window
    peer_min_sources: int = 5          # internal sources with the same pattern before it is treated as routine
    auth_ports: list[int] = field(default_factory=lambda: list(DEFAULT_AUTH_PORTS))
    stale_days: int = 30               # scan vs traffic gap before a result is flagged as stale
    pan_utc_offset: float = 0.0        # Palo Alto timestamps have no zone; hours offset from UTC
    threat_map: str = ""               # optional CSV threat_id,cve for Palo Alto signatures

    def __post_init__(self):
        self._nets = [ipaddress.ip_network(n, strict=False) for n in self.internal_networks]
        self._excluded = [ipaddress.ip_network(n, strict=False) for n in self.exclude_sources]

    @staticmethod
    def _in(ip: str, nets) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets if n.version == a.version)

    def is_internal(self, ip: str) -> bool:
        return self._in(ip, self._nets)

    def is_excluded(self, ip: str) -> bool:
        return bool(self._excluded) and self._in(ip, self._excluded)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


@dataclass
class Touch:
    """Traffic from one source to one vulnerable service (dst, port, proto).

    Counts are kept per sensor. Zeek and the firewall often see the SAME sessions, so the combined figure is
    the largest single-sensor count, never the sum (no double counting).
    """
    src: str
    dst: str
    port: int
    proto: str
    by_source: dict = field(default_factory=dict)   # sensor -> [established, attempts, denied]
    first_ts: float = float("inf")
    last_ts: float = float("-inf")
    first_est: float = float("inf")
    sources: set = field(default_factory=set)
    samples: list = field(default_factory=list)
    pre_nat: set = field(default_factory=set)

    def _max(self, i: int) -> int:
        return max((b[i] for b in self.by_source.values()), default=0)

    @property
    def established(self) -> int:
        return self._max(0)

    @property
    def attempts(self) -> int:
        return self._max(1)

    @property
    def denied(self) -> int:
        return self._max(2)

    def add(self, c: Connection) -> None:
        self.first_ts = min(self.first_ts, c.ts)
        self.last_ts = max(self.last_ts, c.ts)
        self.sources.add(c.source)
        if c.pre_nat_dst and len(self.pre_nat) < 5:
            self.pre_nat.add(f"{c.pre_nat_dst}:{c.pre_nat_dst_port}")
        b = self.by_source.setdefault(c.source, [0, 0, 0])
        b[{"established": 0, "denied": 2}.get(c.outcome, 1)] += 1
        if c.outcome == "established":
            self.first_est = min(self.first_est, c.ts)
        if c.evidence and len(self.samples) < MAX_SAMPLE_REFS:
            self.samples.append(c.evidence)


@dataclass
class ServiceStats:
    """All traffic to one vulnerable service, from every source: context for the analyst, never a score."""
    by_source: dict = field(default_factory=dict)   # sensor -> [established, attempts, denied]
    srcs: set = field(default_factory=set)
    srcs_capped: bool = False

    def add(self, c: Connection) -> None:
        b = self.by_source.setdefault(c.source, [0, 0, 0])
        b[{"established": 0, "denied": 2}.get(c.outcome, 1)] += 1
        if len(self.srcs) < DISTINCT_SOURCE_CAP:
            self.srcs.add(c.src)
        elif c.src not in self.srcs:
            self.srcs_capped = True

    def as_dict(self) -> dict:
        m = lambda i: max((b[i] for b in self.by_source.values()), default=0)  # noqa: E731
        return {"established": m(0), "attempts": m(1), "denied": m(2),
                "distinct_sources": len(self.srcs), "distinct_sources_capped": self.srcs_capped}


@dataclass
class TrafficStats:
    total: int = 0
    auth_records: int = 0
    threat_records: int = 0
    excluded: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    dst_not_scanned: set = field(default_factory=set)
    single_contact_sources: int = 0


class _Parked:
    """Compact copy of a connection from a source seen only once so far (most internet background noise)."""
    __slots__ = ("ts", "src", "dst", "dst_port", "proto", "source", "outcome", "orig_bytes", "resp_bytes",
                 "duration", "pre_nat_dst", "pre_nat_dst_port", "evidence")

    def __init__(self, c: Connection):
        for k in self.__slots__:
            setattr(self, k, getattr(c, k))


class Collector:
    """One pass over every record. Memory grows with distinct (source, window) keys, not with log size.

    A source that is seen exactly once can never be a scan or a brute force, so its single record is parked
    and only expanded into the window counters when a second record from it arrives. This keeps one-off
    internet background noise cheap. Scanned hosts are always tracked in full because their onward
    connections are needed for attack paths.
    """

    def __init__(self, vulns: list[Vulnerability], hosts: dict[str, HostInfo], settings: Settings):
        self.s = settings
        self.hosts = hosts
        self.index: dict[tuple, list[Vulnerability]] = {}
        for v in vulns:
            if v.port > 0:
                self.index.setdefault((v.host, v.port, v.proto), []).append(v)
        self.behaviour = Behaviour(settings)
        self.services: dict[tuple, ServiceStats] = {}
        self.touches: dict[tuple, Touch] = {}
        self.stats = TrafficStats()
        self._parked: dict[str, _Parked] = {}
        self._multi: set[str] = set()

    def add(self, c: Connection) -> None:
        st = self.stats
        if self.s.is_excluded(c.src):
            st.excluded += 1
            return
        st.first_ts = c.ts if st.first_ts is None else min(st.first_ts, c.ts)
        st.last_ts = c.ts if st.last_ts is None else max(st.last_ts, c.ts)
        if c.threat is not None:
            st.threat_records += 1
            self.behaviour.add_threat(c)
            return
        if c.auth is not None:
            st.auth_records += 1
            self.behaviour.add_auth(c)
            return
        st.total += 1
        if c.dst not in self.hosts and len(st.dst_not_scanned) < DISTINCT_SOURCE_CAP:
            st.dst_not_scanned.add(c.dst)
        key = (c.dst, c.dst_port, c.proto)
        if key in self.index:
            svc = self.services.get(key)
            if svc is None:
                svc = self.services[key] = ServiceStats()
            svc.add(c)
        src = c.src
        if src in self._multi or src in self.hosts:
            self._full(c)
        elif src in self._parked:
            self._multi.add(src)
            self._full(self._parked.pop(src))
            self._full(c)
        else:
            self._parked[src] = _Parked(c)

    def _full(self, c: Connection) -> None:
        self.behaviour.add_conn(c)
        key = (c.dst, c.dst_port, c.proto)
        if key in self.index:
            tk = (c.src,) + key
            t = self.touches.get(tk)
            if t is None:
                t = self.touches[tk] = Touch(c.src, c.dst, c.dst_port, c.proto)
            t.add(c)

    def finish(self) -> list[Detection]:
        self.stats.single_contact_sources = len(self._parked)
        # Parked single records still matter as context for the hostile-source contact check.
        for c in self._parked.values():
            key = (c.dst, c.dst_port, c.proto)
            if key in self.index:
                t = self.touches.setdefault((c.src,) + key, Touch(c.src, c.dst, c.dst_port, c.proto))
                t.add(c)
        self._parked.clear()
        return self.behaviour.evaluate()


def correlate(conns: Iterable[Connection], vulns: list[Vulnerability], hosts: dict[str, HostInfo],
              settings: Settings) -> Collector:
    col = Collector(vulns, hosts, settings)
    for c in conns:
        col.add(c)
    col.detections = col.finish()
    return col


# ---- join + score -----------------------------------------------------------------------------------------
def _strength(d: Detection) -> int:
    """Order detections on a finding from most to least telling."""
    base = {"ips-exploit": 70, "auth-brute-force": 60, "ips-brute-force": 50, "brute-force": 40,
            "vertical-scan": 20, "ips-scan": 10, "horizontal-scan": 10}[d.kind]
    return base + 30 * d.success + 10 * bool(d.not_blocked)


def targets_of(d: Detection, index: dict, hosts: dict) -> list[tuple]:
    """The (dst, port, proto) keys a detection points at that VulnPath can rank.

    A vulnerable service always qualifies. A login attack on a scanned host also qualifies even when the
    attacked port has no vulnerability, because stolen credentials are the foothold a local
    privilege-escalation flaw on that host needs.
    """
    out = []
    for t in d.targets:
        if t in index:
            out.append(t)
        elif d.kind in CREDENTIAL_KINDS and t[0] in hosts:
            out.append(t)
    return out


def build_findings(col: Collector, settings: Settings, chains: list[dict]) -> list[dict]:
    index, hosts, touches = col.index, col.hosts, col.touches
    groups: dict[tuple, list[Detection]] = {}
    for d in col.detections:
        if d.routine:
            continue
        for t in targets_of(d, index, hosts):
            groups.setdefault(t, []).append(d)

    host_vulns: dict[str, list[Vulnerability]] = {}
    for vs in index.values():
        for v in vs:
            host_vulns.setdefault(v.host, []).append(v)
    chains_by_host: dict[str, list[dict]] = {}
    for c in chains:
        chains_by_host.setdefault(c["host"], []).append(c)

    findings = []
    for (dst, port, proto), dets in groups.items():
        dets = sorted(dets, key=lambda d: (-_strength(d), d.src))
        vs = sorted(index.get((dst, port, proto), []), key=lambda v: (-v.severity, v.plugin_id))
        reasons: list[str] = []
        score = 0
        if vs:
            top = vs[0]
            score = SEVERITY_POINTS.get(top.severity, 0)
            reasons.append(f"highest severity on this service: {top.severity_label} (+{score})")
            if any(v.exploit_available for v in vs):
                score += 10
                reasons.append("Nessus reports a public exploit (+10)")
            from .chains import stage   # local import: chains imports this module
            if any(stage(v) == "remote-unauth" and v.severity >= 3 for v in vs):
                score += 10
                reasons.append("a High or Critical flaw here needs no credentials over the network (+10)")
        else:
            reasons.append("no vulnerability on this port; listed because it is a login attack on a scanned host")

        kinds = {d.kind for d in dets}
        srcs = sorted({d.src for d in dets})
        ext = [s for s in srcs if not settings.is_internal(s)]
        vuln_cves = {c for v in vs for c in v.cves}

        ips = [d for d in dets if d.kind == "ips-exploit"]
        if ips:
            matched = sorted({c for d in ips for c in d.cves} & vuln_cves)
            unblocked = sum(d.not_blocked for d in ips)
            pts = {(True, True): 40, (True, False): 20, (False, True): 20, (False, False): 10}[
                (bool(matched), bool(unblocked))]
            score += pts
            reasons.append(("IPS signature for the scanned CVE " + ", ".join(matched) if matched else
                            "IPS exploit signature on this service, not mapped to the scanned CVE")
                           + (f", {unblocked} not blocked" if unblocked else ", all blocked") + f" (+{pts})")
        auth = [d for d in dets if d.kind == "auth-brute-force"]
        if auth:
            score += 25
            reasons.append(f"{sum(d.failed for d in auth)} failed logins in authentication logs (+25)")
            if any(d.success for d in auth):
                score += 30
                reasons.append("a successful login followed the failures (+30)")
        ipsb = [d for d in dets if d.kind == "ips-brute-force"]
        if ipsb:
            pts = 20 + (10 if any(d.not_blocked for d in ipsb) else 0)
            score += pts
            reasons.append(f"firewall brute-force signature ({sum(d.attempts for d in ipsb)} detections) (+{pts})")
        brute = [d for d in dets if d.kind == "brute-force"]
        if brute:
            score += 20
            reasons.append("brute-force connection pattern (+20)")
            if any(d.success for d in brute) and not any(d.success for d in auth):
                score += 15
                reasons.append("a long session followed the attempts: possible successful login (+15)")
        if "vertical-scan" in kinds:
            score += 10
            reasons.append("this host was port-scanned (+10)")
        if "horizontal-scan" in kinds:
            score += 5
            reasons.append("this service was hit by a sweep across many hosts (+5)")
        if "ips-scan" in kinds:
            score += 5
            reasons.append("the firewall flagged a scan against this service (+5)")

        if ext:
            score += 10
            reasons.append(f"{len(ext)} hostile source(s) outside the internal networks (+10)")
        if len(srcs) >= 3:
            score += 5
            reasons.append(f"{len(srcs)} distinct hostile sources (+5)")

        # Did any hostile source get a session through?
        contact_est = sum(touches[(s, dst, port, proto)].established
                          for s in srcs if (s, dst, port, proto) in touches)
        contact_est = max(contact_est, sum(d.established for d in dets if d.kind == "brute-force"))
        unblocked_ips = sum(d.not_blocked for d in dets if d.kind.startswith("ips-") and d.kind != "ips-scan")
        success = any(d.success for d in dets)
        if contact_est:
            score += 10
            reasons.append(f"hostile sources completed {contact_est} session(s) with this service (+10)")
        elif not unblocked_ips and not success:
            score -= 10
            reasons.append("no hostile session completed, no login succeeded and no IPS detection got through (-10)")

        host_chains = chains_by_host.get(dst, [])
        chain_names = []
        for c in host_chains:
            if c["type"] == "documented":
                score += 15
                reasons.append(f"host matches the published chain {c['name']} (+15)")
                chain_names.append(c["name"])
            elif (port, proto) in {(e["port"], e["protocol"]) for e in c["entries"]}:
                score += 10
                reasons.append("this service is the entry point of an inferred same-host chain (+10)")
                chain_names.append(c["name"])

        info = hosts.get(dst)
        stale = False
        if info and info.scan_time is not None:
            gap = abs(min(d.first for d in dets) - info.scan_time) / 86400
            if gap > settings.stale_days:
                stale = True
                score -= 10
                reasons.append(f"scan is {gap:.0f} days from the activity; result may be stale (-10)")

        outcome = "contact" if (contact_est or unblocked_ips or success) else "no-contact"
        others = [v for v in host_vulns.get(dst, []) if (v.port, v.proto) != (port, proto)]
        findings.append({
            "id": "",
            "priority_score": score,
            "target_ip": dst,
            "target_hostname": info.hostname if info else "",
            "port": port,
            "protocol": proto,
            "kinds": sorted(kinds, key=lambda k: list(KIND_LABEL).index(k)),
            "outcome": outcome,
            "possible_login_success": success,
            "hostile_sources": srcs,
            "external_sources": len(ext),
            "first_seen": min(d.first for d in dets),
            "last_seen": max(d.last for d in dets),
            "vulnerabilities": [_vuln_dict(v) for v in vs],
            "other_vulnerabilities_on_host": len(others),
            "behaviours": [_det_dict(d, settings) for d in dets[:MAX_BEHAVIOURS_PER_FINDING]],
            "behaviours_not_shown": max(len(dets) - MAX_BEHAVIOURS_PER_FINDING, 0),
            "service_traffic": col.services[(dst, port, proto)].as_dict() if (dst, port, proto) in col.services
            else None,
            "pre_nat_destinations": sorted({p for s in srcs for p in (touches[(s, dst, port, proto)].pre_nat
                                            if (s, dst, port, proto) in touches else ())}),
            "chains": chain_names,
            "scan_stale": stale,
            "assessment": _assessment(dets, vs, success, contact_est, unblocked_ips),
            "score_reasons": reasons,
            "evidence": _evidence(dets, vs),
        })
    findings.sort(key=lambda f: (-f["priority_score"], f["target_ip"], f["port"], f["protocol"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F{i:04d}"
    return findings


def _assessment(dets, vs, success, contact_est, unblocked) -> str:
    kinds = {d.kind for d in dets}
    what = "vulnerable service" if vs else "login service on a scanned host"
    if success and kinds & {"auth-brute-force"}:
        return (f"Failed logins against this {what} were followed by a successful login from the same source. "
                "Highest-priority lead: check that account and the host for follow-on activity. "
                "Not confirmation of compromise.")
    if "ips-exploit" in kinds and unblocked:
        return (f"An IPS exploit signature fired against this {what} and was NOT blocked. Check the host for "
                "signs of compromise and patch first. Not confirmation of exploitation.")
    if success:
        return (f"A brute-force pattern against this {what} was followed by a long session from the same "
                "source, which may be a successful login. Check the host's authentication logs.")
    if kinds & CREDENTIAL_KINDS:
        return (f"Repeated login attempts against this {what}. Check for account lockouts and successful "
                "logins, and patch or restrict access.")
    if "ips-exploit" in kinds:
        return f"IPS detected exploit attempts against this {what}; the firewall blocked them. Patch to remove the exposure."
    if contact_est:
        return (f"A scanning source reached this {what} and completed sessions with it. It has been found; "
                "prioritise the patch. Reachability is not exploitation.")
    return f"This {what} was scanned, but no session completed. Patch on the normal schedule unless other leads appear."


def _evidence(dets, vs) -> list[str]:
    out = []
    for d in dets[:10]:
        for r in d.success_evidence + d.evidence[:2]:
            out.append(r.as_text())
    out += [v.evidence.as_text() for v in vs if v.evidence]
    seen, uniq = set(), []
    for e in out:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq[:20]


def _det_dict(d: Detection, settings: Settings) -> dict:
    return {
        "kind": d.kind, "label": d.label, "source_ip": d.src, "external": not settings.is_internal(d.src),
        "first_seen": d.first, "last_seen": d.last, "windows": d.windows,
        "attempts": d.attempts, "failed": d.failed, "targets": d.n_targets,
        "detail": d.detail, "possible_success": d.success, "success_detail": d.success_detail,
        "blocked": d.blocked, "not_blocked": d.not_blocked, "cves": sorted(d.cves),
        "signatures": [f"{n} ×{c}" for n, c in sorted(d.signatures.items())],
        "users": len(d.users), "routine": d.routine, "routine_reason": d.routine_reason,
        "evidence": [r.as_text() for r in d.success_evidence + d.evidence],
    }


def build_sources(col: Collector, settings: Settings, findings: list[dict]) -> list[dict]:
    """One row per source with at least one detection, including routine ones (marked as such)."""
    by_src: dict[str, list[Detection]] = {}
    for d in col.detections:
        by_src.setdefault(d.src, []).append(d)
    fids: dict[str, list[str]] = {}
    for f in findings:
        for s in f["hostile_sources"]:
            fids.setdefault(s, []).append(f["id"])
    out = []
    for src, dets in by_src.items():
        live = [d for d in dets if not d.routine]
        dets = sorted(dets, key=lambda d: (-_strength(d), d.kind, d.scope))
        out.append({
            "source_ip": src,
            "external": not settings.is_internal(src),
            "kinds": sorted({d.kind for d in live}, key=lambda k: list(KIND_LABEL).index(k)),
            "routine_only": not live,
            "possible_login_success": any(d.success for d in live),
            "targets_contacted": sum(d.n_targets for d in live),
            "vulnerable_targets": len(fids.get(src, [])),
            "finding_ids": fids.get(src, [])[:50],
            "first_seen": min(d.first for d in dets),
            "last_seen": max(d.last for d in dets),
            "detections": [_det_dict(d, settings) for d in dets[:20]],
            "score": max((_strength(d) for d in live), default=0) + 5 * len(fids.get(src, [])),
        })
    out.sort(key=lambda s: (s["routine_only"], -s["vulnerable_targets"], -s["score"], s["source_ip"]))
    return out


def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "plugin_id": v.plugin_id, "name": v.plugin_name, "severity": v.severity_label,
        "cves": v.cves, "cvss3_score": v.cvss3_score, "cvss3_vector": v.cvss3_vector,
        "exploit_available": v.exploit_available, "exploit_frameworks": v.exploit_frameworks,
        "service": v.service,
    }

