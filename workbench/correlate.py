"""Join observed traffic with Nessus results. Deterministic rules only, every decision explained."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

from .model import Connection, EvidenceRef, HostInfo, Vulnerability

DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "127.0.0.0/8"]
SEVERITY_POINTS = {4: 40, 3: 30, 2: 15, 1: 5}
MAX_SAMPLE_REFS = 5
SCANNER_TRACK_CAP = 10_000


@dataclass
class Settings:
    internal_networks: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL))
    scanner_threshold: int = 20        # distinct dst:port pairs from one source = probing behaviour
    stale_days: int = 30               # scan vs traffic gap before a result is flagged as stale
    pan_utc_offset: float = 0.0        # Palo Alto timestamps have no zone; hours offset from UTC
    threat_map: str = ""               # optional CSV threat_id,cve for Palo Alto signatures

    def __post_init__(self):
        self._nets = [ipaddress.ip_network(n, strict=False) for n in self.internal_networks]

    def is_internal(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._nets if n.version == a.version)


@dataclass
class Touch:
    """All traffic from one source to one vulnerable service (dst, port, proto)."""
    src: str
    dst: str
    port: int
    proto: str
    # Counts are kept per telemetry source. Zeek and the firewall often see the SAME sessions, so the
    # combined figure is the largest single-source count, never the sum (no double counting).
    by_source: dict = field(default_factory=dict)   # source -> {"est", "att", "den", "out", "in"}
    first_ts: float = float("inf")
    last_ts: float = float("-inf")
    sources: set = field(default_factory=set)
    samples: list[EvidenceRef] = field(default_factory=list)
    pre_nat: set = field(default_factory=set)
    # firewall threat-log (IPS) detections on this source -> service pair
    exploit_hits: int = 0
    exploit_blocked: int = 0
    scan_hits: int = 0
    signatures: dict = field(default_factory=dict)      # name -> count
    threat_cves: set = field(default_factory=set)
    threat_samples: list[EvidenceRef] = field(default_factory=list)

    def _max(self, k: str) -> int:
        return max((b[k] for b in self.by_source.values()), default=0)

    @property
    def established(self) -> int:
        return self._max("est")

    @property
    def attempts(self) -> int:
        return self._max("att")

    @property
    def denied(self) -> int:
        return self._max("den")

    @property
    def bytes_to_server(self) -> int:
        return self._max("out")

    @property
    def bytes_from_server(self) -> int:
        return self._max("in")

    @property
    def exploit_unblocked(self) -> int:
        return self.exploit_hits - self.exploit_blocked

    def add(self, c: Connection) -> None:
        self.first_ts = min(self.first_ts, c.ts)
        self.last_ts = max(self.last_ts, c.ts)
        self.sources.add(c.source)
        if c.pre_nat_dst and len(self.pre_nat) < 5:
            self.pre_nat.add(f"{c.pre_nat_dst}:{c.pre_nat_dst_port}")
        if c.threat is not None:
            th = c.threat
            if th.subtype == "scan":
                self.scan_hits += 1
            else:
                self.exploit_hits += 1
                self.exploit_blocked += th.blocked
                self.threat_cves.update(th.cves)
                if len(self.signatures) < 20 or th.name in self.signatures:
                    self.signatures[th.name] = self.signatures.get(th.name, 0) + 1
            if c.evidence and len(self.threat_samples) < MAX_SAMPLE_REFS:
                self.threat_samples.append(c.evidence)
            return
        b = self.by_source.setdefault(c.source, {"est": 0, "att": 0, "den": 0, "out": 0, "in": 0})
        b[{"established": "est", "denied": "den"}.get(c.outcome, "att")] += 1
        b["out"] += c.orig_bytes
        b["in"] += c.resp_bytes
        if c.evidence and len(self.samples) < MAX_SAMPLE_REFS:
            self.samples.append(c.evidence)


@dataclass
class TrafficStats:
    total: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    dst_not_scanned: set = field(default_factory=set)
    src_targets: dict = field(default_factory=dict)   # src -> set of (dst, port), capped


def correlate(conns: Iterable[Connection], vulns: list[Vulnerability], hosts: dict[str, HostInfo],
              settings: Settings) -> tuple[dict, TrafficStats]:
    index: dict[tuple, list[Vulnerability]] = {}
    for v in vulns:
        if v.port > 0:
            index.setdefault((v.host, v.port, v.proto), []).append(v)

    touches: dict[tuple, Touch] = {}
    stats = TrafficStats()
    for c in conns:
        stats.total += 1
        stats.first_ts = c.ts if stats.first_ts is None else min(stats.first_ts, c.ts)
        stats.last_ts = c.ts if stats.last_ts is None else max(stats.last_ts, c.ts)
        tgt = stats.src_targets.setdefault(c.src, set())
        if len(tgt) < SCANNER_TRACK_CAP:
            tgt.add((c.dst, c.dst_port))
        if c.dst not in hosts and len(stats.dst_not_scanned) < SCANNER_TRACK_CAP:
            stats.dst_not_scanned.add(c.dst)
        key = (c.dst, c.dst_port, c.proto)
        if key in index:
            tk = (c.src,) + key
            t = touches.get(tk)
            if t is None:
                t = touches[tk] = Touch(c.src, c.dst, c.dst_port, c.proto)
            t.add(c)
    return {"index": index, "touches": touches}, stats


def build_findings(touches: dict, index: dict, hosts: dict[str, HostInfo], stats: TrafficStats,
                   settings: Settings, chained_hosts: set[str], path_hops: set[tuple]) -> list[dict]:
    findings = []
    for (src, dst, port, proto), t in sorted(touches.items()):
        vs = sorted(index[(dst, port, proto)], key=lambda v: (-v.severity, v.plugin_id))
        top = vs[0]
        reasons: list[str] = []
        score = SEVERITY_POINTS.get(top.severity, 0)
        reasons.append(f"highest severity {top.severity_label} (+{score})")

        n_targets = len(stats.src_targets.get(src, ()))
        scanner = n_targets >= settings.scanner_threshold or t.scan_hits > 0
        vuln_cves = {c for v in vs for c in v.cves}
        cve_match = sorted(t.threat_cves & vuln_cves)
        if t.established:
            outcome = "established"
            score += 20
            reasons.append(f"{t.established} established connection(s) to the vulnerable service (+20)")
        elif t.attempts:
            outcome = "attempted"
            score += 5
            reasons.append(f"{t.attempts} connection attempt(s), none completed (+5)")
        elif t.denied:
            outcome = "denied"
            reasons.append(f"{t.denied} connection(s) denied by firewall (+0)")
        else:
            outcome = "ips-only"
            reasons.append("seen only in firewall threat logs (no traffic log for these sessions)")

        if t.exploit_hits:
            activity = "exploit-attempt"
            if cve_match:
                score += 25
                reasons.append(f"IPS signature maps to the scanned CVE ({', '.join(cve_match)}) (+25)")
            else:
                score += 10
                reasons.append("IPS signature fired on the vulnerable service; not mapped to the scanned CVE (+10)")
            if t.exploit_unblocked:
                score += 10
                reasons.append(f"{t.exploit_unblocked} detection(s) were alert-only, not blocked (+10)")
            else:
                reasons.append(f"all {t.exploit_hits} detection(s) were blocked by the firewall")
        elif scanner:
            activity = "probing"
            score -= 15
            reasons.append("firewall flagged this source as a scan (-15)" if t.scan_hits else
                           f"source contacted {n_targets} distinct host:port pairs; broad scan, not aimed at this "
                           f"service (-15)")
        else:
            activity = "targeting"

        external = not settings.is_internal(src)
        if external:
            score += 10
            reasons.append("source is outside the internal networks (+10)")
        if any(v.exploit_available for v in vs):
            score += 15
            reasons.append("Nessus reports a public exploit is available (+15)")
        if (src, dst, port, proto) in path_hops:
            score += 10
            reasons.append("connection is a hop on a candidate attack path (+10)")
        if dst in chained_hosts:
            score += 10
            reasons.append("host also has a candidate vulnerability chain (+10)")

        scan_time = hosts.get(dst).scan_time if dst in hosts else None
        stale = False
        if scan_time is not None:
            gap_days = abs(t.first_ts - scan_time) / 86400
            if gap_days > settings.stale_days:
                stale = True
                score -= 10
                reasons.append(f"scan is {gap_days:.0f} days from the traffic; result may be stale (-10)")

        if t.exploit_hits and t.exploit_unblocked and cve_match:
            assessment = (f"An IPS signature for the scanned vulnerability ({', '.join(cve_match)}) fired and was "
                          "NOT blocked. Highest-priority lead: check this host for signs of compromise. "
                          "This is still not confirmation of exploitation.")
        elif t.exploit_hits and t.exploit_unblocked:
            assessment = ("An IPS signature fired against this vulnerable service and was not blocked. The signature "
                          "is not mapped to the scanned CVE, so check whether it is relevant. Not confirmation "
                          "of exploitation.")
        elif t.exploit_hits:
            assessment = "IPS detected exploit attempts against this vulnerable service; the firewall blocked them."
        elif outcome == "established":
            assessment = ("Traffic reached a service Nessus reports as vulnerable. "
                          "This is NOT evidence of exploitation; review the session content.")
        elif outcome == "attempted":
            assessment = "Connection attempts toward a vulnerable service; no session was established."
        else:
            assessment = "Connections toward a vulnerable service were blocked."

        findings.append({
            "id": "",
            "priority_score": score,
            "activity": activity,
            "outcome": outcome,
            "direction": "inbound-external" if external else "internal",
            "source_ip": src,
            "target_ip": dst,
            "target_hostname": hosts[dst].hostname if dst in hosts else "",
            "port": port,
            "protocol": proto,
            "vulnerabilities": [_vuln_dict(v) for v in vs],
            "traffic": {
                "established": t.established, "attempts": t.attempts, "denied": t.denied,
                "by_source": {k: {"established": v["est"], "attempts": v["att"], "denied": v["den"]}
                              for k, v in sorted(t.by_source.items())},
                "bytes_to_server": t.bytes_to_server, "bytes_from_server": t.bytes_from_server,
                "first_seen": t.first_ts, "last_seen": t.last_ts,
                "telemetry_sources": sorted(t.sources),
                "pre_nat_destinations": sorted(t.pre_nat),
            },
            "ips": {
                "exploit_detections": t.exploit_hits, "blocked": t.exploit_blocked,
                "not_blocked": t.exploit_unblocked, "scan_detections": t.scan_hits,
                "signatures": [f"{n} ×{c}" for n, c in sorted(t.signatures.items())],
                "cves_matched": cve_match,
            },
            "scan_stale": stale,
            "assessment": assessment,
            "score_reasons": reasons,
            "evidence": [r.as_text() for r in t.samples] + [r.as_text() for r in t.threat_samples] + [v.evidence.as_text() for v in vs if v.evidence],
        })
    findings.sort(key=lambda f: (-f["priority_score"], f["target_ip"], f["port"], f["source_ip"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F{i:04d}"
    return findings


def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "plugin_id": v.plugin_id, "name": v.plugin_name, "severity": v.severity_label,
        "cves": v.cves, "cvss3_score": v.cvss3_score, "cvss3_vector": v.cvss3_vector,
        "exploit_available": v.exploit_available, "exploit_frameworks": v.exploit_frameworks,
        "service": v.service,
    }
