"""Internal data model. Every record keeps a pointer back to the raw file and line it came from."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class EvidenceRef:
    file_id: str      # first 12 hex chars of the file's SHA-256
    path: str         # path relative to the case folder
    locator: str      # e.g. "line 42" or "ReportHost 10.0.1.10 / plugin 12345 / port 443"

    def as_text(self) -> str:
        return f"{self.path} [{self.file_id}] {self.locator}"


@dataclass
class Connection:
    """One network observation, normalized from Zeek (later Palo Alto)."""
    ts: float                 # epoch seconds, UTC
    src: str
    src_port: Optional[int]
    dst: str
    dst_port: int
    proto: str                # tcp / udp / icmp
    source: str               # "zeek", "paloalto"
    outcome: str              # "established", "attempt", "denied"
    service: str = ""
    orig_bytes: int = 0
    resp_bytes: int = 0
    state: str = ""           # vendor state, e.g. Zeek conn_state "SF"
    session_id: str = ""      # Zeek uid / PAN session id
    evidence: Optional[EvidenceRef] = None
    pre_nat_dst: str = ""     # original destination when the firewall translated it (dst is post-NAT)
    pre_nat_dst_port: Optional[int] = None
    app: str = ""
    rule: str = ""
    threat: Optional["ThreatHit"] = None   # set for IPS/threat detections (not a connection count)


@dataclass
class ThreatHit:
    """A firewall threat-log detection (e.g. Palo Alto IPS signature)."""
    subtype: str              # vulnerability / scan / spyware / ...
    name: str                 # signature name as logged
    threat_id: str
    severity: str
    action: str               # alert / reset-both / drop ...
    blocked: bool
    direction: str
    cves: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    host: str                 # IP address as scanned
    hostname: str
    port: int                 # 0 means host-level (not tied to a listening service)
    proto: str
    service: str
    plugin_id: str
    plugin_name: str
    severity: int             # Nessus 0-4
    cves: list[str] = field(default_factory=list)
    cvss3_vector: str = ""
    cvss3_score: Optional[float] = None
    cvss2_vector: str = ""
    exploit_available: bool = False
    exploitability_ease: str = ""
    exploit_frameworks: list[str] = field(default_factory=list)
    synopsis: str = ""
    solution: str = ""
    scan_time: Optional[float] = None
    evidence: Optional[EvidenceRef] = None

    @property
    def severity_label(self) -> str:
        return ["Info", "Low", "Medium", "High", "Critical"][max(0, min(self.severity, 4))]

    @property
    def label(self) -> str:
        cve = ", ".join(self.cves[:3]) if self.cves else f"plugin {self.plugin_id}"
        return f"{cve} ({self.severity_label})"


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os: str = ""
    scan_time: Optional[float] = None
