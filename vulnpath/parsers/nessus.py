"""Nessus .nessus (NessusClientData_v2) parser, streaming with iterparse."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterator

from ..evidence import EvidenceFile
from ..model import EvidenceRef, HostInfo, Vulnerability

PARSER_VERSION = "nessus_v2/0.1"
MIN_SEVERITY = 1  # skip informational (severity 0) items


def _refuse_dtd(ef: EvidenceFile) -> None:
    """A .nessus export never needs a DTD; refusing one blocks entity-expansion tricks."""
    with open(ef.path, "rb") as f:
        head = f.read(64 * 1024).upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        raise ValueError("file contains a DTD/entity declaration; refusing to parse")


def _scan_time(props: dict) -> float | None:
    for key in ("HOST_END_TIMESTAMP", "HOST_START_TIMESTAMP"):
        if props.get(key, "").isdigit():
            return float(props[key])
    for key in ("HOST_END", "HOST_START"):
        v = props.get(key)
        if v:
            try:
                return datetime.strptime(v.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
    return None


def parse(ef: EvidenceFile, hosts: dict[str, HostInfo]) -> Iterator[Vulnerability]:
    """Yield vulnerabilities; fills `hosts` with host properties as a side effect."""
    ef.parser = PARSER_VERSION
    _refuse_dtd(ef)
    pending: list[ET.Element] = []
    try:
        for event, el in ET.iterparse(ef.path, events=("end",)):
            if el.tag == "ReportItem":
                pending.append(el)
            elif el.tag == "ReportHost":
                name = el.get("name", "")
                props = {t.get("name"): (t.text or "") for t in el.iter("tag")}
                ip = props.get("host-ip") or name
                hostname = props.get("host-fqdn") or props.get("netbios-name") or props.get("hostname") or ""
                st = _scan_time(props)
                hosts[ip] = HostInfo(ip=ip, hostname=hostname, os=props.get("operating-system", ""), scan_time=st)
                if not props.get("host-ip"):
                    ef.issues.append(f"ReportHost {name}: no host-ip tag, using name attribute")
                if st is None:
                    ef.issues.append(f"ReportHost {name}: no scan timestamp")
                for item in pending:
                    v = _item(item, ip, hostname, st, ef)
                    if v is not None:
                        ef.records_parsed += 1
                        yield v
                pending.clear()
                el.clear()
    except ET.ParseError as e:
        ef.issues.append(f"XML parse error: {e}")
        ef.records_skipped += 1


def _item(item: ET.Element, ip: str, hostname: str, scan_time, ef: EvidenceFile) -> Vulnerability | None:
    try:
        sev = int(item.get("severity", "0"))
        port = int(item.get("port", "0"))
    except ValueError:
        ef.records_skipped += 1
        ef.issues.append(f"{ip}: ReportItem with bad severity/port")
        return None
    if sev < MIN_SEVERITY:
        return None

    def text(tag):
        e = item.find(tag)
        return (e.text or "").strip() if e is not None and e.text else ""

    score = text("cvss3_base_score")
    frameworks = [n.replace("exploit_framework_", "") for n in
                  ("exploit_framework_metasploit", "exploit_framework_core", "exploit_framework_canvas")
                  if text(n).lower() == "true"]
    pid = item.get("pluginID", "")
    return Vulnerability(
        host=ip,
        hostname=hostname,
        port=port,
        proto=(item.get("protocol") or "tcp").lower(),
        service=item.get("svc_name", ""),
        plugin_id=pid,
        plugin_name=item.get("pluginName", ""),
        severity=sev,
        cves=[c.text.strip() for c in item.findall("cve") if c.text],
        cvss3_vector=text("cvss3_vector"),
        cvss3_score=float(score) if score else None,
        cvss2_vector=text("cvss_vector"),
        exploit_available=text("exploit_available").lower() == "true",
        exploitability_ease=text("exploitability_ease"),
        exploit_frameworks=frameworks,
        synopsis=text("synopsis"),
        solution=text("solution"),
        scan_time=scan_time,
        evidence=EvidenceRef(ef.file_id, ef.rel_path, f"ReportHost {ip} / plugin {pid} / port {port}/{item.get('protocol', '')}"),
    )
