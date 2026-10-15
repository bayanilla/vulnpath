"""Palo Alto Networks Traffic and Threat logs, from wherever they were collected.

Two layouts are recognised by content:
  * header CSV   - exported from the firewall or Panorama web UI (Monitor > Export to CSV).
                   Columns are matched by name, so column order does not matter.
  * syslog CSV   - raw lines from a syslog server / collector, with or without a syslog prefix.
                   Columns are read by PAN-OS documented position; newer PAN-OS versions only append
                   fields, so the positions used here (0-35) are stable.
Lines of other log types (SYSTEM, CONFIG, ...) are counted and skipped, not treated as errors.

PAN-OS timestamps carry no time zone. They are interpreted with the configured UTC offset.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ..detect import open_text
from ..evidence import EvidenceFile
from ..model import Connection, EvidenceRef, ThreatHit

PARSER_VERSION = "paloalto/0.2"
WANTED = {"TRAFFIC", "THREAT"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SYSLOG_START = re.compile(r"(?:^|[\s>])(\d*,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,]*,([A-Z]+),)")
NOT_BLOCKED = {"alert", "allow", ""}

# Syslog field positions (PAN-OS Traffic / Threat log field docs). Fields 0-30 are shared.
POS = {"time": 6, "src": 7, "dst": 8, "nat_src": 9, "nat_dst": 10, "rule": 11, "app": 14, "type": 3,
       "subtype": 4, "session": 22, "repeat": 23, "sport": 24, "dport": 25, "nat_dport": 27, "proto": 29, "action": 30}
POS_TRAFFIC = {"bytes_sent": 32, "bytes_recv": 33, "elapsed": 36, "end_reason": 46}
# App-ID values for sessions that completed the handshake but never carried application data.
NO_DATA_APPS = {"incomplete", "insufficient-data"}
POS_THREAT = {"threat": 32, "severity": 34, "direction": 35}

# Header CSV column aliases, compared after lower-casing and stripping non-alphanumerics.
ALIASES = {
    "time": ["generatetime", "generatedtime", "timegenerated", "receivetime", "time"],
    "type": ["type", "logtype"],
    "subtype": ["threatcontenttype", "subtype", "contenttype"],
    "src": ["sourceaddress", "sourceip", "srcip", "src"],
    "dst": ["destinationaddress", "destinationip", "dstip", "dst"],
    "nat_dst": ["natdestinationip", "natdst"],
    "sport": ["sourceport", "sport", "srcport"],
    "dport": ["destinationport", "dport", "dstport"],
    "nat_dport": ["natdestinationport", "natdport"],
    "proto": ["ipprotocol", "protocol", "proto"],
    "action": ["action"],
    "session": ["sessionid"],
    "app": ["application", "app"],
    "rule": ["rule", "rulename"],
    "bytes_sent": ["bytessent"],
    "bytes_recv": ["bytesreceived"],
    "end_reason": ["sessionendreason"],
    "elapsed": ["elapsedtimesec", "elapsedtime"],
    "repeat": ["repeatcount"],
    "threat": ["threatcontentname", "threatname", "threatid", "name"],
    "threat_id": ["threatid"],
    "severity": ["severity"],
    "direction": ["direction"],
    "cve": ["cve", "cves"],
}


def _norm(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", h.lower())


def header_map(header: list[str]) -> dict[str, int]:
    normed = [_norm(h) for h in header]
    out = {}
    for key, names in ALIASES.items():
        for n in names:
            if n in normed:
                out[key] = normed.index(n)
                break
    return out


def looks_like_header(line: str) -> bool:
    try:
        cols = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return False
    m = header_map(cols)
    return all(k in m for k in ("src", "dst", "dport", "action"))


def looks_like_syslog(line: str) -> bool:
    return SYSLOG_START.search(line) is not None


def load_threat_map(path: Path | None) -> dict[str, list[str]]:
    """Optional threat ID -> CVE list (CSV with columns threat_id,cve), e.g. exported from Panorama."""
    if not path or not path.exists():
        return {}
    out: dict[str, list[str]] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tid = (row.get("threat_id") or "").strip()
            cve = (row.get("cve") or "").strip().upper()
            if tid and cve:
                out.setdefault(tid, []).append(cve)
    return out


def _ts(value: str, offset_hours: float) -> float:
    dt = datetime.strptime(value.strip(), "%Y/%m/%d %H:%M:%S")
    return dt.replace(tzinfo=timezone(timedelta(hours=offset_hours))).timestamp()


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _proto(v: str) -> str:
    v = (v or "").strip().lower()
    return {"6": "tcp", "17": "udp", "1": "icmp"}.get(v, v)


def _threat_id(name: str, explicit: str) -> str:
    if explicit:
        return explicit.strip()
    m = re.search(r"\((\d+)\)\s*$", name)
    return m.group(1) if m else ""


def _record(get, ef: EvidenceFile, locator: str, offset: float, tmap: dict) -> Connection | None:
    """`get(key)` returns the field value or ''. Returns None for log types we skip."""
    ltype = get("type").upper() or ("THREAT" if get("threat") else "TRAFFIC")
    if ltype not in WANTED:
        return None
    if ltype == "TRAFFIC" and get("subtype").lower() == "start":
        return None   # log-at-session-start entry; the session's end entry carries the result
    src, dst = get("src"), get("dst")
    dport = _int(get("dport"))
    if not src or not dst or dport is None:
        raise ValueError("missing source, destination or destination port")
    nat_dst = get("nat_dst")
    nat_dport = _int(get("nat_dport"), 0)
    pre_dst, pre_port = "", None
    if nat_dst and nat_dst not in ("0.0.0.0", "::") and nat_dst != dst:
        # Inbound NAT: the scanner saw the translated (internal) address, so match on that.
        pre_dst, pre_port = dst, dport
        dst = nat_dst
        if nat_dport:
            dport = nat_dport
    action = get("action").lower()
    proto = _proto(get("proto"))
    sent, recv = _int(get("bytes_sent"), 0), _int(get("bytes_recv"), 0)
    threat = None
    if ltype == "THREAT":
        name = get("threat")
        tid = _threat_id(name, get("threat_id"))
        cves = sorted({c.upper() for c in CVE_RE.findall(name + " " + get("cve"))} | set(tmap.get(tid, [])))
        threat = ThreatHit(subtype=get("subtype").lower(), name=name, threat_id=tid,
                           severity=get("severity").lower(), action=action,
                           blocked=action not in NOT_BLOCKED, direction=get("direction").lower(), cves=cves,
                           repeat=max(_int(get("repeat"), 1) or 1, 1))
        outcome = "threat"
    elif action == "allow":
        # An allowed session with no bytes back never got an answer from the server, and one that App-ID
        # saw no data in ("incomplete") never got past the handshake.
        outcome = "established" if recv > 0 and get("app").lower() not in NO_DATA_APPS else "attempt"
    else:
        outcome = "denied"
    return Connection(
        ts=_ts(get("time"), offset), src=src, src_port=_int(get("sport")), dst=dst, dst_port=dport,
        proto=proto, source="paloalto", outcome=outcome, service=get("app"), orig_bytes=sent,
        resp_bytes=recv, state=action, session_id=get("session"),
        evidence=EvidenceRef(ef.file_id, ef.rel_path, f"{locator} {ltype.lower()} session {get('session')}"),
        pre_nat_dst=pre_dst, pre_nat_dst_port=pre_port, app=get("app"), rule=get("rule"), threat=threat,
        duration=_float(get("elapsed")),
    )


def parse(ef: EvidenceFile, utc_offset: float = 0.0, threat_map: dict | None = None) -> Iterator[Connection]:
    ef.parser = PARSER_VERSION
    tmap = threat_map or {}
    skipped_types: dict[str, int] = {}
    hmap: dict[str, int] | None = None
    with open_text(ef.path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip("\r\n﻿")
            if not line.strip():
                continue
            try:
                if hmap is None and lineno == 1 and looks_like_header(line):
                    hmap = header_map(next(csv.reader([line])))
                    continue
                if hmap is not None:
                    cols = next(csv.reader([line]))

                    def get(k, cols=cols):
                        i = hmap.get(k)
                        return cols[i].strip() if i is not None and i < len(cols) else ""
                else:
                    m = SYSLOG_START.search(line)
                    if not m:
                        raise ValueError("not a Palo Alto log line")
                    cols = next(csv.reader([line[m.start(1):]]))
                    pos = dict(POS, **(POS_THREAT if cols[3] == "THREAT" else POS_TRAFFIC))

                    def get(k, cols=cols, pos=pos):
                        i = pos.get(k)
                        return cols[i].strip() if i is not None and i < len(cols) else ""
                conn = _record(get, ef, f"line {lineno}", utc_offset, tmap)
            except (ValueError, csv.Error, IndexError) as e:
                ef.records_skipped += 1
                ef.issues.append(f"line {lineno}: {e}")
                continue
            if conn is None:
                t = get("type").upper() or "UNKNOWN"
                if t == "TRAFFIC":
                    t = "TRAFFIC session-start"
                skipped_types[t] = skipped_types.get(t, 0) + 1
                continue
            ef.records_parsed += 1
            yield conn
    for t, n in sorted(skipped_types.items()):
        ef.issues.append(f"{n} {t} log line(s) ignored (only TRAFFIC end and THREAT logs are used)")
    if ef.records_parsed:
        ef.issues.append(f"timestamps have no time zone; interpreted as UTC{utc_offset:+g}")
