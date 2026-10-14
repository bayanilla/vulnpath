"""Zeek conn.log parser (native TSV or JSON), streaming line by line."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterator

from ..detect import open_text
from ..evidence import EvidenceFile
from ..model import Connection, EvidenceRef

PARSER_VERSION = "zeek_conn/0.1"

# conn_state values where the TCP handshake completed (Zeek docs, conn.log).
ESTABLISHED_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
# Attempts that never completed a handshake: no reply, rejected, or half-open.
ATTEMPT_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def _ts(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        # Zeek JSON can use ISO8601 timestamps
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def _int(value, default=0):
    if value in (None, "", "-", "(empty)"):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _outcome(proto: str, state: str, orig_bytes: int, resp_bytes: int) -> str:
    if proto == "tcp":
        if state in ESTABLISHED_STATES:
            return "established"
        return "attempt"
    # UDP / ICMP have no handshake: treat a reply as two-way communication.
    return "established" if resp_bytes > 0 or state == "SF" else "attempt"


def _build(rec: dict, ef: EvidenceFile, lineno: int) -> Connection:
    proto = (rec.get("proto") or "").lower()
    state = rec.get("conn_state") or ""
    ob, rb = _int(rec.get("orig_bytes")), _int(rec.get("resp_bytes"))
    svc = rec.get("service") or ""
    if svc in ("-", "(empty)"):
        svc = ""
    return Connection(
        ts=_ts(str(rec["ts"])),
        src=str(rec["id.orig_h"]),
        src_port=_int(rec.get("id.orig_p"), None),
        dst=str(rec["id.resp_h"]),
        dst_port=_int(rec["id.resp_p"]),
        proto=proto,
        source="zeek",
        outcome=_outcome(proto, state, ob, rb),
        service=svc,
        orig_bytes=ob,
        resp_bytes=rb,
        state=state,
        session_id=str(rec.get("uid") or ""),
        evidence=EvidenceRef(ef.file_id, ef.rel_path, f"line {lineno} uid {rec.get('uid', '')}"),
    )


def parse(ef: EvidenceFile) -> Iterator[Connection]:
    ef.parser = PARSER_VERSION
    fields: list[str] | None = None
    sep = "\t"
    with open_text(ef.path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            try:
                if line.startswith("#"):
                    if line.startswith("#separator"):
                        token = line.split(" ", 1)[1].strip()
                        sep = token.encode().decode("unicode_escape")
                    elif line.startswith("#fields"):
                        fields = line.split(sep)[1:]
                    continue
                if line.startswith("{"):
                    rec = json.loads(line)
                else:
                    if fields is None:
                        raise ValueError("data line before #fields header")
                    vals = line.split(sep)
                    if len(vals) != len(fields):
                        raise ValueError(f"expected {len(fields)} columns, got {len(vals)}")
                    rec = dict(zip(fields, vals))
                for req in ("ts", "id.orig_h", "id.resp_h", "id.resp_p"):
                    if rec.get(req) in (None, "", "-"):
                        raise ValueError(f"missing {req}")
                conn = _build(rec, ef, lineno)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                ef.records_skipped += 1
                ef.issues.append(f"line {lineno}: {e}")
                continue
            ef.records_parsed += 1
            yield conn
