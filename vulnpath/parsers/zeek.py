"""Zeek parsers (native TSV or JSON), streaming line by line.

conn.log gives connections. ssh.log, ntlm.log and kerberos.log give authentication results, which turn a
brute-force *pattern* in conn.log into evidence of failed (and possibly successful) logins.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

from ..detect import open_text
from ..evidence import EvidenceFile
from ..model import AuthResult, Connection, EvidenceRef

PARSER_VERSION = "zeek/0.2"

# conn_state values where the TCP handshake completed (Zeek docs, conn.log).
ESTABLISHED_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
# Attempts that never completed a handshake: no reply, rejected, or half-open.
ATTEMPT_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}
# OTH: no SYN seen (the session started before the capture or log rotation). Not a failure.
MIDSTREAM_STATES = {"OTH"}

# Kerberos errors that mean a wrong password or an unknown user. KDC_ERR_PREAUTH_REQUIRED is the normal
# first step of every Windows logon and must NOT be counted as a failure.
KERBEROS_FAILURES = {"KDC_ERR_PREAUTH_FAILED", "KDC_ERR_C_PRINCIPAL_UNKNOWN", "KRB_AP_ERR_BAD_INTEGRITY"}


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


def _float(value) -> Optional[float]:
    if value in (None, "", "-", "(empty)"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool(value) -> Optional[bool]:
    if value in (True, "T", "true", "True"):
        return True
    if value in (False, "F", "false", "False"):
        return False
    return None


def _str(value) -> str:
    return "" if value in (None, "-", "(empty)") else str(value)


def _outcome(proto: str, state: str, orig_bytes: int, resp_bytes: int) -> str:
    if proto == "tcp":
        if state in ESTABLISHED_STATES:
            return "established"
        if state in MIDSTREAM_STATES and resp_bytes > 0:
            return "established"
        return "attempt"
    # UDP / ICMP have no handshake: treat a reply as two-way communication.
    return "established" if resp_bytes > 0 or state == "SF" else "attempt"


def _base(rec: dict, ef: EvidenceFile, lineno: int, **kw) -> Connection:
    return Connection(
        ts=_ts(str(rec["ts"])),
        src=str(rec["id.orig_h"]),
        src_port=_int(rec.get("id.orig_p"), None),
        dst=str(rec["id.resp_h"]),
        dst_port=_int(rec["id.resp_p"]),
        source="zeek",
        session_id=str(rec.get("uid") or ""),
        evidence=EvidenceRef(ef.file_id, ef.rel_path, f"line {lineno} uid {rec.get('uid', '')}"),
        **kw,
    )


def _conn(rec: dict, ef: EvidenceFile, lineno: int) -> Connection:
    proto = (rec.get("proto") or "").lower()
    state = rec.get("conn_state") or ""
    ob, rb = _int(rec.get("orig_bytes")), _int(rec.get("resp_bytes"))
    return _base(rec, ef, lineno, proto=proto, outcome=_outcome(proto, state, ob, rb),
                 service=_str(rec.get("service")), orig_bytes=ob, resp_bytes=rb, state=state,
                 duration=_float(rec.get("duration")))


def _ssh(rec: dict, ef: EvidenceFile, lineno: int) -> Optional[Connection]:
    ok = _bool(rec.get("auth_success"))
    if ok is None:
        return None   # no authentication result seen (e.g. a banner grab); conn.log has the connection
    attempts = _int(rec.get("auth_attempts"))
    failures = max(attempts - 1, 0) if ok else max(attempts, 1)
    return _base(rec, ef, lineno, proto="tcp", outcome="auth", service="ssh",
                 auth=AuthResult("ssh", ok, failures))


def _ntlm(rec: dict, ef: EvidenceFile, lineno: int) -> Optional[Connection]:
    ok = _bool(rec.get("success"))
    if ok is None:
        status = _str(rec.get("status"))   # older Zeek versions log a status string instead
        ok = None if not status else status.upper() == "SUCCESS"
    if ok is None:
        return None
    user = _str(rec.get("username"))
    dom = _str(rec.get("domainname"))
    return _base(rec, ef, lineno, proto="tcp", outcome="auth", service="ntlm",
                 auth=AuthResult("ntlm", ok, 0 if ok else 1, f"{dom}\\{user}" if dom else user))


def _kerberos(rec: dict, ef: EvidenceFile, lineno: int) -> Optional[Connection]:
    ok = _bool(rec.get("success"))
    err = _str(rec.get("error_msg")).upper()
    if ok is False and err not in KERBEROS_FAILURES:
        return None   # pre-authentication requests and other routine errors are normal
    if ok is None:
        return None
    client = _str(rec.get("client"))
    return _base(rec, ef, lineno, proto=(_str(rec.get("proto")) or "tcp").lower(), outcome="auth",
                 service="kerberos", auth=AuthResult("kerberos", ok, 0 if ok else 1, client.split("/")[0]))


BUILDERS: dict[str, Callable] = {"conn": _conn, "ssh": _ssh, "ntlm": _ntlm, "kerberos": _kerberos}


def parse(ef: EvidenceFile, kind: str = "conn") -> Iterator[Connection]:
    """Stream one Zeek log. `kind` is conn, ssh, ntlm or kerberos."""
    ef.parser = f"{PARSER_VERSION} {kind}"
    build = BUILDERS[kind]
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
                conn = build(rec, ef, lineno)
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                ef.records_skipped += 1
                ef.issues.append(f"line {lineno}: {e}")
                continue
            ef.records_parsed += 1
            if conn is not None:
                yield conn
