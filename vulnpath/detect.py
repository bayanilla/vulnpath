"""Identify source type from file content, not from file names."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

SNIFF_BYTES = 64 * 1024
ZEEK_KINDS = ("conn", "ssh", "ntlm", "kerberos")


def open_text(path: Path):
    """Open plain or gzip text for streaming reads (Zeek logs are often rotated as .gz)."""
    with open(path, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, "rt", encoding="utf-8", errors="replace", newline="")


def _head(path: Path) -> str:
    try:
        with open_text(path) as f:
            return f.read(SNIFF_BYTES)
    except (OSError, EOFError, gzip.BadGzipFile):
        return ""


def detect(path: Path) -> str:
    head = _head(path)
    if not head:
        return "unsupported"
    stripped = head.lstrip()

    # Nessus v2 XML export
    if stripped.startswith("<"):
        if "<NessusClientData_v2" in head:
            return "nessus"
        if stripped.startswith("<?xml"):
            return "unsupported"
        # otherwise it may be a syslog line with a <PRI> prefix; keep checking

    # Zeek TSV: header block with #separator and #path
    if stripped.startswith("#separator"):
        for line in head.splitlines():
            if line.startswith("#path"):
                parts = line.split(None, 1)
                kind = parts[1].strip() if len(parts) > 1 else ""
                return f"zeek_{kind}" if kind in ZEEK_KINDS else f"zeek_{kind or 'unknown'}_unsupported"
        return "unsupported"

    # Zeek JSON: one object per line with id.* fields
    if stripped.startswith("{"):
        first = stripped.splitlines()[0]
        try:
            obj = json.loads(first)
        except json.JSONDecodeError:
            return "unsupported"
        if isinstance(obj, dict) and "id.orig_h" in obj and "id.resp_p" in obj:
            if "conn_state" in obj or "orig_bytes" in obj or "history" in obj:
                return "zeek_conn"
            if "auth_success" in obj or "auth_attempts" in obj or "kex_alg" in obj or "host_key_alg" in obj:
                return "zeek_ssh"
            if "request_type" in obj and ("client" in obj or "service" in obj):
                return "zeek_kerberos"
            if "server_nb_computer_name" in obj or "domainname" in obj:
                return "zeek_ntlm"
            return "zeek_other_unsupported"
        return "unsupported"

    # Palo Alto: header CSV export, or raw syslog lines (possibly mixed with other log types)
    from .parsers.paloalto import looks_like_header, looks_like_syslog
    lines = [ln for ln in stripped.lstrip("\ufeff").splitlines() if ln.strip()]
    if lines and looks_like_header(lines[0]):
        return "paloalto"
    if lines and sum(1 for ln in lines[:50] if looks_like_syslog(ln)) >= max(1, min(len(lines[:50]), 50) // 2):
        return "paloalto"
    return "unsupported"
