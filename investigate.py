#!/usr/bin/env python3
"""Offline vulnerability investigation workbench (POC).

Usage:
    python investigate.py --input ./case_folder --output ./results
"""
import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 9):
    sys.exit("Python 3.9 or newer is required.")

from workbench.correlate import DEFAULT_INTERNAL, Settings  # noqa: E402
from workbench.pipeline import DEFAULT_RULES, InputError, run  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Correlate raw Zeek / Palo Alto logs with a Nessus scan, offline.")
    ap.add_argument("--input", "-i", required=True, type=Path, help="folder of raw vendor files (read only)")
    ap.add_argument("--output", "-o", required=True, type=Path, help="folder for results (created if missing)")
    ap.add_argument("--internal", nargs="+", default=DEFAULT_INTERNAL, metavar="CIDR",
                    help="internal network ranges (default: RFC1918)")
    ap.add_argument("--scan-threshold", type=int, default=20,
                    help="distinct host:port pairs from one source that count as probing (default 20)")
    ap.add_argument("--stale-days", type=int, default=30,
                    help="flag findings where the scan is this many days from the traffic (default 30)")
    ap.add_argument("--pan-utc-offset", type=float, default=0.0, metavar="HOURS",
                    help="time zone of Palo Alto timestamps as hours from UTC, e.g. -5 (default 0)")
    ap.add_argument("--threat-map", default="", metavar="CSV",
                    help="optional CSV (threat_id,cve) mapping Palo Alto threat IDs to CVEs")
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="known vulnerability chains JSON")
    a = ap.parse_args(argv)
    try:
        run(a.input, a.output, Settings(a.internal, a.scan_threshold, a.stale_days,
                                        a.pan_utc_offset, a.threat_map), a.rules)
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
