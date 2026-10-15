#!/usr/bin/env python3
"""VulnPath: which vulnerable services are being targeted (offline POC).

Usage:
    python investigate.py --input ./case_folder --output ./results
"""
import argparse
import sys
from pathlib import Path

if sys.version_info < (3, 9):
    sys.exit("Python 3.9 or newer is required.")

from vulnpath.correlate import DEFAULT_INTERNAL, Settings  # noqa: E402
from vulnpath.pipeline import DEFAULT_RULES, InputError, run  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Find scanning, brute force and IPS detections in raw Zeek / Palo Alto logs and rank the "
                    "vulnerable services (from a Nessus scan) they target. Runs offline.")
    ap.add_argument("--input", "-i", required=True, type=Path, help="folder of raw vendor files (read only)")
    ap.add_argument("--output", "-o", required=True, type=Path, help="folder for results (created if missing)")
    ap.add_argument("--internal", nargs="+", default=DEFAULT_INTERNAL, metavar="CIDR",
                    help="internal network ranges (default: RFC1918)")
    ap.add_argument("--exclude-sources", nargs="+", default=[], metavar="CIDR",
                    help="sources to ignore entirely: vulnerability scanners, admin and monitoring hosts")
    ap.add_argument("--window", type=float, default=15, metavar="MINUTES",
                    help="length of the time window behaviour is counted in (default 15)")
    ap.add_argument("--sweep-hosts", type=int, default=20,
                    help="distinct hosts on one port within a window that make a sweep (default 20)")
    ap.add_argument("--portscan-ports", type=int, default=15,
                    help="distinct ports on one host within a window that make a port scan (default 15)")
    ap.add_argument("--brute-attempts", type=int, default=10,
                    help="short connections to one login service within a window that make brute force (default 10)")
    ap.add_argument("--auth-failures", type=int, default=5,
                    help="failed logins in Zeek authentication logs within a window (default 5)")
    ap.add_argument("--stale-days", type=int, default=30,
                    help="flag findings where the scan is this many days from the activity (default 30)")
    ap.add_argument("--pan-utc-offset", type=float, default=0.0, metavar="HOURS",
                    help="time zone of Palo Alto timestamps as hours from UTC, e.g. -5 (default 0)")
    ap.add_argument("--threat-map", default="", metavar="CSV",
                    help="optional CSV (threat_id,cve) mapping Palo Alto threat IDs to CVEs")
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="known vulnerability chains JSON")
    a = ap.parse_args(argv)
    try:
        settings = Settings(internal_networks=a.internal, exclude_sources=a.exclude_sources,
                            window_minutes=a.window, sweep_min_hosts=a.sweep_hosts,
                            portscan_min_ports=a.portscan_ports, brute_min_attempts=a.brute_attempts,
                            auth_min_failures=a.auth_failures, stale_days=a.stale_days,
                            pan_utc_offset=a.pan_utc_offset, threat_map=a.threat_map)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        run(a.input, a.output, settings, a.rules)
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
