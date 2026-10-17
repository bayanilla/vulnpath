"""MITRE ATT&CK techniques for each detection, and matches against recent threat-intelligence reports.

Every detection gets the ATT&CK technique its behaviour shows. Reports in rules/threat_intel.json then add
context: a report's rule matches when a detection of the listed kind hits a listed port, or a host whose
Nessus results carry a listed CVE or product. Matches explain themselves and cite the report. Only rules
tied to the target (a CVE or product on the host) or a listed source address change the priority score;
a port-only rule is context.
"""
from __future__ import annotations

import json
from pathlib import Path

from .behavior import CREDENTIAL_KINDS, SPRAY_MIN_USERS, Detection

TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1595": "Active Scanning",
    "T1595.001": "Scanning IP Blocks",
    "T1595.002": "Vulnerability Scanning",
}
SCAN_KINDS = {"horizontal-scan", "vertical-scan", "ips-scan"}
RULE_KEYS = {"kinds", "ports", "cves", "products", "external_only", "technique", "why"}


def name(tid: str) -> str:
    return f"{tid} {TECHNIQUES[tid]}" if tid in TECHNIQUES else tid


def baseline(d: Detection, external: bool) -> list[str]:
    """The ATT&CK technique(s) the detection itself shows, whatever any report says."""
    if d.kind in SCAN_KINDS:
        out = ["T1595.001" if d.kind == "horizontal-scan" else "T1595"] if external else ["T1046"]
    elif d.kind == "auth-brute-force":
        out = ["T1110.003" if len(d.users) >= SPRAY_MIN_USERS else "T1110.001"]
    elif d.kind in CREDENTIAL_KINDS:
        out = ["T1110"]
    else:   # ips-exploit
        out = ["T1190" if external else "T1210"]
    if d.success and d.kind in CREDENTIAL_KINDS:
        out.append("T1078")
    return out


def load(path: Path) -> list[dict]:
    """Reports from the rules file. A malformed rule raises, so a bad edit fails the tests, not a case."""
    if not path or not path.exists():
        return []
    reports = json.loads(path.read_text(encoding="utf-8")).get("reports", [])
    for r in reports:
        for key in ("id", "title", "publisher", "published", "url"):
            if not r.get(key):
                raise ValueError(f"threat intel report {r.get('id', '?')}: missing {key}")
        for rule in r.get("rules", []):
            unknown = set(rule) - RULE_KEYS
            if unknown or not rule.get("kinds") or not rule.get("technique") or not rule.get("why"):
                raise ValueError(f"threat intel report {r['id']}: bad rule {rule}")
    return reports


def threat_ids(reports: list[dict]) -> dict[str, list[str]]:
    """Palo Alto threat ID -> CVEs, as named in the reports. Merged into the --threat-map."""
    out: dict[str, list[str]] = {}
    for r in reports:
        for tid, cves in r.get("threat_ids", {}).items():
            out.setdefault(str(tid), []).extend(c.upper() for c in cves)
    return out


class Intel:
    def __init__(self, reports: list[dict]):
        self.reports = reports
        self.bad_ips = {ip: r for r in reports for ip in r.get("source_ips", [])}

    def match(self, d: Detection, external: bool, port: int, host_cves: set, host_products: str) -> list[dict]:
        """Report rules this detection matches against one target service.

        `host_cves` and `host_products` (lower-cased Nessus plugin names) describe the whole target host,
        because a scanner often reports a product's flaw on a different port from the one attacked.
        """
        out = []
        r = self.bad_ips.get(d.src)
        if r:
            out.append(self._hit(r, None, f"source {d.src} is listed as actor infrastructure", True))
        for r in self.reports:
            for rule in r.get("rules", []):
                if d.kind not in rule["kinds"]:
                    continue
                if rule.get("external_only") and not external:
                    continue
                if rule.get("ports") and port not in rule["ports"]:
                    continue
                tied = []
                if rule.get("cves"):
                    hit = sorted(set(c.upper() for c in rule["cves"]) & (host_cves | set(d.cves)))
                    if not hit:
                        continue
                    tied.append("the host has " + ", ".join(hit))
                if rule.get("products"):
                    hit = [p for p in rule["products"] if p.lower() in host_products]
                    if not hit:
                        continue
                    tied.append("Nessus reports " + ", ".join(hit) + " on the host")
                why = rule["why"] + (f" ({'; '.join(tied)})" if tied else "")
                out.append(self._hit(r, rule["technique"], why, bool(tied)))
        return out

    @staticmethod
    def _hit(r: dict, technique: str | None, why: str, targeted: bool) -> dict:
        return {"report": r["id"], "title": r["title"], "publisher": r["publisher"], "published": r["published"],
                "url": r["url"], "actors": r.get("actors", []), "technique": technique, "why": why,
                "targeted": targeted}
