"""End-to-end run: inventory -> detect -> parse -> behaviour -> join to Nessus -> chain -> report."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .chains import attack_paths, load_known_chains, same_host_chains
from .correlate import Settings, build_findings, build_sources, correlate, targets_of
from .detect import detect
from .diagram import render
from .evidence import inventory, verify_unchanged
from .parsers import nessus, paloalto, zeek
from .report import ts, write_csv, write_html, write_json, write_sources_csv

ZEEK_TYPES = {"zeek_conn": "conn", "zeek_ssh": "ssh", "zeek_ntlm": "ntlm", "zeek_kerberos": "kerberos"}
TRAFFIC_TYPES = set(ZEEK_TYPES) | {"paloalto"}
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "known_chains.json"


class InputError(Exception):
    pass


def load_scans(nessus_files, notices: list[str], step) -> tuple[dict, list, list[str]]:
    """Parse every .nessus file and keep, for each host, only the results of its most recent scan.

    Case folders often hold several weekly exports. Merging them would keep vulnerabilities that a later
    scan shows as fixed, and list the rest twice.
    """
    per_file = []
    for ef in nessus_files:
        step(f"Parsing Nessus: {ef.rel_path}")
        hosts: dict = {}
        try:
            vulns = list(nessus.parse(ef, hosts))
        except ValueError as e:
            ef.issues.append(str(e))
            notices.append(f"{ef.rel_path} was not parsed: {e}")
            continue
        per_file.append((ef, hosts, vulns))

    best: dict[str, tuple] = {}   # ip -> (scan_time, order, ef, hostinfo)
    for order, (ef, hosts, _) in enumerate(per_file):
        for ip, info in hosts.items():
            key = (info.scan_time if info.scan_time is not None else float("-inf"), order)
            if ip not in best or key > best[ip][:2]:
                best[ip] = key + (ef, info)
    hosts = {ip: b[3] for ip, b in best.items()}
    vulns = [v for ef, _, vs in per_file for v in vs if best[v.host][2] is ef]
    coverage = []
    multi = sum(1 for ip in best if sum(ip in h for _, h, _ in per_file) > 1)
    if multi:
        coverage.append(f"{multi} host(s) appear in more than one Nessus file; only each host's most recent "
                        "scan was used.")
    return hosts, vulns, coverage


def run(case_dir: Path, out_dir: Path, settings: Settings | None = None,
        rules_path: Path = DEFAULT_RULES, log=print) -> dict:
    settings = settings or Settings()
    case_dir, out_dir = case_dir.resolve(), out_dir.resolve()
    if not case_dir.is_dir():
        raise InputError(f"input folder not found: {case_dir}")
    if out_dir == case_dir or case_dir in out_dir.parents:
        raise InputError("output folder must be outside the input folder (evidence is never written to)")
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    proc_log: list[dict] = []

    def step(msg):
        log(msg)
        proc_log.append({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "step": msg})

    step(f"Hashing files in {case_dir}")
    files = inventory(case_dir)
    for ef in files:
        ef.source_type = detect(ef.path)
    found = sorted({ef.source_type for ef in files})
    step(f"{len(files)} file(s); detected: {', '.join(found) or 'nothing'}")

    notices: list[str] = []
    nessus_files = [ef for ef in files if ef.source_type == "nessus"]
    traffic_files = [ef for ef in files if ef.source_type in TRAFFIC_TYPES]
    if not nessus_files:
        notices.append("No Nessus (.nessus) file was found, so no vulnerability correlation was possible.")
    if not any(ef.source_type in ("zeek_conn", "paloalto") for ef in traffic_files):
        notices.append("No supported traffic logs (Zeek conn.log or Palo Alto Traffic/Threat) were found, "
                       "so scans and connection-pattern brute force could not be detected.")
    if not any(ef.source_type in ("zeek_ssh", "zeek_ntlm", "zeek_kerberos") for ef in traffic_files):
        notices.append("No Zeek ssh.log, ntlm.log or kerberos.log was found. Brute force is detected from "
                       "connection patterns and firewall signatures only, without login results.")

    hosts, vulns, scan_coverage = load_scans(nessus_files, notices, step)
    step(f"{len(vulns)} vulnerability result(s) (severity Low+) on {len(hosts)} host(s)")

    threat_map = paloalto.load_threat_map(Path(settings.threat_map)) if settings.threat_map else {}
    if settings.threat_map and not threat_map:
        notices.append(f"Threat map {settings.threat_map} was empty or not found; IPS signatures are matched by port only.")

    def all_records():
        for ef in traffic_files:
            step(f"Streaming: {ef.rel_path}")
            if ef.source_type == "paloalto":
                yield from paloalto.parse(ef, settings.pan_utc_offset, threat_map)
            else:
                yield from zeek.parse(ef, ZEEK_TYPES[ef.source_type])

    col = correlate(all_records(), vulns, hosts, settings)
    stats = col.stats
    live = [d for d in col.detections if not d.routine]
    step(f"{stats.total:,} connection(s), {stats.auth_records:,} login record(s), {stats.threat_records:,} "
         f"threat record(s); {len(live)} hostile behaviour detection(s)")

    targeted: dict[tuple, list] = {}
    for d in live:
        for t in targets_of(d, col.index, hosts):
            targeted.setdefault(t, []).append(d)
    known = load_known_chains(rules_path)
    chains = same_host_chains(vulns, known, targeted)
    findings = build_findings(col, settings, chains)
    sources = build_sources(col, settings, findings)
    paths = attack_paths(col, settings, chains)
    step(f"{len(findings)} targeted service(s), {len(sources)} source(s) with detections, "
         f"{len(paths)} candidate path(s), {len(chains)} same-host chain(s)")

    changed = verify_unchanged(files)
    integrity = ("All input files re-hashed after processing; none changed." if not changed
                 else f"WARNING: these inputs changed during processing: {', '.join(changed)}")
    if changed:
        notices.append(integrity)

    routine = [d for d in col.detections if d.routine]
    coverage = scan_coverage + [
        f"{len(hosts)} host(s) in the Nessus scan; {len(col.index)} vulnerable service(s); "
        f"{len({f['target_ip'] for f in findings})} host(s) drew hostile behaviour.",
        f"{len(stats.dst_not_scanned)} destination IP(s) in the traffic were not in the scan (no vulnerability data).",
        f"{sum(1 for v in vulns if v.port == 0)} host-level vulnerability result(s) (port 0) used for chaining only.",
        f"{sum(1 for f in findings if f['scan_stale'])} finding(s) where the scan is more than "
        f"{settings.stale_days} days from the activity.",
        f"{stats.single_contact_sources:,} source(s) made a single connection and were not evaluated for scanning "
        "or brute force.",
    ]
    if settings.exclude_sources:
        coverage.append(f"{stats.excluded:,} record(s) from excluded sources ({', '.join(settings.exclude_sources)}) "
                        "were not analysed.")
    if routine:
        coverage.append(f"{len(routine)} brute-force pattern(s) from internal sources were treated as normal use "
                        "because many peers do the same (see the sources table).")
    if col.behaviour.ips_other:
        coverage.append(f"{col.behaviour.ips_other:,} firewall threat record(s) of other types (spyware, virus, "
                        "URL, file) are not attacks on a listening service and were not used.")
    for ef in files:
        if ef.source_type.endswith("_unsupported") or ef.source_type == "unsupported":
            coverage.append(f"Skipped {ef.rel_path}: not a supported source ({ef.source_type}).")
        if ef.records_skipped:
            coverage.append(f"{ef.rel_path}: {ef.records_skipped} malformed record(s) skipped (see data_quality.json).")

    manifest = [ef.to_dict() for ef in files]
    window = f"{ts(stats.first_ts)} to {ts(stats.last_ts)}" if stats.first_ts else "no traffic"
    ctx = {
        "case": str(case_dir), "version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "sources": [s for s in found if s == "nessus" or s in TRAFFIC_TYPES],
        "traffic_total": stats.total, "auth_total": stats.auth_records, "threat_total": stats.threat_records,
        "traffic_window": window, "vuln_services": len(col.index),
        "findings": findings, "hostile_sources": sources, "paths": paths, "chains": chains,
        "notices": notices, "coverage": coverage, "manifest": manifest, "integrity": integrity,
        "settings": settings.as_dict(),
    }

    svg = render(findings, paths, chains)
    (out_dir / "attack_paths.svg").write_text(svg, encoding="utf-8")
    write_html(out_dir / "report.html", ctx, svg)
    write_csv(out_dir / "findings.csv", findings)
    write_sources_csv(out_dir / "sources.csv", sources)
    write_json(out_dir / "findings.json", {
        "generated": ctx["generated"], "vulnpath_version": __version__, "settings": settings.as_dict(),
        "findings": findings, "hostile_sources": sources, "attack_paths": paths, "same_host_chains": chains})
    write_json(out_dir / "evidence_manifest.json", {"case": str(case_dir), "files": manifest,
                                                    "integrity_check": integrity})
    write_json(out_dir / "data_quality.json", {
        "coverage": coverage, "notices": notices,
        "per_file": [{"path": m["path"], "parser": m["parser"], "skipped": m["records_skipped"],
                      "issues": m["issues"]} for m in manifest],
        "processing_log": proc_log, "elapsed_seconds": round(time.time() - started, 2)})
    step(f"Done in {time.time() - started:.1f}s. Open {out_dir / 'report.html'}")
    return ctx
