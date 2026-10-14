"""End-to-end run: inventory -> detect -> parse -> correlate -> chain -> report."""
from __future__ import annotations

import itertools
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .chains import attack_paths, load_known_chains, same_host_chains
from .correlate import Settings, build_findings, correlate
from .detect import detect
from .diagram import render
from .evidence import inventory, verify_unchanged
from .parsers import nessus, paloalto, zeek
from .report import ts, write_csv, write_html, write_json

TRAFFIC_PARSERS = {"zeek_conn": zeek.parse, "paloalto": paloalto.parse}
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "known_chains.json"


class InputError(Exception):
    pass


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
    traffic_files = [ef for ef in files if ef.source_type in TRAFFIC_PARSERS]
    if not nessus_files:
        notices.append("No Nessus (.nessus) file was found, so no vulnerability correlation was possible.")
    if not traffic_files:
        notices.append("No supported traffic logs (Zeek conn.log or Palo Alto Traffic/Threat) were found, "
                       "so no network activity was analysed.")

    hosts: dict = {}
    vulns = []
    for ef in nessus_files:
        step(f"Parsing Nessus: {ef.rel_path}")
        try:
            vulns.extend(nessus.parse(ef, hosts))
        except ValueError as e:
            ef.issues.append(str(e))
            notices.append(f"{ef.rel_path} was not parsed: {e}")
    step(f"{len(vulns)} vulnerability result(s) (severity Low+) on {len(hosts)} host(s)")

    threat_map = paloalto.load_threat_map(Path(settings.threat_map)) if settings.threat_map else {}
    if settings.threat_map and not threat_map:
        notices.append(f"Threat map {settings.threat_map} was empty or not found; IPS signatures are matched by port only.")

    def all_conns():
        for ef in traffic_files:
            step(f"Streaming traffic: {ef.rel_path}")
            if ef.source_type == "paloalto":
                yield from paloalto.parse(ef, settings.pan_utc_offset, threat_map)
            else:
                yield from TRAFFIC_PARSERS[ef.source_type](ef)

    joined, stats = correlate(all_conns(), vulns, hosts, settings)
    index, touches = joined["index"], joined["touches"]
    step(f"{stats.total:,} connection(s) analysed; {len(touches)} source→vulnerable-service pair(s)")

    known = load_known_chains(rules_path)
    chains = same_host_chains(vulns, known, touches)
    paths = attack_paths(touches, index, hosts, chains, settings)
    hops = {(h["from"], h["to"], h["port"], h["protocol"]) for p in paths for h in p["hops"]}
    findings = build_findings(touches, index, hosts, stats, settings, {c["host"] for c in chains}, hops)
    step(f"{len(findings)} finding(s), {len(paths)} candidate path(s), {len(chains)} same-host chain(s)")

    changed = verify_unchanged(files)
    integrity = ("All input files re-hashed after processing; none changed." if not changed
                 else f"WARNING: these inputs changed during processing: {', '.join(changed)}")
    if changed:
        notices.append(integrity)

    scanned_seen = len({t.dst for t in touches.values()})
    coverage = [
        f"{len(hosts)} host(s) in the Nessus scan; {scanned_seen} of them received traffic on a vulnerable port.",
        f"{len(stats.dst_not_scanned)} destination IP(s) in the traffic were not in the scan (no vulnerability data).",
        f"{sum(1 for v in vulns if v.port == 0)} host-level vulnerability result(s) (port 0) used for chaining only.",
        f"{sum(1 for f in findings if f['scan_stale'])} finding(s) where the scan is more than "
        f"{settings.stale_days} days from the traffic.",
    ]
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
        "sources": [s for s in found if s in ("nessus",) or s in TRAFFIC_PARSERS],
        "traffic_total": stats.total, "traffic_window": window,
        "vuln_services": len(index), "findings": findings, "paths": paths, "chains": chains,
        "notices": notices, "coverage": coverage, "manifest": manifest, "integrity": integrity,
    }

    svg = render(findings, paths, chains)
    (out_dir / "attack_paths.svg").write_text(svg, encoding="utf-8")
    write_html(out_dir / "report.html", ctx, svg)
    write_csv(out_dir / "findings.csv", findings)
    write_json(out_dir / "findings.json", {
        "generated": ctx["generated"], "vulnpath_version": __version__, "settings": {
            "internal_networks": settings.internal_networks, "scanner_threshold": settings.scanner_threshold,
            "stale_days": settings.stale_days, "pan_utc_offset": settings.pan_utc_offset,
            "threat_map": settings.threat_map},
        "findings": findings, "attack_paths": paths, "same_host_chains": chains})
    write_json(out_dir / "evidence_manifest.json", {"case": str(case_dir), "files": manifest,
                                                    "integrity_check": integrity})
    write_json(out_dir / "data_quality.json", {
        "coverage": coverage, "notices": notices,
        "per_file": [{"path": m["path"], "parser": m["parser"], "skipped": m["records_skipped"],
                      "issues": m["issues"]} for m in manifest],
        "processing_log": proc_log, "elapsed_seconds": round(time.time() - started, 2)})
    step(f"Done in {time.time() - started:.1f}s. Open {out_dir / 'report.html'}")
    return ctx
