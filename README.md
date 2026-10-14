# VulnPath (POC)

**Which vulnerable hosts are actually being targeted, and where an attacker could go next.** An offline tool that correlates raw network telemetry with Nessus scans.

Point it at a folder of **raw** files: a Nessus scan plus whatever traffic you have (Zeek and/or Palo Alto). It reports:

- which vulnerable hosts were **targeted** on a vulnerable port, and whether the traffic was **established**, only **attempted**, **denied** by the firewall, or part of **scan-like probing**
- **possible exploit attempts**, when a Palo Alto IPS signature fired against a vulnerable service, and whether the firewall blocked it
- **candidate attack paths** across hosts, following observed connections in time order (for example external → web01 → app02)
- **same-host vulnerability chains**, either a published chain matched by CVE (such as ProxyShell) or a generic one (an unauthenticated remote flaw plus a privilege-escalation or post-auth flaw on the same host)

Everything is a hypothesis with evidence attached. Nothing in the output claims exploitation.

## Requirements

- Python 3.9 or newer. Tested on 3.11 and 3.13.
- **No third-party packages.** It uses the standard library only, so there is nothing to `pip install` and nothing to vendor for an air-gapped network. Copy the folder and run it.
- Windows, Linux or macOS.

## Run with the launcher window (no command line)

- **Windows:** double-click `Run VulnPath.bat`.
- **Linux:** `./run_vulnpath.sh`. This needs the OS tkinter package: `python3-tk` on Debian/Ubuntu, or `python3-tkinter` on RHEL/Rocky.

In the window, pick the case folder, set any options, and click **Run analysis**. Then click **Open report**. The launcher uses Python's built-in tkinter, so there is still nothing to pip install.

## Interactive report

`report.html` is still a single offline file, with no CDN and no server. In a browser, it lets you:

- search across IPs, hostnames, CVEs and IPS signatures
- filter by severity, activity, outcome, telemetry source and external-only, then sort any column
- **click a host in the diagram** to focus the whole report on it. Its findings and paths stay, and everything else fades.
- click a finding or attack path to highlight it in the diagram
- download the currently filtered findings as CSV

When printed, or opened with JavaScript disabled, it shows the full static report.

## Run from the command line

```
python investigate.py --input <case folder> --output <results folder>
```

To try it on the bundled synthetic case:

```
python samples/make_demo_case.py          # (re)creates samples/case_demo
python investigate.py -i samples/case_demo -o demo_results --threat-map samples/demo_threat_map.csv
```

Then open `demo_results/report.html` in any browser. It works offline: no CDN, and the diagram is inline SVG.

| Option | Default | Meaning |
|---|---|---|
| `--internal CIDR ...` | RFC1918 | Your internal ranges. Anything outside them counts as external. |
| `--scan-threshold N` | 20 | Distinct host:port pairs from one source before it counts as probing. |
| `--stale-days N` | 30 | Flags findings where the scan and the traffic are more than N days apart. |
| `--pan-utc-offset H` | 0 | Time zone of Palo Alto timestamps, in hours from UTC (e.g. `-5`). PAN-OS logs carry no zone. |
| `--threat-map CSV` | none | `threat_id,cve` list so IPS signatures can be matched to Nessus CVEs. Without it, matching is by port. |
| `--rules FILE` | `rules/known_chains.json` | List of published exploit chains. |

## Supported inputs

Files are detected by **content**, not by name.

| Source | Format | Status |
|---|---|---|
| Nessus | `.nessus` v2 XML | Supported (required for vulnerability correlation) |
| Zeek | `conn.log` TSV or JSON, plain or `.gz` | Supported |
| Palo Alto | Traffic and Threat logs: Web UI/Panorama CSV export (header row), or raw syslog CSV from a collector (with or without the `<PRI>` prefix, mixed log types OK) | Supported. SYSTEM/CONFIG and other log types are counted and skipped. CEF/LEEF from a SIEM is not supported yet. |
| Cortex Xpanse | CSV/JSON export | After Palo Alto. Adds "exposed to the internet" context, not traffic. |

Unsupported files are listed in the report and skipped. Originals are opened read-only, hashed with SHA-256 before and after the run, and never written to. The output folder must be outside the case folder.

## Outputs

| File | Contents |
|---|---|
| `report.html` | Summary, diagram, attack paths, chains, findings, coverage, evidence manifest, limitations |
| `attack_paths.svg` | The diagram on its own, for slides |
| `findings.csv` | One row per source → vulnerable service. Opens in Excel. |
| `findings.json` | Findings, attack paths and chains, with evidence and scoring reasons |
| `evidence_manifest.json` | Every input file with its SHA-256, detected type, parser and record counts |
| `data_quality.json` | Malformed lines, skipped files, coverage gaps, processing log |

Every finding points back to `file [sha256 prefix] line N uid ...` and to the Nessus `ReportHost / plugin / port`.

## How decisions are made

All rules are deterministic, with no AI in the analysis.

- **Match:** traffic destination IP + port + protocol equals a Nessus result. Host-level results (port 0, such as local privilege escalation) are never matched to traffic. They are used only for chaining.
- **Outcome (Zeek `conn_state`):** SF/S1/S2/S3/RSTO/RSTR count as established. S0/REJ/SH/... count as attempted.
- **Outcome (Palo Alto Traffic):** `allow` with bytes received counts as established. `allow` with no reply counts as attempted. deny/drop/reset counts as denied.
- **Palo Alto NAT:** when a NAT destination is logged, matching uses the translated (internal) address the scanner saw. The public address is kept as "via NAT".
- **Palo Alto Threat:** a `vulnerability`-type detection on a vulnerable service is a possible exploit attempt. `alert`/`allow` means not blocked. Anything else means blocked. A `scan` detection counts as probing. A CVE match comes from the threat map or from a CVE in the signature text.
- **Probing:** the source touched at least `--scan-threshold` distinct host:port pairs.
- **Attack path:** follows only *established* connections or *unblocked* IPS detections into vulnerable services. A hop X → Y counts only if it happened at or after the time X was first reached. Depth is capped at 4 and the number of paths at 50.
- **Vulnerability stage:** taken from the CVSS vector. AV:N with PR:N is a remote, no-credential entry point. AV:N with PR:L/H needs a foothold. AV:L is local, i.e. privilege escalation.
- **Priority score:** severity, established traffic, external source, public exploit, being a hop on an attack path, and having a same-host chain all add points. Scan-like probing and a stale scan subtract. Each finding lists its reasons.

## Adding a published chain

Add an entry to `rules/known_chains.json` with the CVEs from the advisory and `min_match` (how many of them must be present on one host).

## Tests

```
python -m unittest discover -s tests -v
```

35 tests cover parsing, content-based detection, gzip input, DTD rejection, evidence integrity, and these negative cases: a vulnerability on a different port, attempts that never connected, connections in the wrong time order, a stale scan, and missing traffic. They also cover the Palo Alto cases: syslog and header-CSV detection, NAT, blocked and unblocked IPS detections, the time-zone offset, and runs with Palo Alto only. Under Python 3.11 and 3.13, all 35 pass.

## Known limitations (POC)

- Hosts are matched by IP. Palo Alto inbound NAT is handled, but DHCP changes and overlapping address ranges are not.
- Palo Alto syslog fields are read by documented PAN-OS position (fields 0-46). This should be checked against a sample from your firewalls.
- Threat logs carry a Threat ID, not a CVE. Without a threat map, IPS detections are matched to vulnerabilities by port only.
- Chains are inferred from CVSS and the rules file. Whether one flaw really grants the access the next one needs has not been verified.
- When Zeek and the firewall both see the same sessions, counts are not added together. The report shows the largest single-sensor count, plus a per-sensor breakdown.
- Only Zeek `conn.log` is used. `http`, `ssl` and `notice` logs could later add payload-level evidence.
- The demo data is synthetic. The CVEs and CVSS vectors are real, but the IPs, hosts and plugin IDs are made up.
