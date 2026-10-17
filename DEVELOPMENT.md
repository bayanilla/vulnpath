# VulnPath development and verification

## Code layout

| Path | Responsibility |
| --- | --- |
| `investigate.py` | Command-line entry point. |
| `launcher.py` | tkinter launcher window. `Run VulnPath.bat` and `run_vulnpath.sh` start it. |
| `assets/` | Múcaro M app icon: `mucaro-mark.svg` (source, same as Pathfinder), PNGs for Tk and `vulnpath.ico` for Windows. `install_linux_shortcut.sh` adds a Linux menu entry that uses it. |
| `vulnpath/evidence.py` | Finds and hashes input files, and re-checks the hashes after the run. |
| `vulnpath/detect.py` | Identifies each file's source type from its content. |
| `vulnpath/parsers/` | One streaming parser per source: `nessus.py`, `zeek.py` (conn, ssh, ntlm, kerberos), `paloalto.py`. |
| `vulnpath/model.py` | Normalised records: connections, login results, threat detections, vulnerabilities, hosts. |
| `vulnpath/behavior.py` | Detects sweeps, port scans, brute force, failed logins and IPS verdicts per source and time window. |
| `vulnpath/correlate.py` | Streams every record once, joins the detections to the scan, and scores the targeted services. |
| `vulnpath/chains.py` | Same-host chains and candidate attack paths, both gated by detected behaviour. |
| `vulnpath/diagram.py` | Pure-Python SVG diagram. |
| `vulnpath/report.py` | HTML, CSV and JSON output, including the report's interactive script. |
| `vulnpath/pipeline.py` | Runs the steps end to end. Used by both the command line and the launcher. |
| `vulnpath/intel.py` | ATT&CK techniques per detection and matches against threat reports. |
| `rules/known_chains.json` | Published exploit chains. |
| `rules/threat_intel.json` | Recent threat reports and the detectable TTPs in them (see INTEL.md). |
| `samples/` | Synthetic demo case, its generator and a demo threat map. |

The analysis engine does not depend on where files come from or where results go, so
it can later run as a batch job in a container without changes to the correlation
logic.

## Tests

```sh
python -m unittest discover -s tests -v
```

The tests use only the standard library. They build the synthetic case in a temporary
folder and check parsing, content-based detection, gzip input, DTD rejection, evidence
integrity and deterministic output. They also cover the scenarios that must **not** produce a finding:

- 40 workstations using a vulnerable SMB service all day
- a user browsing a host whose vulnerability is on another port
- eight workstations whose logon traffic matches the brute-force pattern (routine)
- the organisation's own vulnerability scanner, once excluded
- a vulnerability that an older scan reports but the newest scan does not
- a scan that found an open port, which must not start an attack path
- connections in the wrong time order for a path
- Kerberos pre-authentication requests, which are part of every normal logon
- a cumulative-update plugin that would otherwise make every Windows host chainable

A separate noisy-network test builds 120 workstations, a domain controller, a file
server, a management server and one attacker sweeping SMB. Only the attacker may appear.

Palo Alto coverage includes syslog and header-CSV detection, NAT, blocked and unblocked
IPS detections, brute-force signatures and repeat counts, session-start entries, the
time-zone offset and runs with Palo Alto data only.

## Demo case

`samples/case_demo` is committed so the tool can be tried immediately. To rebuild it
after changing the generator:

```sh
python samples/make_demo_case.py
```

All addresses, hostnames, plugin IDs and Palo Alto threat IDs in it are fabricated.
CVE IDs and CVSS vectors are real. Run it with `--exclude-sources 10.0.0.250`, the
demo's own vulnerability scanner; without that option the scanner shows up as a
hostile source, which is also worth seeing once.

## Verification limits

- Parsers have been checked against documented formats and synthetic data only. Real
  exports from each collection point should be checked before results are relied on.
- Performance has been measured on synthetic data only: a 3-million-line Zeek log with a
  million distinct internet sources took about 80 seconds and 2 GB of memory. Real logs
  from your sensors should be timed before a large case is run.
- Detection thresholds are starting points. Check them against a day of your own
  traffic before relying on them.
