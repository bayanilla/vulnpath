# VulnPath development and verification

## Code layout

| Path | Responsibility |
| --- | --- |
| `investigate.py` | Command-line entry point. |
| `launcher.py` | tkinter launcher window. `Run VulnPath.bat` and `run_vulnpath.sh` start it. |
| `vulnpath/evidence.py` | Finds and hashes input files, and re-checks the hashes after the run. |
| `vulnpath/detect.py` | Identifies each file's source type from its content. |
| `vulnpath/parsers/` | One streaming parser per source: `nessus.py`, `zeek.py`, `paloalto.py`. |
| `vulnpath/model.py` | Normalised records: connections, threat detections, vulnerabilities, hosts. |
| `vulnpath/correlate.py` | Matches traffic to vulnerable services, classifies it and scores findings. |
| `vulnpath/chains.py` | Same-host chains and candidate attack paths. |
| `vulnpath/diagram.py` | Pure-Python SVG diagram. |
| `vulnpath/report.py` | HTML, CSV and JSON output, including the report's interactive script. |
| `vulnpath/pipeline.py` | Runs the steps end to end. Used by both the command line and the launcher. |
| `rules/known_chains.json` | Published exploit chains. |
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
integrity and deterministic output. They also cover the scenarios that must **not**
produce a finding or a path:

- a vulnerability on a different port from the observed traffic
- attempts that never established a session
- connections in the wrong time order for a path
- a stale scan
- missing traffic sources
- sessions seen by both Zeek and the firewall, which must not be double counted

Palo Alto coverage includes syslog and header-CSV detection, NAT, blocked and unblocked
IPS detections, the time-zone offset and runs with Palo Alto data only.

## Demo case

`samples/case_demo` is committed so the tool can be tried immediately. To rebuild it
after changing the generator:

```sh
python samples/make_demo_case.py
```

All addresses, hostnames, plugin IDs and Palo Alto threat IDs in it are fabricated.
CVE IDs and CVSS vectors are real.

## Verification limits

- Parsers have been checked against documented formats and synthetic data only. Real
  exports from each collection point should be checked before results are relied on.
- Performance on large cases has not been benchmarked.
