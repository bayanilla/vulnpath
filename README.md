# Múcaro | VulnPath

**Which vulnerable hosts are actually being targeted, and where an attacker could go next.**

VulnPath compares a Nessus vulnerability scan with the network traffic your sensors
recorded. It shows which vulnerable services received traffic, whether that traffic
was blocked, attempted or established, and how an attacker could move from one
vulnerable host to the next. Analysts can then decide which hosts to examine first.

**AI-assisted proof of concept.** VulnPath is a local investigation aid for analysts.
It reads raw files you already have: Nessus exports, Zeek connection logs and Palo
Alto Networks Traffic and Threat logs. It never scans hosts, contacts the network or
sends data anywhere. Its findings are leads to validate. They do not establish that a
vulnerability was exploited or that a host is compromised.

## Contents

- [Start VulnPath](#start-vulnpath)
- [Prepare a case folder](#prepare-a-case-folder)
- [Review the report](#review-the-report)
- [Interpret and validate the findings](#interpret-and-validate-the-findings)
- [Save and share results](#save-and-share-results)
- [Evidence handling and practical limits](#evidence-handling-and-practical-limits)
- [Further documentation](#further-documentation)

## Start VulnPath

VulnPath needs Python 3.9 or later and nothing else. It uses only the Python standard
library, so there is nothing to `pip install` and nothing to bundle for an air-gapped
network. Copy the folder to the analyst workstation and run it.

**With the launcher window**

- **Windows:** double-click `Run VulnPath.bat`. The python.org installer includes
  everything the window needs.
- **Linux:** run `./run_vulnpath.sh`. The window needs your distribution's tkinter
  package: `python3-tk` on Debian or Ubuntu, `python3-tkinter` on RHEL or Rocky.

Choose the case folder and a results folder, adjust **Options** if needed, and select
**Run analysis**. When the run finishes, select **Open report**.

**From the command line**

```sh
python investigate.py --input <case folder> --output <results folder>
```

To try VulnPath without real data, run it on the bundled synthetic case:

```sh
python investigate.py -i samples/case_demo -o demo_results --threat-map samples/demo_threat_map.csv
```

Then open `demo_results/report.html` in a browser. The demo case contains fabricated
hosts, addresses and plugin IDs. Its CVEs and CVSS vectors are real, so the scenarios
behave realistically.

| Option | Default | Use it to |
| --- | --- | --- |
| `--internal CIDR ...` | RFC 1918 ranges | Name your internal networks. Other sources are treated as external. |
| `--pan-utc-offset HOURS` | `0` | Set the time zone of Palo Alto timestamps, for example `-5`. PAN-OS logs carry no zone. |
| `--threat-map CSV` | none | Supply a `threat_id,cve` list so IPS signatures can be matched to Nessus CVEs. |
| `--stale-days N` | `30` | Flag findings where the scan and the traffic are more than N days apart. |
| `--scan-threshold N` | `20` | Set how many distinct host:port pairs one source must contact to count as probing. |
| `--rules FILE` | `rules/known_chains.json` | Use a different list of published exploit chains. |

The launcher window offers the same options.

## Prepare a case folder

Put the original vendor exports in one folder. Subfolders are fine. Do not convert,
trim or re-save the files; VulnPath reads them as exported and identifies each file by
its content, not its name.

| Source | What to export | Role |
| --- | --- | --- |
| Nessus | `.nessus` (v2 XML) | **Required.** The list of vulnerable hosts and services. |
| Zeek | `conn.log`, TSV or JSON, plain or `.gz` | Observed connections. |
| Palo Alto | Traffic and Threat logs, as a web UI or Panorama CSV export, or raw syslog lines from a collector | Observed connections, firewall decisions, NAT and IPS detections. |

Provide Nessus plus at least one traffic source. Zeek and Palo Alto can be used
together. Palo Alto SYSTEM, CONFIG and other log types can stay in the folder; they are
counted and skipped. Files VulnPath does not recognise are listed in the report, not
silently ignored.

**Start small.** A day of traffic and the matching scan is enough to check that the
results make sense before running a larger case.

## Review the report

`report.html` is a single file that works offline. It needs no server and loads
nothing from the internet.

1. Read the **Summary** for the number of findings, established connections to
   vulnerable services, unblocked IPS detections, attack paths and chains. Check the
   notices beneath it; they say when a source is missing.
2. Use the **Attack-path diagram** to see how traffic reaches vulnerable hosts. Solid
   purple lines are hops on a candidate attack path, red lines are IPS detections, and
   dashed or dotted lines are attempts, probing or firewall denies. A red **CHAIN**
   badge marks a host with a same-host vulnerability chain. **Select a host** to focus
   the whole report on it; select it again to clear the focus.
3. Work through **Findings**, which are ranked by priority score. Search by IP,
   hostname, CVE or signature, filter by severity, activity, outcome or sensor, and
   sort any column. Select a row to highlight it in the diagram. Expand **why /
   evidence** to see how the score was built and which log lines support it.
4. Review **Candidate attack paths**: each hop lists the observed connection, its time
   range and the vulnerabilities on the target.
5. Review **Same-host vulnerability chains**: a published chain matched by CVE, such as
   ProxyShell, or an inferred chain of a remote entry flaw plus a privilege-escalation
   or post-authentication flaw on the same host.
6. Check **Coverage and data quality** for scanned hosts with no traffic, traffic to
   unscanned hosts, stale scans, skipped files and malformed lines.

## Interpret and validate the findings

Treat each finding as a precise question for the asset owner or incident responder:

> Traffic from this source reached this service, which the scan reports as vulnerable,
> at these times. Was the service patched or protected, and do the host's own logs show
> anything after that connection?

**Worked example:** in the demo case, an external address made established HTTPS
connections to web01, and an IPS signature for the same CVE that Nessus reported fired
without being blocked. web01 then connected to app02 over SMB, where Nessus reports
MS17-010. Give the responder the finding IDs, the time range and the evidence lines.
They can check web01's web-server and endpoint logs from that window and then decide
whether app02 needs the same review.

What the activity labels mean:

| Label | Meaning | What it does not mean |
| --- | --- | --- |
| **exploit-attempt** | An IPS vulnerability signature fired against the vulnerable service. | It does not mean the exploit succeeded, even when not blocked. |
| **targeting**, established | A session completed with the vulnerable service. | A completed connection is reachability, not exploitation. |
| **targeting**, attempted | Connections were tried but no session completed. | |
| **denied** | The firewall refused the connections. | |
| **probing** | The source contacted many hosts and ports, or the firewall flagged a scan. | Probing is broad and is not aimed at this service in particular. |

A **candidate attack path** follows established connections, or unblocked IPS
detections, into vulnerable services in time order. It shows where an attacker *could*
have gone. It does not show that anyone did. An **inferred chain** is based on each
vulnerability's access requirements from its CVSS vector; VulnPath does not verify that
the first flaw gives the access the second one needs. A **published chain** carries
more weight because the combination is documented.

A **stale scan** warning means the scan and the traffic are far apart in time, so the
host may have been patched or changed. Unfamiliar results warrant validation, not an
automatic incident declaration or blocking decision.

## Save and share results

Each run writes these files to the results folder:

| File | Contents |
| --- | --- |
| `report.html` | The interactive report. Print it or save it as PDF from the browser for a static copy. |
| `attack_paths.svg` | The diagram on its own, for slides and documents. |
| `findings.csv` | One row per source and vulnerable service. Opens in Excel. |
| `findings.json` | Findings, attack paths and chains with evidence and scoring reasons, for other tools. |
| `evidence_manifest.json` | Every input file with its SHA-256 hash, detected type, parser version and record counts. |
| `data_quality.json` | Coverage gaps, skipped files, malformed lines and the processing log. |

In the report, **Download CSV (filtered)** saves only the findings that match the
current search and filters.

Every finding cites its evidence as `file [hash prefix] line N` together with the Nessus
`ReportHost / plugin / port`, so a reviewer can go back to the original record.

## Evidence handling and practical limits

| Consideration | What to expect |
| --- | --- |
| Original files | Opened read-only, hashed with SHA-256 before and after the run, and never modified. The results folder must be outside the case folder. Hashing supports integrity checks; it is not by itself a complete chain of custody. |
| Network use | None. VulnPath makes no network connections and the report loads nothing from the internet. |
| Host identity | Hosts are matched by IP address. Palo Alto inbound NAT is resolved to the internal address Nessus scanned. DHCP changes and overlapping address ranges are not resolved. |
| Time zones | Zeek timestamps are UTC. Palo Alto timestamps have no zone and are read with `--pan-utc-offset`; a wrong offset can reorder attack-path hops. |
| Overlapping sensors | When Zeek and the firewall see the same sessions, counts are not added together. The report shows the larger single-sensor count and a per-sensor breakdown. |
| Palo Alto formats | Syslog lines are read by documented PAN-OS field position. Check a sample line from each of your collection points. CEF and LEEF from a SIEM are not supported yet. |
| IPS to CVE matching | Threat logs carry a Threat ID, not a CVE. Without `--threat-map`, IPS detections are matched to vulnerabilities by port only. |
| Size | Logs are streamed line by line, so memory grows with the number of source-to-vulnerable-service pairs, not with log size. Large cases have not been benchmarked yet. The diagram shows at most 40 hosts, and attack paths are capped at 4 hops and 50 paths. |
| Not yet supported | Xpanse exposure data, Zeek logs other than `conn.log`, and CEF/LEEF input. |

Review sensitive inputs before sharing a report. VulnPath does not encrypt its output,
and reports contain internal addresses, hostnames and vulnerability details.

## Further documentation

- [Methods and decision rules](METHODS.md): how traffic is classified, matched and
  scored, how paths and chains are built, and how to add a published chain.
- [Development and verification](DEVELOPMENT.md): code layout, tests and the demo case.
