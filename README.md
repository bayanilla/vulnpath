# Múcaro | VulnPath

**Which vulnerable systems are being targeted, so you can fix those first.**

VulnPath looks for hostile behaviour in the network traffic your sensors recorded:
scanning and reconnaissance, brute-force and password-spraying attempts, and exploit
attempts caught by the firewall's IPS. It then checks those targets against a Nessus
vulnerability scan and ranks the vulnerable services that drew the attention, so
analysts know which systems to remediate or examine first. Ordinary use of a vulnerable
service, such as workstations talking to a domain controller, is not a finding.

**AI-assisted proof of concept.** VulnPath is a local investigation aid for analysts.
It reads raw files you already have: Nessus exports, Zeek connection and login logs,
and Palo Alto Networks Traffic and Threat logs. It never scans hosts, contacts the network or
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
  To add VulnPath to the application menu with its icon, run `./install_linux_shortcut.sh`
  once (per user, no root).
- **macOS:** run `./run_vulnpath.sh`. The python.org installer includes tkinter.

The window, taskbar and Dock show the Múcaro M icon from `assets/`.

Choose the case folder and a results folder, adjust **Options** if needed, and select
**Run analysis**. When the run finishes, select **Open report**.

**From the command line**

```sh
python investigate.py --input <case folder> --output <results folder>
```

To try VulnPath without real data, run it on the bundled synthetic case:

```sh
python investigate.py -i samples/case_demo -o demo_results --threat-map samples/demo_threat_map.csv --exclude-sources 10.0.0.250
```

Then open `demo_results/report.html` in a browser. The demo case contains fabricated
hosts, addresses and plugin IDs. Its CVEs and CVSS vectors are real, so the scenarios
behave realistically.

| Option | Default | Use it to |
| --- | --- | --- |
| `--exclude-sources CIDR ...` | none | Ignore your own vulnerability scanners, admin, backup and monitoring hosts. Without this they will be the top "scanners" in every case. |
| `--internal CIDR ...` | RFC 1918 ranges | Name your internal networks. Other sources are treated as external. |
| `--window MINUTES` | `15` | Set the time window that scans and login attempts are counted in. |
| `--sweep-hosts N` | `20` | Set how many hosts on one port, mostly failing, make a sweep. |
| `--portscan-ports N` | `15` | Set how many ports on one host, mostly failing, make a port scan. |
| `--brute-attempts N` | `10` | Set how many short, repetitive connections to one login service make a brute-force pattern. |
| `--auth-failures N` | `5` | Set how many failed logins in Zeek's login logs make a brute-force detection. |
| `--pan-utc-offset HOURS` | `0` | Set the time zone of Palo Alto timestamps, for example `-5`. PAN-OS logs carry no zone. |
| `--threat-map CSV` | none | Supply a `threat_id,cve` list so IPS signatures can be matched to Nessus CVEs. |
| `--stale-days N` | `30` | Flag findings where the scan and the activity are more than N days apart. |
| `--rules FILE` | `rules/known_chains.json` | Use a different list of published exploit chains. |
| `--intel FILE` | `rules/threat_intel.json` | Use a different list of threat-intelligence reports. |

The launcher window offers the most common options: internal networks, sources to
ignore, the detection window, the Palo Alto time zone, the threat map and the stale-scan
limit.

## Prepare a case folder

Put the original vendor exports in one folder. Subfolders are fine. Do not convert,
trim or re-save the files; VulnPath reads them as exported and identifies each file by
its content, not its name.

| Source | What to export | Role |
| --- | --- | --- |
| Nessus | `.nessus` (v2 XML) | **Required.** The list of vulnerable hosts and services. Several exports can go in one case; each host's most recent scan is used. |
| Zeek | `conn.log`, TSV or JSON, plain or `.gz` | Connections: scans and brute-force patterns. |
| Zeek | `ssh.log`, `ntlm.log`, `kerberos.log` | Login results: failed logins, password spraying, and a success after failures. Strongly recommended. |
| Palo Alto | Traffic and Threat logs, as a web UI or Panorama CSV export, or raw syslog lines from a collector | Connections, firewall decisions, NAT, and IPS exploit, brute-force and scan detections. |

Provide Nessus plus at least one traffic source. Zeek and Palo Alto can be used
together. Palo Alto SYSTEM, CONFIG and other log types can stay in the folder; they are
counted and skipped. Files VulnPath does not recognise are listed in the report, not
silently ignored.

**Start small.** A day of traffic and the matching scan is enough to check that the
results make sense before running a larger case.

## Review the report

`report.html` is a single file that works offline. It needs no server and loads
nothing from the internet.

Use the **Theme** menu at the top right to switch between Classic Light and the Múcaro
themes (SOC Dark, Nord Calm, High Contrast, Matrix, Mucaro Dusk, Field Notebook and
Terminal Amber). The choice is remembered in that browser. Printed copies always use
Classic Light.

1. Read the **Summary** for the number of targeted vulnerable services, possible login
   successes, unblocked IPS detections and hostile sources. Check the notices beneath it;
   they say when a source is missing, for example when no Zeek login logs were supplied.
2. Use the **Hostile activity diagram** to see who targeted what. Purple lines are
   failed logins followed by a success, red lines are IPS detections (dashed when
   blocked), orange lines are brute force, grey dashed lines are scans, and black lines
   are onward connections from a host that was reached. A red **CHAIN** badge marks a
   host with a same-host vulnerability chain. **Select a host** to focus the whole
   report on it; select it again to clear the focus.
3. Work through **Remediation priorities**. Each row is one service that drew hostile
   behaviour, ranked by how strong the behaviour is and how serious the vulnerability
   is. Search and filter by severity, behaviour, contact, external sources or possible
   login success. Expand **why / evidence** to see how the score was built and which log
   lines support it.
4. Review **Hostile sources**: every source with a detection, what it did and how many
   of its targets were vulnerable. Sources marked *routine* matched the brute-force
   pattern but behave like many internal peers, so they produce no finding.
5. Review **Candidate attack paths**: a hostile source that got through to a host,
   followed by that host's later connections to other vulnerable services.
6. Review **Same-host vulnerability chains**: a published chain matched by CVE, such as
   ProxyShell, or an inferred chain where hostile activity reached a way into the host
   and the host also has a flaw that needs a foothold, such as a privilege escalation.
7. Check **Coverage and data quality** for sources that were ignored or treated as
   routine, single-contact sources, stale scans, skipped files and malformed lines.

## Interpret and validate the findings

Treat each finding as a precise question for the asset owner or incident responder:

> This source scanned, attacked or tried to log in to this service, which the scan
> reports as vulnerable, at these times. Was the service patched or protected, and do the
> host's own logs show anything after that activity?

**Worked example:** in the demo case, an external address made 120 failed SSH logins to
web01 and then logged in successfully, followed by a 30-minute session. web01's SSH
server is vulnerable to regreSSHion, and the host also has a local privilege escalation
(PwnKit). That is the top finding. Give the responder the finding ID, the time range
and the evidence lines. They can check web01's authentication logs for the account that
logged in and what it did next.

What the behaviour labels mean:

| Label | Meaning | What it does not mean |
| --- | --- | --- |
| **IPS exploit** | A firewall IPS vulnerability signature fired against the service. | It does not mean the exploit succeeded, even when not blocked. |
| **failed logins** | Zeek's login logs show repeated failures from one source in a window. Many user names means password spraying. | A later success may be a legitimate user; check the account. |
| **IPS brute force** | A firewall brute-force signature fired. | |
| **brute force** | Many short, repetitive connections to a login service, from conn.log or firewall traffic. A pattern, not a login result. | |
| **port scan** | One source tried many ports on this host, most of them failing. | |
| **sweep** | One source tried many hosts on this port, most of them failing. | A sweep is broad and is not aimed at this service in particular. |
| **firewall scan** | The firewall's scan protection flagged the source. | |
| **possible login success** | A successful login, or a long session, followed the failures from the same source. | It is not proof of compromise, but it is the strongest lead VulnPath gives. |

A **candidate attack path** shows where an attacker *could* have gone after getting
through. It does not show that anyone did. An **inferred chain** is based on each
vulnerability's access requirements from its CVSS vector; VulnPath does not verify that
the first step gives the access the second one needs. A **published chain** carries
more weight because the combination is documented.

A **stale scan** warning means the scan and the activity are far apart in time, so the
host may have been patched or changed. Unfamiliar results warrant validation, not an
automatic incident declaration or blocking decision.

## Save and share results

Each run writes these files to the results folder:

| File | Contents |
| --- | --- |
| `report.html` | The interactive report. Print it or save it as PDF from the browser for a static copy. |
| `attack_paths.svg` | The diagram on its own, for slides and documents. |
| `findings.csv` | One row per targeted service, in priority order. Opens in Excel. |
| `sources.csv` | One row per source with a detection, including routine ones. |
| `findings.json` | Findings, hostile sources, attack paths and chains with evidence and scoring reasons, for other tools. |
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
| Thresholds | Scans and brute force are counted in fixed windows (15 minutes by default). A slow scan spread over hours stays under the thresholds. Tune `--window` and the thresholds to your environment. |
| Routine traffic | When five or more internal sources show the same brute-force pattern against one service, those within 3x the median are treated as normal use. External sources are never suppressed. |
| Host identity | Hosts are matched by IP address. Palo Alto inbound NAT is resolved to the internal address Nessus scanned. DHCP changes and overlapping address ranges are not resolved. |
| Time zones | Zeek timestamps are UTC. Palo Alto timestamps have no zone and are read with `--pan-utc-offset`; a wrong offset can reorder attack-path hops. |
| Overlapping sensors | When Zeek and the firewall see the same sessions, counts are not added together. The report shows the larger single-sensor count and a per-sensor breakdown. |
| Palo Alto formats | Syslog lines are read by documented PAN-OS field position. Check a sample line from each of your collection points. CEF and LEEF from a SIEM are not supported yet. |
| IPS to CVE matching | Threat logs carry a Threat ID, not a CVE. Without `--threat-map`, IPS detections are matched to vulnerabilities by port only. |
| Login results | Without Zeek `ssh.log`, `ntlm.log` or `kerberos.log`, brute force is a connection pattern only. RDP logins are not visible to Zeek once encrypted. |
| Size | Logs are streamed line by line. Memory grows with the number of distinct sources and time windows, not with log size; a source seen only once is stored compactly. On a synthetic 3-million-line Zeek log with a million distinct internet sources, a run took about 80 seconds and 2 GB of memory. The report shows the top 1,000 findings and 500 sources; the CSV and JSON files hold all of them. The diagram shows at most 40 hosts, and attack paths are capped at 4 hops and 50 paths. |
| Not yet supported | Xpanse exposure data, Zeek logs other than conn, ssh, ntlm and kerberos, and CEF/LEEF input. |

Review sensitive inputs before sharing a report. VulnPath does not encrypt its output,
and reports contain internal addresses, hostnames and vulnerability details.

## Further documentation

- [Methods and decision rules](METHODS.md): how behaviour is detected, matched to the
  scan and scored, how paths and chains are built, and how to add a published chain.
- [Threat intelligence rules](INTEL.md): ATT&CK techniques, recent threat reports and
  the weekly update that adds them.
- [Development and verification](DEVELOPMENT.md): code layout, tests and the demo case.
