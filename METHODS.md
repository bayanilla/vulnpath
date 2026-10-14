# VulnPath methods and decision rules

All analysis rules are deterministic. The same inputs and options always produce the
same findings, and no AI model is involved in the analysis.

## Matching traffic to vulnerabilities

- A finding is created when a traffic record's destination IP, port and protocol match
  a Nessus result of severity Low or higher. Informational results are ignored.
- Host-level Nessus results (port 0, such as a local privilege escalation) are never
  matched to traffic. They are used only to build same-host chains.
- Records are grouped by source IP and vulnerable service, so one finding covers all
  traffic from one source to one service.
- When Palo Alto logs a NAT destination, matching uses the translated internal address
  and port, which is what Nessus scanned. The public address is kept as "via NAT".

## Classifying traffic

| Source | Established | Attempted | Denied |
| --- | --- | --- | --- |
| Zeek `conn.log` (TCP) | `conn_state` SF, S1, S2, S3, RSTO or RSTR | Any other state, such as S0, REJ or SH | Not applicable |
| Zeek `conn.log` (UDP, ICMP) | Bytes returned by the responder, or `conn_state` SF | No reply | Not applicable |
| Palo Alto Traffic | `allow` with bytes received | `allow` with no bytes received | `deny`, `drop` or `reset-*` |

- **Palo Alto Threat logs** are not counted as connections. A `vulnerability` detection
  against a vulnerable service makes the finding an **exploit-attempt**. An action of
  `alert` or `allow` means not blocked; any other action means blocked. A `scan`
  detection marks the source as probing.
- **CVE match for IPS signatures** comes from the `--threat-map` CSV or from a CVE ID
  written in the signature name. Without either, the detection is matched by port only
  and the finding says so.
- **Probing:** a source that contacted at least `--scan-threshold` distinct host:port
  pairs, or that the firewall flagged with a scan detection.
- **Overlapping sensors:** counts are kept per sensor. The combined figure is the
  largest single-sensor count, never the sum, because Zeek and the firewall usually see
  the same sessions.

## Priority score

Each finding starts from its highest vulnerability severity and gains or loses points
for the evidence around it. Every finding lists its reasons in the report.

| Factor | Points |
| --- | --- |
| Severity Critical / High / Medium / Low | +40 / +30 / +15 / +5 |
| Established connection to the vulnerable service | +20 |
| Attempts only | +5 |
| IPS signature matches the scanned CVE | +25 |
| IPS signature on the service, CVE not matched | +10 |
| IPS detection not blocked | +10 |
| Source outside the internal networks | +10 |
| Public exploit available (Nessus) | +15 |
| Connection is a hop on a candidate attack path | +10 |
| Target host has a same-host chain | +10 |
| Scan-like probing | −15 |
| Scan more than `--stale-days` from the traffic | −10 |

The score orders the work; it is not a probability or a confidence level.

## Candidate attack paths

- Edges are established connections, or unblocked IPS detections, into vulnerable
  services.
- Paths start at external sources, or at internal sources that nothing else reached.
- A hop from X to Y is chained only if it was seen at or after the first time X was
  reached, so connections that happened earlier do not create a path.
- Depth is capped at 4 hops and the total at 50 paths.
- Every path is labelled "candidate (hypothetical)" and lists the evidence still
  missing to confirm or rule out compromise.

## Same-host chains

Each vulnerability is given an access stage from its CVSS vector (v3, or v2 when v3 is
missing):

| Stage | CVSS v3 | Meaning |
| --- | --- | --- |
| remote-unauth | `AV:N` or `AV:A` with `PR:N` | Reachable over the network without credentials; a possible way in. |
| remote-auth | `AV:N` or `AV:A` with `PR:L` or `PR:H` | Needs credentials or a foothold. |
| local | `AV:L` or `AV:P` | Needs local access; often privilege escalation. |
| unknown | No vector | Access requirements unknown. |

- **Published chain:** the host has at least `min_match` of the CVEs listed for a chain
  in `rules/known_chains.json`.
- **Inferred chain:** the host has a High or Critical remote-unauth flaw on a listening
  port, plus a High or Critical remote-auth or local flaw. It is skipped when a
  published chain already covers the host.
- A chain notes whether its entry point received established traffic.

Inferred chains do not verify that the first flaw provides the access the second needs.

## Adding a published chain

Add an entry to `rules/known_chains.json`:

```json
{
  "name": "Short name of the chain",
  "cves": ["CVE-YYYY-NNNN", "CVE-YYYY-NNNN"],
  "min_match": 2,
  "reference": "Advisory or report that documents the chain",
  "description": "One or two sentences on what the combination allows."
}
```

`min_match` is how many of the listed CVEs must be present on one host for the chain to
match.

## Input handling

- Files are identified by content: the `NessusClientData_v2` root element, the Zeek
  `#separator` header or JSON fields, and the Palo Alto header row or syslog layout.
- `.nessus` files containing a DTD or entity declaration are refused.
- Malformed lines are skipped, counted and listed in `data_quality.json`. They never
  stop the run.
- Spreadsheet formulas in exported CSV cells are neutralised, because log content is
  untrusted.
