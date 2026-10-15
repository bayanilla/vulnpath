# VulnPath methods and decision rules

All analysis rules are deterministic. The same inputs and options always produce the
same findings, and no AI model is involved in the analysis.

VulnPath works in two steps. It first detects hostile behaviour in the traffic alone,
then uses the Nessus scan to decide which of those behaviours point at something worth
fixing. Plain traffic to a vulnerable service, however much of it, is not a finding.

## Classifying connections

| Source | Established | Failed |
| --- | --- | --- |
| Zeek `conn.log` (TCP) | `conn_state` SF, S1, S2, S3, RSTO or RSTR, or OTH with bytes returned | S0, REJ, RSTOS0, RSTRH, SH or SHR |
| Zeek `conn.log` (UDP, ICMP) | Bytes returned by the responder, or `conn_state` SF | No reply |
| Palo Alto Traffic | `allow` with bytes received and an identified application | `allow` with no bytes received or the application `incomplete`; `deny`, `drop` or `reset-*` |

- Palo Alto session-start entries (log at session start) are skipped, so each session
  is counted once from its end entry.
- `OTH` means Zeek saw no SYN, usually because the session started before the log did.
  It is not counted as a failure.

## Detecting behaviour

Behaviour is counted per source in fixed time windows of `--window` minutes (15 by
default).

| Behaviour | Rule |
| --- | --- |
| **Sweep** | One source tried at least `--sweep-hosts` (20) hosts on the same port in a window, and at least half the connections failed. |
| **Port scan** | One source tried at least `--portscan-ports` (15) ports on one host in a window, and at least half the connections failed. |
| **Brute force (pattern)** | One source opened at least `--brute-attempts` (10) connections to a login port on one host in a window; at least 80 % were short (under 10 seconds) or failed; and either half failed or their sizes were nearly identical (coefficient of variation 0.25 or less). Login ports: 21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986. |
| **Failed logins** | Zeek `ssh.log`, `ntlm.log` or `kerberos.log` show at least `--auth-failures` (5) failed logins from one source to one service in a window. Five or more different user names is reported as password spraying. |
| **IPS exploit** | A Palo Alto Threat log of subtype `vulnerability`. No threshold. |
| **IPS brute force** | A `vulnerability` Threat log whose signature name contains "brute force". |
| **Firewall scan** | A Palo Alto Threat log of subtype `scan`. |

- **Possible login success:** a successful login in the Zeek login logs, or a long session
  (5 minutes or more, or 100 KB or more) on the same login service, from the same
  source, after the failures began.
- **Kerberos:** only `KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN` and
  `KRB_AP_ERR_BAD_INTEGRITY` count as failures. `KDC_ERR_PREAUTH_REQUIRED` is the normal
  first step of every Windows logon and is ignored.
- **IPS actions:** an action of `alert` or `allow` means not blocked; any other action
  means blocked. PAN-OS repeat counts are honoured.
- **Routine patterns:** when at least five internal sources match the brute-force
  pattern against the same service, the ones within three times the median attempt
  count are treated as normal use (SMB and SQL clients often look like this). External
  sources and sources with a possible login success are never suppressed. Routine
  sources are listed, marked as such, and produce no finding.
- **Excluded sources:** records from `--exclude-sources` are not analysed at all. Put your
  own vulnerability scanners, admin, backup and monitoring hosts here.
- **Single-contact sources:** a source seen only once can never be a scan or a brute
  force, so it is stored compactly and not evaluated. Its connection still counts in
  the service's traffic totals.

## Matching behaviour to vulnerabilities

- A finding is one service (host, port and protocol) that drew at least one detection.
- A detection matches a service when its target host, port and protocol match a Nessus
  result of severity Low or higher. Informational results are ignored.
- Login attacks (failed logins, brute force) on a scanned host also become a finding when
  the attacked port has no vulnerability, because stolen credentials are the foothold
  that a local privilege escalation on that host needs.
- Host-level Nessus results (port 0) are never matched to traffic. They are used only
  for same-host chains.
- When Palo Alto logs a NAT destination, matching uses the translated internal address
  and port, which is what Nessus scanned. The public address is kept as "via NAT".
- When several `.nessus` files cover the same host, only that host's most recent scan
  is used.

## Priority score

Each behaviour type counts once per finding, however many sources showed it. Every
finding lists its reasons in the report.

| Factor | Points |
| --- | --- |
| Highest severity on the service: Critical / High / Medium / Low | +40 / +30 / +15 / +5 |
| Public exploit available (Nessus) | +10 |
| A High or Critical flaw on the service needs no credentials over the network | +10 |
| IPS signature for the scanned CVE, not blocked / blocked | +40 / +20 |
| IPS signature not mapped to the scanned CVE, not blocked / blocked | +20 / +10 |
| Failed logins in authentication logs | +25 |
| A successful login followed the failures | +30 |
| IPS brute-force signature (+10 more if not blocked) | +20 |
| Brute-force connection pattern | +20 |
| A long session followed the brute-force pattern (when no login logs show a success) | +15 |
| Port scan of the host | +10 |
| Sweep that included the service | +5 |
| Firewall scan detection | +5 |
| A hostile source outside the internal networks | +10 |
| Three or more distinct hostile sources | +5 |
| A hostile source completed a session with the service | +10 |
| No session completed, no login succeeded and no IPS detection got through | −10 |
| The host matches a published chain | +15 |
| The service is the entry point of an inferred chain | +10 |
| Scan more than `--stale-days` from the activity | −10 |

The score orders the work; it is not a probability or a confidence level.

## Candidate attack paths

- A path starts at a hostile source that got through to a host: a successful login after
  failures, an unblocked IPS detection, or an established session during a brute-force
  or IPS-detected attack. A scan that merely found an open port does not start a path.
- It then follows established connections from that host to other vulnerable services.
- A hop from X to Y is chained only if it was seen at or after the time X was reached,
  so connections that happened earlier do not create a path.
- Paths need at least two hops. Depth is capped at 4 hops. All paths are ranked
  (external start, strength of the first hop, highest severity, length) before the list
  is trimmed to 50.
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
  in `rules/known_chains.json`. Published chains are always reported, with a note on
  whether hostile activity reached the host.
- **Inferred chain:** reported only for hosts that drew hostile behaviour. The entry
  must be a targeted High or Critical remote-unauth flaw on a listening port, or a login
  attack on the host. The host must also have a High or Critical remote-auth or local
  flaw. It is skipped when a published chain already covers the host.
- **Cumulative updates are not entry points.** Plugins in the Nessus family "Windows :
  Microsoft Bulletins", or listing ten or more CVEs, carry the CVSS vector of their worst
  CVE and would otherwise make every unpatched Windows host look chainable.

Inferred chains do not verify that the first step provides the access the second needs.

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
  `#path` header or JSON fields, and the Palo Alto header row or syslog layout.
- `.nessus` files containing a DTD or entity declaration are refused.
- Malformed lines are skipped, counted and listed in `data_quality.json`. They never
  stop the run.
- Spreadsheet formulas in exported CSV cells are neutralised, because log content is
  untrusted.
