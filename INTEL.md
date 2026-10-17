# Threat intelligence rules

`rules/threat_intel.json` lists recent threat-intelligence reports and the behaviour in
them that VulnPath can see. A weekly scheduled task proposes new entries as a draft pull
request; a person reviews and merges it. Nothing is added without review.

## What VulnPath does with it

- **ATT&CK on every detection.** Each detection carries the MITRE ATT&CK technique its
  behaviour shows, whatever the reports say:

  | Detection | Internal source | External source |
  | --- | --- | --- |
  | Sweep | T1046 Network Service Discovery | T1595.001 Scanning IP Blocks |
  | Port scan, firewall scan | T1046 Network Service Discovery | T1595 Active Scanning |
  | Failed logins | T1110.001 Password Guessing, or T1110.003 Password Spraying with 5+ user names | same |
  | Brute-force pattern, IPS brute force | T1110 Brute Force | same |
  | IPS exploit | T1210 Exploitation of Remote Services | T1190 Exploit Public-Facing Application |
  | Any login attack followed by a possible success | adds T1078 Valid Accounts | same |

- **Report rules.** A rule matches a detection against one targeted service when every
  condition it lists holds. The finding then shows the report, its date, a link and the
  reason, and gains the rule's technique.
- **Priority.** A rule tied to the target (the host has a listed CVE, or Nessus names a
  listed product on it) adds 10 points. A detection from a listed source address adds
  10 points. A rule with only kinds and ports is context and changes no score.
- **Threat IDs.** `threat_ids` maps Palo Alto threat IDs to CVEs. They are merged into
  `--threat-map`, which wins where both name the same ID.

## Format

```json
{
  "id": "vendor-short-name",            // unique, stable
  "title": "…", "publisher": "…",
  "published": "YYYY-MM-DD",
  "url": "https://…",                   // the primary report, not a news article
  "actors": ["…"],
  "techniques": ["T1110.003"],          // what the report lists, for reference
  "rules": [{
    "kinds": ["auth-brute-force"],      // required: detection kinds (vulnpath/behavior.py KIND_LABEL)
    "ports": [443],                     // optional: targeted port
    "external_only": true,              // optional: source outside --internal
    "cves": ["CVE-…"],                  // optional: CVE on the target host per Nessus, or on the IPS hit
    "products": ["FortiOS"],            // optional: text in a Nessus plugin name on the target host
    "technique": "T1110.003",           // required, and must be in vulnpath/intel.py TECHNIQUES
    "why": "…"                          // required: one plain sentence an analyst will read
  }],
  "threat_ids": {"97562": ["CVE-…"]},   // optional
  "source_ips": ["…"]                   // optional: addresses the report lists, as published
}
```

`python -m unittest discover -s tests` checks every entry: required fields, ISO dates,
known techniques and detection kinds, CVE format and valid addresses.

## Weekly update procedure

1. Read the reports published since the newest `published` date in the file, from
   primary sources: CISA and partner advisories, FBI/IC3, Google Threat Intelligence
   (Mandiant), Microsoft Threat Intelligence, CrowdStrike, Palo Alto Unit 42, Cisco
   Talos and similar.
2. Keep only behaviour visible in Zeek conn, ssh, ntlm and kerberos logs, Palo Alto
   Traffic and Threat logs, or a Nessus scan: scanning, brute force, password spraying,
   exploitation of a listening service, named CVEs, Palo Alto threat IDs and source
   addresses. Leave out phishing, malware on endpoints and anything inside TLS.
3. Map each kept behaviour to ATT&CK. Prefer a rule tied to the target (CVE or product)
   over a port-only rule, and never add a port-only rule for a port as common as 443
   without `external_only`.
4. If a TTP needs a detection VulnPath does not have yet, add the detection in
   `vulnpath/behavior.py` with tests, and document it in `METHODS.md`.
5. Add a test for any new rule shape, run the tests, and open a draft pull request that
   lists each report, what was added and what was left out and why.
