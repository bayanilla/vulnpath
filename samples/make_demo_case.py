#!/usr/bin/env python3
"""Generate the synthetic demo case (Zeek conn logs + a .nessus file).

All IPs, hostnames and plugin IDs are made up. CVE IDs and CVSS vectors are real, chosen so the
scenarios are realistic. Usage: python samples/make_demo_case.py [output_folder]
"""
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

T0 = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc).timestamp()
SCAN = "Thu Oct  1 09:00:00 2026"
OLD_SCAN = "Tue Jun  2 09:00:00 2026"

ZEEK_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
               "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
               "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"]
ZEEK_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
              "string", "bool", "bool", "count", "string", "count", "count", "count", "count", "set[string]"]

# host, hostname, os, scan time, [(port, proto, svc, plugin, name, sev, cves, cvss3 vector, score, exploit, frameworks)]
HOSTS = [
    ("10.0.1.10", "web01.corp.local", "Linux Kernel 5.4 on Ubuntu 20.04", SCAN, [
        (443, "tcp", "www", "900101", "Apache HTTP Server 2.4.49 Path Traversal", 3, ["CVE-2021-41773"],
         "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, True, ["metasploit"]),
        (22, "tcp", "ssh", "900102", "OpenSSH < 9.8p1 Signal Handler Race (regreSSHion)", 3, ["CVE-2024-6387"],
         "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, True, []),
        (0, "tcp", "general", "900103", "Ubuntu polkit pkexec Local Privilege Escalation (PwnKit)", 3,
         ["CVE-2021-4034"], "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, True, ["metasploit"]),
    ]),
    ("10.0.1.15", "mail01.corp.local", "Microsoft Windows Server 2016", SCAN, [
        (443, "tcp", "www", "900201", "Microsoft Exchange Server RCE (ProxyShell, part 1)", 4,
         ["CVE-2021-34473", "CVE-2021-34523"], "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, True,
         ["metasploit"]),
        (443, "tcp", "www", "900202", "Microsoft Exchange Server Security Feature Bypass (ProxyShell, part 2)", 3,
         ["CVE-2021-31207"], "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, True, []),
    ]),
    ("10.0.2.20", "app02.corp.local", "Microsoft Windows Server 2012 R2", SCAN, [
        (445, "tcp", "cifs", "900301", "MS17-010: Security Update for Microsoft Windows SMB Server", 3,
         ["CVE-2017-0144"], "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, True, ["metasploit"]),
    ]),
    ("10.0.2.30", "db01.corp.local", "Microsoft Windows Server 2012 R2", SCAN, [
        (445, "tcp", "cifs", "900301", "MS17-010: Security Update for Microsoft Windows SMB Server", 3,
         ["CVE-2017-0144"], "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, True, ["metasploit"]),
    ]),
    ("10.0.1.30", "portal.corp.local", "Linux Kernel 4.18 on Red Hat 8", SCAN, [
        (8009, "tcp", "ajp13", "900401", "Apache Tomcat AJP File Read/Inclusion (Ghostcat)", 4,
         ["CVE-2020-1938"], "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, True, ["metasploit"]),
    ]),
    ("10.0.1.40", "rdp01.corp.local", "Microsoft Windows Server 2008 R2", OLD_SCAN, [
        (3389, "tcp", "msrdp", "900501", "Microsoft RDP RCE (BlueKeep)", 4, ["CVE-2019-0708"],
         "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, True, ["metasploit"]),
    ]),
]


def nessus_xml() -> str:
    out = ['<?xml version="1.0" ?>', '<NessusClientData_v2>', '<Report name="Quarterly internal scan">']
    for ip, fqdn, os_, scan, items in HOSTS:
        out.append(f'<ReportHost name="{ip}"><HostProperties>')
        for k, v in [("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_),
                     ("HOST_START", scan), ("HOST_END", scan)]:
            out.append(f'<tag name="{k}">{escape(v)}</tag>')
        out.append('</HostProperties>')
        for port, proto, svc, pid, name, sev, cves, vec, score, expl, fw in items:
            out.append(f'<ReportItem port="{port}" svc_name="{svc}" protocol="{proto}" severity="{sev}" '
                       f'pluginID="{pid}" pluginName="{escape(name)}" pluginFamily="Synthetic">')
            for c in cves:
                out.append(f'<cve>{c}</cve>')
            out.append(f'<cvss3_vector>{vec}</cvss3_vector><cvss3_base_score>{score}</cvss3_base_score>')
            out.append(f'<exploit_available>{"true" if expl else "false"}</exploit_available>')
            if expl:
                out.append('<exploitability_ease>Exploits are available</exploitability_ease>')
            for f in fw:
                out.append(f'<exploit_framework_{f}>true</exploit_framework_{f}>')
            out.append(f'<synopsis>{escape(name)}</synopsis><solution>Apply the vendor update.</solution>')
            out.append('</ReportItem>')
        # an informational item that must be ignored
        out.append(f'<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" '
                   f'pluginName="Nessus Scan Information"><plugin_output>info</plugin_output></ReportItem>')
        out.append('</ReportHost>')
    out.append('</Report></NessusClientData_v2>')
    return "\n".join(out)


class Conns:
    def __init__(self, seed=7):
        self.rows = []
        self.rng = random.Random(seed)
        self.n = 0

    def add(self, t, src, dst, dport, state, proto="tcp", svc="-", ob=0, rb=0):
        self.n += 1
        uid = f"C{self.n:07d}demo"
        self.rows.append({"ts": round(T0 + t, 6), "uid": uid, "id.orig_h": src,
                          "id.orig_p": self.rng.randint(1025, 65000), "id.resp_h": dst, "id.resp_p": dport,
                          "proto": proto, "service": svc, "duration": 0.5, "orig_bytes": ob, "resp_bytes": rb,
                          "conn_state": state, "history": "ShADadfF" if state == "SF" else "S"})


def build(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "scans").mkdir(exist_ok=True)
    (out / "zeek").mkdir(exist_ok=True)
    (out / "scans" / "internal_q4.nessus").write_text(nessus_xml(), encoding="utf-8")

    c = Conns()
    # Scenario A: external source reaches web01:443 (vulnerable Apache), then web01 reaches app02:445 (MS17-010).
    for i in range(12):
        c.add(2 * 3600 + i * 60, "203.0.113.50", "10.0.1.10", 443, "SF", svc="ssl", ob=900 + i, rb=4200)
    for i in range(3):
        c.add(2 * 3600 + 40 * 60 + i * 30, "10.0.1.10", "10.0.2.20", 445, "SF", svc="smb", ob=5300, rb=1800)
    # app02 tries db01:445 but never completes a handshake (attempt, not a path hop).
    for i in range(4):
        c.add(3 * 3600 + i * 10, "10.0.2.20", "10.0.2.30", 445, "S0")
    # Scanner sweeps the DMZ: probing.
    for h in ["10.0.1.10", "10.0.1.15", "10.0.1.30", "10.0.1.40"]:
        for p in [21, 22, 23, 25, 80, 443, 445, 3389, 8009, 8080]:
            c.add(3600 + len(c.rows), "198.51.100.7", h, p, "REJ" if p in (21, 23) else "S0")
    # Normal user browsing the portal on 443: vulnerability is on 8009, so no finding.
    for i in range(20):
        c.add(4 * 3600 + i * 120, "10.0.5.100", "10.0.1.30", 443, "SF", svc="ssl", ob=700, rb=30000)
    # Attempts against rdp01 (stale scan): attempted + stale.
    for i in range(6):
        c.add(6 * 3600 + i * 5, "203.0.113.77", "10.0.1.40", 3389, "S0")
    # Background noise: DNS.
    for i in range(2000):
        c.add(i * 20, f"10.0.5.{c.rng.randint(2, 250)}", "10.0.0.53", 53, "SF", proto="udp", svc="dns",
              ob=60, rb=120)
    c.rows.sort(key=lambda r: r["ts"])

    lines = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
             "#path\tconn", "#open\t2026-10-10-00-00-00",
             "#fields\t" + "\t".join(ZEEK_FIELDS), "#types\t" + "\t".join(ZEEK_TYPES)]
    for r in c.rows:
        lines.append("\t".join(str(r.get(f, "-")) for f in ZEEK_FIELDS))
    lines.insert(500, "this line is corrupted")
    lines.append("#close\t2026-10-11-00-00-00")
    (out / "zeek" / "conn.00_00_00-23_59_59.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Second day, Zeek JSON format. mail01 talks to app02 at 01:00, BEFORE mail01 is reached at 05:00,
    # so it must NOT be chained after the inbound hop (time order).
    j = Conns(seed=11)
    j.n = 900000
    day2 = 86400
    for i in range(2):
        j.add(day2 + 3600 + i, "10.0.1.15", "10.0.2.20", 445, "SF", svc="smb", ob=400, rb=300)
    for i in range(5):
        j.add(day2 + 5 * 3600 + i * 60, "203.0.113.60", "10.0.1.15", 443, "SF", svc="ssl", ob=2500, rb=800)
    with open(out / "zeek" / "conn.day2.json", "w", encoding="utf-8") as f:
        for r in j.rows:
            f.write(json.dumps(r) + "\n")

    write_paloalto(out / "firewall")
    (out / "analyst_notes.txt").write_text("Case notes: not a log file, should be skipped.\n", encoding="utf-8")
    return out


def _pan_time(t: float) -> str:
    return datetime.fromtimestamp(T0 + t, tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def _pan_row(kind, subtype, t, src, dst, nat_dst, dport, action, sess, app="ssl", sent=0, recv=0,
             threat="", severity="", direction="client-to-server"):
    """Build a PAN-OS syslog CSV row using documented field positions."""
    r = [""] * 60
    r[0], r[1], r[2], r[3], r[4], r[6] = "1", _pan_time(t), "013201000123", kind, subtype, _pan_time(t)
    r[7], r[8], r[9], r[10], r[11] = src, dst, "0.0.0.0", nat_dst, "inbound-dmz"
    r[14], r[15], r[16], r[17], r[20], r[22], r[23] = app, "vsys1", "untrust", "dmz", "default", str(sess), "1"
    r[24], r[25], r[26], r[27], r[29], r[30] = "51234", str(dport), "0", str(dport), "tcp", action
    if kind == "TRAFFIC":
        r[31], r[32], r[33], r[46] = str(sent + recv), str(sent), str(recv), "tcp-fin" if recv else "aged-out"
    else:
        r[32], r[33], r[34], r[35] = threat, "any", severity, direction
    while r and r[-1] == "":
        r.pop()
    return ",".join(f'"{v}"' if "," in v else v for v in r)


def write_paloalto(folder: Path) -> None:
    """Palo Alto logs from two places: a syslog collector (mixed log types) and a web-UI CSV export.

    Firewall public IPs 198.18.10.x are NATed to the DMZ hosts the scanner saw (10.0.1.x).
    Threat IDs 95001/95002 are made up and mapped to CVEs in samples/demo_threat_map.csv.
    """
    folder.mkdir(exist_ok=True)
    pre = "<14>Oct 10 {} fw-edge-01 "
    lines = []
    for i in range(12):
        t = 2 * 3600 + i * 60
        lines.append((t, _pan_row("TRAFFIC", "end", t, "203.0.113.50", "198.18.10.10", "10.0.1.10", 443, "allow",
                                  70000 + i, sent=900, recv=4200)))
    for i in range(3):
        t = 2 * 3600 + 5 * 60 + i * 60
        lines.append((t, _pan_row("THREAT", "vulnerability", t, "203.0.113.50", "198.18.10.10", "10.0.1.10", 443,
                                  "alert", 70005 + i, threat="Apache HTTP Server Path Traversal Vulnerability(95001)",
                                  severity="critical")))
    for i in range(6):
        t = 6 * 3600 + i * 5
        lines.append((t, _pan_row("THREAT", "vulnerability", t, "203.0.113.77", "198.18.10.40", "10.0.1.40", 3389,
                                  "reset-both", 71000 + i, app="ms-rdp",
                                  threat="Microsoft RDP Remote Code Execution Vulnerability(95002)",
                                  severity="critical")))
    t = 3600 + 30
    lines.append((t, _pan_row("THREAT", "scan", t, "198.51.100.7", "198.18.10.10", "10.0.1.10", 22, "drop", 72000,
                              app="ssh", threat="TCP Port Scan(8001)", severity="medium")))
    for i, msg in enumerate(["general,0,0,general,informational,\"HA peer link up\"",
                             "general,0,0,general,informational,\"Log forwarding resumed\""]):
        t = 1800 + i
        lines.append((t, f"1,{_pan_time(t)},013201000123,SYSTEM,{msg}"))
    lines.sort(key=lambda x: x[0])
    with open(folder / "pa-syslog-collector.log", "w", encoding="utf-8") as f:
        for t, row in lines:
            hhmmss = datetime.fromtimestamp(T0 + t, tz=timezone.utc).strftime("%H:%M:%S")
            f.write(pre.format(hhmmss) + row + "\n")

    # Web UI export: header row, columns in UI order and naming.
    hdr = ["Receive Time", "Serial #", "Type", "Threat/Content Type", "Generate Time", "Source address",
           "Destination address", "NAT Source IP", "NAT Destination IP", "Rule", "Application", "Source Zone",
           "Destination Zone", "Session ID", "Source Port", "Destination Port", "NAT Source Port",
           "NAT Destination Port", "IP Protocol", "Action", "Bytes", "Bytes Sent", "Bytes Received",
           "Session End Reason"]
    rows = []
    for i in range(3):   # blocked attempts at the Ghostcat AJP port
        tt = _pan_time(7 * 3600 + i * 30)
        rows.append([tt, "013201000123", "TRAFFIC", "end", tt, "203.0.113.90", "198.18.10.30", "0.0.0.0",
                     "10.0.1.30", "deny-ajp", "incomplete", "untrust", "dmz", str(73000 + i), "40000", "8009", "0",
                     "8009", "tcp", "deny", "74", "74", "0", "policy-deny"])
    for i in range(5):   # normal HTTPS to the portal: vulnerability is on 8009, so no finding
        tt = _pan_time(8 * 3600 + i * 30)
        rows.append([tt, "013201000123", "TRAFFIC", "end", tt, "192.0.2.25", "198.18.10.30", "0.0.0.0",
                     "10.0.1.30", "inbound-dmz", "ssl", "untrust", "dmz", str(74000 + i), "41000", "443", "0",
                     "443", "tcp", "allow", "9000", "1200", "7800", "tcp-fin"])
    import csv as _csv
    with open(folder / "panorama_traffic_export.csv", "w", newline="", encoding="utf-8") as f:
        w = _csv.writer(f)
        w.writerow(hdr)
        w.writerows(rows)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "case_demo"
    print(f"Demo case written to {build(target)}")
