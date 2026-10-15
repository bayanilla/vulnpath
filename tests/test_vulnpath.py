"""Tests run with the standard library only:  python -m unittest discover -s tests -v"""
import csv
import json
import random
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "samples"))

import make_demo_case  # noqa: E402
from vulnpath.chains import is_rollup, stage  # noqa: E402
from vulnpath.correlate import Settings  # noqa: E402
from vulnpath.detect import detect  # noqa: E402
from vulnpath.diagram import render  # noqa: E402
from vulnpath.evidence import EvidenceFile, inventory, sha256_file  # noqa: E402
from vulnpath.model import Vulnerability  # noqa: E402
from vulnpath.parsers import nessus, paloalto, zeek  # noqa: E402
from vulnpath.pipeline import InputError, run  # noqa: E402
from vulnpath.report import write_csv  # noqa: E402


THREAT_MAP = str(ROOT / "samples" / "demo_threat_map.csv")


def DEMO_SETTINGS(**kw):
    kw.setdefault("exclude_sources", [make_demo_case.NESSUS_SCANNER])
    return Settings(threat_map=THREAT_MAP, **kw)


def quiet(*_):
    pass


class DemoCase(unittest.TestCase):
    """End-to-end run on the synthetic case, covering positive and negative scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.case = make_demo_case.build(cls.tmp / "case")
        cls.hashes = {p: sha256_file(p) for p in cls.case.rglob("*") if p.is_file()}
        cls.out = cls.tmp / "results"
        cls.ctx = run(cls.case, cls.out, DEMO_SETTINGS(), log=quiet)
        cls.F = cls.ctx["findings"]
        cls.S = {s["source_ip"]: s for s in cls.ctx["hostile_sources"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def finding(self, dst, port):
        [f] = [f for f in self.F if (f["target_ip"], f["port"]) == (dst, port)]
        return f

    def behaviour(self, f, src, kind):
        [b] = [b for b in f["behaviours"] if (b["source_ip"], b["kind"]) == (src, kind)]
        return b

    def test_outputs_written(self):
        for name in ["report.html", "attack_paths.svg", "findings.csv", "sources.csv", "findings.json",
                     "evidence_manifest.json", "data_quality.json"]:
            self.assertTrue((self.out / name).stat().st_size > 0, name)

    def test_evidence_not_modified(self):
        for p, h in self.hashes.items():
            self.assertEqual(sha256_file(p), h, p)
        self.assertIn("none changed", self.ctx["integrity"])

    # ---- what must NOT be a finding ----
    def test_normal_use_of_vulnerable_service_is_not_a_finding(self):
        # 40 workstations use app02's vulnerable SMB service all day; only the password sprayer is hostile.
        f = self.finding("10.0.2.20", 445)
        self.assertEqual(f["hostile_sources"], ["10.0.5.77"])
        for w in range(10, 50):
            self.assertNotIn(f"10.0.5.{w}", self.S)

    def test_routine_peer_pattern_is_suppressed(self):
        for w in range(60, 68):
            self.assertTrue(self.S[f"10.0.5.{w}"]["routine_only"], w)
            self.assertEqual(self.S[f"10.0.5.{w}"]["vulnerable_targets"], 0)
        self.assertTrue(any("normal use" in c for c in self.ctx["coverage"]))

    def test_browsing_a_host_is_not_a_finding(self):
        # the portal is vulnerable on 8009; a user browsing 443 is not hostile
        self.assertNotIn("10.0.5.100", self.S)
        self.assertFalse([f for f in self.F if f["target_ip"] == "10.0.1.30" and f["port"] == 443])

    def test_excluded_source_ignored(self):
        self.assertNotIn(make_demo_case.NESSUS_SCANNER, self.S)
        self.assertTrue(any("excluded sources" in c for c in self.ctx["coverage"]))

    # ---- behaviours ----
    def test_ssh_brute_force_with_success_ranks_first(self):
        f = self.F[0]
        self.assertEqual((f["target_ip"], f["port"]), ("10.0.1.10", 22))
        self.assertTrue(f["possible_login_success"])
        b = self.behaviour(f, "203.0.113.120", "auth-brute-force")
        self.assertEqual(b["failed"], 120)
        self.assertIn("successful ssh login", b["success_detail"])
        self.assertIn("ssh.log", " ".join(b["evidence"]))
        self.assertIn("Not confirmation", f["assessment"])

    def test_password_spray(self):
        b = self.behaviour(self.finding("10.0.2.20", 445), "10.0.5.77", "auth-brute-force")
        self.assertIn("12 different user names", b["detail"])
        self.assertFalse(b["possible_success"])

    def test_internal_brute_force_pattern(self):
        f = self.finding("10.0.2.30", 445)
        b = self.behaviour(f, "10.0.5.200", "brute-force")
        self.assertEqual(b["attempts"], 120)
        self.assertFalse(b["routine"])

    def test_sweep_detected(self):
        s = self.S["198.51.100.7"]
        self.assertIn("horizontal-scan", s["kinds"])
        self.assertIn("ips-scan", s["kinds"])
        b = self.behaviour(self.finding("10.0.1.10", 443), "198.51.100.7", "horizontal-scan")
        self.assertEqual(b["targets"], 40)

    def test_port_scan_through_nat(self):
        f = self.finding("10.0.1.30", 8009)
        b = self.behaviour(f, "203.0.113.90", "vertical-scan")
        self.assertEqual((b["targets"], b["failed"]), (20, 20))
        self.assertIn("198.18.10.30:8009", f["pre_nat_destinations"])

    def test_unblocked_ips_alert_matching_cve(self):
        f = self.finding("10.0.1.10", 443)
        b = self.behaviour(f, "203.0.113.50", "ips-exploit")
        self.assertEqual((b["not_blocked"], b["blocked"]), (3, 0))
        self.assertEqual(b["cves"], ["CVE-2021-41773"])
        self.assertIn("NOT blocked", f["assessment"])
        self.assertTrue(any("CVE-2021-41773" in r and "+40" in r for r in f["score_reasons"]))

    def test_blocked_ips_and_stale_scan(self):
        f = self.finding("10.0.1.40", 3389)
        b = self.behaviour(f, "203.0.113.77", "ips-exploit")
        self.assertEqual((b["not_blocked"], b["blocked"]), (0, 6))
        self.assertIn("blocked them", f["assessment"])
        self.assertTrue(f["scan_stale"])

    def test_sensors_not_double_counted(self):
        # Zeek (13 sessions incl. one scanner hit) and the firewall (12) saw the same traffic to web01:443
        st = self.finding("10.0.1.10", 443)["service_traffic"]
        self.assertEqual(st["established"], 13)

    # ---- paths and chains ----
    def test_path_from_unblocked_ips(self):
        self.assertIn(["203.0.113.50", "10.0.1.10", "10.0.2.20"], [p["hosts"] for p in self.ctx["paths"]])

    def test_time_order_respected(self):
        # mail01 -> app02 happened before mail01 was reached, so it must not extend the path.
        for p in self.ctx["paths"]:
            self.assertNotIn(["10.0.1.15", "10.0.2.20"], [p["hosts"][i:i + 2] for i in range(len(p["hosts"]) - 1)])

    def test_scans_do_not_start_paths(self):
        self.assertFalse([p for p in self.ctx["paths"] if p["start"] == "198.51.100.7"])
        for p in self.ctx["paths"]:
            self.assertEqual(p["status"], "candidate (hypothetical)")

    def test_documented_chain(self):
        c = [c for c in self.ctx["chains"] if c["host"] == "10.0.1.15"]
        self.assertEqual([x["type"] for x in c], ["documented"])
        self.assertTrue(c[0]["entry_targeted"])
        self.assertIn("ProxyShell (Microsoft Exchange)", self.finding("10.0.1.15", 443)["chains"])

    def test_inferred_chain_needs_targeted_entry(self):
        [c] = [c for c in self.ctx["chains"] if c["host"] == "10.0.1.10"]
        self.assertEqual(c["type"], "inferred")
        stages = [s["stage"] for s in c["steps"]]
        self.assertIn("credentials", stages)
        self.assertIn("local", stages)

    def test_no_chain_on_single_vuln_host(self):
        self.assertFalse([c for c in self.ctx["chains"] if c["host"] in ("10.0.2.20", "10.0.2.30")])

    # ---- inputs ----
    def test_latest_scan_per_host_wins(self):
        # the Q3 export still lists a Struts flaw on web01 that the Q4 scan no longer reports
        blob = json.dumps(self.ctx["findings"]) + json.dumps(self.ctx["chains"])
        self.assertNotIn("900104", blob)
        self.assertTrue(any("more than one Nessus file" in c for c in self.ctx["coverage"]))
        self.assertEqual(len(self.finding("10.0.2.30", 445)["vulnerabilities"]), 1)

    def test_data_quality(self):
        dq = json.loads((self.out / "data_quality.json").read_text())
        [zeek_q] = [x for x in dq["per_file"] if x["path"].startswith("zeek/conn.00")]
        self.assertEqual(zeek_q["skipped"], 1)
        self.assertTrue(any("analyst_notes.txt" in c for c in dq["coverage"]))

    def test_system_logs_skipped_not_errors(self):
        dq = json.loads((self.out / "data_quality.json").read_text())
        [pa] = [x for x in dq["per_file"] if x["path"].endswith("pa-syslog-collector.log")]
        self.assertEqual(pa["skipped"], 0)
        self.assertTrue(any("2 SYSTEM" in i for i in pa["issues"]))

    def test_never_claims_exploitation(self):
        for f in self.F:
            for word in ("was exploited", "is compromised", "confirmed"):
                self.assertNotIn(word, f["assessment"].lower())

    def test_deterministic(self):
        ctx2 = run(self.case, self.tmp / "results2", DEMO_SETTINGS(), log=quiet)
        self.assertEqual(ctx2["findings"], self.F)
        self.assertEqual(ctx2["paths"], self.ctx["paths"])
        self.assertEqual(ctx2["hostile_sources"], self.ctx["hostile_sources"])


class NoisyNetwork(unittest.TestCase):
    """A busier, more realistic network: lots of ordinary use of vulnerable services, one real attacker."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        case = cls.tmp / "case"
        case.mkdir()
        rng = random.Random(3)
        smb = ("445", "57608", "SMB Signing not required", 2, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
        ldap = ("389", "153953", "LDAP signing not required", 2, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
        roll = ("445", "183000", "KB5044284: Windows Security Update", 4, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        office = ("0", "190000", "Microsoft Office Security Update", 3, "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
        hosts = {"10.0.0.5": [smb, ldap, roll, office], "10.0.1.30": [smb, roll, office]}
        for i in range(1, 31):
            hosts[f"10.0.5.{i}"] = [smb, roll, office]
        x = ['<?xml version="1.0" ?><NessusClientData_v2><Report name="r">']
        for ip, items in hosts.items():
            x.append(f'<ReportHost name="{ip}"><HostProperties><tag name="host-ip">{ip}</tag>'
                     '<tag name="HOST_END">Thu Oct  8 09:00:00 2026</tag></HostProperties>')
            for port, pid, name, sev, vec in items:
                fam = "Windows : Microsoft Bulletins" if pid == "183000" else "Misc."
                cves = "".join(f"<cve>CVE-2026-{1000 + n}</cve>" for n in range(12 if pid == "183000" else 1))
                x.append(f'<ReportItem port="{port}" protocol="tcp" severity="{sev}" pluginID="{pid}" '
                         f'pluginName="{name}" pluginFamily="{fam}">{cves}<cvss3_vector>{vec}</cvss3_vector>'
                         '</ReportItem>')
            x.append("</ReportHost>")
        x.append("</Report></NessusClientData_v2>")
        (case / "scan.nessus").write_text("".join(x))
        t0 = 1791590400.0
        rows = []
        inet = [f"52.1.{a}.{b}" for a in range(20) for b in range(1, 40)]
        for i in range(1, 121):
            w = f"10.0.5.{i}" if i <= 30 else f"10.0.6.{i}"
            for _ in range(10):
                t = t0 + rng.random() * 86400
                rows += [(t, w, "10.0.0.5", 445, "SF"), (t + 1, w, "10.0.0.5", 389, "SF"),
                         (t + 2, w, "10.0.1.30", 445, "SF")]
            for d in rng.sample(inet, 40):   # browsing: many destinations, all successful
                rows.append((t0 + rng.random() * 3600, w, d, 443, "SF"))
        for i in range(1, 31):               # management server pushes to every workstation
            rows.append((t0 + 3600 + i, "10.0.0.9", f"10.0.5.{i}", 445, "SF"))
        for i in range(1, 41):               # the attacker: an SMB sweep of the workstation subnet, mostly closed
            rows.append((t0 + 50000 + i, "10.0.7.66", f"10.0.5.{i}", 445, "SF" if i in (3, 7) else "S0"))
        rows.sort()
        lines = ["#separator \\x09", "#path\tconn",
                 "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\t"
                 "resp_bytes\tconn_state"]
        for n, (t, s, d, p, st) in enumerate(rows):
            lines.append(f"{t:.3f}\tC{n}\t{s}\t50000\t{d}\t{p}\ttcp\t{30.0 if st == 'SF' else '-'}\t"
                         f"{rng.randint(500, 9000) if st == 'SF' else 0}\t{4000 if st == 'SF' else 0}\t{st}")
        (case / "conn.log").write_text("\n".join(lines) + "\n")
        cls.ctx = run(case, cls.tmp / "out", Settings(), log=quiet)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_only_the_attacker_produces_findings(self):
        srcs = {s for f in self.ctx["findings"] for s in f["hostile_sources"]}
        self.assertEqual(srcs, {"10.0.7.66"})
        self.assertEqual(len(self.ctx["findings"]), 30)   # 40 addresses swept, 30 of them scanned
        self.assertEqual([s["source_ip"] for s in self.ctx["hostile_sources"]], ["10.0.7.66"])

    def test_hosts_the_attacker_reached_rank_first(self):
        top = {f["target_ip"] for f in self.ctx["findings"][:2]}
        self.assertEqual(top, {"10.0.5.3", "10.0.5.7"})

    def test_rollup_does_not_create_inferred_chains(self):
        self.assertEqual(self.ctx["chains"], [])


class Units(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _ef(self, name, text):
        p = self.tmp / name
        p.write_text(text)
        return EvidenceFile(p, name, p.stat().st_size, sha256_file(p))

    def test_detection_ignores_filenames(self):
        case = make_demo_case.build(self.tmp / "c")
        (case / "scans" / "internal_q4.nessus").rename(case / "scans" / "export.dat")
        (case / "zeek" / "conn.day2.json").rename(case / "zeek" / "random.txt")
        (case / "zeek" / "ssh.log").rename(case / "zeek" / "a.log")
        (case / "zeek" / "ntlm.json").rename(case / "zeek" / "b.txt")
        types = {ef.rel_path: detect(ef.path) for ef in inventory(case)}
        self.assertEqual(types["scans/export.dat"], "nessus")
        self.assertEqual(types["zeek/random.txt"], "zeek_conn")
        self.assertEqual(types["zeek/a.log"], "zeek_ssh")
        self.assertEqual(types["zeek/b.txt"], "zeek_ntlm")
        self.assertEqual(types["analyst_notes.txt"], "unsupported")

    def test_gzip_zeek(self):
        import gzip
        case = make_demo_case.build(self.tmp / "c")
        src = case / "zeek" / "conn.00_00_00-23_59_59.log"
        with open(src, "rb") as f, gzip.open(self.tmp / "c" / "conn.log.gz", "wb") as g:
            g.write(f.read())
        src.unlink()
        [ef] = [e for e in inventory(case) if e.rel_path == "conn.log.gz"]
        self.assertEqual(detect(ef.path), "zeek_conn")
        self.assertGreater(len(list(zeek.parse(ef))), 2000)

    def test_zeek_midstream_is_not_a_failure(self):
        ef = self._ef("c.log", "#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\t"
                               "id.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\n"
                               "1.0\tC1\t10.0.0.1\t1\t10.0.0.2\t22\ttcp\t900\t500\t9000\tOTH\n")
        [c] = list(zeek.parse(ef))
        self.assertEqual((c.outcome, c.duration), ("established", 900.0))

    def test_kerberos_routine_errors_ignored(self):
        recs = [{"ts": 1, "uid": "K1", "id.orig_h": "10.0.0.1", "id.orig_p": 1, "id.resp_h": "10.0.0.5",
                 "id.resp_p": 88, "request_type": "AS", "client": "bob/CORP", "success": False,
                 "error_msg": "KDC_ERR_PREAUTH_REQUIRED"},
                {"ts": 2, "uid": "K2", "id.orig_h": "10.0.0.1", "id.orig_p": 1, "id.resp_h": "10.0.0.5",
                 "id.resp_p": 88, "request_type": "AS", "client": "bob/CORP", "success": False,
                 "error_msg": "KDC_ERR_PREAUTH_FAILED"}]
        ef = self._ef("k.json", "\n".join(json.dumps(r) for r in recs) + "\n")
        self.assertEqual(detect(ef.path), "zeek_kerberos")
        out = list(zeek.parse(ef, "kerberos"))
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0].auth.failures, out[0].auth.user), (1, "bob"))

    def test_ntlm_status_string(self):
        rec = {"ts": 1, "uid": "N1", "id.orig_h": "10.0.0.1", "id.orig_p": 1, "id.resp_h": "10.0.0.5",
               "id.resp_p": 445, "username": "bob", "domainname": "CORP", "status": "STATUS_LOGON_FAILURE"}
        ef = self._ef("n.json", json.dumps(rec) + "\n")
        [c] = list(zeek.parse(ef, "ntlm"))
        self.assertEqual((c.auth.success, c.auth.user), (False, "CORP\\bob"))

    def test_nessus_rejects_dtd(self):
        p = self.tmp / "c" / "evil.nessus"
        p.parent.mkdir()
        p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><NessusClientData_v2/>')
        [ef] = inventory(self.tmp / "c")
        with self.assertRaises(ValueError):
            list(nessus.parse(ef, {}))

    def test_nessus_skips_info_items(self):
        case = make_demo_case.build(self.tmp / "c")
        [ef] = [e for e in inventory(case) if e.rel_path.endswith("q4.nessus")]
        hosts = {}
        vulns = list(nessus.parse(ef, hosts))
        self.assertFalse([v for v in vulns if v.plugin_id == "19506"])
        self.assertEqual(len(hosts), 6)
        self.assertIsNotNone(hosts["10.0.1.10"].scan_time)
        self.assertEqual(vulns[0].plugin_family, "Synthetic")

    def test_output_inside_input_refused(self):
        case = make_demo_case.build(self.tmp / "c")
        with self.assertRaises(InputError):
            run(case, case / "results", log=quiet)

    def test_missing_traffic_does_not_crash(self):
        case = make_demo_case.build(self.tmp / "c")
        shutil.rmtree(case / "zeek")
        shutil.rmtree(case / "firewall")
        ctx = run(case, self.tmp / "out", log=quiet)
        self.assertEqual(ctx["findings"], [])
        self.assertTrue(any("No supported traffic" in n for n in ctx["notices"]))

    def test_stage_from_cvss(self):
        mk = lambda v3="", v2="": Vulnerability("h", "", 1, "tcp", "", "1", "", 3, cvss3_vector=v3, cvss2_vector=v2)  # noqa
        self.assertEqual(stage(mk("CVSS:3.0/AV:N/AC:L/PR:N/UI:N")), "remote-unauth")
        self.assertEqual(stage(mk("CVSS:3.1/AV:N/AC:L/PR:H/UI:N")), "remote-auth")
        self.assertEqual(stage(mk("CVSS:3.0/AV:L/AC:L/PR:L/UI:N")), "local")
        self.assertEqual(stage(mk(v2="CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P")), "remote-unauth")
        self.assertEqual(stage(mk()), "unknown")

    def test_rollup_detection(self):
        v = Vulnerability("h", "", 445, "tcp", "", "1", "", 4, plugin_family="Windows : Microsoft Bulletins")
        self.assertTrue(is_rollup(v))
        v = Vulnerability("h", "", 445, "tcp", "", "1", "", 4, cves=[f"CVE-2026-{i}" for i in range(12)])
        self.assertTrue(is_rollup(v))
        self.assertFalse(is_rollup(Vulnerability("h", "", 445, "tcp", "", "1", "", 4, cves=["CVE-2017-0144"])))

    def test_pan_detection_ignores_filenames(self):
        case = make_demo_case.build(self.tmp / "c")
        (case / "firewall" / "pa-syslog-collector.log").rename(case / "firewall" / "a.dat")
        (case / "firewall" / "panorama_traffic_export.csv").rename(case / "firewall" / "b.txt")
        types = {ef.rel_path: detect(ef.path) for ef in inventory(case)}
        self.assertEqual(types["firewall/a.dat"], "paloalto")
        self.assertEqual(types["firewall/b.txt"], "paloalto")

    def test_pan_utc_offset(self):
        case = make_demo_case.build(self.tmp / "c")
        [ef] = [e for e in inventory(case) if e.rel_path.endswith("panorama_traffic_export.csv")]
        t0 = next(paloalto.parse(ef, 0)).ts
        [ef] = [e for e in inventory(case) if e.rel_path.endswith("panorama_traffic_export.csv")]
        t5 = next(paloalto.parse(ef, -5)).ts
        self.assertEqual(t5 - t0, 5 * 3600)

    def _pan(self, subtype="end", app="ssl", recv="5", kind="TRAFFIC", extra=None):
        r = ["1", "2026/10/10 02:00:00", "0123", kind, subtype, "", "2026/10/10 02:00:00", "1.2.3.4", "10.0.0.5",
             "0.0.0.0", "0.0.0.0", "r", "", "", app, "vsys1", "u", "t", "e1", "e2", "d", "", "99", "1", "5555",
             "443", "0", "0", "", "tcp", "allow", "10", "5", recv, "2", "", "12"]
        for i, v in (extra or {}).items():
            r[i] = v
        return "<14>Oct 10 02:00:00 fw " + ",".join(r)

    def test_pan_session_start_and_incomplete(self):
        ef = self._ef("p.log", "\n".join([self._pan("start"), self._pan(app="incomplete"), self._pan()]) + "\n")
        out = list(paloalto.parse(ef))
        self.assertEqual([c.outcome for c in out], ["attempt", "established"])
        self.assertEqual(out[1].duration, 12.0)
        self.assertTrue(any("session-start" in i for i in ef.issues))

    def test_pan_threat_repeat_count(self):
        line = self._pan("vulnerability", kind="THREAT",
                         extra={23: "7", 30: "alert", 32: "SSH User Authentication Brute Force Attempt(40015)",
                                33: "any", 34: "high", 35: "client-to-server"})
        ef = self._ef("t.log", line + "\n")
        [c] = list(paloalto.parse(ef))
        self.assertEqual((c.threat.repeat, c.threat.is_brute_force, c.threat.blocked), (7, True, False))

    def test_without_threat_map_matches_by_port(self):
        case = make_demo_case.build(self.tmp / "c")
        ctx = run(case, self.tmp / "out", Settings(exclude_sources=[make_demo_case.NESSUS_SCANNER]), log=quiet)
        [f] = [f for f in ctx["findings"] if (f["target_ip"], f["port"]) == ("10.0.1.10", 443)]
        self.assertTrue(any("not mapped" in r for r in f["score_reasons"]))

    def test_nessus_scanner_is_flagged_unless_excluded(self):
        case = make_demo_case.build(self.tmp / "c")
        ctx = run(case, self.tmp / "out", Settings(threat_map=THREAT_MAP), log=quiet)
        [s] = [s for s in ctx["hostile_sources"] if s["source_ip"] == make_demo_case.NESSUS_SCANNER]
        self.assertIn("vertical-scan", s["kinds"])

    def test_palo_alto_only(self):
        case = make_demo_case.build(self.tmp / "c")
        shutil.rmtree(case / "zeek")
        ctx = run(case, self.tmp / "out", DEMO_SETTINGS(), log=quiet)
        self.assertEqual(ctx["sources"], ["nessus", "paloalto"])
        self.assertIn(("10.0.1.10", 443), [(f["target_ip"], f["port"]) for f in ctx["findings"]])
        self.assertTrue(any("ssh.log" in n for n in ctx["notices"]))

    def test_pan_syslog_header_variants(self):
        line = ("<14>Oct 10 02:00:00 fw 1,2026/10/10 02:00:00,0123,TRAFFIC,end,,2026/10/10 02:00:00,"
                "1.2.3.4,10.0.0.5,0.0.0.0,0.0.0.0,r,,,ssl,vsys1,u,t,e1,e2,d,,99,1,5555,443,0,0,,tcp,allow,10,5,5")
        self.assertTrue(paloalto.looks_like_syslog(line))
        self.assertFalse(paloalto.looks_like_syslog("hello,world"))
        self.assertTrue(paloalto.looks_like_header("Source Address,Destination Address,Destination Port,Action"))

    def test_single_contact_sources_are_cheap(self):
        lines = ["#separator \\x09", "#path\tconn",
                 "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state"]
        for i in range(5000):
            lines.append(f"{1000 + i}\tC{i}\t52.{i // 250}.{i % 250}.1\t1\t10.0.0.5\t443\ttcp\tS0")
        case = self.tmp / "c"
        case.mkdir()
        (case / "conn.log").write_text("\n".join(lines) + "\n")
        ctx = run(case, self.tmp / "out", log=quiet)
        self.assertTrue(any("5,000 source(s) made a single connection" in c for c in ctx["coverage"]))

    def test_diagram_scales(self):
        b = {"kind": "horizontal-scan", "source_ip": "", "external": True, "possible_success": False,
             "not_blocked": 0, "blocked": 0, "attempts": 1, "failed": 1}
        F = [{"target_ip": f"10.1.{i // 250}.{i % 250}", "target_hostname": "", "port": 445, "protocol": "tcp",
              "vulnerabilities": [], "behaviours": [dict(b, source_ip=f"52.0.{i // 250}.{i % 250}")]}
             for i in range(20000)]
        t = time.time()
        svg = render(F, [], [])
        self.assertLess(time.time() - t, 5)
        self.assertLessEqual(svg.count('class="node"'), 40)

    def test_csv_formula_injection_neutralised(self):
        f = {"id": "F1", "priority_score": 1, "target_ip": "2.2.2.2", "target_hostname": "=cmd|' /C calc'!A0",
             "port": 1, "protocol": "tcp", "vulnerabilities": [], "kinds": [], "possible_login_success": False,
             "outcome": "no-contact", "hostile_sources": [], "external_sources": 0, "first_seen": 0,
             "last_seen": 0, "chains": [], "scan_stale": False, "assessment": "", "score_reasons": [],
             "evidence": []}
        write_csv(self.tmp / "x.csv", [f])
        with open(self.tmp / "x.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        self.assertTrue(rows[1][3].startswith("'="))


if __name__ == "__main__":
    unittest.main()
