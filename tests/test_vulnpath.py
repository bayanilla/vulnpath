"""Tests run with the standard library only:  python -m unittest discover -s tests -v"""
import csv
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "samples"))

import make_demo_case  # noqa: E402
from vulnpath.chains import stage  # noqa: E402
from vulnpath.correlate import Settings  # noqa: E402
from vulnpath.detect import detect  # noqa: E402
from vulnpath.evidence import inventory, sha256_file  # noqa: E402
from vulnpath.model import Vulnerability  # noqa: E402
from vulnpath.parsers import nessus, paloalto, zeek  # noqa: E402
from vulnpath.pipeline import InputError, run  # noqa: E402
from vulnpath.report import write_csv  # noqa: E402


THREAT_MAP = str(ROOT / "samples" / "demo_threat_map.csv")


def DEMO_SETTINGS(**kw):
    return Settings(threat_map=THREAT_MAP, **kw)


class DemoCase(unittest.TestCase):
    """End-to-end run on the synthetic case, covering positive and negative scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.case = make_demo_case.build(cls.tmp / "case")
        cls.hashes = {p: sha256_file(p) for p in cls.case.rglob("*") if p.is_file()}
        cls.out = cls.tmp / "results"
        cls.ctx = run(cls.case, cls.out, DEMO_SETTINGS(), log=lambda m: None)
        cls.F = cls.ctx["findings"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def find(self, src, dst, port):
        return [f for f in self.F if (f["source_ip"], f["target_ip"], f["port"]) == (src, dst, port)]

    def test_outputs_written(self):
        for name in ["report.html", "attack_paths.svg", "findings.csv", "findings.json",
                     "evidence_manifest.json", "data_quality.json"]:
            self.assertTrue((self.out / name).stat().st_size > 0, name)

    def test_evidence_not_modified(self):
        for p, h in self.hashes.items():
            self.assertEqual(sha256_file(p), h, p)
        self.assertIn("none changed", self.ctx["integrity"])

    def test_external_to_vulnerable_service_is_established_targeting(self):
        [f] = self.find("203.0.113.60", "10.0.1.15", 443)
        self.assertEqual((f["activity"], f["outcome"], f["direction"]), ("targeting", "established", "inbound-external"))
        self.assertIn("CVE-2021-34473", f["vulnerabilities"][0]["cves"])
        self.assertTrue(any("line" in e for e in f["evidence"]))

    def test_multi_hop_path(self):
        hosts = [p["hosts"] for p in self.ctx["paths"]]
        self.assertIn(["203.0.113.50", "10.0.1.10", "10.0.2.20"], hosts)

    def test_time_order_respected(self):
        # mail01 -> app02 happened before mail01 was reached, so it must not extend the path.
        for p in self.ctx["paths"]:
            self.assertNotIn(["10.0.1.15", "10.0.2.20"], [p["hosts"][i:i + 2] for i in range(len(p["hosts"]) - 1)])

    def test_attempts_are_not_path_hops(self):
        for p in self.ctx["paths"]:
            self.assertNotIn("10.0.2.30", p["hosts"])
        [f] = self.find("10.0.2.20", "10.0.2.30", 445)
        self.assertEqual(f["outcome"], "attempted")

    def test_different_service_is_not_a_finding(self):
        # portal is vulnerable on 8009, users only talk to 443
        self.assertEqual(self.find("10.0.5.100", "10.0.1.30", 443), [])

    def test_scanner_is_probing(self):
        scan = [f for f in self.F if f["source_ip"] == "198.51.100.7"]
        self.assertTrue(scan)
        self.assertTrue(all(f["activity"] == "probing" and f["outcome"] == "attempted" for f in scan))

    def test_stale_scan_flagged(self):
        [f] = self.find("203.0.113.77", "10.0.1.40", 3389)
        self.assertTrue(f["scan_stale"])

    def test_never_claims_exploitation(self):
        for f in self.F:
            if f["outcome"] == "established":
                self.assertTrue("NOT evidence of exploitation" in f["assessment"]
                                or "not confirmation of exploitation" in f["assessment"], f["assessment"])
        for p in self.ctx["paths"]:
            self.assertEqual(p["status"], "candidate (hypothetical)")

    def test_documented_chain(self):
        c = [c for c in self.ctx["chains"] if c["host"] == "10.0.1.15"]
        self.assertEqual([x["type"] for x in c], ["documented"])
        self.assertEqual(set(c[0]["matched_cves"]), {"CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"})

    def test_generic_chain_uses_host_level_privesc(self):
        [c] = [c for c in self.ctx["chains"] if c["host"] == "10.0.1.10"]
        self.assertEqual(c["type"], "generic")
        self.assertIn("local", [s["stage"] for s in c["steps"]])
        self.assertTrue(c["entry_reached"])

    def test_no_chain_on_single_vuln_host(self):
        self.assertFalse([c for c in self.ctx["chains"] if c["host"] == "10.0.2.20"])

    def test_data_quality(self):
        dq = json.loads((self.out / "data_quality.json").read_text())
        [zeek_q] = [x for x in dq["per_file"] if x["path"].startswith("zeek/") and x["path"].endswith(".log")]
        self.assertEqual(zeek_q["skipped"], 1)
        self.assertTrue(any("analyst_notes.txt" in c for c in dq["coverage"]))

    def test_deterministic(self):
        out2 = self.tmp / "results2"
        ctx2 = run(self.case, out2, DEMO_SETTINGS(), log=lambda m: None)
        self.assertEqual(ctx2["findings"], self.F)
        self.assertEqual(ctx2["paths"], self.ctx["paths"])


    # ---- Palo Alto ----
    def test_unblocked_ips_alert_matching_cve(self):
        [f] = self.find("203.0.113.50", "10.0.1.10", 443)
        self.assertEqual(f["activity"], "exploit-attempt")
        self.assertEqual((f["ips"]["not_blocked"], f["ips"]["blocked"]), (3, 0))
        self.assertEqual(f["ips"]["cves_matched"], ["CVE-2021-41773"])
        self.assertIn("NOT blocked", f["assessment"])
        self.assertIn("not confirmation", f["assessment"])
        self.assertEqual(f["traffic"]["telemetry_sources"], ["paloalto", "zeek"])
        self.assertEqual(self.F[0]["id"], f["id"])  # ranked first

    def test_sensors_not_double_counted(self):
        # Zeek and the firewall both saw the same 12 sessions to web01:443
        [f] = self.find("203.0.113.50", "10.0.1.10", 443)
        self.assertEqual(f["traffic"]["established"], 12)
        self.assertEqual(set(f["traffic"]["by_source"]), {"zeek", "paloalto"})

    def test_blocked_ips_detection(self):
        [f] = self.find("203.0.113.77", "10.0.1.40", 3389)
        self.assertEqual((f["ips"]["not_blocked"], f["ips"]["blocked"]), (0, 6))
        self.assertIn("blocked them", f["assessment"])

    def test_nat_translated_to_scanned_address(self):
        [f] = self.find("203.0.113.90", "10.0.1.30", 8009)
        self.assertEqual(f["outcome"], "denied")
        self.assertEqual(f["traffic"]["pre_nat_destinations"], ["198.18.10.30:8009"])

    def test_pan_traffic_to_non_vulnerable_port_ignored(self):
        self.assertEqual(self.find("192.0.2.25", "10.0.1.30", 443), [])

    def test_firewall_scan_detection_is_probing(self):
        [f] = self.find("198.51.100.7", "10.0.1.10", 22)
        self.assertEqual(f["activity"], "probing")
        self.assertIn("paloalto", f["traffic"]["telemetry_sources"])

    def test_system_logs_skipped_not_errors(self):
        dq = json.loads((self.out / "data_quality.json").read_text())
        [pa] = [x for x in dq["per_file"] if x["path"].endswith("pa-syslog-collector.log")]
        self.assertEqual(pa["skipped"], 0)
        self.assertTrue(any("2 SYSTEM" in i for i in pa["issues"]))


class Units(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_detection_ignores_filenames(self):
        case = make_demo_case.build(self.tmp / "c")
        (case / "scans" / "internal_q4.nessus").rename(case / "scans" / "export.dat")
        (case / "zeek" / "conn.day2.json").rename(case / "zeek" / "random.txt")
        types = {ef.rel_path: detect(ef.path) for ef in inventory(case)}
        self.assertEqual(types["scans/export.dat"], "nessus")
        self.assertEqual(types["zeek/random.txt"], "zeek_conn")
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

    def test_nessus_rejects_dtd(self):
        p = self.tmp / "c" / "evil.nessus"
        p.parent.mkdir()
        p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><NessusClientData_v2/>')
        [ef] = inventory(self.tmp / "c")
        with self.assertRaises(ValueError):
            list(nessus.parse(ef, {}))

    def test_nessus_skips_info_items(self):
        case = make_demo_case.build(self.tmp / "c")
        [ef] = [e for e in inventory(case) if e.rel_path.endswith(".nessus")]
        hosts = {}
        vulns = list(nessus.parse(ef, hosts))
        self.assertFalse([v for v in vulns if v.plugin_id == "19506"])
        self.assertEqual(len(hosts), 6)
        self.assertIsNotNone(hosts["10.0.1.10"].scan_time)

    def test_output_inside_input_refused(self):
        case = make_demo_case.build(self.tmp / "c")
        with self.assertRaises(InputError):
            run(case, case / "results", log=lambda m: None)

    def test_missing_traffic_does_not_crash(self):
        case = make_demo_case.build(self.tmp / "c")
        shutil.rmtree(case / "zeek")
        shutil.rmtree(case / "firewall")
        ctx = run(case, self.tmp / "out", log=lambda m: None)
        self.assertEqual(ctx["findings"], [])
        self.assertTrue(any("No supported traffic" in n for n in ctx["notices"]))

    def test_stage_from_cvss(self):
        mk = lambda v3="", v2="": Vulnerability("h", "", 1, "tcp", "", "1", "", 3, cvss3_vector=v3, cvss2_vector=v2)  # noqa
        self.assertEqual(stage(mk("CVSS:3.0/AV:N/AC:L/PR:N/UI:N")), "remote-unauth")
        self.assertEqual(stage(mk("CVSS:3.1/AV:N/AC:L/PR:H/UI:N")), "remote-auth")
        self.assertEqual(stage(mk("CVSS:3.0/AV:L/AC:L/PR:L/UI:N")), "local")
        self.assertEqual(stage(mk(v2="CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P")), "remote-unauth")
        self.assertEqual(stage(mk()), "unknown")

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

    def test_without_threat_map_matches_by_port(self):
        case = make_demo_case.build(self.tmp / "c")
        ctx = run(case, self.tmp / "out", Settings(), log=lambda m: None)
        [f] = [f for f in ctx["findings"] if (f["source_ip"], f["port"]) == ("203.0.113.50", 443)]
        self.assertEqual(f["activity"], "exploit-attempt")
        self.assertEqual(f["ips"]["cves_matched"], [])
        self.assertIn("not mapped", f["assessment"])

    def test_palo_alto_only(self):
        case = make_demo_case.build(self.tmp / "c")
        shutil.rmtree(case / "zeek")
        ctx = run(case, self.tmp / "out", DEMO_SETTINGS(), log=lambda m: None)
        self.assertEqual(ctx["sources"], ["nessus", "paloalto"])
        self.assertIn(["203.0.113.50", "10.0.1.10"], [p["hosts"] for p in ctx["paths"]])

    def test_pan_syslog_header_variants(self):
        line = ("<14>Oct 10 02:00:00 fw 1,2026/10/10 02:00:00,0123,TRAFFIC,end,,2026/10/10 02:00:00,"
                "1.2.3.4,10.0.0.5,0.0.0.0,0.0.0.0,r,,,ssl,vsys1,u,t,e1,e2,d,,99,1,5555,443,0,0,,tcp,allow,10,5,5")
        self.assertTrue(paloalto.looks_like_syslog(line))
        self.assertFalse(paloalto.looks_like_syslog("hello,world"))
        self.assertTrue(paloalto.looks_like_header("Source Address,Destination Address,Destination Port,Action"))

    def test_csv_formula_injection_neutralised(self):
        f = {"id": "F1", "priority_score": 1, "activity": "targeting", "outcome": "attempted",
             "direction": "internal", "source_ip": "1.1.1.1", "target_ip": "2.2.2.2",
             "target_hostname": "=cmd|' /C calc'!A0", "port": 1, "protocol": "tcp",
             "vulnerabilities": [{"severity": "High", "cves": [], "exploit_available": False}],
             "traffic": {"established": 0, "attempts": 1, "denied": 0, "first_seen": 0, "last_seen": 0,
                         "pre_nat_destinations": []},
             "ips": {"not_blocked": 0, "blocked": 0, "signatures": [], "cves_matched": []},
             "scan_stale": False, "assessment": "", "evidence": []}
        write_csv(self.tmp / "x.csv", [f])
        with open(self.tmp / "x.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        self.assertTrue(rows[1][7].startswith("'="))


if __name__ == "__main__":
    unittest.main()
