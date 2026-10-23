"""Tests for helpers of scripts/build_vulnerabilities.py and scripts/fetch_upstream.py. No network access.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import build_vulnerabilities as bv  # noqa: E402
import fetch_upstream as fu  # noqa: E402
import lib_corpus as lc  # noqa: E402

CORPUS = lc.load_corpus(lc.JSON_PATH)
CREDITS = [{"value": "A", "type": "finder"}, {"value": "B", "type": "coordinator"},
           {"value": "C", "type": None}, {"value": "A", "type": "reporter"}, {"value": "D", "type": "tool"}]
NO_UPSTREAM = ({"cve.org": {}, "ghsa": {}, "osv": {}}, {})


def action_rows(d, upstream=NO_UPSTREAM):
    """The action list of a corpus, each row as {column: value}."""
    h, rows = bv.table_action_list(d, bv.build_links(d), *upstream)
    return [dict(zip(h, r)) for r in rows]


def one_cve_record(iid, potential, cve, relation, cvss):
    """A minimal live record with one validated CVE, enough for the CVE-side tables."""
    return {"id": iid, "title": iid, "date": "2026",
            "report": {"ai_role": ["AI system/harness attacked"], "observed_severity": "Negligible", "potential_severity": potential},
            "validated_cve": [cve],
            "validated_cve_details": {"cves": [{"cve": cve, "relation": relation, "cvss_version": "3.1", "cvss_score": cvss,
                                                "cisa_kev": False, "cwe": [], "cna": "test", "published": "2026-01-01",
                                                "product": "test/test", "title": cve}]}}


class Credits(unittest.TestCase):
    def test_all_credits_with_role(self):
        self.assertEqual(bv.credits_all(CREDITS), "A (finder); B (coordinator); C; A (reporter); D (tool)")

    def test_discovery_credits_only_deduplicated(self):
        # coordinator is dropped; untyped C is kept; the second A (reporter) is a duplicate value.
        self.assertEqual(bv.credits_discovery(CREDITS), "A, C, D")

    def test_no_credits(self):
        self.assertEqual(bv.credits_all(None), "")
        self.assertEqual(bv.credits_discovery([]), "")


class InPlay(unittest.TestCase):
    """Methodology §3.3 "Scores": a CVE link is in play when the CVE's flaw is part of what happened in the event."""

    def test_table_covers_every_relation_once(self):
        rels = [r for _, group, _ in lc.IN_PLAY_TABLE for r in group]
        self.assertEqual(sorted(rels), sorted(lc.RELATION_ORDER))

    def test_discovered_cve_gets_ibss(self):
        # CVE-2026-5194 (wolfSSL) is linked only by `discovered` (DR-2026-058).
        self.assertIn("CVE-2026-5194", bv.ibss_per_cve(bv.build_links(CORPUS)))

    def test_toolkit_and_related_never_count(self):
        self.assertFalse({"toolkit", "related"} & lc.IN_PLAY)

    def test_firefox_rollups_are_ai_discovered(self):
        # DR-2026-095 is a discovery campaign: Mozilla shipped the Claude Mythos Preview finds in three rollup CVEs.
        rec = next(i for i in lc.records(CORPUS) if i["id"] == "DR-2026-095")
        self.assertEqual(lc.disclosure_classes(rec), {"AI-discovered"})


COUNTED, SUB = "incidents", "sub_threshold_incidents"


class Ibss(unittest.TestCase):
    """lc.ibss, the per-entity score of methodology §3.3 "Scores"; adversarial examples of the step-2c plan."""

    def test_counted_record_adds_once(self):
        # One counted incident reaches a CWE through three CVEs.
        s = lc.ibss([(COUNTED, "DR-2026-001", "High", "Critical", {"AI-stack"})] * 3)
        self.assertEqual((s.obs, s.pot), (8, 16))

    def test_one_weight_per_class(self):
        # A counted High/High record, two AI-discovered and two AI-stack sub-threshold records.
        s = lc.ibss([(COUNTED, "DB-2026-001", "High", "High", set()),
                     (SUB, "DR-2026-101", "Negligible", "High", {"AI-discovered"}),
                     (SUB, "DR-2026-102", "Negligible", "Medium", {"AI-discovered"}),
                     (SUB, "DR-2026-103", "Low", "Medium", {"AI-stack"}),
                     (SUB, "DR-2026-104", "Negligible", "High", {"AI-stack"})])
        self.assertEqual((s.obs, s.pot), (8 + 1 + 2, 8 + 8 + 8))
        self.assertEqual(s.pot_tiers, ("High", "High", "High"))

    def test_maxima_from_different_records(self):
        s = lc.ibss([(SUB, "DR-2026-101", "Low", "Medium", {"AI-stack"}),
                     (SUB, "DR-2026-102", "Negligible", "High", {"AI-stack"})])
        self.assertEqual((s.obs, s.pot), (2, 8))

    def test_record_with_two_classes_enters_both(self):
        s = lc.ibss([(SUB, "DR-2026-101", "Low", "High", {"AI-stack"}),
                     (SUB, "DR-2026-101", "Low", "High", {"AI-discovered"})])
        self.assertEqual((s.obs, s.pot), (4, 16))

    def test_analyst_path_and_cve_path(self):
        # Thread B: an analyst CWE (report.weaknesses[].cwe) counts under all classes of its record.
        counted = lc.ibss([(COUNTED, "DB-2026-001", "High", "High", {"AI-stack"}),
                           (COUNTED, "DB-2026-001", "High", "High", {"AI-stack", "AI-discovered"})])
        self.assertEqual((counted.obs, counted.pot), (8, 8))
        sub = lc.ibss([(SUB, "DR-2026-101", "Negligible", "High", {"AI-stack"}),
                       (SUB, "DR-2026-101", "Negligible", "High", {"AI-stack", "AI-discovered"})])
        self.assertEqual((sub.obs, sub.pot), (2, 16))

    def test_sub_threshold_contribution_needs_a_class(self):
        with self.assertRaises(ValueError):
            lc.ibss([(SUB, "DR-2026-101", "Low", "High", set())])

    def test_weights_are_a_parameter(self):
        linear = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1}
        s = lc.ibss([(COUNTED, "DB-2026-001", "High", "Critical", set()),
                     (SUB, "DR-2026-101", "Low", "Medium", {"AI-stack"})], weights=linear)
        self.assertEqual((s.obs, s.pot), (4 + 2, 5 + 3))

    def test_related_link_does_not_count(self):
        # CVE-2026-30623: DR-2026-059 (counted, self-vulnerability) and DR-2026-080 (sub-threshold, related).
        d = CORPUS
        rec = next(i for i in d["incidents"] if i["id"] == "DR-2026-059")
        want = (lc.SEV_WEIGHT[rec["report"]["observed_severity"]], lc.SEV_WEIGHT[rec["report"]["potential_severity"]])
        got = bv.ibss_per_cve(bv.build_links(d))["CVE-2026-30623"]
        self.assertEqual((got["obs"], got["pot"]), want)

    def test_class_cap_on_real_records(self):
        # CVE-2026-54316 is in DR-2026-056 (potential Critical) and DR-2026-062 (High), both AI-stack disclosures.
        d = CORPUS
        self.assertEqual(bv.ibss_per_cve(bv.build_links(d))["CVE-2026-54316"]["pot"], 16)


class BothArrays(unittest.TestCase):
    """The CVE-side tables read both live arrays; every CVE, in-play CNA CWE and non-CVE identifier appears there."""

    def rows(self, table):
        h, rows = table
        return [dict(zip(h, r)) for r in rows]

    def test_sub_threshold_cve_is_listed(self):
        d = CORPUS
        row = next(r for r in self.rows(bv.table_cve_incidents(bv.build_links(d))) if r["cve"] == "CVE-2026-42824")
        self.assertEqual((row["incident_count"], row["sub_threshold_incident_count"], row["sub_threshold_incidents"]),
                         (0, 1, ["DR-2026-081"]))

    def expected(self, d):
        """Every CVE, every CNA CWE of an in-play link and every non-CVE identifier of the live records."""
        cves, cwes, non = set(), set(), set()
        for rec, c in lc.cve_links(d):
            cves.add(c["cve"])
            if c["relation"] in lc.IN_PLAY:
                cwes.update(c.get("cwe") or [])
        for rec in lc.records(d):
            non.update(n["id"] for n in (rec.get("validated_cve_details") or {}).get("non_cve_identifiers") or [])
        return cves, cwes, non

    def test_coverage_in_memory(self):
        # Sub-threshold records such as DR-2026-081 and DR-2026-088 (which alone carries CWE-121 and other CWEs of its
        # AI-discovered CVEs) must reach every table.
        d = CORPUS
        links = bv.build_links(d)
        cves, cwes, non = self.expected(d)
        self.assertEqual(cves - {r["cve"] for r in self.rows(bv.table_cve_incidents(links))}, set())
        self.assertEqual(cwes - {r["cwe"] for r in self.rows(bv.table_cwe_ibss_cve_path(links))}, set())
        self.assertEqual(non - {r["identifier"] for r in self.rows(bv.table_non_cve(d))}, set())

    def test_coverage_of_the_files(self):
        def column(name, col):
            with (ROOT / "vulnerabilities" / name).open(encoding="utf-8") as fh:
                return {r[col] for r in csv.DictReader(fh)}
        cves, cwes, non = self.expected(CORPUS)
        self.assertEqual(cves - column("cve_incidents.csv", "cve"), set())
        self.assertEqual(cwes - column("cwe_ibss_cve_path.csv", "cwe"), set())
        self.assertEqual(non - column("non_cve_identifiers.csv", "identifier"), set())

    def test_md_table_rejects_a_short_row(self):
        with self.assertRaises(ValueError):
            bv.md_table(["a", "b"], [["only one cell"]])


class ActionList(unittest.TestCase):
    def test_discovered_cve_is_patched(self):
        row = next(r for r in action_rows(CORPUS) if r["identifier"] == "CVE-2026-5194")
        self.assertEqual((row["action"], row["evidence"], row["scope"]), ("patch", "discovered", "AI-discovered disclosure"))

    def test_order_by_ibss_potential_then_cvss(self):
        # The finder is no triage signal: a `discovered` CVE ranks with `self-vulnerability` ones, and IBSS potential
        # orders before CVSS (automate_sourcing_handover.md §5.8 item 5).
        d = {"incidents": [one_cve_record("DR-2026-001", "High", "CVE-2000-0002", "self-vulnerability", 9.8),
                           one_cve_record("DR-2026-002", "Critical", "CVE-2000-0001", "discovered", 5.0),
                           one_cve_record("DR-2026-003", "High", "CVE-2000-0003", "self-vulnerability", 7.0)]}
        rows = [r for r in action_rows(d) if r["action"] == "patch"]
        self.assertEqual([(r["identifier"], r["ibss_potential"]) for r in rows],
                         [("CVE-2000-0001", 16), ("CVE-2000-0002", 8), ("CVE-2000-0003", 8)])


class Fetch(unittest.TestCase):
    def test_ids_include_sub_threshold_records(self):
        # Class A checks sub-threshold records too, so the fetcher must cache their CVEs (methodology §10.2).
        d = json.loads(fu.JSON_PATH.read_text(encoding="utf-8"))
        self.assertIn("DR-2026-081", [i["id"] for i in d["sub_threshold_incidents"]])
        self.assertIn("CVE-2026-42824", fu.ids_from_json(d)[0])

    def test_titleless_cves_from_cache(self):
        self.assertEqual(fu.titleless_cves(["CVE-2021-3156", "CVE-2026-33017", "CVE-0000-0000"]), ["CVE-2021-3156"])

    def test_cached_404_is_not_fetched_again(self):
        def no_network(*a, **k):
            raise AssertionError("run() must not fetch a lookup whose 404 is cached")
        orig, fu.get = fu.get, no_network
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "osv-by-cve" / "CVE-2000-0001.json"
                manifest = {"osv-by-cve:CVE-2000-0001": {"http_status": 404}}
                plan = [("osv-by-cve", "osv-by-cve:CVE-2000-0001", out, "https://example.invalid", {}, 0, lambda r: None)]
                self.assertEqual(fu.run(plan, manifest, Path(tmp) / "manifest.json", False, "2026-09-26"), (0, 1, 0))
        finally:
            fu.get = orig


if __name__ == "__main__":
    unittest.main()
