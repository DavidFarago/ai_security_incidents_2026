"""Tests for helpers of scripts/build_vulnerabilities.py and scripts/fetch_upstream.py. No network access.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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
        rec = next(i for i in d["incidents"] if i["id"] == "DR-2026-081")
        d["incidents"].remove(rec)
        d["sub_threshold_incidents"] = [rec]
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
