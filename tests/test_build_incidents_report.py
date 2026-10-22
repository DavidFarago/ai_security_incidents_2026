"""The derived incident reports in incidents/ must equal what scripts/build_incidents_report.py renders from the JSON.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import build_incidents_report as bir  # noqa: E402
import lib_corpus  # noqa: E402
from corpus_helpers import incident, move  # noqa: E402

BASE = ROOT / "incidents" / "all_2026_ai_software_security_incidents"
CORPUS = lib_corpus.load_corpus(lib_corpus.JSON_PATH)


class ReportsUpToDate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = bir.render(CORPUS)

    def test_four_files(self):
        self.assertEqual(sorted(self.texts), sorted([".csv", ".md", "_sub_threshold.csv", "_sub_threshold.md"]))

    def test_csv_files_match(self):
        for suffix in (".csv", "_sub_threshold.csv"):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.texts[suffix], Path(f"{BASE}{suffix}").read_bytes().decode("utf-8"))

    def test_md_files_match(self):
        for suffix in (".md", "_sub_threshold.md"):
            with self.subTest(suffix=suffix):
                want = Path(f"{BASE}{suffix}").read_text(encoding="utf-8").splitlines()
                got = self.texts[suffix].splitlines()
                for n, (g, w) in enumerate(zip(got, want), 1):
                    self.assertEqual(g, w, f"first difference at line {n}")
                self.assertEqual(len(got), len(want))


class SubThresholdReport(unittest.TestCase):
    def test_moved_records_appear_only_in_the_sub_threshold_files(self):
        # DR-2026-081 has a CVE; DR-2026-065 has none (its class comes from ai_role).
        d = copy.deepcopy(CORPUS)
        for iid in ("DR-2026-081", "DR-2026-065"):
            move(d, iid)
        texts = bir.render(d)
        for iid in ("DR-2026-081", "DR-2026-065"):
            title = incident(d, iid)["title"]
            with self.subTest(iid=iid):
                self.assertIn(title, texts["_sub_threshold.md"])
                self.assertIn(iid, texts["_sub_threshold.csv"])
                self.assertNotIn(title, texts[".md"])
                self.assertNotIn(iid, texts[".csv"])


class VerisCategories(unittest.TestCase):
    def test_block_without_variety_has_no_colon(self):
        # VERIS actor.partner and action.unknown have no variety.
        blocks = {"partner": {"motive": ["NA"]}, "internal": {"variety": ["Developer", "Other"]}}
        self.assertEqual(bir.veris_categories(blocks), "partner; internal:Developer; Other")


if __name__ == "__main__":
    unittest.main()
