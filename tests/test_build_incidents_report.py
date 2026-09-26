"""The derived incident reports in incidents/ must equal what scripts/build_incidents_report.py renders from the JSON.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_incidents_report as bir  # noqa: E402
import lib_corpus  # noqa: E402

BASE = ROOT / "incidents" / "all_2026_ai_software_security_incidents"


class ReportsUpToDate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csv_text, cls.md_text = bir.render(lib_corpus.load_corpus(lib_corpus.JSON_PATH))

    def test_csv_matches(self):
        self.assertEqual(self.csv_text, BASE.with_suffix(".csv").read_bytes().decode("utf-8"))

    def test_md_matches(self):
        want = BASE.with_suffix(".md").read_text(encoding="utf-8").splitlines()
        got = self.md_text.splitlines()
        for n, (g, w) in enumerate(zip(got, want), 1):
            self.assertEqual(g, w, f"first difference at line {n}")
        self.assertEqual(len(got), len(want))
        self.assertEqual(self.md_text, BASE.with_suffix(".md").read_text(encoding="utf-8"))


class VerisCategories(unittest.TestCase):
    def test_block_without_variety_has_no_colon(self):
        # VERIS actor.partner and action.unknown have no variety.
        blocks = {"partner": {"motive": ["NA"]}, "internal": {"variety": ["Developer", "Other"]}}
        self.assertEqual(bir.veris_categories(blocks), "partner; internal:Developer; Other")


if __name__ == "__main__":
    unittest.main()
