"""Tests for helpers of scripts/build_vulnerabilities.py and scripts/fetch_upstream.py. No network access.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_vulnerabilities as bv  # noqa: E402
import fetch_upstream as fu  # noqa: E402

CREDITS = [{"value": "A", "type": "finder"}, {"value": "B", "type": "coordinator"},
           {"value": "C", "type": None}, {"value": "A", "type": "reporter"}, {"value": "D", "type": "tool"}]


class Credits(unittest.TestCase):
    def test_all_credits_with_role(self):
        self.assertEqual(bv.credits_all(CREDITS), "A (finder); B (coordinator); C; A (reporter); D (tool)")

    def test_discovery_credits_only_deduplicated(self):
        # coordinator is dropped; untyped C is kept; the second A (reporter) is a duplicate value.
        self.assertEqual(bv.credits_discovery(CREDITS), "A, C, D")

    def test_no_credits(self):
        self.assertEqual(bv.credits_all(None), "")
        self.assertEqual(bv.credits_discovery([]), "")


class Fetch(unittest.TestCase):
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
