"""The derived incident reports in incidents/ must equal what scripts/build_incidents_report.py renders from the JSON.

Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import copy
import csv
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import build_incidents_report as bir  # noqa: E402
import lib_corpus  # noqa: E402
from corpus_helpers import add_record, incident, next_id  # noqa: E402

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
    def test_sub_threshold_records_appear_only_in_the_sub_threshold_files(self):
        # 2026-081 has a CVE; 2026-065 has none (its class comes from ai_role).
        d = CORPUS
        texts = bir.render(d)
        for iid in ("2026-081", "2026-065"):
            title = incident(d, iid)["title"]
            with self.subTest(iid=iid):
                self.assertIn(title, texts["_sub_threshold.md"])
                self.assertIn(iid, texts["_sub_threshold.csv"])
                self.assertNotIn(title, texts[".md"])
                self.assertNotIn(iid, texts[".csv"])


class ScopeLine(unittest.TestCase):
    def test_later_records_are_counted(self):
        # Records numbered 100 or higher are not part of the 2026-08-26 consolidation (methodology §4.1).
        d = copy.deepcopy(CORPUS)
        add_record(d, "2026-081", next_id(d), "sub_threshold_incidents")
        later = sum(1 for _, x in lib_corpus.numbered_ids(d) if lib_corpus.incident_number(x) >= 100)
        line = next(x for x in bir.render(d)[".md"].splitlines() if x.startswith("- **Scope & union.**"))
        self.assertIn(f"{later} record{'' if later == 1 else 's'} numbered 100 or higher", line)
        self.assertIn(f"lists the {len(d['incidents'])} counted incidents", line)


class IdLine(unittest.TestCase):
    def test_format_and_counts_per_source_kind(self):
        # Methodology §4.1: the ID is 2026-nnn; source_kind DB/DR tells register-listed records from the others.
        line = next(x for x in bir.render(CORPUS)[".md"].splitlines() if x.startswith("- **Incident IDs.**"))
        self.assertIn("`2026-nnn`", line)
        for k in ("DB", "DR"):
            n = sum(1 for i in CORPUS["incidents"] if i.get("source_kind") == k)
            self.assertIn(f"`source_kind` {k}", line)
            self.assertIn(f"{n} incidents", line)


class SourceLine(unittest.TestCase):
    def test_live_aiid_is_counted(self):
        # Incidents added to AIID after the export of 2026-08-24 cite the live AIID (`incidentdatabase.ai`).
        n = sum(1 for i in CORPUS["incidents"] for s in i["sources"] if s["source"] == "incidentdatabase.ai")
        self.assertGreater(n, 0)
        line = next(x for x in bir.render(CORPUS)[".md"].splitlines() if x.startswith("- **Original sources cited**"))
        self.assertIn(f"AIID (live) {n}", line)

    def test_live_aiid_link_is_labelled_like_the_export(self):
        url = "https://incidentdatabase.ai/cite/1627"
        self.assertEqual(bir.cite_md({"source": "incidentdatabase.ai", "locator": "AIID 1627", "url": url}), f"[AIID 1627]({url})")


class AiInitiatedColumns(unittest.TestCase):
    def test_three_states_and_the_rationale(self):
        # Methodology §5.3: report.ai_initiated is true, false or absent; the CSV writes true, false or an empty cell.
        d = copy.deepcopy(CORPUS)
        for iid, value in (("2026-006", True), ("2026-002", False)):
            rep = incident(d, iid)["report"]
            rep["ai_initiated"], rep["ai_initiated_rationale"] = value, f"Reason for {iid}."
        for k in ("ai_initiated", "ai_initiated_rationale"):
            incident(d, "2026-028")["report"].pop(k, None)
        rep = incident(d, "2026-035")["report"]
        rep.pop("ai_initiated", None)
        rep["ai_initiated_rationale"] = "Reason for 2026-035."
        rows = list(csv.reader(io.StringIO(bir.render_csv(d["incidents"]))))
        head = rows[0]
        self.assertLess(head.index("ai_security_mechanism"), head.index("ai_initiated"))
        self.assertLess(head.index("potential_severity_rationale"), head.index("ai_initiated_rationale"))
        by_id = {row[0]: dict(zip(head, row)) for row in rows[1:]}
        self.assertEqual(by_id["2026-006"]["ai_initiated"], "true")
        self.assertEqual(by_id["2026-002"]["ai_initiated"], "false")
        self.assertEqual(by_id["2026-028"]["ai_initiated"], "")
        self.assertEqual(by_id["2026-006"]["ai_initiated_rationale"], "Reason for 2026-006.")
        self.assertEqual(by_id["2026-028"]["ai_initiated_rationale"], "")
        # A rationale without the flag (methodology §5.3): empty flag cell, rationale written.
        self.assertEqual(by_id["2026-035"]["ai_initiated"], "")
        self.assertEqual(by_id["2026-035"]["ai_initiated_rationale"], "Reason for 2026-035.")


class VerisCategories(unittest.TestCase):
    def test_block_without_variety_has_no_colon(self):
        # VERIS actor.partner and action.unknown have no variety.
        blocks = {"partner": {"motive": ["NA"]}, "internal": {"variety": ["Developer", "Other"]}}
        self.assertEqual(bir.veris_categories(blocks), "partner; internal:Developer; Other")


if __name__ == "__main__":
    unittest.main()
