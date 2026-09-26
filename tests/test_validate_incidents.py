"""Tests for scripts/validate_incidents.py.

Each mutation test changes one value in an in-memory copy of the corpus (or of the upstream cache) and asserts
that the verifier reports exactly that defect. The corpus and the cache are read once from the repository.
Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lib_corpus  # noqa: E402
import validate_incidents as vi  # noqa: E402

CORPUS = lib_corpus.load_corpus(lib_corpus.JSON_PATH)
UPSTREAM = lib_corpus.load_upstream(lib_corpus.UPSTREAM_DIR)


def incident(d, iid):
    return next(i for i in d["incidents"] if i["id"] == iid)


def link(d, iid, cve):
    return next(c for c in incident(d, iid)["validated_cve_details"]["cves"] if c["cve"] == cve)


def has(result, check, **where):
    return any(f.check == check and all(getattr(f, k) == v for k, v in where.items()) for f in result.errors)


class RealCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = vi.validate(CORPUS, UPSTREAM)

    def test_no_class_a_errors(self):
        a = [f for f in self.r.errors if f.cls == "A"]
        self.assertEqual(a, [], "\n".join(map(str, a[:20])))

    def test_no_errors(self):
        # The gate is green: no error of either class, including veris-schema.
        self.assertEqual(self.r.errors, [], "\n".join(map(str, self.r.errors[:20])))

    def test_disclosure_rule_measurement(self):
        self.assertEqual(
            sorted(self.r.measurements["disclosure_rule_fails"]),
            ["DR-2026-%03d" % n for n in (79, 80, 81, 83, 84, 85, 87, 88, 89, 91, 93, 94, 95)],
        )

    def test_core_checks_pass(self):
        self.assertEqual(vi.core_checks(CORPUS), [])


class Mutations(unittest.TestCase):
    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self, up=UPSTREAM):
        return vi.validate(self.d, up)

    # ---- Class A
    def test_wrong_cna(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["cna"] = "someone"
        self.assertTrue(has(self.run_v(), "cna", cve="CVE-2026-33017", incident="DR-2026-008"))

    def test_wrong_published(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["published"] = "2020-01-01"
        self.assertTrue(has(self.run_v(), "published", cve="CVE-2026-33017"))

    def test_wrong_product(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["product"] = "x/y"
        self.assertTrue(has(self.run_v(), "product", cve="CVE-2026-33017"))

    def test_wrong_title(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["title"] = "made up"
        self.assertTrue(has(self.run_v(), "title", cve="CVE-2026-33017"))

    def test_cvss_score_not_in_any_container(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["cvss_score"] = 1.1
        self.assertTrue(has(self.run_v(), "cvss", cve="CVE-2026-33017"))

    def test_cvss_version_and_score_from_different_entries(self):
        # CVE-2026-1979 has CNA scores 4.0/4.8 and 2.0/4.3: the pair 4.0/4.3 exists nowhere.
        iid = next(i["id"] for i in self.d["incidents"] if "CVE-2026-1979" in (i.get("validated_cve") or []))
        c = link(self.d, iid, "CVE-2026-1979")
        c["cvss_version"], c["cvss_score"] = "4.0", 4.3
        self.assertTrue(has(self.run_v(), "cvss", cve="CVE-2026-1979"))

    def test_cwe_not_in_upstream(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["cwe"] = ["CWE-1"]
        self.assertTrue(has(self.run_v(), "cwe", cve="CVE-2026-33017"))

    def test_upstream_rejected(self):
        up = copy.deepcopy(UPSTREAM)
        up["cve.org"]["CVE-2026-33017"]["cveMetadata"]["state"] = "REJECTED"
        self.assertTrue(has(self.run_v(up), "state", cve="CVE-2026-33017"))

    def test_kev_flag_for_non_kev_cve(self):
        c = link(self.d, "DR-2026-008", "CVE-2026-21858")
        self.assertFalse(c["cisa_kev"])
        c["cisa_kev"], c["kev_date_added"] = True, "2026-01-01"
        self.assertTrue(has(self.run_v(), "cisa_kev", cve="CVE-2026-21858"))

    def test_kev_date_wrong(self):
        c = link(self.d, "DR-2026-008", "CVE-2026-33017")
        self.assertTrue(c["cisa_kev"])
        c["kev_date_added"] = "2020-01-01"
        self.assertTrue(has(self.run_v(), "kev_date_added", cve="CVE-2026-33017"))

    def test_credit_type_wrong(self):
        c = link(self.d, "DR-2026-085", "CVE-2026-55803")
        self.assertEqual(c["credits"][0], {"value": "Michael Maturi (michaelmaturi)", "type": "finder"})
        c["credits"][0]["type"] = "coordinator"
        self.assertTrue(has(self.run_v(), "credits", cve="CVE-2026-55803"))

    def test_credit_user_must_be_copied(self):
        up = copy.deepcopy(UPSTREAM)
        up["cve.org"]["CVE-2026-55803"]["containers"]["cna"]["credits"][0]["user"] = "00000000-0000-4000-8000-000000000000"
        self.assertTrue(has(self.run_v(up), "credits", cve="CVE-2026-55803"))

    def test_credit_dropped(self):
        c = link(self.d, "DR-2026-085", "CVE-2026-55803")
        c["credits"].pop()
        self.assertTrue(has(self.run_v(), "credits", cve="CVE-2026-55803"))

    def test_override_accepts_named_field_only(self):
        c = link(self.d, "DR-2026-008", "CVE-2026-33017")
        c["cna"], c["published"] = "someone", "2020-01-01"
        c["overrides"] = {"cna": "test reason"}
        r = self.run_v()
        self.assertFalse(has(r, "cna", cve="CVE-2026-33017"))
        self.assertTrue(has(r, "published", cve="CVE-2026-33017"))
        self.assertIn(("DR-2026-008", "CVE-2026-33017", "cna", "test reason"), r.overrides)

    def test_titleless_cve_needs_cached_alias_lookup(self):
        up = copy.deepcopy(UPSTREAM)
        cve = "CVE-2026-30623"  # no CNA title, not on KEV: the chain needs the alias lookups
        up["manifest"].pop("ghsa-by-cve:" + cve, None)
        self.assertTrue(has(self.run_v(up), "title-lookup", cve=cve))

    # ---- Class B
    def test_validated_cve_differs_from_details(self):
        incident(self.d, "DR-2026-008")["validated_cve"].append("CVE-2000-0001")
        self.assertTrue(has(self.run_v(), "validated-cve-set", incident="DR-2026-008"))

    def test_added_wrong(self):
        incident(self.d, "DR-2026-008")["validated_cve_details"]["added"] = []
        self.assertTrue(has(self.run_v(), "added", incident="DR-2026-008"))

    def test_in_original_wrong(self):
        c = link(self.d, "DR-2026-008", "CVE-2026-33017")
        c["in_original"] = not c["in_original"]
        self.assertTrue(has(self.run_v(), "in-original", incident="DR-2026-008"))

    def test_non_exploited_cve_in_veris_action(self):
        i = incident(self.d, "DR-2026-008")
        i["veris"]["action"].setdefault("hacking", {})["cve"] = "CVE-2026-33017; CVE-2026-21858"  # 2nd is attempted
        self.assertTrue(has(self.run_v(), "veris-action-cve", incident="DR-2026-008"))

    def test_exploited_cve_missing_from_veris_action(self):
        i = incident(self.d, "DR-2026-008")
        i["veris"]["action"]["hacking"]["cve"] = "CVE-2026-33017"
        self.assertTrue(has(self.run_v(), "veris-action-cve", incident="DR-2026-008"))

    def test_unknown_relation(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["relation"] = "primary"
        self.assertTrue(has(self.run_v(), "relation", cve="CVE-2026-33017"))

    def test_kev_date_without_flag(self):
        c = link(self.d, "DR-2026-008", "CVE-2026-21858")
        c["kev_date_added"] = "2026-01-01"
        self.assertTrue(has(self.run_v(), "kev-date-iff-flag", cve="CVE-2026-21858"))

    def test_intrinsic_fields_differ_between_incidents(self):
        # CVE-2026-33634 is cited by DB-2026-001 and DR-2026-010.
        link(self.d, "DR-2026-010", "CVE-2026-33634")["note"] = "x"  # note is per link: allowed
        self.assertFalse(has(self.run_v(), "intrinsic-agree", cve="CVE-2026-33634"))
        link(self.d, "DR-2026-010", "CVE-2026-33634")["cna"] = "someone"
        self.assertTrue(has(self.run_v(), "intrinsic-agree", cve="CVE-2026-33634"))

    def test_count_by_status_wrong(self):
        self.d["counts"]["by_status"]["Confirmed"] += 1
        self.assertTrue(has(self.run_v(), "counts"))

    def test_ranking_table_mismatch(self):
        self.d["ranking_table"][0]["observed"] = "Low"
        self.assertTrue(has(self.run_v(), "ranking-table", incident="DB-2026-001"))

    def test_db_prefix_without_register_source(self):
        i = incident(self.d, "DB-2026-001")
        for s in i["sources"]:
            s["source"] = "Grok_DeepResearch_ai_incidents_2026.md"
        self.assertTrue(has(self.run_v(), "id-prefix", incident="DB-2026-001"))

    def test_duplicate_number(self):
        self.d["incidents"][1]["id"] = self.d["incidents"][0]["id"]
        self.assertTrue(has(self.run_v(), "id-unique"))

    def test_source_not_in_catalog(self):
        incident(self.d, "DB-2026-001")["sources"][0]["source"] = "unknown.md"
        self.assertTrue(has(self.run_v(), "source-catalog", incident="DB-2026-001"))

    def test_veris_schema_violation(self):
        i = incident(self.d, "DB-2026-001")
        i["veris"]["actor"]["external"]["variety"] = ["Martian"]
        self.assertTrue(has(self.run_v(), "veris-schema", incident="DB-2026-001"))

    def test_core_checks_numbering_gap(self):
        self.d["incidents"].pop(5)
        self.assertTrue(vi.core_checks(self.d))

    def test_malformed_id_is_reported_not_raised(self):
        self.d["incidents"][0]["id"] = "DB-2026-01a"
        r = self.run_v()   # must not raise ValueError
        self.assertTrue(has(r, "id-format", incident="DB-2026-01a"))
        self.assertTrue(any(f.check == "id-format" for f in vi.core_checks(self.d)))
        self.assertFalse(has(r, "numbering"), "numbering must be skipped, not reported, while an ID is malformed")

    def test_malformed_id_stops_builder_with_message(self):
        import build_incidents_report as bir
        self.d["incidents"][0]["id"] = "DB-2026-01a"
        with self.assertRaises(SystemExit) as cm:
            bir.render(self.d)
        self.assertIn("DB-2026-01a", str(cm.exception.code))

    def test_relation_containing_order_is_filed_as_relation(self):
        link(self.d, "DR-2026-008", "CVE-2026-33017")["relation"] = "border"
        r = self.run_v()
        self.assertTrue(has(r, "relation", incident="DR-2026-008", cve="CVE-2026-33017"))
        self.assertFalse(has(r, "numbering"))

    def test_credits_missing_although_record_has_them(self):
        del link(self.d, "DR-2026-085", "CVE-2026-55803")["credits"]
        self.assertTrue(has(self.run_v(), "credits", cve="CVE-2026-55803"))

    def test_related_only_incident_is_no_disclosure(self):
        # DR-2026-025 has only 'related' CVEs; with Negligible harm it would fail (a) and (c), but it is no disclosure.
        incident(self.d, "DR-2026-025")["report"]["observed_severity"] = "Negligible"
        self.assertNotIn("DR-2026-025", self.run_v().measurements["disclosure_rule_fails"])

    def test_review_list_from_incident_100(self):
        new = copy.deepcopy(incident(self.d, "DR-2026-081"))   # self-vulnerability only, no KEV, Negligible
        new["id"] = new["veris"]["incident_id"] = "DR-2026-100"
        self.d["incidents"].append(new)
        review = self.run_v().measurements["decision1_review"]
        self.assertIn("DR-2026-100", review)
        self.assertNotIn("DR-2026-081", review, "the list starts at incident 100")


if __name__ == "__main__":
    unittest.main()
