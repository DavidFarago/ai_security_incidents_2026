"""Tests for scripts/validate_incidents.py.

Each mutation test changes one value in an in-memory copy of the corpus (or of the upstream cache) and asserts
that the verifier reports exactly that defect. The corpus and the cache are read once from the repository.
Run: python3 -m unittest discover tests
"""
from __future__ import annotations

import copy
import sys
import unittest
from collections import Counter
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


def has(result, check, msg=None, **where):
    """A finding of `check` at `where`, whose message contains `msg` when given."""
    return any(f.check == check and (msg is None or msg in f.message) and all(getattr(f, k) == v for k, v in where.items())
               for f in result.errors)


def by_number(rec):
    return lib_corpus.incident_number(rec["id"])


def take(d, iid):
    """Remove a counted record from incidents and its ranking_table row."""
    rec = incident(d, iid)
    d["incidents"].remove(rec)
    d["ranking_table"] = [x for x in d["ranking_table"] if x["id"] != iid]
    return rec


def move(d, iid):
    """Move a counted record to sub_threshold_incidents (methodology §3.3), keeping that array in ID order."""
    rec = take(d, iid)
    d.setdefault("sub_threshold_incidents", []).append(rec)
    d["sub_threshold_incidents"].sort(key=by_number)
    return rec


def sub(d, iid):
    return next(i for i in d["sub_threshold_incidents"] if i["id"] == iid)


def retire(d, iid, into, reason="duplicate"):
    """Retire a counted record (methodology §10.2): frozen, in a wrapper in retired_incidents, in ID order."""
    w = {"id": iid, "retired_on": "2026-10-03", "reason": reason, "into": into, "note": "test", "record": take(d, iid)}
    d.setdefault("retired_incidents", []).append(w)
    d["retired_incidents"].sort(key=by_number)
    return w


def add_record(d, like, iid, array="incidents", bump=True):
    """Append a copy of `like` with a new ID to `array`; with bump, raise id_scheme.highest_assigned to its number."""
    new = copy.deepcopy(incident(d, like))
    new["id"] = new["veris"]["incident_id"] = iid
    d.setdefault(array, []).append(new)
    if bump:
        d["id_scheme"]["highest_assigned"] = lib_corpus.incident_number(iid)
    return new


def recount(d):
    """Recompute counts.* and id_scheme.counts over incidents, as an analyst fixing them by hand would."""
    inc, cnt = d["incidents"], d["counts"]
    cnt["total_incidents"] = len(inc)
    cnt["by_observed_severity"] = {s: sum(1 for i in inc if i["report"]["observed_severity"] == s) for s in lib_corpus.SEVERITIES}
    cnt["by_status"] = {s: sum(1 for i in inc if i["veris"]["security_incident"] == s) for s in lib_corpus.STATUSES}
    cnt["citations_by_source"] = dict(Counter(s["source"] for i in inc for s in i["sources"]))
    d["id_scheme"]["counts"] = {p: sum(1 for i in inc if i["id"].startswith(p + "-")) for p in ("DB", "DR")}


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
            ["DR-2026-%03d" % n for n in (56, 58, 60, 62, 79, 80, 81, 83, 84, 85, 87, 88, 89, 91, 93, 94, 95)],
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

    def test_confirmed_without_effect(self):
        # Methodology §3.1: Confirmed needs an affected asset; DB-2026-016 has only data_disclosure "Yes".
        conf = incident(self.d, "DB-2026-016")["veris"]["attribute"]["confidentiality"]
        self.assertEqual(conf["data_disclosure"], "Yes")
        conf["data_disclosure"] = "No"
        self.assertTrue(has(self.run_v(), "status-effect", incident="DB-2026-016"))

    def test_unknown_disclosure_counts_as_effect(self):
        incident(self.d, "DB-2026-016")["veris"]["attribute"]["confidentiality"]["data_disclosure"] = "Unknown"
        self.assertFalse(has(self.run_v(), "status-effect", incident="DB-2026-016"))

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


class Numbering(unittest.TestCase):
    """Methodology §4.1: the numbers over incidents, sub_threshold_incidents and retired_incidents are exactly
    001..id_scheme.highest_assigned, and each array is in ascending number order."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def numbering(self):
        return [f for f in vi.core_checks(self.d) if f.check == "numbering"]

    def test_deleted_top_record_is_missing(self):
        # DB-2026-099 has no CVE, so no cve_validation value changes; with the counts fixed by hand, only the
        # high-water mark shows the deletion.
        take(self.d, "DB-2026-099")
        recount(self.d)
        r = vi.validate(self.d, UPSTREAM)
        self.assertEqual([f.check for f in r.errors], ["numbering"], "\n".join(map(str, r.errors)))
        self.assertTrue(has(r, "numbering", msg="missing 099"))

    def test_new_record_above_highest_assigned(self):
        add_record(self.d, "DR-2026-081", "DR-2026-100", bump=False)
        self.assertTrue(any("above highest_assigned 100" in f.message for f in self.numbering()))

    def test_new_record_with_bump_is_clean(self):
        add_record(self.d, "DR-2026-081", "DR-2026-100", "sub_threshold_incidents")
        self.assertEqual(self.numbering(), [])

    def test_highest_assigned_missing(self):
        del self.d["id_scheme"]["highest_assigned"]
        self.assertTrue(any("id_scheme.highest_assigned" in f.message for f in self.numbering()))

    def test_highest_assigned_not_an_integer(self):
        self.d["id_scheme"]["highest_assigned"] = "99"
        self.assertTrue(any("id_scheme.highest_assigned" in f.message for f in self.numbering()))

    def test_number_in_two_arrays_is_doubled(self):
        self.d["sub_threshold_incidents"] = [copy.deepcopy(incident(self.d, "DR-2026-081"))]
        self.assertTrue(any("doubled 081" in f.message for f in self.numbering()))

    def test_stale_folded_array_shows_as_missing(self):
        # Records in an array the verifier does not know are invisible, so their numbers are missing.
        self.d["folded_incidents"] = [take(self.d, "DR-2026-081")]
        self.assertTrue(any("missing 081" in f.message for f in self.numbering()))

    def test_sub_threshold_in_ascending_order(self):
        move(self.d, "DR-2026-081")
        move(self.d, "DR-2026-083")
        self.d["sub_threshold_incidents"].reverse()
        self.assertTrue(any("sub_threshold_incidents is not in ascending" in f.message for f in self.numbering()))


class SubThreshold(unittest.TestCase):
    """Methodology §3.3, §10.2: a disclosure that fails (a)–(c) keeps its complete record in sub_threshold_incidents;
    it is verified like a counted record, and the verifier forces its promotion when (a) or (c) holds."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self, up=UPSTREAM):
        return vi.validate(self.d, up)

    def test_move_keeps_numbering(self):
        move(self.d, "DR-2026-081")
        self.assertEqual(vi.core_checks(self.d), [])

    # ---- sub-threshold records are verified like counted ones
    def test_class_a(self):
        move(self.d, "DR-2026-085")
        c = next(c for c in sub(self.d, "DR-2026-085")["validated_cve_details"]["cves"] if c["cve"] == "CVE-2026-55803")
        c["credits"][0]["type"] = "coordinator"
        self.assertTrue(has(self.run_v(), "credits", incident="DR-2026-085", cve="CVE-2026-55803"))

    def test_veris_schema(self):
        move(self.d, "DR-2026-081")["veris"]["confidence"] = "Martian"
        self.assertTrue(has(self.run_v(), "veris-schema", incident="DR-2026-081"))

    def test_status_effect(self):
        move(self.d, "DR-2026-081")["veris"]["security_incident"] = "Confirmed"
        self.assertTrue(has(self.run_v(), "status-effect", incident="DR-2026-081"))

    def test_validated_cve_set(self):
        move(self.d, "DR-2026-081")["validated_cve"].append("CVE-2000-0001")
        self.assertTrue(has(self.run_v(), "validated-cve-set", incident="DR-2026-081"))

    def test_id_format(self):
        move(self.d, "DR-2026-081")["id"] = "DR-2026-08x"
        self.assertTrue(has(self.run_v(), "id-format", incident="DR-2026-08x"))

    # ---- counts cover incidents; cve_validation covers every live record
    def test_counts_cover_incidents_only(self):
        move(self.d, "DR-2026-081")
        self.assertTrue(has(self.run_v(), "counts", msg="counts.total_incidents"))

    def test_cve_validation_covers_sub_threshold_records(self):
        move(self.d, "DR-2026-062")
        move(self.d, "DR-2026-089")
        bad = [f for f in self.run_v().errors if f.check == "counts" and f.message.startswith("cve_validation.")]
        self.assertEqual(bad, [], "\n".join(map(str, bad)))

    # ---- promotion: (a) and (c) are mechanical, so a sub-threshold record that meets one is an error
    def kev_listed(self, cve):
        up = copy.deepcopy(UPSTREAM)
        up["kev"][cve] = {"cveID": cve, "dateAdded": "2026-10-01", "vulnerabilityName": "test"}
        return up

    def test_kev_listed_cve_must_be_promoted(self):
        up = self.kev_listed("CVE-2026-42824")
        c = move(self.d, "DR-2026-081")["validated_cve_details"]["cves"][0]
        c["cisa_kev"], c["kev_date_added"] = True, "2026-10-01"
        r = self.run_v(up)
        self.assertTrue(has(r, "sub-threshold", msg="(a)", incident="DR-2026-081"))
        self.assertFalse(has(r, "cisa_kev", incident="DR-2026-081"))

    def test_kev_flag_cannot_dodge_promotion(self):
        # Class A forces the copied flag: leaving cisa_kev false after a KEV refresh is an error of its own.
        up = self.kev_listed("CVE-2026-42824")
        move(self.d, "DR-2026-081")
        self.assertTrue(has(self.run_v(up), "cisa_kev", incident="DR-2026-081", cve="CVE-2026-42824"))

    def test_realized_harm_must_be_promoted(self):
        rec = move(self.d, "DR-2026-081")
        rec["veris"]["security_incident"], rec["report"]["observed_severity"] = "Confirmed", "Low"
        rec["veris"]["attribute"]["confidentiality"]["data_disclosure"] = "Yes"
        r = self.run_v()
        self.assertTrue(has(r, "sub-threshold", msg="(c)", incident="DR-2026-081"))
        self.assertFalse(has(r, "status-effect", incident="DR-2026-081"))

    def test_negligible_near_miss_disclosure_stays(self):
        move(self.d, "DR-2026-081")
        move(self.d, "DR-2026-079")
        self.assertFalse(has(self.run_v(), "sub-threshold"))

    # ---- only disclosures (methodology §3.3 definition)
    def test_attack_relation_is_no_disclosure(self):
        move(self.d, "DR-2026-062")["validated_cve_details"]["cves"][0]["relation"] = "exploited"
        self.assertTrue(has(self.run_v(), "sub-threshold", msg="not a vulnerability disclosure", incident="DR-2026-062"))

    def test_related_only_is_no_disclosure(self):
        move(self.d, "DR-2026-025")
        self.assertTrue(has(self.run_v(), "sub-threshold", msg="not a vulnerability disclosure", incident="DR-2026-025"))

    def test_record_without_cve_passes(self):
        # Whether a record without a CVE is a disclosure is judgment (Class C).
        move(self.d, "DR-2026-065")
        self.assertFalse(has(self.run_v(), "sub-threshold", incident="DR-2026-065"))

    # ---- measurement
    def test_population_per_class(self):
        move(self.d, "DR-2026-079")
        move(self.d, "DR-2026-081")
        move(self.d, "DR-2026-083")
        m = self.run_v().measurements
        self.assertEqual(m["sub_threshold_classes"], {"AI-discovered": 1, "AI-stack": 2})
        self.assertEqual(m["sub_threshold_records"], 3)
        self.assertNotIn("DR-2026-081", m["disclosure_rule_fails"], "the measurement covers incidents only")


class Retirement(unittest.TestCase):
    """Methodology §4.1, §10.2: a retired record keeps its number; its wrapper is checked, the frozen record is not."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self):
        return vi.validate(self.d, UPSTREAM)

    def test_retired_record_keeps_numbering(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])
        self.assertEqual(vi.core_checks(self.d), [])

    def test_valid_wrapper_is_clean_and_record_is_frozen(self):
        w = retire(self.d, "DR-2026-081", ["DR-2026-083"])
        w["record"]["veris"]["confidence"] = "Martian"
        r = self.run_v()
        self.assertFalse(has(r, "retired"), "\n".join(map(str, r.errors)))
        self.assertFalse(has(r, "veris-schema", incident="DR-2026-081"))

    def test_wrapper_id_differs_from_record(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])["record"]["id"] = "DR-2026-083"
        self.assertTrue(has(self.run_v(), "retired", msg="record.id", incident="DR-2026-081"))

    def test_unknown_reason(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"], reason="obsolete")
        self.assertTrue(has(self.run_v(), "retired", msg="reason", incident="DR-2026-081"))

    def test_into_empty(self):
        retire(self.d, "DR-2026-081", [])
        self.assertTrue(has(self.run_v(), "retired", msg="into", incident="DR-2026-081"))

    def test_into_names_no_live_record(self):
        retire(self.d, "DR-2026-081", ["DR-2026-777"])
        self.assertTrue(has(self.run_v(), "retired", msg="into", incident="DR-2026-081"))

    def test_into_names_a_retired_record(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])
        retire(self.d, "DR-2026-083", ["DR-2026-087"])
        r = self.run_v()
        self.assertTrue(has(r, "retired", msg="into", incident="DR-2026-081"))
        self.assertFalse(has(r, "retired", incident="DR-2026-083"))

    def test_bad_date(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])["retired_on"] = "03.10.2026"
        self.assertTrue(has(self.run_v(), "retired", msg="retired_on", incident="DR-2026-081"))

    def test_retired_number_is_not_reused(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])
        add_record(self.d, "DR-2026-083", "DR-2026-081", "sub_threshold_incidents", bump=False)
        self.assertTrue(has(self.run_v(), "numbering", msg="doubled 081"))

    def test_malformed_retired_id(self):
        w = retire(self.d, "DR-2026-081", ["DR-2026-083"])
        w["id"] = w["record"]["id"] = "DR-2026-08x"
        self.assertTrue(has(self.run_v(), "id-format", incident="DR-2026-08x"))


class DisclosureClasses(unittest.TestCase):
    """Decision 14 item 3 (methodology §3.3): classes are derived per CVE link, and from ai_role for a record
    without a validated CVE."""

    @staticmethod
    def rec(roles, *relations):
        return {"report": {"ai_role": list(roles)},
                "validated_cve_details": {"cves": [{"cve": f"CVE-2026-{n:05d}", "relation": r} for n, r in enumerate(relations)]}}

    def test_per_link(self):
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI system/harness attacked"], "self-vulnerability")), {"AI-stack"})
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI-generated weakness"], "self-vulnerability")), {"AI-written"})
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI-discovered vulnerability"], "discovered", "related")), {"AI-discovered"})

    def test_several_classes(self):
        r = self.rec(["AI-discovered vulnerability"], "discovered", "self-vulnerability")
        self.assertEqual(lib_corpus.disclosure_classes(r), {"AI-discovered", "AI-stack"})

    def test_from_ai_role_without_cve(self):
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI-generated weakness"])), {"AI-written"})
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI-discovered vulnerability", "AI security control"])), {"AI-discovered"})
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI system/harness attacked"])), {"AI-stack"})
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI-generated weakness", "AI-discovered vulnerability"])),
                         {"AI-written", "AI-discovered"})

    def test_related_only_has_no_class(self):
        self.assertEqual(lib_corpus.disclosure_classes(self.rec(["AI system/harness attacked"], "related")), set())

    def test_is_cve_disclosure(self):
        self.assertTrue(lib_corpus.is_cve_disclosure(self.rec([], "discovered", "related")))
        self.assertTrue(lib_corpus.is_cve_disclosure(self.rec([], "self-vulnerability")))
        self.assertFalse(lib_corpus.is_cve_disclosure(self.rec([], "self-vulnerability", "exploited")))
        self.assertFalse(lib_corpus.is_cve_disclosure(self.rec([], "self-malicious-release")))
        self.assertFalse(lib_corpus.is_cve_disclosure(self.rec([], "related")))
        self.assertFalse(lib_corpus.is_cve_disclosure(self.rec([])))


if __name__ == "__main__":
    unittest.main()
