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
sys.path.insert(0, str(ROOT / "tests"))

import lib_corpus  # noqa: E402
import validate_incidents as vi  # noqa: E402
from corpus_helpers import add_record, by_number, incident, link, move, next_id, promote, recount, retire, sub, take  # noqa: E402

CORPUS = lib_corpus.load_corpus(lib_corpus.JSON_PATH)
UPSTREAM = lib_corpus.load_upstream(lib_corpus.UPSTREAM_DIR)


def has(result, check, msg=None, **where):
    """A finding of `check` at `where`, whose message contains `msg` when given."""
    return any(f.check == check and (msg is None or msg in f.message) and all(getattr(f, k) == v for k, v in where.items())
               for f in result.errors)


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
        # Every counted disclosure meets methodology §3.3 (a) or (c); the ones that failed are sub-threshold records.
        self.assertEqual(self.r.measurements["disclosure_rule_fails"], [])

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

    # ---- methodology §4.2, §4.3: the motive of a deliberate action; a false positive has no effect
    def test_deliberate_action_needs_a_motive(self):
        # DR-2026-008 has a hacking action; motive NA means an unintentional action.
        incident(self.d, "DR-2026-008")["veris"]["actor"]["external"]["motive"] = ["NA"]
        self.assertTrue(has(self.run_v(), "motive", incident="DR-2026-008"))

    def test_error_with_motive_na_passes(self):
        # DB-2026-026 has only an error action, and an error is unintentional.
        self.assertEqual(incident(self.d, "DB-2026-026")["veris"]["action"].keys(), {"error"})
        self.assertFalse(has(self.run_v(), "motive", incident="DB-2026-026"))

    def test_false_positive_with_effect(self):
        incident(self.d, "DB-2026-096")["veris"]["attribute"]["confidentiality"]["data_disclosure"] = "Potentially"
        self.assertTrue(has(self.run_v(), "status-effect", msg="False positive", incident="DB-2026-096"))

    def test_false_positive_with_ai_role(self):
        # Methodology §5.1: the roles describe AI's part in a security incident, and a false positive is none.
        incident(self.d, "DB-2026-096")["report"]["ai_role"] = ["AI security control"]
        self.assertTrue(has(self.run_v(), "false-positive-role", incident="DB-2026-096"))

    def test_false_positives_have_no_ai_role(self):
        self.assertFalse(has(self.run_v(), "false-positive-role"))

    # ---- methodology §4.3, §4.6: event chains and the actor of a misuse
    def add_malware(self, iid):
        """Give a record with only a hacking action a second action category."""
        incident(self.d, iid)["veris"]["action"]["malware"] = {"variety": ["Trojan"], "vector": ["Software update"]}

    def test_several_action_categories_need_an_event_chain(self):
        self.add_malware("DR-2026-008")
        incident(self.d, "DR-2026-008")["veris"].pop("plus", None)
        self.assertTrue(has(self.run_v(), "event-chain", msg="no veris.plus.event_chain", incident="DR-2026-008"))

    def test_event_chain_step_without_counterpart(self):
        # DR-2026-008 has only an external actor; a step by an internal actor has no counterpart.
        self.add_malware("DR-2026-008")
        incident(self.d, "DR-2026-008")["veris"]["plus"] = {"event_chain": [
            {"actor": "int", "action": "hak", "asset": "srv", "attribute": "cp", "summary": "a"},
            {"actor": "ext", "action": "mal", "asset": "srv", "attribute": "cp", "summary": "b"}]}
        self.assertTrue(has(self.run_v(), "event-chain", msg="step 1: actor 'int'", incident="DR-2026-008"))

    def test_event_chain_must_cover_every_action_category(self):
        self.add_malware("DR-2026-008")
        incident(self.d, "DR-2026-008")["veris"]["plus"] = {"event_chain": [
            {"actor": "ext", "action": "hak", "asset": "srv", "attribute": "cp", "summary": "a"},
            {"actor": "ext", "action": "unk", "asset": "unk", "attribute": "unk", "summary": "b"}]}
        r = self.run_v()
        self.assertTrue(has(r, "event-chain", msg="malware appears in no step", incident="DR-2026-008"))
        self.assertFalse(has(r, "event-chain", msg="step 2", incident="DR-2026-008"), "unk is always allowed")

    def test_misuse_needs_a_trusted_actor(self):
        incident(self.d, "DR-2026-008")["veris"]["action"]["misuse"] = {"variety": ["Privilege abuse"], "vector": ["Remote access"]}
        self.assertTrue(has(self.run_v(), "misuse-actor", incident="DR-2026-008"))

    # ---- ranking_table order (methodology §9.3): observed desc, potential desc, ID asc
    def add_counted_copy(self, like):
        """A copy of a counted record with the next ID, and a copy of its ranking_table row (not yet placed)."""
        new = add_record(self.d, like, next_id(self.d, like[:2]))
        row = dict(next(x for x in self.d["ranking_table"] if x["id"] == like), id=new["id"])
        return new, row

    def test_ranking_table_in_id_order_fails(self):
        self.d["ranking_table"].sort(key=by_number)
        self.assertTrue(has(self.run_v(), "ranking-table", msg="ranking order"))

    def test_new_record_at_its_ranking_position(self):
        # DB-2026-001 is Critical/Critical; its copy belongs after the last Critical/Critical row, not at the end.
        new, row = self.add_counted_copy("DB-2026-001")
        rows = self.d["ranking_table"]
        last_tie = max(k for k, x in enumerate(rows) if (x["observed"], x["potential"]) == (row["observed"], row["potential"]))
        rows.insert(last_tie + 1, row)
        self.assertFalse(has(self.run_v(), "ranking-table"))

    def test_new_record_in_id_position_fails(self):
        new, row = self.add_counted_copy("DB-2026-001")
        self.d["ranking_table"].append(row)
        self.assertTrue(has(self.run_v(), "ranking-table", msg="ranking order"))

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



class Numbering(unittest.TestCase):
    """Methodology §4.1: the numbers over incidents, sub_threshold_incidents and retired_incidents are exactly
    001..id_scheme.highest_assigned, and each array is in ascending number order."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def numbering(self):
        return [f for f in vi.core_checks(self.d) if f.check == "numbering"]

    def test_deleted_top_record_is_missing(self):
        # The record numbered highest_assigned has no CVE, so no cve_validation value changes; with the counts fixed
        # by hand, only the high-water mark shows the deletion.
        n = self.d["id_scheme"]["highest_assigned"]
        top = next(i for i in lib_corpus.records(self.d) if lib_corpus.incident_number(i["id"]) == n)
        self.assertFalse(top.get("validated_cve"), f"{top['id']} has CVEs; the test needs a record without")
        take(self.d, top["id"])
        recount(self.d)
        r = vi.validate(self.d, UPSTREAM)
        self.assertEqual([f.check for f in r.errors], ["numbering"], "\n".join(map(str, r.errors)))
        self.assertTrue(has(r, "numbering", msg=f"missing {n:03d}"))

    def test_new_record_above_highest_assigned(self):
        iid = next_id(self.d)
        add_record(self.d, "DR-2026-081", iid, bump=False)
        self.assertTrue(any(f"above highest_assigned {iid[-3:]}" in f.message for f in self.numbering()))

    def test_new_record_with_bump_is_clean(self):
        add_record(self.d, "DR-2026-081", next_id(self.d), "sub_threshold_incidents")
        self.assertEqual(self.numbering(), [])

    def test_highest_assigned_missing(self):
        del self.d["id_scheme"]["highest_assigned"]
        self.assertTrue(any("id_scheme.highest_assigned" in f.message for f in self.numbering()))

    def test_highest_assigned_not_an_integer(self):
        self.d["id_scheme"]["highest_assigned"] = "99"
        self.assertTrue(any("id_scheme.highest_assigned" in f.message for f in self.numbering()))

    def test_number_in_two_arrays_is_doubled(self):
        self.d["incidents"].append(copy.deepcopy(sub(self.d, "DR-2026-081")))
        self.assertTrue(any("doubled 081" in f.message for f in self.numbering()))

    def test_stale_folded_array_shows_as_missing(self):
        # Records in an array the verifier does not know are invisible, so their numbers are missing.
        self.d["folded_incidents"] = [take(self.d, "DR-2026-081")]
        self.assertTrue(any("missing 081" in f.message for f in self.numbering()))

    def test_sub_threshold_in_ascending_order(self):
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
        promote(self.d, "DR-2026-081")
        self.assertEqual(vi.core_checks(self.d), [])
        move(self.d, "DR-2026-081")
        self.assertEqual(vi.core_checks(self.d), [])

    # ---- sub-threshold records are verified like counted ones
    def test_class_a(self):
        c = next(c for c in sub(self.d, "DR-2026-085")["validated_cve_details"]["cves"] if c["cve"] == "CVE-2026-55803")
        c["credits"][0]["type"] = "coordinator"
        self.assertTrue(has(self.run_v(), "credits", incident="DR-2026-085", cve="CVE-2026-55803"))

    def test_veris_schema(self):
        sub(self.d, "DR-2026-081")["veris"]["confidence"] = "Martian"
        self.assertTrue(has(self.run_v(), "veris-schema", incident="DR-2026-081"))

    def test_status_effect(self):
        sub(self.d, "DR-2026-081")["veris"]["security_incident"] = "Confirmed"
        self.assertTrue(has(self.run_v(), "status-effect", incident="DR-2026-081"))

    def test_validated_cve_set(self):
        sub(self.d, "DR-2026-081")["validated_cve"].append("CVE-2000-0001")
        self.assertTrue(has(self.run_v(), "validated-cve-set", incident="DR-2026-081"))

    def test_id_format(self):
        sub(self.d, "DR-2026-081")["id"] = "DR-2026-08x"
        self.assertTrue(has(self.run_v(), "id-format", incident="DR-2026-08x"))

    # ---- counts cover incidents; cve_validation covers every live record
    def test_counts_cover_incidents_only(self):
        promote(self.d, "DR-2026-081")
        self.assertTrue(has(self.run_v(), "counts", msg="counts.total_incidents"))

    def test_cve_validation_covers_sub_threshold_records(self):
        # A move changes no cve_validation value, because it covers both live arrays.
        promote(self.d, "DR-2026-062")
        promote(self.d, "DR-2026-089")
        recount(self.d)
        bad = [f for f in self.run_v().errors if f.check == "counts" and f.message.startswith("cve_validation.")]
        self.assertEqual(bad, [], "\n".join(map(str, bad)))

    # ---- promotion: (a) and (c) are mechanical, so a sub-threshold record that meets one is an error
    def kev_listed(self, cve):
        up = copy.deepcopy(UPSTREAM)
        up["kev"][cve] = {"cveID": cve, "dateAdded": "2026-10-01", "vulnerabilityName": "test"}
        return up

    def test_kev_listed_cve_must_be_promoted(self):
        up = self.kev_listed("CVE-2026-42824")
        c = sub(self.d, "DR-2026-081")["validated_cve_details"]["cves"][0]
        c["cisa_kev"], c["kev_date_added"] = True, "2026-10-01"
        r = self.run_v(up)
        self.assertTrue(has(r, "sub-threshold", msg="(a)", incident="DR-2026-081"))
        self.assertFalse(has(r, "cisa_kev", incident="DR-2026-081"))

    def test_kev_flag_cannot_dodge_promotion(self):
        # Class A forces the copied flag: leaving cisa_kev false after a KEV refresh is an error of its own.
        up = self.kev_listed("CVE-2026-42824")
        self.assertTrue(has(self.run_v(up), "cisa_kev", incident="DR-2026-081", cve="CVE-2026-42824"))

    def test_realized_harm_must_be_promoted(self):
        rec = sub(self.d, "DR-2026-081")
        rec["veris"]["security_incident"], rec["report"]["observed_severity"] = "Confirmed", "Low"
        rec["veris"]["attribute"]["confidentiality"]["data_disclosure"] = "Yes"
        r = self.run_v()
        self.assertTrue(has(r, "sub-threshold", msg="(c)", incident="DR-2026-081"))
        self.assertFalse(has(r, "status-effect", incident="DR-2026-081"))

    def test_negligible_near_miss_disclosure_stays(self):
        self.assertFalse(has(self.run_v(), "sub-threshold"))

    # ---- only disclosures (methodology §3.3 definition)
    def test_attack_relation_is_no_disclosure(self):
        sub(self.d, "DR-2026-062")["validated_cve_details"]["cves"][0]["relation"] = "exploited"
        self.assertTrue(has(self.run_v(), "sub-threshold", msg="not a vulnerability disclosure", incident="DR-2026-062"))

    def test_related_only_is_no_disclosure(self):
        move(self.d, "DR-2026-025")
        self.assertTrue(has(self.run_v(), "sub-threshold", msg="not a vulnerability disclosure", incident="DR-2026-025"))

    def test_record_without_cve_passes(self):
        # Whether a record without a CVE is a disclosure is judgment (Class C). DR-2026-065 has no CVE.
        self.assertFalse(has(self.run_v(), "sub-threshold", incident="DR-2026-065"))

    # ---- measurement
    def test_population_per_class(self):
        # The 21 disclosures that fail methodology §3.3 (a)-(c): 17 with a CVE and DR-2026-065, 086, 090, 092 without.
        m = self.run_v().measurements
        self.assertEqual(m["sub_threshold_classes"], {"AI-discovered": 9, "AI-stack": 12})
        self.assertEqual(m["sub_threshold_records"], 21)
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


class Sources(unittest.TestCase):
    """Methodology §10.2: every live record has at least one `sources` entry, an object with a non-empty `source`.
    A malformed entry is a finding, never an exception. A retired record is frozen and not checked."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self):
        return vi.validate(self.d, UPSTREAM)

    def row(self, iid):
        return next(x for x in self.d["ranking_table"] if x["id"] == iid)

    def assert_only_sources_finding(self, iid):
        r = self.run_v()
        self.assertTrue(has(r, "sources", incident=iid), "\n".join(map(str, r.errors)))
        self.assertEqual({f.check for f in r.errors}, {"sources"}, "\n".join(map(str, r.errors)))

    # ---- at least one entry
    def test_counted_record_without_sources(self):
        # Counts and the ranking row are fixed by hand, so only the sources check can catch it.
        incident(self.d, "DR-2026-078")["sources"] = []
        recount(self.d)
        self.row("DR-2026-078")["sources"] = ""
        self.assert_only_sources_finding("DR-2026-078")

    def test_counted_db_record_without_sources(self):
        # The id-prefix error also fires (no register source is left), but the sources check names the cause.
        incident(self.d, "DB-2026-016")["sources"] = []
        recount(self.d)
        self.row("DB-2026-016")["sources"] = ""
        self.assertTrue(has(self.run_v(), "sources", incident="DB-2026-016"))

    def test_sub_threshold_record_without_sources(self):
        sub(self.d, "DR-2026-081")["sources"] = []
        self.assert_only_sources_finding("DR-2026-081")

    def test_sub_threshold_record_with_sources_missing(self):
        del sub(self.d, "DR-2026-081")["sources"]
        self.assert_only_sources_finding("DR-2026-081")

    def test_retired_record_is_not_checked(self):
        retire(self.d, "DR-2026-081", ["DR-2026-083"])["record"]["sources"] = []
        self.assertFalse(has(self.run_v(), "sources"))

    # ---- malformed entries: a finding from validate and core_checks, a message from the builder, never a crash
    def check_malformed(self, entry=None):
        """Append a malformed entry to DR-2026-081 (or, without `entry`, check the record as the test left it)."""
        import build_incidents_report as bir
        if entry is not None:
            incident(self.d, "DR-2026-081")["sources"].append(entry)
        self.assert_only_sources_finding("DR-2026-081")
        self.assertTrue(any(f.check == "sources" and f.incident == "DR-2026-081" for f in vi.core_checks(self.d)))
        with self.assertRaises(SystemExit) as cm:
            bir.render(self.d)
        self.assertIn("DR-2026-081", str(cm.exception.code))

    def test_string_entry(self):
        self.check_malformed("Grok_DeepResearch_ai_incidents_2026.md")

    def test_entry_without_source(self):
        self.check_malformed({"locator": "item 23"})

    def test_entry_with_empty_source(self):
        self.check_malformed({"source": " "})

    def test_unhashable_source(self):
        self.check_malformed({"source": ["Grok_DeepResearch_ai_incidents_2026.md"]})

    def test_locator_not_a_string(self):
        # The source itself is well-formed, so counts and the ranking row stay right; only the locator is reported.
        incident(self.d, "DR-2026-081")["sources"][0]["locator"] = 3
        self.check_malformed()

    def test_unhashable_url(self):
        # check_reference compares veris.reference with the record's sources[].url.
        for url in (["https://example.org/a"], {"href": "https://example.org/a"}):
            with self.subTest(url=url):
                self.setUp()
                incident(self.d, "DR-2026-081")["sources"][0]["url"] = url
                self.check_malformed()

    def test_sources_not_a_list(self):
        incident(self.d, "DR-2026-081")["sources"] = "ClaudeCode_DeepResearch_ai_incidents_2026.md"
        r = self.run_v()
        self.assertEqual(len([f for f in r.errors if f.check == "sources"]), 1, "one finding, not one per character")
        self.assertTrue(has(r, "sources", msg="not a list", incident="DR-2026-081"))


class Locate(unittest.TestCase):
    """lib_corpus.locate: a locator path in a report's own terms -> the 1-based line span of the passage."""

    LINES = [
        "# Title",                          # 1
        "## 1. Intro",                      # 2
        "text",                             # 3
        "## 3. Cases",                      # 4
        "### 3.1 First",                    # 5
        "**Alpha.** a",                     # 6
        "more a",                           # 7
        "**Beta (b).** b",                  # 8
        "### 3.10 Tenth",                   # 9
        "**Alpha.** again",                 # 10
        "## 4. Finder",                     # 11
        "**12. Item twelve — 2026.** x",    # 12
        "Sources: y",                       # 13
        "",                                 # 14
        "**13. Item thirteen.** z",         # 15
        "## Other heading",                 # 16
    ]

    def loc(self, locator):
        return lib_corpus.locate(self.LINES, locator)

    def test_section_spans_to_next_heading_of_same_or_higher_level(self):
        self.assertEqual(self.loc("§3"), (4, 10))
        self.assertEqual(self.loc("§3.1"), (5, 8))
        self.assertEqual(self.loc("§3.10"), (9, 10))

    def test_bold_lead_inside_section(self):
        self.assertEqual(self.loc("§3.1 › Alpha"), (6, 7))
        self.assertEqual(self.loc("§3 › Beta (b)"), (8, 8), "regex characters are literal; the span ends at a heading")

    def test_item(self):
        self.assertEqual(self.loc("§4 › item 12"), (12, 14))
        self.assertEqual(self.loc("item 13"), (15, 15))

    def test_heading_text(self):
        self.assertEqual(self.loc("Other heading"), (16, 16))

    def test_failures_are_reasons(self):
        for bad in ("Alpha", "item 99", "§3.1 › Gamma", "§5", "", "§3 › "):
            self.assertIsInstance(self.loc(bad), str, bad)
        self.assertIn("2", self.loc("Alpha"), "ambiguous: two matches")


class SourceLocators(unittest.TestCase):
    """Methodology §10.2: every sources entry has a locator and a url. A report held in this repo is cited by a
    permalink pinned to a commit, with a line range inside the passage that the locator names; a register url ends
    with the register item of the locator."""

    CLAUDE = "ClaudeCode_DeepResearch_ai_incidents_2026.md"

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self):
        return vi.validate(self.d, UPSTREAM)

    def entry(self, iid="DR-2026-081", source=CLAUDE):
        return next(s for s in incident(self.d, iid)["sources"] if s["source"] == source)

    def permalink(self, source=CLAUDE):
        return self.d["sources_catalog"][source]["permalink"]

    def flagged(self, iid="DR-2026-081"):
        r = self.run_v()
        return has(r, "source-locator", incident=iid)

    def test_real_entry_resolves(self):
        e = self.entry()
        self.assertEqual(e["locator"], "item 23")
        self.assertEqual(e["url"], self.permalink() + "?plain=1#L128-L129")
        self.assertFalse(self.flagged())

    def test_range_inside_another_item(self):
        self.entry()["url"] = self.permalink() + "?plain=1#L131-L132"     # item 24
        self.assertTrue(self.flagged())

    def test_unknown_item(self):
        self.entry()["locator"] = "item 99"
        self.assertTrue(self.flagged())

    def test_permalink_of_another_report(self):
        self.entry()["url"] = self.permalink("ChatGPT_DeepResearch_ai_incidents_2026.md") + "?plain=1#L128-L129"
        self.assertTrue(self.flagged())

    def test_reversed_range(self):
        self.entry()["url"] = self.permalink() + "?plain=1#L129-L128"
        self.assertTrue(self.flagged())

    def test_range_past_end_of_file(self):
        self.entry()["url"] = self.permalink() + "?plain=1#L128-L9999"
        self.assertTrue(self.flagged())

    def test_url_without_line_range(self):
        self.entry()["url"] = self.permalink()
        self.assertTrue(self.flagged())

    def test_report_changed_after_pinning(self):
        self.d["sources_catalog"][self.CLAUDE]["sha256"] = "0" * 64
        self.assertTrue(has(self.run_v(), "source-locator", msg="sha256"))

    def test_register_url_names_another_item(self):
        e = self.entry("DB-2026-001", "vz-risk/VCDB")
        e["url"] = e["url"].rsplit("/", 1)[0] + "/99999"
        self.assertTrue(self.flagged("DB-2026-001"))

    def test_locator_and_url_are_required(self):
        e = self.entry()
        e["locator"] = ""
        del e["url"]
        r = self.run_v()
        self.assertTrue(has(r, "sources", msg="locator", incident="DR-2026-081"))
        self.assertTrue(has(r, "sources", msg="url", incident="DR-2026-081"))


class Reference(unittest.TestCase):
    """Methodology §10.2: veris.reference lists the reporting on the record's event, as URLs separated by "; ", none of
    them a discovery channel. A difference from an adopted VCDB coding is explained in `overrides` on that VCDB entry."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self):
        return vi.validate(self.d, UPSTREAM)

    def set_ref(self, value, iid="DR-2026-081"):
        incident(self.d, iid)["veris"]["reference"] = value

    def add_ref(self, url, iid="DR-2026-081"):
        v = incident(self.d, iid)["veris"]
        v["reference"] += "; " + url

    def flagged(self, iid="DR-2026-081"):
        return has(self.run_v(), "reference", incident=iid)

    # ---- form
    def test_cve_token(self):
        self.add_ref("CVE-2026-42824")
        self.assertTrue(self.flagged())

    def test_urls_joined_by_a_space(self):
        self.set_ref("https://a.example/x https://b.example/y")
        self.assertTrue(self.flagged())

    def test_urls_joined_without_space(self):
        self.set_ref("https://a.example/x;https://b.example/y")
        self.assertTrue(self.flagged())

    def test_empty(self):
        self.set_ref("")
        self.assertTrue(self.flagged())

    def test_duplicate(self):
        self.add_ref(incident(self.d, "DR-2026-081")["veris"]["reference"].split("; ")[0])
        self.assertTrue(self.flagged())

    # ---- no discovery channel
    def test_own_vcdb_issue(self):
        self.add_ref("https://github.com/vz-risk/VCDB/issues/23174", "DB-2026-001")
        self.assertTrue(self.flagged("DB-2026-001"))

    def test_other_records_aiid_page(self):
        self.add_ref("https://incidentdatabase.ai/cite/1412")
        self.assertTrue(self.flagged())

    def test_repo_permalink(self):
        self.add_ref(next(s["url"] for s in incident(self.d, "DR-2026-081")["sources"]))
        self.assertTrue(self.flagged())

    # ---- overrides on the VCDB record whose coding was adopted
    def vcdb_record_entry(self, iid="DB-2026-024"):
        return next(s for s in incident(self.d, iid)["sources"] if s["locator"].startswith("data/json/"))

    def test_valid_register_override_is_printed(self):
        self.vcdb_record_entry()["overrides"] = {"reference": "test reason 7f3a"}
        r = self.run_v()
        self.assertFalse(has(r, "sources", incident="DB-2026-024"))
        self.assertIn("test reason 7f3a", vi.report(r, False))

    def test_override_with_empty_reason(self):
        self.vcdb_record_entry()["overrides"] = {"reference": " "}
        self.assertTrue(has(self.run_v(), "sources", msg="overrides", incident="DB-2026-024"))

    def test_override_not_a_dict(self):
        self.vcdb_record_entry()["overrides"] = "reference differs"
        self.assertTrue(has(self.run_v(), "sources", msg="overrides", incident="DB-2026-024"))

    def test_override_on_a_vcdb_issue(self):
        e = next(s for s in incident(self.d, "DB-2026-001")["sources"] if s["locator"].startswith("issues/"))
        e["overrides"] = {"reference": "x"}
        self.assertTrue(has(self.run_v(), "sources", msg="overrides", incident="DB-2026-001"))

    def test_override_on_an_aiid_entry(self):
        incident(self.d, "DB-2026-003")["sources"][0]["overrides"] = {"reference": "x"}
        self.assertTrue(has(self.run_v(), "sources", msg="overrides", incident="DB-2026-003"))


class AdoptedCoding(unittest.TestCase):
    """Methodology §10.2: `adopted: true` marks the VCDB record whose VERIS coding a record follows; only that entry may
    carry `overrides`. A VCDB record is cited by a URL pinned to a VCDB commit."""

    def setUp(self):
        self.d = copy.deepcopy(CORPUS)

    def run_v(self):
        return vi.validate(self.d, UPSTREAM)

    def entry(self, iid, prefix):
        return next(s for s in incident(self.d, iid)["sources"] if s["locator"].startswith(prefix))

    def test_adopted_on_a_vcdb_issue(self):
        self.entry("DB-2026-001", "issues/")["adopted"] = True
        self.assertTrue(has(self.run_v(), "sources", msg="adopted", incident="DB-2026-001"))

    def test_adopted_on_an_aiid_entry(self):
        self.entry("DB-2026-003", "AIID")["adopted"] = True
        self.assertTrue(has(self.run_v(), "sources", msg="adopted", incident="DB-2026-003"))

    def test_adopted_not_true(self):
        self.entry("DB-2026-024", "data/json/")["adopted"] = "yes"
        self.assertTrue(has(self.run_v(), "sources", msg="adopted", incident="DB-2026-024"))

    def test_override_on_a_record_that_is_not_adopted(self):
        e = self.entry("DB-2026-024", "data/json/")
        e.pop("adopted", None)
        e["overrides"] = {"reference": "x"}
        self.assertTrue(has(self.run_v(), "sources", msg="overrides", incident="DB-2026-024"))

    def test_record_url_on_master(self):
        e = self.entry("DB-2026-024", "data/json/")
        e["url"] = "https://github.com/vz-risk/VCDB/blob/master/" + e["locator"]
        self.assertTrue(has(self.run_v(), "source-locator", msg="pinned", incident="DB-2026-024"))

    def test_real_adopted_entries_are_pinned_and_marked(self):
        n = 0
        for rec in lib_corpus.records(CORPUS):
            for s in rec["sources"]:
                if s["source"] == "vz-risk/VCDB" and s["locator"].startswith("data/json/"):
                    n += 1
                    self.assertIs(s.get("adopted"), True, rec["id"])
                    self.assertRegex(s["url"], r"^https://github\.com/vz-risk/VCDB/blob/[0-9a-f]{40}/", rec["id"])
        self.assertGreaterEqual(n, 11)


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
