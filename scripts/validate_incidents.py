#!/usr/bin/env python3
"""Verify the 2026 incidents JSON: every mechanical claim, against the upstream cache and against itself.

Class A (lookup): each copied field of validated_cve_details.cves[] is re-derived from the records cached under
  vulnerabilities/upstream/ by scripts/fetch_upstream.py, with the rules of methodology §10.2 ("Copied CVE
  metadata"). A mismatch is an error unless the cves[] entry names the field in `overrides`; every override is printed.
Class B (bookkeeping): set algebra of the validated layer, the VERIS action.*.cve alignment, vocabularies, the ID
  scheme, ranking_table vs incidents, recomputable counts, and the VERIS block against the VERIS JSON schema.
  No overrides.

The verifier does NOT and CANNOT check judgment (Class C): whether a CVE belongs to the incident, its `relation`,
the notes, severities and their rationales, ai_role, or the inclusion decision. Each of those needs a cited source
sentence from the analyst; a clean run says nothing about them.

Offline, deterministic. Needs the `jsonschema` package for the VERIS schema check (missing -> error, never a pass).
Usage: python3 scripts/validate_incidents.py [--json PATH] [--upstream DIR] [--verbose]
Exit status: 0 when no error, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_corpus as lc  # noqa: E402

CVE_URL = "https://www.cve.org/CVERecord?id={}"
CVSS_KEYS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
CLASS_A_FIELDS = ["state", "cna", "published", "product", "title", "cvss", "cwe", "credits", "cisa_kev",
                  "kev_date_added", "record_url"]
LOW_OR_HIGHER = {"Critical", "High", "Medium", "Low"}
DISCLOSURE_RELATIONS = {"self-vulnerability", "discovered"}    # methodology §3.3: the relations that define a class
DISCLOSURE_ALLOWED = DISCLOSURE_RELATIONS | {"related"}        # may accompany them; related alone is no disclosure
INTRINSIC = ("state", "cna", "published", "product", "cvss_version", "cvss_score", "cwe", "cisa_kev", "title", "credits")
FROZEN_COUNTS = ["counts.from_ai_software_security_incidents_2026", "counts.from_merged_incidents_2026_VERIS_described"]


@dataclass
class Finding:
    cls: str            # "A" or "B"
    check: str
    message: str
    incident: str | None = None
    cve: str | None = None

    def __str__(self):
        where = " ".join(x for x in (self.incident, self.cve) if x)
        return f"[{self.cls}] {self.check}: {where + ': ' if where else ''}{self.message}"


@dataclass
class Result:
    errors: list = field(default_factory=list)
    overrides: list = field(default_factory=list)     # (incident, cve, field, reason)
    incomplete: list = field(default_factory=list)    # (incident, cve, field, what upstream has)
    title_sources: Counter = field(default_factory=Counter)
    measurements: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)

    def add(self, *a, **k):
        self.errors.append(Finding(*a, **k))


def has_effect(attribute: dict) -> bool:
    """Methodology §3.1: the VERIS attribute section records an effect on the asset (an unknown effect counts)."""
    return ((attribute.get("confidentiality") or {}).get("data_disclosure") in ("Yes", "Potentially", "Unknown")
            or bool((attribute.get("integrity") or {}).get("variety"))
            or bool((attribute.get("availability") or {}).get("variety")))


# ----------------------------------------------------------------------------- derivation rules (methodology §10.2)
def cna_of(rec):
    return (rec.get("containers") or {}).get("cna") or {}


def containers(rec):
    c = rec.get("containers") or {}
    return [c.get("cna") or {}] + list(c.get("adp") or [])


def exp_product(rec):
    aff = cna_of(rec).get("affected") or []
    return "; ".join(sorted({f"{a.get('vendor') or '?'}/{a.get('product') or '?'}" for a in aff}))


def exp_credits(rec):
    """Every CNA credit as {value, type[, user]}, in record order; type None where the record gives none; user (CVE User
    Registry UUID) only where the record has one."""
    return [{"value": x.get("value"), "type": x.get("type"), **({"user": x["user"]} if x.get("user") else {})}
            for x in cna_of(rec).get("credits") or []]


def cvss_pairs(rec):
    out = set()
    for cont in containers(rec):
        for m in cont.get("metrics") or []:
            for k in CVSS_KEYS:
                if k in m:
                    out.add((str(m[k].get("version")), float(m[k].get("baseScore"))))
    return out


def cwe_sets(rec):
    out = []
    for cont in containers(rec):
        ids = {x["cweId"] for p in cont.get("problemTypes") or [] for x in p.get("descriptions") or [] if x.get("cweId")}
        if ids:
            out.append(ids)
    return out


def first_sentence(text):
    text = " ".join(text.split())
    m = re.search(r"\.\s", text)
    return text[:m.start() + 1] if m else text


def exp_title(cve, rec, up):
    """(title, source) by the fallback chain, or (None, reason) when a needed lookup is not cached."""
    t = cna_of(rec).get("title")
    if t:
        return t, "CNA title"
    if cve in up["kev"]:
        return up["kev"][cve]["vulnerabilityName"], "KEV vulnerabilityName"
    man = up["manifest"]
    for key in ("ghsa-by-cve:" + cve, "osv-by-cve:" + cve):
        if key not in man or man[key].get("http_status") not in (200, 404):
            return None, f"alias lookup {key} not cached; run scripts/fetch_upstream.py"
    reviewed = sorted((a for a in up["ghsa-by-cve"].get(cve) or [] if a.get("type") == "reviewed"), key=lambda a: a["ghsa_id"])
    if reviewed and reviewed[0].get("summary"):
        return reviewed[0]["summary"], "GitHub reviewed advisory summary"
    osv = up["osv-by-cve"].get(cve) or {}
    if osv.get("summary"):
        return osv["summary"], "OSV summary"
    desc = [x["value"] for x in cna_of(rec).get("descriptions") or [] if (x.get("lang") or "").startswith("en")]
    if desc:
        return first_sentence(desc[0]), "CNA description, first sentence"
    return "", "none available"


def split_ids(s):
    return [x.strip() for x in (s or "").split(";") if x.strip()]


# ----------------------------------------------------------------------------- core checks (used by the builders)
def core_checks(d: dict) -> list[Finding]:
    """The checks the builders rely on, as Class B findings; empty = pass.

    The ID format is checked first. While an ID is malformed its number is unknown, so the 001..n numbering check
    is skipped instead of reported (validate() names the skip).
    """
    out = []
    incidents = d["incidents"]
    malformed = [i["id"] for i in incidents if lc.incident_number(i["id"]) is None]
    for x in malformed:
        out.append(Finding("B", "id-format", "ID is not DB-/DR-2026-nnn (§4.1)", x))
    if not malformed and [lc.incident_number(i["id"]) for i in incidents] != list(range(1, len(incidents) + 1)):
        out.append(Finding("B", "numbering", "incidents are not in 001..n order"))
    for i in incidents:
        det = i.get("validated_cve_details") or {}
        if sorted(i.get("validated_cve") or []) != sorted(c["cve"] for c in det.get("cves") or []):
            out.append(Finding("B", "validated-cve-set", "validated_cve != validated_cve_details.cves", i["id"]))
        for c in det.get("cves") or []:
            if c["relation"] not in lc.RELATION_ORDER:
                out.append(Finding("B", "relation", f"unknown relation {c['relation']!r}", i["id"], c["cve"]))
    seen = {}
    for _, c in lc.cve_links(d):
        key = tuple(json.dumps(c.get(k), sort_keys=True) for k in INTRINSIC)
        if seen.setdefault(c["cve"], key) != key:
            out.append(Finding("B", "intrinsic-agree", "intrinsic fields differ between incidents — Table 2 assumes they agree", cve=c["cve"]))
    return out


# ----------------------------------------------------------------------------- Class A
def check_class_a(d, up, r: Result):
    for inc, c in lc.cve_links(d):
        iid, cve = inc["id"], c["cve"]
        ov = c.get("overrides") or {}
        for f, why in sorted(ov.items()):
            if f in CLASS_A_FIELDS:
                r.overrides.append((iid, cve, f, why))
            else:
                r.add("B", "override-field", f"override names {f!r}, which is not a Class A field", iid, cve)

        def bad(f, msg):
            if f not in ov:
                r.add("A", f, msg, iid, cve)

        rec = up["cve.org"].get(cve)
        if rec is None:
            r.add("A", "record", "no cached cve.org record; run scripts/fetch_upstream.py", iid, cve)
            continue
        meta = rec.get("cveMetadata") or {}
        if meta.get("state") != "PUBLISHED":
            bad("state", f"cached record state is {meta.get('state')!r}; only PUBLISHED CVEs may be cited (§6.4 Rule 1)")
        elif c.get("state") != "PUBLISHED":
            bad("state", f"JSON says {c.get('state')!r}, record says PUBLISHED")
        if c.get("cna") != meta.get("assignerShortName"):
            bad("cna", f"JSON {c.get('cna')!r} != record {meta.get('assignerShortName')!r}")
        pub = (meta.get("datePublished") or "")[:10]
        if c.get("published") != pub:
            bad("published", f"JSON {c.get('published')!r} != record {pub!r}")
        p = exp_product(rec)
        if c.get("product") != p:
            bad("product", f"JSON {str(c.get('product'))[:80]!r} != record {p[:80]!r}")
        t, src = exp_title(cve, rec, up)
        if t is None:
            r.add("A", "title-lookup", src, iid, cve)
        else:
            r.title_sources[src] += 1
            if c.get("title") != t:
                bad("title", f"JSON {str(c.get('title'))[:60]!r} != {src} {t[:60]!r}")
        pairs = cvss_pairs(rec)
        if c.get("cvss_score") is None and c.get("cvss_version") is None:
            if pairs:
                r.incomplete.append((iid, cve, "cvss", sorted(pairs)))
        elif c.get("cvss_score") is None or c.get("cvss_version") is None:
            bad("cvss", "cvss_version and cvss_score must both be set or both be empty")
        elif (str(c["cvss_version"]), float(c["cvss_score"])) not in pairs:
            bad("cvss", f"({c['cvss_version']}, {c['cvss_score']}) is in no container; record has {sorted(pairs)}")
        sets = cwe_sets(rec)
        if not c.get("cwe"):
            if sets:
                r.incomplete.append((iid, cve, "cwe", [sorted(s) for s in sets]))
        elif not any(set(c["cwe"]) <= s for s in sets):
            bad("cwe", f"{c['cwe']} is not a subset of one container's CWEs {[sorted(s) for s in sets]}")
        cr = exp_credits(rec)
        if cr:
            if c.get("credits") != cr:
                got = c.get("credits") or []
                diff = next((k for k, (a, b) in enumerate(zip(got, cr)) if a != b), min(len(got), len(cr)))
                bad("credits", f"JSON has {len(got)} credits, record {len(cr)}; first difference at entry {diff}")
        elif c.get("credits"):
            bad("credits", "the CVE record has no CNA credits; other attribution evidence belongs in the note (§6.7)")
        if up["kev_catalog"] is None:
            r.add("A", "cisa_kev", "CISA KEV catalog not cached; run scripts/fetch_upstream.py", iid, cve)
        else:
            k = up["kev"].get(cve)
            if bool(c.get("cisa_kev")) != bool(k):
                bad("cisa_kev", f"JSON {bool(c.get('cisa_kev'))} but catalog {up['kev_catalog'].get('catalogVersion')} says {bool(k)}")
            elif k and c.get("kev_date_added") != k.get("dateAdded"):
                bad("kev_date_added", f"JSON {c.get('kev_date_added')!r} != catalog {k.get('dateAdded')!r}")
        if c.get("record_url") != CVE_URL.format(cve):
            bad("record_url", f"{c.get('record_url')!r} is not the cve.org template")


# ----------------------------------------------------------------------------- Class B
def check_class_b(d, up, r: Result):
    core = core_checks(d)
    r.errors += core
    n_bad = sum(1 for f in core if f.check == "id-format")
    if n_bad:
        r.skipped.append(f"numbering and number uniqueness ({n_bad} malformed IDs)")

    incidents = d["incidents"]
    catalog = d.get("sources_catalog") or {}
    ids = [i["id"] for i in incidents]
    for x, n in Counter(ids).items():
        if n > 1:
            r.add("B", "id-unique", f"{x} occurs {n} times", x)
    for x, n in Counter(n for n in map(lc.incident_number, ids) if n is not None).items():
        if n > 1:
            r.add("B", "id-unique", f"number {x:03d} is used {n} times (numbers are unique across prefixes)")

    for i in incidents:
        iid, det, v, rep = i["id"], i.get("validated_cve_details") or {}, i["veris"], i["report"]
        srcs = [s.get("source") for s in i.get("sources") or []]
        want = "DB" if any(s in lc.REGISTER_SOURCES for s in srcs) else "DR"
        if not iid.startswith(want + "-"):
            r.add("B", "id-prefix", f"prefix must be {want} (register source: {want == 'DB'})", iid)
        if v.get("incident_id") != iid:
            r.add("B", "veris-incident-id", f"veris.incident_id {v.get('incident_id')!r} != id", iid)
        for s in i.get("sources") or []:
            if s.get("source") not in catalog:
                r.add("B", "source-catalog", f"source {s.get('source')!r} is not in sources_catalog", iid)
        if v.get("security_incident") not in lc.STATUSES:
            r.add("B", "vocabulary", f"security_incident {v.get('security_incident')!r}", iid)
        elif v["security_incident"] in ("Confirmed", "Suspected") and not has_effect(v.get("attribute") or {}):
            r.add("B", "status-effect", f"{v['security_incident']} without an effect in veris.attribute "
                  "(methodology §3.1): use Near miss or record the effect", iid)
        for k in ("observed_severity", "potential_severity"):
            if rep.get(k) not in lc.SEVERITIES:
                r.add("B", "vocabulary", f"report.{k} {rep.get(k)!r}", iid)

        cves = det.get("cves") or []
        vset = [c["cve"] for c in cves]
        orig = set(det.get("original_cve_mentions") or [])
        if sorted(det.get("added") or []) != sorted(set(vset) - orig):
            r.add("B", "added", f"added {sorted(det.get('added') or [])} != validated - original {sorted(set(vset) - orig)}", iid)
        removed = sorted(x.get("cve") for x in det.get("removed") or [])
        if removed != sorted(orig - set(vset)):
            r.add("B", "removed", f"removed {removed} != original - validated {sorted(orig - set(vset))}", iid)
        for c in cves:
            if bool(c.get("in_original")) != (c["cve"] in orig):
                r.add("B", "in-original", f"in_original={c.get('in_original')} but original_cve_mentions says {c['cve'] in orig}", iid, c["cve"])
            if bool(c.get("kev_date_added")) != bool(c.get("cisa_kev")):
                r.add("B", "kev-date-iff-flag", "kev_date_added must be present exactly when cisa_kev is true", iid, c["cve"])
        exploited = {c["cve"] for c in cves if c["relation"] == "exploited"}
        act = v.get("action") or {}
        in_veris = set()
        for blk in ("hacking", "malware"):
            ids_ = split_ids((act.get(blk) or {}).get("cve"))
            in_veris |= set(ids_)
            for x in ids_:
                if x not in exploited:
                    r.add("B", "veris-action-cve", f"action.{blk}.cve holds {x}, which is not a validated 'exploited' CVE (§6.4)", iid, x)
        for x in sorted(exploited - in_veris):
            r.add("B", "veris-action-cve", f"exploited CVE {x} is in neither action.hacking.cve nor action.malware.cve", iid, x)

    check_ranking_table(d, r)
    check_counts(d, r)
    check_veris_schema(d, up, r)


def check_ranking_table(d, r):
    rows = d.get("ranking_table") or []
    by_id = {x["id"]: x for x in rows}
    if [x["id"] for x in rows] != [i["id"] for i in d["incidents"]] or len(by_id) != len(rows):
        r.add("B", "ranking-table", "ranking_table ids differ from incidents (set or order)")
    for i in d["incidents"]:
        row = by_id.get(i["id"])
        if row is None:
            continue
        want = {"incident": i["title"], "date": i["date"], "status": i["veris"]["security_incident"],
                "observed": i["report"]["observed_severity"], "potential": i["report"]["potential_severity"],
                "sources": "; ".join(dict.fromkeys(s["source"] for s in i["sources"])),
                "validated_cve": "; ".join(i.get("validated_cve") or [])}
        for k, val in want.items():
            if row.get(k) != val:
                r.add("B", "ranking-table", f"{k}: table {str(row.get(k))[:60]!r} != incident {val[:60]!r}", i["id"])


def check_counts(d, r):
    inc = d["incidents"]
    cnt = d.get("counts") or {}

    def eq(path, got, want):
        if got != want:
            r.add("B", "counts", f"{path} = {got!r}, recomputed {want!r}")

    eq("counts.total_incidents", cnt.get("total_incidents"), len(inc))
    eq("counts.by_observed_severity", cnt.get("by_observed_severity"),
       {s: sum(1 for i in inc if i["report"]["observed_severity"] == s) for s in lc.SEVERITIES})
    eq("counts.by_status", cnt.get("by_status"), {s: sum(1 for i in inc if i["veris"]["security_incident"] == s) for s in lc.STATUSES})
    eq("counts.citations_by_source", dict(sorted((cnt.get("citations_by_source") or {}).items())),
       dict(sorted(Counter(s["source"] for i in inc for s in i["sources"]).items())))
    r.skipped += FROZEN_COUNTS
    eq("id_scheme.counts", (d.get("id_scheme") or {}).get("counts"),
       {p: sum(1 for i in inc if i["id"].startswith(p + "-")) for p in ("DB", "DR")})
    cv = d.get("cve_validation") or {}
    dets = [i.get("validated_cve_details") or {} for i in inc]
    eq("cve_validation.incidents_with_validated_cve", cv.get("incidents_with_validated_cve"), sum(1 for i in inc if i.get("validated_cve")))
    eq("cve_validation.distinct_validated_cves", cv.get("distinct_validated_cves"), len({x for i in inc for x in i.get("validated_cve") or []}))
    eq("cve_validation.cves_added", cv.get("cves_added"), sorted({x for det in dets for x in det.get("added") or []}))
    eq("cve_validation.cves_removed", sorted(cv.get("cves_removed") or []), sorted({x["cve"] for det in dets for x in det.get("removed") or []}))
    eq("cve_validation.incidents_with_non_cve_identifiers_only", cv.get("incidents_with_non_cve_identifiers_only"),
       sum(1 for i, det in zip(inc, dets) if not i.get("validated_cve") and det.get("non_cve_identifiers")))
    rel = Counter(c["relation"] for _, c in lc.cve_links(d))
    got = (cv.get("relation_revision") or {}).get("counts") or {}
    eq("cve_validation.relation_revision.counts", got, {k: rel[k] for k in got})
    changes = {(x["id"], x["field"]): (x.get("before"), x.get("after")) for x in (cv.get("veris_action_cve_alignment") or {}).get("changes") or []}
    marked = {(i["id"], det["veris_cve_field"]): (det.get("veris_cve_before"), det.get("veris_cve_after"))
              for i, det in zip(inc, dets) if det.get("veris_cve_field")}
    eq("cve_validation.veris_action_cve_alignment.changes", changes, marked)


def check_veris_schema(d, up, r):
    if up["veris_schema"] is None:
        r.add("B", "veris-schema", "VERIS schema not cached (upstream/veris/vcdb-merged.json); run scripts/fetch_upstream.py")
        return
    try:
        import jsonschema
    except ImportError:
        r.add("B", "veris-schema", "package 'jsonschema' is not installed; the VERIS schema check cannot run")
        return
    val = jsonschema.Draft4Validator(up["veris_schema"])
    for i in d["incidents"]:
        for e in sorted(val.iter_errors(i["veris"]), key=lambda e: list(map(str, e.absolute_path))):
            path = ".".join(map(str, e.absolute_path)) or "(top level)"
            r.add("B", "veris-schema", f"{path}: {e.message[:160]}", i["id"])


# ----------------------------------------------------------------------------- measurements (never fail)
def measure(d, r):
    fails, review = [], []
    for i in d["incidents"]:
        cves = (i.get("validated_cve_details") or {}).get("cves") or []
        rels = {c["relation"] for c in cves}
        n = lc.incident_number(i["id"])
        kev = any(c.get("cisa_kev") for c in cves)
        # handover §4 / §10 decision 1: from incident 100 on, every incident whose validated CVEs are all
        # self-vulnerability, with no KEV-listed CVE and observed Negligible, is listed for review of condition (b).
        if n is not None and n >= 100 and rels == {"self-vulnerability"} and not kev and i["report"]["observed_severity"] == "Negligible":
            review.append(i["id"])
        if not rels or not rels <= DISCLOSURE_ALLOWED or not rels & DISCLOSURE_RELATIONS:
            continue
        harm = i["veris"]["security_incident"] == "Confirmed" and i["report"]["observed_severity"] in LOW_OR_HIGHER
        if not (kev or harm):
            fails.append(i["id"])
    r.measurements["disclosure_rule_fails"] = fails
    r.measurements["decision1_review"] = review


def validate(d: dict, up: dict) -> Result:
    r = Result()
    check_class_a(d, up, r)
    check_class_b(d, up, r)
    measure(d, r)
    return r


def report(r: Result, verbose: bool) -> str:
    L = []
    by = defaultdict(list)
    for f in r.errors:
        by[(f.cls, f.check)].append(f)
    n_a = sum(1 for f in r.errors if f.cls == "A")
    L.append(f"errors: {len(r.errors)} (Class A {n_a}, Class B {len(r.errors) - n_a})")
    for (cls, check), fs in sorted(by.items()):
        L.append(f"  [{cls}] {check}: {len(fs)}")
        for f in fs if verbose or len(fs) <= 40 else fs[:40]:
            L.append(f"      {f}")
        if not verbose and len(fs) > 40:
            L.append(f"      … {len(fs) - 40} more (--verbose)")
    L.append(f"overrides: {len(r.overrides)}")
    L += [f"  {i} {c} {f}: {why}" for i, c, f, why in r.overrides]
    inc = Counter(f for _, _, f, _ in r.incomplete)
    L.append(f"incomplete (JSON empty, upstream has a value; not an error): {dict(sorted(inc.items()))}")
    if verbose:
        L += [f"  {i} {c} {f}: upstream {v}" for i, c, f, v in r.incomplete]
    L.append(f"title sources: {dict(r.title_sources.most_common())}")
    L.append(f"skipped (frozen historical values; checks that cannot run): {', '.join(r.skipped)}")
    f = r.measurements.get("disclosure_rule_fails") or []
    L.append(f"measurement — disclosure incidents failing methodology §3.3 conditions (a) and (c): {len(f)}"
             + (f" ({', '.join(f)})" if f else "") + "; condition (b) is judgment")
    f = r.measurements.get("decision1_review") or []
    L.append(f"measurement — incidents >= 100 with only self-vulnerability CVEs, no KEV, observed Negligible (review §3.3 condition (b)): {len(f)}"
             + (f" ({', '.join(f)})" if f else ""))
    L.append("Class C (judgment) is not checked: relation, CVE membership, notes, severities, ai_role, inclusion.")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default=lc.JSON_PATH, type=Path)
    ap.add_argument("--upstream", default=lc.UPSTREAM_DIR, type=Path)
    ap.add_argument("--verbose", action="store_true", help="list every finding and every incomplete field")
    a = ap.parse_args()
    r = validate(lc.load_corpus(a.json), lc.load_upstream(a.upstream))
    print(report(r, a.verbose))
    sys.exit(1 if r.errors else 0)


if __name__ == "__main__":
    main()
