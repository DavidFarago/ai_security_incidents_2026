#!/usr/bin/env python3
"""Verify the 2026 incidents JSON: every mechanical claim, against the upstream cache and against itself.

Class A (lookup): each copied field of validated_cve_details.cves[] is re-derived from the records cached under
  vulnerabilities/upstream/ by scripts/fetch_upstream.py, with the rules of methodology §10.2 ("Copied CVE
  metadata"). A mismatch is an error unless the cves[] entry names the field in `overrides`; every override is printed,
  as is every `overrides` reason on a VCDB entry whose coding a record adopted (methodology §10.2).
Class B (bookkeeping): set algebra of the validated layer, the VERIS action.*.cve alignment, vocabularies, the ID
  scheme with its numbering over all record arrays up to id_scheme.highest_assigned, the sub-threshold rule
  (a disclosure that meets methodology §3.3 (a) or (c) must be promoted), the wrappers of retired records, the
  `sources` of every live record (at least one entry, each with `source`, `locator` and `url`; §10.2) and each
  entry's position (a register url names the register item of the locator; a report held in this repo is cited by
  its pinned permalink with a line range inside the passage that the locator names), `veris.reference` (URLs only,
  separated by "; ", none of them a discovery channel),
  ranking_table (each counted incident once, in ranking order: methodology §9.3), the motive of deliberate actions
  and no effect on a false positive (methodology §4.2, §4.3), recomputable counts, and the VERIS block against the
  VERIS JSON schema. No overrides.

Every check of a record runs over the live records, `incidents` and `sub_threshold_incidents` alike (methodology
§10.2); counts and the ranking table cover `incidents` only. A retired record is frozen: only its wrapper is checked.

Only the `sources` check of core_checks reports a malformed `sources` entry. Every other check that reads `sources`
skips such an entry, for example through lc.source_names or lc.is_source_entry, instead of crashing on it.

The verifier does NOT and CANNOT check judgment (Class C): whether a CVE belongs to the incident, its `relation`,
the notes, severities and their rationales, ai_role, the inclusion decision, §3.3 condition (b), or whether a
record without a CVE is a vulnerability disclosure. Each of those needs a cited source sentence from the analyst; a
clean run says nothing about them.

Offline, deterministic. Needs the `jsonschema` package for the VERIS schema check (missing -> error, never a pass).
Usage: python3 scripts/validate_incidents.py [--json PATH] [--upstream DIR] [--verbose]
Exit status: 0 when no error, 1 otherwise.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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
INTRINSIC = ("state", "cna", "published", "product", "cvss_version", "cvss_score", "cwe", "cisa_kev", "title", "credits")
FROZEN_COUNTS = ["counts.from_ai_software_security_incidents_2026", "counts.from_merged_incidents_2026_VERIS_described"]
# VERIS actions that someone takes on purpose; their actor needs a motive other than NA (methodology §4.2).
DELIBERATE_ACTIONS = {"hacking", "malware", "social", "misuse"}


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
def source_problems(rec) -> list[str]:
    """What is wrong with a live record's `sources` (methodology §10.2); [] when nothing is."""
    srcs = rec.get("sources")
    if not isinstance(srcs, list):
        return [f"sources is {'missing' if srcs is None else 'not a list'}; every live record needs at least one "
                "source (§10.2)"]
    if not srcs:
        return ["sources is empty; every live record needs at least one source (§10.2)"]
    out = []
    for n, s in enumerate(srcs):
        if not lc.is_source_entry(s):
            out.append(f"sources[{n}] {str(s)[:60]!r} is not an object with a non-empty string `source` (§10.2)")
            continue
        for k in ("locator", "url"):
            if k not in s:
                out.append(f"sources[{n}] has no `{k}` (§10.2)")
            elif not (isinstance(s[k], str) and s[k].strip()):
                out.append(f"sources[{n}].{k} {s[k]!r} is not a non-empty string (§10.2)")
        if "adopted" in s:
            if not lc.is_vcdb_record(s):
                out.append(f"sources[{n}].adopted is allowed only on a VCDB record entry (data/json/…) (§10.2)")
            elif s["adopted"] is not True:
                out.append(f"sources[{n}].adopted {s['adopted']!r} must be true; leave it out for a coding not adopted (§10.2)")
        if "overrides" in s:
            ov = s["overrides"]
            if not lc.is_adopted_coding(s):
                out.append(f"sources[{n}].overrides is allowed only on a VCDB record entry marked adopted: true, whose "
                           "coding the record follows (§10.2)")
            elif not (isinstance(ov, dict) and ov and all(isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip()
                                                         for k, v in ov.items())):
                out.append(f"sources[{n}].overrides must map VERIS fields to non-empty reasons (§10.2)")
    return out


def core_checks(d: dict) -> list[Finding]:
    """The checks the builders rely on, as Class B findings; empty = pass. They cover the live records, and the
    numbering also the retired ones.

    Every live record has at least one `sources` entry, an object with non-empty strings `source`, `locator` and `url`
    (methodology §10.2). A malformed entry is reported here, so the builders stop with a message instead of crashing
    on it.

    ranking_table holds each counted incident exactly once (methodology §9.3), so that the incident report, which
    follows it, drops no record; check_ranking_table checks its order and its fields.

    The ID format is checked first. While an ID is malformed its number is unknown, so the numbering check is skipped
    instead of reported (validate() names the skip). Numbering (methodology §4.1): each array is in ascending order,
    and the numbers of incidents, sub_threshold_incidents and retired_incidents together are exactly
    001..id_scheme.highest_assigned, with no gap and no double. A moved or retired record keeps its number, no number
    is reused, and deleting the highest-numbered record is detected.
    """
    out = []
    recs = lc.records(d)
    ids = lc.numbered_ids(d)
    malformed = [x for _, x in ids if lc.incident_number(x) is None]
    for x in malformed:
        out.append(Finding("B", "id-format", "ID is not DB-/DR-2026-nnn (§4.1)", x))
    if not malformed:
        arrays = lc.LIVE_ARRAYS + (lc.RETIRED_ARRAY,)
        for name in arrays:
            nums = [lc.incident_number(x) for a, x in ids if a == name]
            if nums != sorted(nums):
                out.append(Finding("B", "numbering", f"{name} is not in ascending number order (§4.1)"))
        count = Counter(lc.incident_number(x) for _, x in ids)
        top = (d.get("id_scheme") or {}).get("highest_assigned")
        if not isinstance(top, int) or isinstance(top, bool):
            out.append(Finding("B", "numbering", f"id_scheme.highest_assigned {top!r} is not an integer; it must hold "
                               "the highest number ever assigned (§4.1)"))
            top = max(count, default=0)
        missing = sorted(set(range(1, top + 1)) - set(count))
        doubled = sorted(n for n, k in count.items() if k > 1)
        above = sorted(n for n in count if n > top)
        if missing or doubled or above:
            out.append(Finding("B", "numbering", f"numbers over {', '.join(arrays)} are not 001..highest_assigned ({top:03d}): "
                               + "; ".join(f"{what} {', '.join(f'{n:03d}' for n in ns)}" for what, ns in
                                           (("missing", missing), ("doubled", doubled), ("above highest_assigned", above)) if ns)))
    rows = [x.get("id") for x in d.get("ranking_table") or []]
    if len(rows) != len(set(rows)) or set(rows) != {i["id"] for i in d["incidents"]}:
        out.append(Finding("B", "ranking-table", "ranking_table ids differ from incidents: each counted incident needs "
                           "exactly one row (§9.3)"))
    for i in recs:
        out += [Finding("B", "sources", msg, i["id"]) for msg in source_problems(i)]
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

    recs = lc.records(d)
    catalog = d.get("sources_catalog") or {}
    ids = [x for _, x in lc.numbered_ids(d)]
    for x, n in Counter(ids).items():
        if n > 1:
            r.add("B", "id-unique", f"{x} occurs {n} times", x)
    for x, n in Counter(n for n in map(lc.incident_number, ids) if n is not None).items():
        if n > 1:
            r.add("B", "id-unique", f"number {x:03d} is used {n} times (numbers are unique across prefixes)")

    for i in recs:
        iid, det, v, rep = i["id"], i.get("validated_cve_details") or {}, i["veris"], i["report"]
        srcs = lc.source_names(i)
        want = "DB" if any(s in lc.REGISTER_SOURCES for s in srcs) else "DR"
        if not iid.startswith(want + "-"):
            r.add("B", "id-prefix", f"prefix must be {want} (register source: {want == 'DB'})", iid)
        if v.get("incident_id") != iid:
            r.add("B", "veris-incident-id", f"veris.incident_id {v.get('incident_id')!r} != id", iid)
        for s in srcs:
            if s not in catalog:
                r.add("B", "source-catalog", f"source {s!r} is not in sources_catalog", iid)
        for s in i["sources"] if isinstance(i.get("sources"), list) else []:
            if lc.is_adopted_coding(s) and isinstance(s.get("overrides"), dict):
                r.overrides += [(iid, f"{s['source']} {s['locator']}", k, v) for k, v in s["overrides"].items()]
        if v.get("security_incident") not in lc.STATUSES:
            r.add("B", "vocabulary", f"security_incident {v.get('security_incident')!r}", iid)
        elif v["security_incident"] in ("Confirmed", "Suspected") and not has_effect(v.get("attribute") or {}):
            r.add("B", "status-effect", f"{v['security_incident']} without an effect in veris.attribute "
                  "(methodology §3.1): use Near miss or record the effect", iid)
        elif v["security_incident"] == "False positive" and has_effect(v.get("attribute") or {}):
            r.add("B", "status-effect", "False positive with an effect in veris.attribute (methodology §4.3): a false "
                  "positive affects no asset, so data_disclosure is No and no integrity or availability variety is set", iid)
        deliberate = sorted(set(v.get("action") or {}) & DELIBERATE_ACTIONS)
        motives = [m for a in (v.get("actor") or {}).values() if isinstance(a, dict) for m in a.get("motive") or []]
        if deliberate and not [m for m in motives if m != "NA"]:
            r.add("B", "motive", f"action {', '.join(deliberate)} needs an actor motive other than NA (methodology §4.2): "
                  "NA means an unintentional action", iid)
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

    check_source_locators(d, r)
    check_reference(d, r)
    check_sub_threshold(d, r)
    check_retired(d, r)
    check_ranking_table(d, r)
    check_counts(d, r)
    check_veris_schema(d, up, r)


VCDB_PINNED = r"https://github\.com/vz-risk/VCDB/blob/[0-9a-f]{40}/"


def check_source_locators(d, r, root: Path = lc.ROOT):
    """Methodology §10.2: where a sources entry points. For a source with a `permalink` in sources_catalog (a report
    held in this repo), the file at `path` still has the catalog `sha256`, `url` is the permalink with a line range
    (?plain=1#L<a>[-L<b>]), the locator resolves to one passage (lc.locate) and the range lies inside it. A VCDB record
    is cited by a URL pinned to a VCDB commit (…/blob/<commit>/<locator>); any other register `url` ends with the
    register item of the locator (its last token). Malformed entries are left to `sources`."""
    catalog = d.get("sources_catalog") or {}
    files = {}
    for name, cat in catalog.items():
        if not cat.get("permalink"):
            continue
        path = root / cat.get("path", "")
        if not path.is_file():
            r.add("B", "source-locator", f"{cat.get('path')!r} of {name} is missing")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != cat.get("sha256"):
            r.add("B", "source-locator", f"{cat['path']} does not match its sources_catalog sha256: the permalink and the "
                  "line ranges were pinned to another version of the file")
        else:
            files[name] = path.read_text(encoding="utf-8").splitlines()
    for i in lc.records(d):
        srcs = i.get("sources") if isinstance(i.get("sources"), list) else []
        for n, s in enumerate(srcs):
            if not (lc.is_source_entry(s) and all(isinstance(s.get(k), str) and s[k].strip() for k in ("locator", "url"))):
                continue
            src, loc, url, cat = s["source"], s["locator"], s["url"], catalog.get(s["source"]) or {}
            where = f"sources[{n}] ({src})"
            if cat.get("permalink"):
                if src not in files:
                    continue
                m = re.fullmatch(re.escape(cat["permalink"]) + r"\?plain=1#L(\d+)(?:-L(\d+))?", url)
                if not m:
                    r.add("B", "source-locator", f"{where}: url is not {cat['permalink']}?plain=1#L<a>[-L<b>]", i["id"])
                span = lc.locate(files[src], loc)
                if isinstance(span, str):
                    r.add("B", "source-locator", f"{where}: locator {loc!r}: {span}", i["id"])
                elif m:
                    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
                    if not span[0] <= a <= b <= span[1]:
                        r.add("B", "source-locator", f"{where}: lines {a}-{b} are not inside {loc!r} (lines "
                              f"{span[0]}-{span[1]})", i["id"])
            elif lc.is_vcdb_record(s) and not re.fullmatch(VCDB_PINNED + re.escape(loc), url):
                r.add("B", "source-locator", f"{where}: url is not pinned to a VCDB commit: "
                      f"https://github.com/vz-risk/VCDB/blob/<commit>/{loc}", i["id"])
            elif src in lc.REGISTER_SOURCES and not url.endswith("/" + loc.split()[-1]):
                r.add("B", "source-locator", f"{where}: url {url!r} does not end with /{loc.split()[-1]}", i["id"])


REGISTER_ITEM = re.compile(r"https?://(www\.)?(github\.com/vz-risk/VCDB(/|$)|incidentdatabase\.ai/cite/)")


def check_reference(d, r):
    """Methodology §10.2: veris.reference lists the reporting on the record's event — URLs separated by "; ", each
    once — and no discovery channel: none of the record's sources[].url, no register item (VCDB, AIID) and no link into
    this repository. Whether a URL is about the event is judgment (Class C)."""
    repos = {c["permalink"].split("/blob/")[0] for c in (d.get("sources_catalog") or {}).values() if c.get("permalink")}
    for i in lc.records(d):
        iid, ref = i["id"], i["veris"].get("reference")
        if not isinstance(ref, str) or not ref.strip():
            r.add("B", "reference", "veris.reference is empty; list the reporting on the event as URLs (§10.2)", iid)
            continue
        srcs = i.get("sources") if isinstance(i.get("sources"), list) else []
        own = {s["url"] for s in srcs if isinstance(s, dict) and isinstance(s.get("url"), str)}
        toks = ref.split("; ")
        for tok in toks:
            if not re.fullmatch(r"https?://\S+", tok) or re.search(r"[;,]https?://", tok):
                r.add("B", "reference", f"{tok[:70]!r} is not one URL; tokens are URLs separated by '; ' (§10.2)", iid)
            elif tok in own or REGISTER_ITEM.match(tok) or any(tok.startswith(p) for p in repos):
                r.add("B", "reference", f"{tok[:90]} is a discovery channel, which belongs in sources[] (§10.2)", iid)
        for tok, n in Counter(toks).items():
            if n > 1:
                r.add("B", "reference", f"{tok[:90]} occurs {n} times", iid)


def check_sub_threshold(d, r):
    """Methodology §3.3: sub_threshold_incidents holds vulnerability disclosures that fail conditions (a)-(c). A
    record with validated CVEs must be a disclosure by its relations; for a record without one that is judgment.
    (a) and (c) are mechanical, so a record that meets either is an error until it is promoted to incidents; (b) is
    judgment."""
    for i in d.get("sub_threshold_incidents") or []:
        iid, rels = i["id"], lc.relations(i)
        if rels and not lc.is_cve_disclosure(i):
            r.add("B", "sub-threshold", f"not a vulnerability disclosure (relations: {', '.join(sorted(rels))}); an attack, "
                  "a malicious release or a context-only record keeps a counted record (§3.3)", iid)
        kev = sorted(c["cve"] for c in (i.get("validated_cve_details") or {}).get("cves") or [] if c.get("cisa_kev"))
        if kev:
            r.add("B", "sub-threshold", f"meets §3.3 (a), KEV-listed {', '.join(kev)}: promote to incidents", iid)
        if lc.realized_harm(i):
            r.add("B", "sub-threshold", f"meets §3.3 (c), Confirmed with observed {i['report']['observed_severity']}: "
                  "promote to incidents", iid)


def check_retired(d, r):
    """Methodology §10.2: a retired record is frozen in a wrapper {id, retired_on, reason, into, note, record}. The
    wrapper is checked; the record is history, so nothing else of it is (an upstream refresh must not touch it)."""
    live = {i["id"] for i in lc.records(d)}
    for w in d.get(lc.RETIRED_ARRAY) or []:
        iid, rec = w.get("id"), w.get("record") or {}
        if rec.get("id") != iid:
            r.add("B", "retired", f"record.id {rec.get('id')!r} != wrapper id", iid)
        if not is_date(w.get("retired_on")):
            r.add("B", "retired", f"retired_on {w.get('retired_on')!r} is not a YYYY-MM-DD date", iid)
        if w.get("reason") not in lc.RETIREMENT_REASONS:
            r.add("B", "retired", f"reason {w.get('reason')!r} is not one of {lc.RETIREMENT_REASONS}", iid)
        into = w.get("into")
        if not isinstance(into, list) or not into:
            r.add("B", "retired", "into must list the live records that took over the record's content", iid)
        else:
            for t in into:
                if not isinstance(t, str) or t not in live:
                    r.add("B", "retired", f"into names {t!r}, which is not a live record", iid)
        extra = sorted(set(w) - {"id", "retired_on", "reason", "into", "note", "record"})
        if extra:
            r.add("B", "retired", f"unknown wrapper fields {extra}", iid)


def is_date(s) -> bool:
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return False
    try:
        dt.date.fromisoformat(s)
    except ValueError:
        return False
    return True


def check_ranking_table(d, r):
    """Methodology §9.3: ranking_table lists the counted incidents in ranking order (lc.ranking_key: observed severity
    descending, potential severity descending, ID ascending), and each row repeats its record's fields. That each
    counted incident has exactly one row is a core check."""
    rows = d.get("ranking_table") or []
    by_id = {x["id"]: x for x in rows}
    got = [x["id"] for x in rows]
    want = [i["id"] for i in sorted(d["incidents"], key=lc.ranking_key)]
    if sorted(got) == sorted(want) and got != want:
        k = next(n for n, (a, b) in enumerate(zip(got, want)) if a != b)
        r.add("B", "ranking-table", f"ranking_table is not in ranking order (§9.3: observed severity desc, potential "
              f"severity desc, ID asc): row {k + 1} is {got[k]}, expected {want[k]}")
    for i in d["incidents"]:
        row = by_id.get(i["id"])
        if row is None:
            continue
        want = {"incident": i["title"], "date": i["date"], "status": i["veris"]["security_incident"],
                "observed": i["report"]["observed_severity"], "potential": i["report"]["potential_severity"],
                "sources": "; ".join(dict.fromkeys(lc.source_names(i))),
                "validated_cve": "; ".join(i.get("validated_cve") or [])}
        for k, val in want.items():
            if row.get(k) != val:
                r.add("B", "ranking-table", f"{k}: table {str(row.get(k))[:60]!r} != incident {val[:60]!r}", i["id"])


def check_counts(d, r):
    """counts.* and id_scheme.counts cover the counted incidents; cve_validation describes the validation of every
    live record, sub-threshold ones included, because the move undoes none of it (methodology §10.2)."""
    inc = d["incidents"]
    recs = lc.records(d)
    cnt = d.get("counts") or {}

    def eq(path, got, want):
        if got != want:
            r.add("B", "counts", f"{path} = {got!r}, recomputed {want!r}")

    eq("counts.total_incidents", cnt.get("total_incidents"), len(inc))
    eq("counts.by_observed_severity", cnt.get("by_observed_severity"),
       {s: sum(1 for i in inc if i["report"]["observed_severity"] == s) for s in lc.SEVERITIES})
    eq("counts.by_status", cnt.get("by_status"), {s: sum(1 for i in inc if i["veris"]["security_incident"] == s) for s in lc.STATUSES})
    eq("counts.citations_by_source", dict(sorted((cnt.get("citations_by_source") or {}).items())),
       dict(sorted(Counter(s for i in inc for s in lc.source_names(i)).items())))
    r.skipped += FROZEN_COUNTS
    eq("id_scheme.counts", (d.get("id_scheme") or {}).get("counts"),
       {p: sum(1 for i in inc if i["id"].startswith(p + "-")) for p in ("DB", "DR")})
    cv = d.get("cve_validation") or {}
    dets = [i.get("validated_cve_details") or {} for i in recs]
    eq("cve_validation.incidents_with_validated_cve", cv.get("incidents_with_validated_cve"), sum(1 for i in recs if i.get("validated_cve")))
    eq("cve_validation.distinct_validated_cves", cv.get("distinct_validated_cves"), len({x for i in recs for x in i.get("validated_cve") or []}))
    eq("cve_validation.cves_added", cv.get("cves_added"), sorted({x for det in dets for x in det.get("added") or []}))
    eq("cve_validation.cves_removed", sorted(cv.get("cves_removed") or []), sorted({x["cve"] for det in dets for x in det.get("removed") or []}))
    eq("cve_validation.incidents_with_non_cve_identifiers_only", cv.get("incidents_with_non_cve_identifiers_only"),
       sum(1 for i, det in zip(recs, dets) if not i.get("validated_cve") and det.get("non_cve_identifiers")))


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
    for i in lc.records(d):
        for e in sorted(val.iter_errors(i["veris"]), key=lambda e: list(map(str, e.absolute_path))):
            path = ".".join(map(str, e.absolute_path)) or "(top level)"
            r.add("B", "veris-schema", f"{path}: {e.message[:160]}", i["id"])


# ----------------------------------------------------------------------------- measurements (never fail)
def measure(d, r):
    fails, review = [], []
    for i in d["incidents"]:
        cves = (i.get("validated_cve_details") or {}).get("cves") or []
        rels = lc.relations(i)
        n = lc.incident_number(i["id"])
        kev = any(c.get("cisa_kev") for c in cves)
        # handover §4 / §10 decision 1: from incident 100 on, every incident whose validated CVEs are all
        # self-vulnerability, with no KEV-listed CVE and observed Negligible, is listed for review of condition (b).
        if n is not None and n >= 100 and rels == {"self-vulnerability"} and not kev and i["report"]["observed_severity"] == "Negligible":
            review.append(i["id"])
        if lc.is_cve_disclosure(i) and not (kev or lc.realized_harm(i)):
            fails.append(i["id"])
    r.measurements["disclosure_rule_fails"] = fails
    r.measurements["decision1_review"] = review
    # The sub-threshold population, reported beside the counts (decision 14 item 5). A record can have several classes.
    sub = d.get("sub_threshold_incidents") or []
    r.measurements["sub_threshold_records"] = len(sub)
    r.measurements["sub_threshold_classes"] = dict(sorted(Counter(k for i in sub for k in lc.disclosure_classes(i)).items()))
    r.measurements["retired_records"] = len(d.get(lc.RETIRED_ARRAY) or [])


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
    L.append(f"measurement — sub_threshold_incidents (disclosures failing §3.3; not counted): {r.measurements.get('sub_threshold_records', 0)} records"
             + (f", by class {r.measurements['sub_threshold_classes']}" if r.measurements.get("sub_threshold_classes") else "")
             + f"; retired_incidents: {r.measurements.get('retired_records', 0)}")
    L.append("Class C (judgment) is not checked: relation, CVE membership, notes, severities, ai_role, inclusion, "
             "§3.3 (b), and whether a record without a CVE is a disclosure.")
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
