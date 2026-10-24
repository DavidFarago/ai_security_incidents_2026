"""Helpers that change an in-memory copy of the corpus, shared by the test modules.

They find a record in either live array (`incidents`, `sub_threshold_incidents`), so a test keeps working when a
record moves between the arrays (methodology §3.3).
"""
from __future__ import annotations

import copy
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import lib_corpus  # noqa: E402


def by_number(rec):
    return lib_corpus.incident_number(rec["id"])


def incident(d, iid):
    """The live record with this ID, in either live array."""
    return next(i for i in lib_corpus.records(d) if i["id"] == iid)


def link(d, iid, cve):
    return next(c for c in incident(d, iid)["validated_cve_details"]["cves"] if c["cve"] == cve)


def sub(d, iid):
    return next(i for i in d["sub_threshold_incidents"] if i["id"] == iid)


def take(d, iid):
    """Remove a live record from its array, and its ranking_table row if it has one."""
    rec = incident(d, iid)
    for name in lib_corpus.LIVE_ARRAYS:
        if rec in (d.get(name) or []):
            d[name].remove(rec)
    d["ranking_table"] = [x for x in d["ranking_table"] if x["id"] != iid]
    return rec


def move(d, iid):
    """Put a live record into sub_threshold_incidents (methodology §3.3), keeping that array in ID order."""
    rec = take(d, iid)
    d.setdefault("sub_threshold_incidents", []).append(rec)
    d["sub_threshold_incidents"].sort(key=by_number)
    return rec


def promote(d, iid):
    """Put a live record into incidents (methodology §3.3 "Promotion"), keeping that array in ID order, and give it its
    ranking_table row in ranking order (§9.3). The counts stay as they are; recount fixes them."""
    rec = take(d, iid)
    d["incidents"].append(rec)
    d["incidents"].sort(key=by_number)
    d["ranking_table"].append({
        "id": iid, "incident": rec["title"], "date": rec["date"], "status": rec["veris"]["security_incident"],
        "observed": rec["report"]["observed_severity"], "potential": rec["report"]["potential_severity"],
        "sources": "; ".join(dict.fromkeys(lib_corpus.source_names(rec))),
        "cve_cwe": "; ".join(v["cve"] for v in rec["report"].get("vulnerabilities") or []),
        "validated_cve": "; ".join(rec.get("validated_cve") or [])})
    order = {i["id"]: k for k, i in enumerate(sorted(d["incidents"], key=lib_corpus.ranking_key))}
    d["ranking_table"].sort(key=lambda x: order[x["id"]])
    return rec


def retire(d, iid, into, reason="duplicate"):
    """Retire a live record (methodology §10.2): frozen, in a wrapper in retired_incidents, in ID order."""
    w = {"id": iid, "retired_on": "2026-10-03", "reason": reason, "into": into, "note": "test", "record": take(d, iid)}
    d.setdefault("retired_incidents", []).append(w)
    d["retired_incidents"].sort(key=by_number)
    return w


def next_id(d, prefix="DR"):
    """The ID that a new record gets: id_scheme.highest_assigned + 1 (methodology §4.1)."""
    return f"{prefix}-2026-{d['id_scheme']['highest_assigned'] + 1:03d}"


def add_record(d, like, iid, array="incidents", bump=True):
    """Append a copy of `like` with a new ID to `array`; with bump, raise id_scheme.highest_assigned to its number."""
    new = copy.deepcopy(incident(d, like))
    new["id"] = new["veris"]["incident_id"] = iid
    d.setdefault(array, []).append(new)
    if bump:
        d["id_scheme"]["highest_assigned"] = lib_corpus.incident_number(iid)
    return new


def recount(d):
    """Recompute counts.* and id_scheme.counts over incidents, and the record count of
    cve_validation.incidents_with_non_cve_identifiers_only over every live record, as an analyst fixing them by hand
    would."""
    inc, cnt = d["incidents"], d["counts"]
    cnt["total_incidents"] = len(inc)
    cnt["by_observed_severity"] = {s: sum(1 for i in inc if i["report"]["observed_severity"] == s) for s in lib_corpus.SEVERITIES}
    cnt["by_status"] = {s: sum(1 for i in inc if i["veris"]["security_incident"] == s) for s in lib_corpus.STATUSES}
    cnt["citations_by_source"] = dict(Counter(s["source"] for i in inc for s in i["sources"]))
    d["id_scheme"]["counts"] = {p: sum(1 for i in inc if i["id"].startswith(p + "-")) for p in ("DB", "DR")}
    d["cve_validation"]["incidents_with_non_cve_identifiers_only"] = sum(
        1 for i in lib_corpus.records(d)
        if not i.get("validated_cve") and (i.get("validated_cve_details") or {}).get("non_cve_identifiers"))
