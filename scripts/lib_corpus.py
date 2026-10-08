"""Shared by the verifier and the builders: load the incidents JSON and the upstream cache; hold the vocabularies.

Standard library only. Nothing here writes a file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ROOT / "incidents" / "all_2026_ai_software_security_incidents.json"
UPSTREAM_DIR = ROOT / "vulnerabilities" / "upstream"

# Relation vocabulary in the order methodology §6.4 Rule 2 lists it.
RELATION_ORDER = ["exploited", "self-malicious-release", "exploited-unconfirmed", "attempted", "toolkit",
                  "self-vulnerability", "discovered", "related"]
RELATION_LABEL = {"self-vulnerability": "self (vulnerability)", "self-malicious-release": "self (malicious release)"}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible"]
STATUSES = ["Confirmed", "Suspected", "Near miss", "False positive"]
LOW_OR_HIGHER = {"Critical", "High", "Medium", "Low"}

# Methodology §3.3: a record with validated CVEs is a vulnerability disclosure when it has a disclosure relation and
# otherwise only `related` (neutral); every other relation makes it an attack or a malicious release.
DISCLOSURE_RELATIONS = {"self-vulnerability", "discovered"}
DISCLOSURE_ALLOWED = DISCLOSURE_RELATIONS | {"related"}
# The three disclosure classes of methodology §3.3. Derived (disclosure_classes), never stored in the JSON.
DISCLOSURE_CLASSES = ["AI-written", "AI-stack", "AI-discovered"]

# Record arrays (methodology §4.1, §10.2). The live records are complete and verified; a retired record is frozen in
# a wrapper and only its number counts. Numbers run over all three arrays.
LIVE_ARRAYS = ("incidents", "sub_threshold_incidents")
RETIRED_ARRAY = "retired_incidents"
RETIREMENT_REASONS = ["duplicate", "merged"]

# Incident registers (methodology §4.1: prefix DB when at least one source is one). Replaced by
# sources_catalog[...].source_class once that field exists (automate_sourcing_handover.md §10, decision 2).
REGISTER_SOURCES = {"incidentdatabase.ai_20260824_ai_incidents_2026.xlsx", "vz-risk/VCDB"}

# Cached per-identifier sources: sub-directory -> {stem: record}.
RECORD_DIRS = ["cve.org", "ghsa", "osv", "ghsa-by-cve", "osv-by-cve"]
KEV_FILE = Path("cisa-kev") / "known_exploited_vulnerabilities.json"
VERIS_SCHEMA_FILE = Path("veris") / "vcdb-merged.json"


def lab(rel: str) -> str:
    """Display label of a relation token (CSV keeps the token)."""
    return RELATION_LABEL.get(rel, rel)


def load_corpus(path: Path = JSON_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_upstream(up: Path = UPSTREAM_DIR) -> dict:
    """Raw upstream records cached by scripts/fetch_upstream.py (never edited). A missing part stays empty or None.

    Keys: one per RECORD_DIRS entry ({stem: record}); "kev" ({cveID: entry}) and "kev_catalog" (the feed without its
    list); "veris_schema" (dict or None); "manifest".
    """
    up = Path(up)
    out: dict = {}
    for src in RECORD_DIRS:
        pdir = up / src
        out[src] = {f.stem: json.loads(f.read_text(encoding="utf-8")) for f in sorted(pdir.glob("*.json"))} if pdir.exists() else {}
    kf = up / KEV_FILE
    feed = json.loads(kf.read_text(encoding="utf-8")) if kf.exists() else None
    out["kev"] = {v["cveID"]: v for v in feed["vulnerabilities"]} if feed else {}
    out["kev_catalog"] = {k: v for k, v in feed.items() if k != "vulnerabilities"} if feed else None
    sf = up / VERIS_SCHEMA_FILE
    out["veris_schema"] = json.loads(sf.read_text(encoding="utf-8")) if sf.exists() else None
    mpath = up / "manifest.json"
    out["manifest"] = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else {}
    return out


ID_RE = re.compile(r"(DB|DR)-2026-(\d{3})")   # methodology §4.1


def incident_number(iid: str) -> int | None:
    """The nnn of DB-/DR-2026-nnn as int; None for an ID that does not match ID_RE."""
    m = ID_RE.fullmatch(iid or "")
    return int(m.group(2)) if m else None


def records(d: dict) -> list:
    """Every live record: the counted `incidents`, then `sub_threshold_incidents` (methodology §3.3, §10.2).
    Retired records are history and are never read as records."""
    return [i for name in LIVE_ARRAYS for i in d.get(name) or []]


def numbered_ids(d: dict) -> list:
    """(array, id) for every number ever assigned: the live records and the wrappers of retired records (§4.1)."""
    return [(name, i.get("id")) for name in LIVE_ARRAYS + (RETIRED_ARRAY,) for i in d.get(name) or []]


def is_source_entry(s) -> bool:
    """A well-formed `sources` entry (methodology §10.2): an object whose `source` is a non-empty string."""
    return isinstance(s, dict) and isinstance(s.get("source"), str) and bool(s["source"].strip())


def source_names(rec: dict) -> list:
    """The `source` of every well-formed `sources` entry of a record, in order; [] when `sources` is missing or not a
    list. A malformed entry is skipped here; the verifier's `sources` check reports it."""
    srcs = rec.get("sources")
    return [s["source"] for s in srcs if is_source_entry(s)] if isinstance(srcs, list) else []


def cve_links(d: dict):
    """Yield (record, cves[] entry) for every validated incident-CVE link of the live records.

    For the verifier; the builders count `incidents` only and iterate it themselves.
    """
    for inc in records(d):
        for c in (inc.get("validated_cve_details") or {}).get("cves") or []:
            yield inc, c


def relations(rec: dict) -> set:
    return {c["relation"] for c in (rec.get("validated_cve_details") or {}).get("cves") or []}


def realized_harm(rec: dict) -> bool:
    """Methodology §3.3 (c): status Confirmed and observed severity Low or higher."""
    return rec["veris"].get("security_incident") == "Confirmed" and rec["report"].get("observed_severity") in LOW_OR_HIGHER


def is_cve_disclosure(rec: dict) -> bool:
    """Methodology §3.3: the record has validated CVEs, at least one with a disclosure relation and none with an attack
    relation. False for a record without a validated CVE: whether that is a disclosure is judgment."""
    rels = relations(rec)
    return bool(rels & DISCLOSURE_RELATIONS) and rels <= DISCLOSURE_ALLOWED


def link_class(relation: str, ai_role) -> str | None:
    """The §3.3 class of one CVE link: self-vulnerability gives AI-written when ai_role contains 'AI-generated
    weakness', else AI-stack; discovered gives AI-discovered; any other relation gives none."""
    if relation == "self-vulnerability":
        return "AI-written" if "AI-generated weakness" in (ai_role or []) else "AI-stack"
    if relation == "discovered":
        return "AI-discovered"
    return None


def disclosure_classes(rec: dict) -> set:
    """The §3.3 classes of a record (decision 14): one per CVE link (link_class). A record without a validated CVE
    takes them from ai_role: 'AI-generated weakness' gives AI-written, 'AI-discovered vulnerability' AI-discovered,
    and a record with neither gets AI-stack."""
    roles = rec["report"].get("ai_role") or []
    cves = (rec.get("validated_cve_details") or {}).get("cves") or []
    if cves:
        return {k for c in cves if (k := link_class(c["relation"], roles))}
    out = {k for role, k in (("AI-generated weakness", "AI-written"), ("AI-discovered vulnerability", "AI-discovered"))
           if role in roles}
    return out or {"AI-stack"}
