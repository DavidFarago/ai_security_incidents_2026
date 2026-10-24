"""Shared by the verifier and the builders: load the incidents JSON and the upstream cache; hold the vocabularies.

Standard library only. Nothing here writes a file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

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
# IBSS (incident-based severity score): the weight of a record's severity doubles per tier (decided 2026-08-28).
SEV_WEIGHT = {"Negligible": 1, "Low": 2, "Medium": 4, "High": 8, "Critical": 16}

# Methodology §3.3 "Scores": a CVE link is in play when the CVE's flaw is part of what happened in the event; only
# in-play links count in IBSS. One row per reason: (in play?, relations, why). Every relation occurs exactly once.
IN_PLAY_TABLE = [
    (True, ("exploited", "exploited-unconfirmed", "attempted"), "The attack used, probably used, or tried to use the flaw."),
    (True, ("self-vulnerability", "discovered"), "The event made the flaw known."),
    (True, ("self-malicious-release",), "The event is the release of the malware that the CVE identifies."),
    (False, ("toolkit",), "The exploit only lay in the attacker's tools; no source shows its use against the victim."),
    (False, ("related",), "The CVE is context only: same product, disclosure batch or campaign."),
]
IN_PLAY = {r for in_play, rels, _ in IN_PLAY_TABLE if in_play for r in rels}

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
REGISTER_SOURCES = {"incidentdatabase.ai_20260824_ai_incidents_2026.xlsx", "incidentdatabase.ai", "vz-risk/VCDB"}

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


def ranking_key(rec: dict) -> tuple:
    """The ranking order of methodology §9.3 as a sort key: report.observed_severity descending,
    report.potential_severity descending, then the ID number ascending. An unknown severity or a malformed ID sorts
    last instead of raising; the verifier reports both."""
    rank = lambda sev: SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)
    n = incident_number(rec.get("id"))
    return rank(rec["report"].get("observed_severity")), rank(rec["report"].get("potential_severity")), n if n is not None else 10 ** 6


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


def is_vcdb_record(s) -> bool:
    """A `sources` entry naming a VCDB-encoded record (`data/json/…`), as opposed to an intake issue."""
    return isinstance(s, dict) and s.get("source") == "vz-risk/VCDB" and str(s.get("locator", "")).startswith("data/json/")


def is_adopted_coding(s) -> bool:
    """A VCDB record entry marked `adopted: true`: the record follows its VERIS coding (methodology §10.2). Only such an
    entry may carry `overrides`, the reasons for deliberate differences from that coding."""
    return is_vcdb_record(s) and s.get("adopted") is True


def source_names(rec: dict) -> list:
    """The `source` of every well-formed `sources` entry of a record, in order; [] when `sources` is missing or not a
    list. A malformed entry is skipped here; the verifier's `sources` check reports it."""
    srcs = rec.get("sources")
    return [s["source"] for s in srcs if is_source_entry(s)] if isinstance(srcs, list) else []


LOCATOR_SEP = " › "


def _heading_level(line: str) -> int:
    m = re.match(r"(#+)\s", line)
    return len(m.group(1)) if m else 0


def locate(lines: list, locator) -> tuple | str:
    """Resolve a locator path (methodology §10.2) in a Markdown file to the 1-based line span (start, end) of its
    passage, or return why it fails.

    The components are separated by LOCATOR_SEP; each is searched inside the span of the previous one:
      '§3.6'     the numbered heading '#… 3.6 …' (also '3.6.');
      'item 23'  the numbered bold item '**23. …';
      any text   the heading '#… <text>' or the bold lead '**<text>**' / '**<text>.**'.
    A heading spans up to the next heading of the same or a higher level; an item or a bold lead spans up to the next
    heading or line that starts in bold. No match, or more than one match inside the span, fails.
    """
    if not isinstance(locator, str) or not locator.strip():
        return "empty locator"
    start, end = 1, len(lines)
    for depth, comp in enumerate(c.strip() for c in locator.split(LOCATOR_SEP)):
        if m := re.fullmatch(r"§(\d+(?:\.\d+)*)", comp):
            pat = re.compile(r"#+\s+" + re.escape(m.group(1)) + r"\.?(\s|$)")
        elif m := re.fullmatch(r"item (\d+)", comp):
            pat = re.compile(r"\*\*" + m.group(1) + r"\.\s")
        elif comp:
            text = re.escape(comp)
            pat = re.compile(rf"#+\s+{text}\s*$|\*\*{text}\.?\*\*")
        else:
            return f"empty component in {locator!r}"
        lo = start if depth == 0 else start + 1
        hits = [n for n in range(lo, end + 1) if pat.match(lines[n - 1])]
        if len(hits) != 1:
            return f"{comp!r} matches {len(hits) or 'no'} line{'' if len(hits) == 1 else 's'} in lines {lo}-{end}"
        s = hits[0]
        level = _heading_level(lines[s - 1])
        if level:
            def stops(line): return 0 < _heading_level(line) <= level
        else:
            def stops(line): return _heading_level(line) > 0 or line.startswith("**")
        start, end = s, next((n - 1 for n in range(s + 1, end + 1) if stops(lines[n - 1])), end)
    return start, end


def cve_links(d: dict):
    """Yield (record, cves[] entry) for every validated record-CVE link of the live records (both live arrays)."""
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


def link_classes(rec: dict, relation: str) -> set:
    """The classes through which one CVE link of a record enters a score: the link's own class (link_class), or, for a
    link without one, the record's classes (disclosure_classes). Only the descriptive segment profile counts such a
    link, a `related` one (automate_sourcing_handover.md §5.6); scores count in-play links only."""
    k = link_class(relation, rec["report"].get("ai_role"))
    return {k} if k else disclosure_classes(rec)


class Score(NamedTuple):
    obs: int
    pot: int
    obs_tiers: tuple   # the severity behind each weight that the score adds, highest first
    pot_tiers: tuple


def ibss(contribs, weights: dict = SEV_WEIGHT) -> Score:
    """IBSS of one entity (methodology §3.3 "Scores") from its contributions, one (array, record_id,
    observed_severity, potential_severity, classes) per record link that involves the entity.

    A counted incident (array `incidents`) adds its weights once, however many of its contributions reach the entity.
    A sub-threshold record adds nothing on its own: per class, the entity gets the highest observed weight and,
    separately, the highest potential weight among the sub-threshold contributions of that class. A contribution enters
    every class it names; one without a class raises ValueError. Thread B passes lc.disclosure_classes(rec) as the
    classes of an analyst CWE (report.weaknesses[].cwe) and, for its linear sensitivity score, the weights 1 to 5 as
    `weights`.
    """
    counted, best = {}, {}
    for array, rid, observed, potential, classes in contribs:
        if array == "incidents":
            counted[rid] = (observed, potential)
        elif array == "sub_threshold_incidents":
            if not classes:
                raise ValueError(f"{rid}: a sub-threshold contribution needs a class (methodology §3.3)")
            for k in classes:
                o, p = best.get(k, (observed, potential))
                best[k] = (max(o, observed, key=weights.get), max(p, potential, key=weights.get))
        else:
            raise ValueError(f"{rid}: {array!r} is not a live array")
    tiers = list(counted.values()) + list(best.values())
    order = lambda ts: tuple(sorted(ts, key=SEVERITIES.index))
    return Score(sum(weights[o] for o, _ in tiers), sum(weights[p] for _, p in tiers),
                 order(o for o, _ in tiers), order(p for _, p in tiers))
