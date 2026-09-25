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


def cve_links(d: dict):
    """Yield (incident, cves[] entry) for every validated incident-CVE link."""
    for inc in d["incidents"]:
        for c in (inc.get("validated_cve_details") or {}).get("cves") or []:
            yield inc, c
