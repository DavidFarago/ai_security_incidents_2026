#!/usr/bin/env python3
"""Build the CVE-side tables of the 2026 AI software-security incident dataset.

Reads  incidents/all_2026_ai_software_security_incidents.json   (source of truth)
Writes vulnerabilities/*.csv and vulnerabilities/README.md         (derived; never edited by hand)

Offline, standard library only, deterministic (no wall-clock dates in the output: the
report is stamped with the dates recorded inside the JSON).

Usage:  python3 scripts/build_vulnerabilities.py [--json PATH] [--out DIR]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_corpus as lc  # noqa: E402
from validate_incidents import core_checks  # noqa: E402

CVE_URL = "https://www.cve.org/CVERecord?id={}"
SEP = "; "  # list separator inside CSV cells (matches veris.action.hacking.cve convention)

# Relation vocabulary in the order the methodology (§6.4) lists it; used as relevance weight.
RELATION_ORDER, RELATION_LABEL, lab = lc.RELATION_ORDER, lc.RELATION_LABEL, lc.lab


def lab_pairs(s):
    """Apply lab() to the relation part of 'incident:relation' strings."""
    return re.sub(r":([a-z-]+)", lambda m: ":" + lab(m.group(1)), s)

RELATION_WEIGHT = {r: len(RELATION_ORDER) - i for i, r in enumerate(RELATION_ORDER)}
EXPLOITED_FAMILY = ["exploited", "exploited-unconfirmed", "attempted", "toolkit"]
IN_PLAY = lc.IN_PLAY  # the relations whose links count in IBSS (methodology §3.3 "Scores")

SEVERITIES = lc.SEVERITIES
CVSS_BANDS = ["9.0-10.0", "7.0-8.9", "4.0-6.9", "0.1-3.9", "no CVSS"]

SEGMENTS = [
    ("ai-exploited", "CVEs used, attempted or carried by the AI-enabled attacker / agent (relation exploited, exploited-unconfirmed, attempted, toolkit)"),
    ("ai-written", "self (vulnerability) CVEs of incidents whose AI role includes 'AI-generated weakness' — vulnerabilities in AI-authored code (Vibe Security Radar corpus)"),
    ("ai-stack-vulnerability", "self (vulnerability) CVEs of all other incidents — disclosed flaws in the affected products, mostly AI-stack components (gateways, coding agents, MCP SDKs, assistants); also the Trivy VS Code extension"),
    ("malicious-release", "self (malicious release) CVEs — package or extension versions that are malware by design (CNA CWE-506): a supply-chain artefact to remove, not a weakness of the product's code"),
    ("ai-discovered", "CVEs credited to the AI system or AI-assisted team the incident is about (relation discovered)"),
    ("related", "CVEs recorded as related context only (relation related)"),
]
SEGMENT_INDEX = {s: i for i, (s, _) in enumerate(SEGMENTS)}
# The segment of a CVE link that has a class of methodology §3.3 (lc.link_class); the other links get theirs by relation.
CLASS_SEGMENT = {"AI-written": "ai-written", "AI-stack": "ai-stack-vulnerability", "AI-discovered": "ai-discovered"}
SUB = "sub_threshold_incidents"   # the live array of the sub-threshold records (methodology §3.3); † in the README

RADAR_RE = re.compile(r"AI tool: (?P<tool>[^;]+); contribution: (?P<contribution>\w+); cause: (?P<cause>\w+)")
LONG_LIST = 10  # incidents with more CVEs than this get their list moved below the table in the .md


# ----------------------------------------------------------------------------- helpers
def cve_key(cve: str):
    _, year, num = cve.split("-")
    return (int(year), int(num))


def cwe_key(cwe: str):
    return int(cwe.split("-")[1])


def iso_date(s: str | None):
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", s or "")
    return dt.date.fromisoformat(m.group(1)) if m else None


def fmt(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:g}"
    if isinstance(v, (list, tuple)):
        return SEP.join(fmt(x) for x in v)
    return str(v)


def md(v):
    return fmt(v).replace("|", "\\|").replace("\n", " ")


def link(cve: str) -> str:
    return f"[{cve}]({CVE_URL.format(cve)})"


def md_table(headers, rows) -> str:
    rows = list(rows)
    for row in rows:
        if len(row) != len(headers):
            raise ValueError(f"row of {len(row)} cells under {len(headers)} headers {headers}: {list(row)[:3]}")
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(md(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def write_csv(path: Path, headers, rows):
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        for row in rows:
            w.writerow([fmt(c) for c in row])


# ----------------------------------------------------------------------------- load & check
def load(path: Path) -> dict:
    """Load the JSON and fail fast on the checks the tables rely on (scripts/validate_incidents.py core_checks).

    The full gate is scripts/validate_incidents.py; it is not run here, so the builder keeps working while
    judgment-level findings (e.g. VERIS schema errors) are open.
    """
    d = lc.load_corpus(path)
    problems = core_checks(d)
    if problems:
        sys.exit(str(problems[0]))
    return d


def build_links(d: dict) -> list[dict]:
    """One entry per record–CVE link of the live records (both live arrays), carrying the record's facts, its array,
    the link's classes (lc.link_classes) and the per-CVE metadata."""
    links = []
    for array in lc.LIVE_ARRAYS:
        for inc in d.get(array) or []:
            links += record_links(inc, array)
    return links


def record_links(inc: dict, array: str) -> list[dict]:
    """The links of one record; the segment comes from the link's class, else from its relation."""
    out = []
    det = inc.get("validated_cve_details") or {}
    roles = list(inc["report"].get("ai_role") or [])
    for c in det.get("cves") or []:
        rel = c["relation"]
        if rel in EXPLOITED_FAMILY:
            seg = "ai-exploited"
        elif rel == "self-malicious-release":
            seg = "malicious-release"
        elif k := lc.link_class(rel, roles):
            seg = CLASS_SEGMENT[k]
        else:
            seg = "related"
        radar = RADAR_RE.search(c.get("note") or "")
        out.append({
            "array": array, "classes": lc.link_classes(inc, rel),
            "incident_id": inc["id"], "incident_title": inc["title"], "incident_date": inc["date"],
            "observed": inc["report"]["observed_severity"], "potential": inc["report"]["potential_severity"],
            "ai_role": roles, "segment": seg,
            "cve": c["cve"], "relation": rel, "in_original": c.get("in_original"), "state": c.get("state"),
            "cna": c.get("cna"), "published": c.get("published"), "product": c.get("product"),
            "cvss_version": c.get("cvss_version"), "cvss_score": c.get("cvss_score"),
            "cwe": list(c.get("cwe") or []), "cisa_kev": bool(c.get("cisa_kev")), "kev_date_added": c.get("kev_date_added"),
            "credits": c.get("credits"), "title": c.get("title"), "note": c.get("note"),
            "radar": radar.groupdict() if radar else None,
        })
    return out


def score(ls):
    """IBSS (lc.ibss) over links: a counted incident adds its weight once, the sub-threshold records once per class."""
    return lc.ibss((l["array"], l["incident_id"], l["observed"], l["potential"], l["classes"]) for l in ls)


def ids_by_array(ls, key="incident_id"):
    """The distinct values of `key` among links, per live array: (counted incidents, sub-threshold records), sorted."""
    return tuple(sorted({l[key] for l in ls if l["array"] == a}) for a in lc.LIVE_ARRAYS)


def live_in_id_order(d):
    """(array, record) for every live record, in ID order over both arrays."""
    return sorted(((a, i) for a in lc.LIVE_ARRAYS for i in d.get(a) or []), key=lambda ai: lc.incident_number(ai[1]["id"]))


# ----------------------------------------------------------------------------- tables
def table_incident_cves(d, links):
    by_inc = defaultdict(list)
    for l in links:
        by_inc[l["incident_id"]].append(l)
    headers = ["incident_id", "observed_severity", "potential_severity", "cve_count", "cves", "cves_by_relation",
               "non_cve_identifier_count", "incident_title", "array"]
    rows = []
    for array, inc in live_in_id_order(d):
        ls = sorted(by_inc.get(inc["id"], []), key=lambda l: (-RELATION_WEIGHT[l["relation"]], cve_key(l["cve"])))
        groups = []
        for rel in RELATION_ORDER:
            cs = [l["cve"] for l in ls if l["relation"] == rel]
            if cs:
                groups.append(f"{rel}: {', '.join(cs)}")
        n_non = len((inc.get("validated_cve_details") or {}).get("non_cve_identifiers") or [])
        rows.append([inc["id"], inc["report"]["observed_severity"], inc["report"]["potential_severity"], len(ls),
                     [l["cve"] for l in ls], " | ".join(groups), n_non, inc["title"], array])
    return headers, rows


def cvss_band_short(score):
    if score is None:
        return "no CVSS"
    if score >= 9.0:
        return "9.0-10.0"
    if score >= 7.0:
        return "7.0-8.9"
    if score >= 4.0:
        return "4.0-6.9"
    return "0.1-3.9"


def ibss_per_cve(links):
    """IBSS of each CVE over its in-play links (absent for CVEs that are only `related`/`toolkit`)."""
    by = defaultdict(list)
    for l in links:
        by[l["cve"]].append(l)
    out = {}
    for cve, ls in by.items():
        ip = sorted((l for l in ls if l["relation"] in IN_PLAY), key=lambda l: l["incident_id"])
        if not ip:
            continue
        s = score(ip)
        out[cve] = {
            "obs": s.obs, "pot": s.pot, "obs_tiers": s.obs_tiers, "pot_tiers": s.pot_tiers,
            "cvss": ls[0]["cvss_score"], "cvss_version": ls[0]["cvss_version"], "kev": ls[0]["cisa_kev"],
            "incidents": [l["incident_id"] for l in ip], "relations": [l["relation"] for l in ip],
            "in_036": any(l["incident_id"] == "DR-2026-036" for l in ip),
        }
    return out


def spearman(xs, ys):
    """Spearman rank correlation with average ranks for ties (stdlib only)."""
    def avg_ranks(v):
        order = sorted(range(len(v)), key=lambda k: v[k])
        ranks = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                ranks[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return ranks
    rx, ry = avg_ranks(xs), avg_ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else float("nan")


def table_cve_incidents(links):
    by_cve = defaultdict(list)
    for l in links:
        by_cve[l["cve"]].append(l)
    ibss = ibss_per_cve(links)
    headers = ["cve", "incident_count", "sub_threshold_incident_count", "incidents", "sub_threshold_incidents", "relations",
               "max_relation", "cisa_kev", "cvss_score", "cvss_version", "ibss_observed", "ibss_potential", "cna", "published",
               "product", "cna_cwe", "title"]
    rows = []
    for cve, ls in by_cve.items():
        ls.sort(key=lambda l: l["incident_id"])
        best = max(ls, key=lambda l: RELATION_WEIGHT[l["relation"]])   # relations of all live records (handover O5)
        first = ls[0]  # intrinsic fields are identical across incidents (checked in the design review)
        ib = ibss.get(cve)
        inc_ids, sub_ids = ids_by_array(ls)
        rows.append([cve, len(inc_ids), len(sub_ids), inc_ids, sub_ids, SEP.join(f"{l['incident_id']}:{l['relation']}" for l in ls),
                     best["relation"], first["cisa_kev"], first["cvss_score"], first["cvss_version"],
                     ib["obs"] if ib else None, ib["pot"] if ib else None, first["cna"],
                     first["published"], first["product"], first["cwe"], first["title"]])
    # CVSS desc (score as published, versions mixed) -> KEV -> relation weight -> CVE id; rows without CVSS last.
    ix = {h: i for i, h in enumerate(headers)}
    cvss, kev, rel = ix["cvss_score"], ix["cisa_kev"], ix["max_relation"]
    rows.sort(key=lambda r: (r[cvss] is None, -(r[cvss] if r[cvss] is not None else 0), not r[kev], -RELATION_WEIGHT[r[rel]], cve_key(r[0])))
    return headers, rows


def table_ibss_vs_cvss(links):
    """The IBSS-vs-CVSS experiment: IBSS_potential band x CVSS band, rank correlations, disagreement lists."""
    per = ibss_per_cve(links)
    tiers_for = defaultdict(set)
    for v in per.values():
        tiers_for[v["pot"]].add(" + ".join(v["pot_tiers"]))
    band_headers = ["ibss_potential", "tiers"] + CVSS_BANDS + ["total_cves"]
    band_rows = []
    for pv in sorted({v["pot"] for v in per.values()}, reverse=True):
        cnt = Counter(cvss_band_short(v["cvss"]) for v in per.values() if v["pot"] == pv)
        band_rows.append([pv, " / ".join(sorted(tiers_for[pv]))] + [cnt[b] for b in CVSS_BANDS] + [sum(cnt.values())])
    scored = [v for v in per.values() if v["cvss"] is not None]
    no036 = [v for v in scored if not v["in_036"]]
    clusters = Counter(tuple(v["incidents"]) for v in no036)   # CVEs of one record share its IBSS value
    unscored = [v for v in per.values() if v["cvss"] is None]
    stats = {
        "n_inplay": len(per), "n_scored": len(scored), "n_single": sum(1 for v in per.values() if len(v["incidents"]) == 1),
        "n_036": sum(1 for v in per.values() if v["in_036"]), "n_no036_scored": len(no036),
        "n_no036_clusters": len(clusters), "top_cluster": clusters.most_common(1)[0] if clusters else ((), 0),
        "n_unscored": len(unscored), "unscored_incidents": sorted({i for v in unscored for i in v["incidents"]}),
        "n_036_const": sum(1 for v in per.values() if v["in_036"] and v["obs"] == 4 and v["pot"] == 8),
        "rho_obs": spearman([v["cvss"] for v in scored], [v["obs"] for v in scored]),
        "rho_pot": spearman([v["cvss"] for v in scored], [v["pot"] for v in scored]),
        "rho_obs_no036": spearman([v["cvss"] for v in no036], [v["obs"] for v in no036]),
        "rho_pot_no036": spearman([v["cvss"] for v in no036], [v["pot"] for v in no036]),
    }
    def order(items):
        return sorted(items, key=lambda cv: (-cv[1]["pot"], -(cv[1]["cvss"] if cv[1]["cvss"] is not None else -1), cve_key(cv[0])))
    def worst(tiers):  # highest severity tier among an entity's in-play incidents
        return min(tiers, key=SEVERITIES.index)
    pot_crit = lambda v: "Critical" in v["pot_tiers"]
    lists = {
        "top_band": order((c, v) for c, v in per.items() if v["pot"] >= 16),
        "low_cvss_high_pot": order((c, v) for c, v in per.items() if v["cvss"] is not None and v["cvss"] < 7.0 and pot_crit(v)),
        "high_cvss_low_pot": order((c, v) for c, v in per.items() if v["cvss"] is not None and v["cvss"] >= 9.0 and SEVERITIES.index(worst(v["pot_tiers"])) >= SEVERITIES.index("Medium")),
        "high_cvss_low_obs": order((c, v) for c, v in per.items() if v["cvss"] is not None and v["cvss"] >= 9.0 and SEVERITIES.index(worst(v["obs_tiers"])) >= SEVERITIES.index("Low")),
    }
    band_share = {}
    for b in CVSS_BANDS:
        vs = [v for v in per.values() if cvss_band_short(v["cvss"]) == b]
        hi = sum(1 for v in vs if "Critical" in v["pot_tiers"])
        band_share[b] = (hi, len(vs), hi / len(vs) if vs else 0.0)
    return {"band_headers": band_headers, "band_rows": band_rows, "stats": stats, "band_share": band_share, **lists}


def table_exploited(links):
    headers = ["cve", "relation", "incident_id", "observed_severity", "potential_severity", "incident_date", "published",
               "days_published_to_incident", "cvss_score", "cvss_version", "cisa_kev", "kev_date_added", "cna", "product",
               "cna_cwe", "title", "note"]
    rows = []
    for l in links:
        if l["relation"] not in EXPLOITED_FAMILY:
            continue
        pub, inc = iso_date(l["published"]), iso_date(l["incident_date"])
        lag = (inc - pub).days if pub and inc else None
        rows.append([l["cve"], l["relation"], l["incident_id"], l["observed"], l["potential"], l["incident_date"], l["published"],
                     lag, l["cvss_score"], l["cvss_version"], l["cisa_kev"], l["kev_date_added"], l["cna"], l["product"],
                     l["cwe"], l["title"], l["note"]])
    rows.sort(key=lambda r: (-RELATION_WEIGHT[r[1]], r[2], cve_key(r[0])))
    return headers, rows


DISCOVERY_CREDIT_TYPES = {"finder", "reporter", "analyst", "tool", None}   # None = role not stated in the record


def credits_all(credits):
    """Every credit with its role, for the CSV: 'value (type)'; an untyped credit without parentheses."""
    return SEP.join(f"{c['value']} ({c['type']})" if c.get("type") else c["value"] for c in credits or [])


def credits_discovery(credits):
    """Discovery credits only (methodology §6.7), duplicate values removed, for the README table."""
    return ", ".join(dict.fromkeys(c["value"] for c in credits or [] if c.get("type") in DISCOVERY_CREDIT_TYPES))


def table_discovered(links):
    headers = ["cve", "incident_id", "credits", "cna", "product", "published", "cvss_score", "cvss_version", "cna_cwe", "title", "array"]
    rows = [[l["cve"], l["incident_id"], credits_all(l["credits"]), l["cna"], l["product"], l["published"], l["cvss_score"], l["cvss_version"],
             l["cwe"], l["title"], l["array"]] for l in links if l["relation"] == "discovered"]
    rows.sort(key=lambda r: (r[1], cve_key(r[0])))
    return headers, rows


def per_array(ls):
    """The number of links per live array: [counted incidents, sub-threshold records]."""
    return [sum(1 for l in ls if l["array"] == a) for a in lc.LIVE_ARRAYS]


def table_cwe_profile(links):
    """CNA-assigned CWE frequency of the validated CVEs, per segment (CVE link = unit), counted per live array, with IBSS
    over the records (lc.ibss: a counted incident once, the sub-threshold records once per class). Rows rank by the links
    of both arrays."""
    seg_links = defaultdict(list)
    for l in links:
        seg_links[l["segment"]].append(l)
    headers = ["segment", "cwe", "cve_links", "sub_threshold_cve_links", "distinct_cves", "sub_threshold_distinct_cves",
               "incidents", "sub_threshold_incidents", "ibss_observed", "ibss_potential",
               "share_of_segment_cwe_tagged_links", "sub_threshold_share_of_segment_cwe_tagged_links"]
    rows, totals = [], []
    for seg, _ in SEGMENTS:
        ls = seg_links.get(seg, [])
        tagged = [l for l in ls if l["cwe"]]
        n_tagged = per_array(tagged)
        by_cwe = defaultdict(list)
        for l in tagged:
            for w in l["cwe"]:
                by_cwe[w].append(l)
        for w, wl in sorted(by_cwe.items(), key=lambda kv: (-len(kv[1]), cwe_key(kv[0]))):
            n, cves, incs, s = per_array(wl), ids_by_array(wl, "cve"), ids_by_array(wl), score(wl)
            rows.append([seg, w, n[0], n[1], len(cves[0]), len(cves[1]), len(incs[0]), len(incs[1]), s.obs, s.pot,
                         *(round(k / t, 3) if t else 0 for k, t in zip(n, n_tagged))])
        n, cves, incs, s = per_array(ls), ids_by_array(ls, "cve"), ids_by_array(ls), score(ls)
        cwes = [{w for l in tagged if l["array"] == a for w in l["cwe"]} for a in lc.LIVE_ARRAYS]
        totals.append([seg, n[0], n[1], len(cves[0]), len(cves[1]), len(incs[0]), len(incs[1]), s.obs, s.pot,
                       n_tagged[0], n_tagged[1], len(cwes[0]), len(cwes[1])])
    total_headers = ["segment", "cve_links", "sub_threshold_cve_links", "distinct_cves", "sub_threshold_distinct_cves",
                     "incidents", "sub_threshold_incidents", "ibss_observed", "ibss_potential",
                     "links_with_cna_cwe", "sub_threshold_links_with_cna_cwe", "distinct_cwes", "sub_threshold_distinct_cwes"]
    return headers, rows, total_headers, totals


def table_cwe_ibss_cve_path(links):
    """CNA-CWE IBSS via in-play CVEs: the CVE-path half of the CWE thread's union formula (lc.ibss: a counted incident once
    per CWE, the sub-threshold records once per class). Ranks follow the combined IBSS."""
    by_cwe, segs = defaultdict(list), defaultdict(set)
    for l in links:
        if l["relation"] not in IN_PLAY:
            continue
        for w in l["cwe"]:
            by_cwe[w].append(l)
            segs[w].add(l["segment"])
    headers = ["cwe", "incidents", "sub_threshold_incidents", "cve_links", "sub_threshold_cve_links", "distinct_cves",
               "sub_threshold_distinct_cves", "ibss_observed", "ibss_potential", "rank_observed", "rank_potential",
               "incident_ids", "sub_threshold_incident_ids", "segments"]
    rows = []
    for w, wl in by_cwe.items():
        incs, n, cves, s = ids_by_array(wl), per_array(wl), ids_by_array(wl, "cve"), score(wl)
        rows.append([w, len(incs[0]), len(incs[1]), n[0], n[1], len(cves[0]), len(cves[1]), s.obs, s.pot, 0, 0,
                     incs[0], incs[1], sorted(segs[w], key=SEGMENT_INDEX.get)])
    ix = {h: i for i, h in enumerate(headers)}
    obs, pot = ix["ibss_observed"], ix["ibss_potential"]
    n_rec = lambda r: r[ix["incidents"]] + r[ix["sub_threshold_incidents"]]
    rows.sort(key=lambda r: (-r[obs], -r[pot], -n_rec(r), cwe_key(r[0])))
    for k, r in enumerate(rows, 1):
        r[ix["rank_observed"]] = k
    for k, r in enumerate(sorted(rows, key=lambda r: (-r[pot], -r[obs], -n_rec(r), cwe_key(r[0]))), 1):
        r[ix["rank_potential"]] = k
    return headers, rows


def table_radar(links):
    headers = ["dimension", "value", "cve_count", "sub_threshold_cve_count"]
    rows = []
    parsed = [l for l in links if l["segment"] == "ai-written" and l["radar"]]
    unparsed = sum(1 for l in links if l["segment"] == "ai-written" and not l["radar"])
    for dim in ("contribution", "cause"):
        by_val = defaultdict(list)
        for l in parsed:
            by_val[l["radar"][dim]].append(l)
        for val, vl in sorted(by_val.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            rows.append([dim, val, *per_array(vl)])
    return headers, rows, len(parsed), unparsed


def table_non_cve(d):
    headers = ["incident_id", "identifier", "scheme", "kind", "note", "array"]
    rows = []
    for array, inc in live_in_id_order(d):
        for n in (inc.get("validated_cve_details") or {}).get("non_cve_identifiers") or []:
            scheme = re.match(r"[A-Za-z]+", n["id"])
            rows.append([inc["id"], n["id"], scheme.group(0) if scheme else "", n.get("kind"), n.get("note"), array])
    return headers, rows


def cvss_band(score):
    if score is None:
        return "no CVSS"
    if score >= 9.0:
        return "Critical 9.0-10.0"
    if score >= 7.0:
        return "High 7.0-8.9"
    if score >= 4.0:
        return "Medium 4.0-6.9"
    return "Low 0.1-3.9"


BANDS = ["Critical 9.0-10.0", "High 7.0-8.9", "Medium 4.0-6.9", "Low 0.1-3.9", "no CVSS"]


def out_of_scope_ids(d):
    """False positives and register-completeness records without an AI component (never carry CVEs)."""
    return {i["id"] for i in d["incidents"]
            if i["veris"]["security_incident"] == "False positive"
            or (i["report"].get("ai_involvement_note") or "").startswith("No AI component")}


def table_coverage(d):
    oos = out_of_scope_ids(d)
    headers = ["observed_severity", "incidents", "with_validated_cve", "without_cve_in_scope", "without_cve_out_of_scope"]
    rows = []
    for s in SEVERITIES + ["total"]:
        incs = [i for i in d["incidents"] if s == "total" or i["report"]["observed_severity"] == s]
        w = sum(1 for i in incs if i.get("validated_cve"))
        wo_oos = sum(1 for i in incs if not i.get("validated_cve") and i["id"] in oos)
        rows.append([s, len(incs), w, len(incs) - w - wo_oos, wo_oos])
    return headers, rows


def table_cvss_vs_observed(d, links):
    """Links of counted incidents per CVSS band and observed severity; the links of sub-threshold records per band only."""
    m, sub = defaultdict(Counter), Counter()
    for l in links:
        if l["array"] == SUB:
            sub[cvss_band(l["cvss_score"])] += 1
        else:
            m[cvss_band(l["cvss_score"])][l["observed"]] += 1
    headers = ["cvss_band_of_cve"] + SEVERITIES + ["total_links", "sub_threshold_links"]
    rows = [[b] + [m[b][s] for s in SEVERITIES] + [sum(m[b].values()), sub[b]] for b in BANDS]
    return headers, rows


def load_upstream(up: Path):
    """Raw upstream records cached by scripts/fetch_upstream.py (read via lib_corpus; never edited here)."""
    u = lc.load_upstream(up)
    return {k: u[k] for k in ("cve.org", "ghsa", "osv")}, u["manifest"]


def ecosystem_from(url):
    u = (url or "").lower()
    for key, name in (("npmjs", "npm"), ("pypi", "PyPI"), ("marketplace.visualstudio", "VS Code Marketplace"), ("rubygems", "RubyGems"),
                      ("crates.io", "crates.io"), ("pkg.go.dev", "Go"), ("nuget", "NuGet"), ("packagist", "Packagist"), ("github.com", "GitHub")):
        if key in u:
            return name
    return u.split("/")[2] if u.startswith("http") and u.count("/") >= 2 else ""


def cve_affected(rec):
    """Flatten containers.cna.affected -> (affected_versions, fixed_or_unaffected, packages[(ecosystem, name)])."""
    cna = (rec or {}).get("containers", {}).get("cna", {})
    parts, fixed, pkgs = [], [], []
    for a in cna.get("affected") or []:
        name = a.get("packageName") or "/".join(x for x in (a.get("vendor"), a.get("product")) if x and x.lower() != "n/a") or a.get("product") or "?"
        if a.get("packageName"):
            pkgs.append((ecosystem_from(a.get("collectionURL")), a["packageName"]))
        ranges = []
        for v in a.get("versions") or []:
            st, ver = v.get("status"), (v.get("version") or "").strip()
            lt, le = v.get("lessThan"), v.get("lessThanOrEqual")
            if st == "unaffected":
                fixed.append(f"{name} {ver}")
                continue
            if st not in (None, "affected"):
                continue
            if lt:
                ranges.append(f"< {lt}" if ver in ("", "0", "0.0.0", "*") else f">= {ver}, < {lt}")
                fixed.append(f"{name} {lt}")
            elif le:
                ranges.append(f"<= {le}" if ver in ("", "0", "0.0.0", "*") else f">= {ver}, <= {le}")
            elif ver:
                ranges.append(ver)
                m = re.match(r"^<\s*([\w.\-+]+)$", ver)
                if m:
                    fixed.append(f"{name} {m.group(1)}")
        if not ranges and a.get("defaultStatus") == "affected":
            ranges.append("all versions (defaultStatus: affected)")
        parts.append(f"{name}: {'; '.join(ranges) if ranges else 'versions not specified'}")
    if parts and all(re.fullmatch(r"(n/a|\?): (n/a|all|versions not specified)", x) for x in parts):
        return "not structured in the CVE record", "", pkgs
    return " | ".join(parts), "; ".join(dict.fromkeys(fixed)), pkgs


def cve_adp_cvss(rec):
    """CVSS from an ADP container (e.g. CISA-ADP) when the CNA gives none -> (score, version, provider)."""
    for adp in (rec or {}).get("containers", {}).get("adp", []) or []:
        for m in adp.get("metrics", []) or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if k in m and m[k].get("baseScore") is not None:
                    return m[k]["baseScore"], k[5:].replace("_", "."), (adp.get("providerMetadata") or {}).get("shortName")
    return None, None, None


def ghsa_packages(rec):
    return [((v.get("package") or {}).get("ecosystem", ""), (v.get("package") or {}).get("name", ""), v.get("vulnerable_version_range", ""), v.get("first_patched_version"))
            for v in (rec or {}).get("vulnerabilities") or []]


def osv_packages(rec):
    out = []
    for a in (rec or {}).get("affected") or []:
        pkg = a.get("package") or {}
        vers = a.get("versions") or []
        rng = []
        for r in a.get("ranges") or []:
            ev = r.get("events") or []
            intro = next((e["introduced"] for e in ev if "introduced" in e), None)
            fix = next((e["fixed"] for e in ev if "fixed" in e), None)
            rng.append(f">= {intro}" + (f", < {fix}" if fix else ""))
        out.append((pkg.get("ecosystem", ""), pkg.get("name", ""), ", ".join(vers) or "; ".join(rng), None))
    return out


PATCH_RELATIONS = {"exploited", "exploited-unconfirmed", "attempted", "toolkit", "self-vulnerability", "discovered"}
ACTION_ORDER = {"patch": 0, "remove": 1, "watch": 2}
# Triage rank of a row's strongest evidence: the relation order of methodology §6.4, except that `discovered` ranks
# with `self-vulnerability`. Both are disclosures without known exploitation, and who found a flaw is no triage signal.
EVIDENCE_RANK = {**RELATION_WEIGHT, "discovered": RELATION_WEIGHT["self-vulnerability"]}


def is_malicious_non_cve(n):
    k = (n.get("kind") or "").lower()
    return "malware" in k or n["id"].startswith(("MAL-", "PYSEC-"))


def table_action_list(d, links, recs, manifest):
    """patch / remove / watch — one row per identifier (CVE or malicious non-CVE id), in triage order: action, KEV,
    evidence (EVIDENCE_RANK), the identifier's IBSS potential, CVSS. A CVE's IBSS potential comes from its in-play
    links; a malicious non-CVE identifier's from the records that list it."""
    headers = ["action", "identifier", "scheme", "artifact", "evidence", "incidents", "sub_threshold_incidents", "max_observed", "cisa_kev", "cvss", "cvss_source",
               "product_or_package", "ecosystem", "affected_versions", "fixed_or_unaffected", "scope", "cna_or_source", "published", "version_data", "note",
               "ibss_potential"]
    rows = []
    by = defaultdict(list)
    for l in links:
        by[l["cve"]].append(l)
    ibss = ibss_per_cve(links)
    for cve, ls in by.items():
        rels = {l["relation"] for l in ls}
        cwes = {w for l in ls for w in l["cwe"]}
        rec = recs["cve.org"].get(cve)
        malicious = "self-malicious-release" in rels or "CWE-506" in cwes
        if malicious:
            action, artifact = "remove", "malicious-release"
        elif rels & PATCH_RELATIONS:
            action, artifact = "patch", "vulnerability"
        elif ls[0]["cisa_kev"] and "related" in rels:
            action, artifact = "watch", "vulnerability"
        else:
            continue
        evidence = max((r for r in rels), key=lambda r: RELATION_WEIGHT[r])
        aff, fixed, pkgs = cve_affected(rec) if rec else ("not fetched", "", [])
        first = ls[0]
        cvss, ver, src = first["cvss_score"], first["cvss_version"], "CNA"
        if cvss is None and rec:
            cvss, ver, prov = cve_adp_cvss(rec)
            src = prov or "ADP" if cvss is not None else ""
        segs = {l["segment"] for l in ls}
        if segs == {"ai-written"}:
            scope = "AI-written corpus (DR-2026-036, aggregate)"
        elif evidence == "toolkit":
            scope = "attacker toolkit (use unconfirmed)"
        elif evidence in ("exploited", "exploited-unconfirmed", "attempted"):
            scope = "attack path of an incident"
        elif evidence == "discovered":
            scope = "AI-discovered disclosure"
        else:
            scope = "AI-stack product disclosure" if action == "patch" else "campaign context"
        eco = "; ".join(dict.fromkeys(e for e, _ in pkgs if e)) if pkgs else ""
        prod = "; ".join(dict.fromkeys(n for _, n in pkgs)) if pkgs else (first["product"] or "")
        rows.append([action, cve, "CVE", artifact, evidence, *ids_by_array(ls),
                     min((l["observed"] for l in ls), key=SEVERITIES.index),   # over all live records
                     first["cisa_kev"], f"{fmt(cvss)} (v{ver})" if cvss is not None else "", src if cvss is not None else "",
                     prod, eco, aff, fixed, scope, first["cna"], first["published"],
                     f"cve.org record fetched {manifest.get(cve, {}).get('fetched_on', '')}" if rec else "not fetched",
                     first["title"] or "", ibss[cve]["pot"] if cve in ibss else None])
    # non-CVE malicious identifiers -> remove
    listed_by = defaultdict(list)   # identifier -> [(array, record)] of the live records that list it, in ID order
    for array, inc in live_in_id_order(d):
        for n in (inc.get("validated_cve_details") or {}).get("non_cve_identifiers") or []:
            if is_malicious_non_cve(n):
                listed_by[n["id"]].append((array, inc))
    seen = set()
    for _, inc in live_in_id_order(d):
        for n in (inc.get("validated_cve_details") or {}).get("non_cve_identifiers") or []:
            if not is_malicious_non_cve(n) or n["id"] in seen:
                continue
            seen.add(n["id"])
            x = n["id"]
            if x.startswith("GHSA-"):
                rec, pk, src = recs["ghsa"].get(x), None, "GitHub Advisory Database"
                pk = ghsa_packages(rec) if rec else []
                pub = (rec or {}).get("published_at", "")[:10]
                title = (rec or {}).get("summary") or n.get("note") or ""
            else:
                rec, src = recs["osv"].get(x), "OSV"
                pk = osv_packages(rec) if rec else []
                pub = (rec or {}).get("published", "")[:10]
                title = (rec or {}).get("summary") or n.get("note") or ""
            eco = "; ".join(dict.fromkeys(e for e, _, _, _ in pk if e))
            names = "; ".join(dict.fromkeys(nm for _, nm, _, _ in pk if nm))
            vers = " | ".join(f"{nm}: {vr}" for _, nm, vr, _ in pk if vr) if pk else ("not fetched" if not rec else "versions not specified")
            fixed = "; ".join(dict.fromkeys(f"{nm} {fp}" for _, nm, _, fp in pk if fp))
            listing = listed_by[x]
            ib = lc.ibss((a, i["id"], i["report"]["observed_severity"], i["report"]["potential_severity"], lc.disclosure_classes(i))
                         for a, i in listing)
            rows.append(["remove", x, x.split("-")[0], "malicious-release", n.get("kind", ""),
                         *([i["id"] for a, i in listing if a == arr] for arr in lc.LIVE_ARRAYS),
                         min((i["report"]["observed_severity"] for _, i in listing), key=SEVERITIES.index), False, "", "",
                         names, eco, vers, fixed, "malicious package release", src, pub,
                         f"{src} record fetched {manifest.get(x, {}).get('fetched_on', '')}" if rec else "not fetched", title, ib.pot])
    # missing values (no IBSS: watch rows; no CVSS) sort last
    ix = {h: i for i, h in enumerate(headers)}
    act, kev, ev, scope, ibp, cv = (ix[k] for k in ("action", "cisa_kev", "evidence", "scope", "ibss_potential", "cvss"))
    rows.sort(key=lambda r: (ACTION_ORDER[r[act]], not r[kev], -(EVIDENCE_RANK.get(r[ev], 0)), "aggregate" in r[scope],
                             -(r[ibp] if r[ibp] is not None else -1), -(float(r[cv].split()[0]) if r[cv] else -1), r[1]))
    return headers, rows


def group_remove_packages(headers, action_rows):
    """Group the advisory rows (GHSA / MAL / PYSEC) of the action list by (package, ecosystem)."""
    grp = {}
    for row in action_rows:
        r = dict(zip(headers, row))
        if r["action"] != "remove" or r["scheme"] == "CVE":
            continue
        vers_all = r["affected_versions"]
        parts = vers_all.split(" | ") if vers_all and vers_all != "not fetched" else [f"{r['product_or_package'] or '?'}: ?"]
        for part in parts:
            name, _, vers = part.partition(": ")
            eco = {"pip": "PyPI"}.get((r["ecosystem"] or "").lower(), r["ecosystem"] or "")
            key = (name.strip().lower(), eco.lower())
            g = grp.setdefault(key, {"name": name.strip(), "eco": eco, "versions": set(), "ids": [], "incidents": set(),
                                     "sub_threshold_incidents": set(), "obs": set()})
            g["versions"].update(v.strip().lstrip("= ") for v in re.split(r"[;,]", vers) if v.strip())
            if r["identifier"] not in g["ids"]:
                g["ids"].append(r["identifier"])
            g["incidents"].update(r["incidents"]); g["sub_threshold_incidents"].update(r["sub_threshold_incidents"])
            g["obs"].add(r["max_observed"])
    return grp


def table_kev(links, action_rows):
    act = {r[1]: r[0] for r in action_rows}
    by = defaultdict(list)
    for l in links:
        if l["cisa_kev"]:
            by[l["cve"]].append(l)
    headers = ["cve", "action", "kev_date_added", "incidents_relations", "cvss", "cvss_version", "product", "cna_cwe", "title"]
    rows = []
    for cve, ls in by.items():
        ls.sort(key=lambda l: l["incident_id"])
        f = ls[0]
        rows.append([cve, act.get(cve, "—"), f["kev_date_added"], SEP.join(f"{l['incident_id']}:{l['relation']}" for l in ls), f["cvss_score"], f["cvss_version"], f["product"], f["cwe"], f["title"]])
    rows.sort(key=lambda r: (ACTION_ORDER.get(r[1], 9), str(r[2] or ""), cve_key(r[0])))
    return headers, rows


def table_incident_cna_cwes(d, links):
    """Thread B input: per incident, the CNA CWEs of its in-play CVEs (§4.2 Rule 1 of the CWE handover)."""
    by_inc = defaultdict(list)
    for l in links:
        by_inc[l["incident_id"]].append(l)
    headers = ["incident_id", "in_play_cve_count", "other_cve_count", "cna_cwes_in_play", "cve_to_cwe_in_play",
               "as_cited_cwe", "as_cited_mapping_basis", "as_cited_confidence", "array"]
    rows = []
    for array, inc in live_in_id_order(d):
        ls = by_inc.get(inc["id"])
        if not ls:
            continue
        inplay = sorted((l for l in ls if l["relation"] in IN_PLAY), key=lambda l: cve_key(l["cve"]))
        cwes = sorted({w for l in inplay for w in l["cwe"]}, key=cwe_key)
        mapping = SEP.join(f"{l['cve']}:{','.join(l['cwe']) or '-'}" for l in inplay)
        ws = inc["report"].get("weaknesses") or []
        rows.append([inc["id"], len(inplay), len(ls) - len(inplay), cwes, mapping,
                     " | ".join(w.get("cwe", "") for w in ws), " | ".join(w.get("mapping_basis", "") for w in ws),
                     " | ".join(w.get("confidence", "") for w in ws), array])
    return headers, rows


# ----------------------------------------------------------------------------- report
def build_report(d, links, T) -> str:
    inc = d["incidents"]
    subs = d.get(SUB) or []
    sub_ids = {i["id"] for i in subs}
    mark = lambda iid: f"{iid}†" if iid in sub_ids else iid                   # † = a sub-threshold record
    mark_ids = lambda text: re.sub(r"(?:DB|DR)-2026-\d{3}", lambda m: mark(m.group(0)), text)
    nm = lambda n, m: f"{n} + {m}†" if m else n                              # a count split by live array
    named = lambda headers, rows: [dict(zip(headers, row)) for row in rows]  # rows by column name
    n_with = sum(1 for i in inc if i.get("validated_cve"))
    n_sub_with = sum(1 for i in subs if i.get("validated_cve"))
    n_sub_links = sum(1 for l in links if l["array"] == SUB)
    distinct = {l["cve"] for l in links}
    _occ = Counter(l["cve"] for l in links)
    pct_single = round(100 * sum(1 for c in _occ.values() if c == 1) / len(_occ))
    if max(_occ.values()) > 2:
        raise SystemExit("a CVE occurs in more than two live records — update the prose that says 'all in exactly two'")
    multi = sorted((c for c, n in Counter(l["cve"] for l in links).items() if n > 1), key=cve_key)
    kev = {l["cve"] for l in links if l["cisa_kev"]}
    expl = [r for r in T["exploited"][1]]
    n_non = len(T["non_cve"][1])
    n_non_inc = len({r[0] for r in T["non_cve"][1]})
    only_non = [i["id"] for i in inc if not i.get("validated_cve") and (i.get("validated_cve_details") or {}).get("non_cve_identifiers")]
    cv = d.get("cve_validation", {})
    rel_counts = Counter(l["relation"] for l in links)

    out = []
    A = out.append
    A("# 2026 AI software-security incidents — CVE-side tables")
    A("")
    A(f"Derived from **`incidents/all_2026_ai_software_security_incidents.json`** (dataset generated {d.get('generated')}; "
      f"CVE validation {cv.get('validated_on')}; incident IDs assigned {d.get('id_scheme', {}).get('assigned_on')}) by "
      "`scripts/build_vulnerabilities.py`. Every table here is a **view of the validated CVE layer** (`validated_cve`, "
      "`validated_cve_details`) of that JSON — the JSON stays the single source of truth; do not edit these files by hand.")
    A("")
    cov = T["coverage"][1]
    oos_n = len(out_of_scope_ids(d))
    serious = [r for r in cov if r[0] in ("Critical", "High")]
    ser_total = sum(r[1] - r[4] for r in serious); ser_without = sum(r[3] for r in serious)
    neg_with = next(r[2] for r in cov if r[0] == "Negligible")
    A("## Coverage — which incidents the CVE lens can see")
    A("")
    A("Everything below is built from the live records that have a validated CVE: the counted incidents (`incidents`) and the sub-threshold "
      "records (`sub_threshold_incidents`, marked † throughout; methodology §3.3). This table says how many counted incidents that is, per "
      "observed-severity tier (`report.observed_severity`), before any CVE statistic is read; the table after it counts the sub-threshold "
      f"records per class. *Out of scope* = the {oos_n} records kept for register completeness (false positives and incidents with no "
      "AI component); they never carry CVEs.")
    A("")
    A(md_table(["Observed severity", "Incidents", "With validated CVE", "Without CVE (in scope)", "Without CVE (out of scope)"], cov))
    A("")
    A(f"- **{ser_without} of the {ser_total} in-scope High/Critical incidents have no CVE.** What identifies them instead: stolen credentials, "
      "misconfiguration, malicious package releases (GHSA/MAL/PYSEC advisories — see the non-CVE identifiers table), prompt injection, agent misuse.")
    A(f"- The CVE-bearing set is disclosure-heavy: {neg_with} of {n_with} incidents with a CVE are observed *Negligible* — the incident is the "
      "disclosure of a vulnerability, nothing has happened yet. Low observed harm in the CVE-side statistics is therefore partly by construction.")
    A(f"- {len(only_non)} incidents are identified only by non-CVE identifiers: {', '.join(only_non)}.")
    A("")
    class_rows = []
    for k in lc.DISCLOSURE_CLASSES:
        rs = [i for i in subs if k in lc.disclosure_classes(i)]
        kl = [l for l in links if l["array"] == SUB and lc.link_class(l["relation"], l["ai_role"]) == k]
        class_rows.append([k, len(rs), sum(1 for i in rs if i.get("validated_cve")), len(kl), len({l["cve"] for l in kl})])
    A(f"**Sub-threshold records per class** ({len(subs)} records, not counted above). A sub-threshold record is a vulnerability disclosure "
      "without a KEV listing, an exploitation report or realized harm (methodology §3.3). A record can have several classes. *CVE links* are "
      "the links whose relation (`validated_cve_details.cves[].relation`) gives the class: `self (vulnerability)` or `discovered`; a record "
      "without a CVE takes its class from `report.ai_role`.")
    A("")
    A(md_table(["Class", "Records", "Records with a CVE", "CVE links", "Distinct CVEs"], class_rows))
    A("")
    A("## Conventions")
    A("")
    A("- **Counted and sub-threshold records.** An ID marked † is a sub-threshold record (`sub_threshold_incidents`); every other ID is a "
      "counted incident (`incidents`). A count without a prefix counts the counted incidents; a `sub_threshold_` column of the CSV files, "
      "and the `+ m†` part of a count here, counts the sub-threshold records. IBSS combines both arrays (see **IBSS**).")
    A("- **Relation** of a CVE to its incident (methodology §6.4, Rule 2). This build uses the methodology's listing order as the "
      "sort weight for ties: " + " > ".join(f"`{r}`" for r in RELATION_ORDER) + ". Only `exploited` CVEs are written to VERIS `action.*.cve`.")
    A("")
    A("  " + md_table(["relation", "meaning (methodology §6.4)"], [
        ["`exploited`", "primary sources show the CVE was exploited in the incident"],
        ["`exploited-unconfirmed`", "same disclosure batch and consistent with the described attack chain, but no source confirms the ID"],
        ["`attempted`", "exploitation was attempted in the incident but did not succeed / was not needed"],
        ["`toolkit`", "an exploit for the CVE was present in the attacker's recovered tooling; use against the victim not confirmed"],
        ["`self (vulnerability)`", "the incident *is* the disclosure of this vulnerability — a flaw in legitimate software; no exploitation by an attacker in this incident is asserted (stored as `self-vulnerability`)"],
        ["`self (malicious release)`", "the incident *is* the publication and execution of the artefact this ID identifies — a package/extension version that is malware by design (CNA CWE-506); harm realized, countermeasure is removal, not patching (stored as `self-malicious-release`)"],
        ["`discovered`", "the CVE is credited to the AI system or AI-assisted team the incident is about"],
        ["`related`", "same product cluster, disclosure batch or campaign, explicitly linked by the sources"],
    ]).replace("\n", "\n  "))
    A("")
    A("- **In play.** A CVE link is *in play* when its relation (`validated_cve_details.cves[].relation` in the JSON) shows that "
      "the CVE's flaw is part of what happened in the event (methodology §3.3, \"Scores\"). Only in-play links count in IBSS and in "
      "the per-incident CNA-CWE table.")
    A("")
    A("  " + md_table(["In play?", "Relation", "Why"], [
        ["yes" if in_play else "no", ", ".join(f"`{lab(r)}`" for r in rels), why] for in_play, rels, why in lc.IN_PLAY_TABLE
    ]).replace("\n", "\n  "))
    A("")
    A("- **CISA KEV** is evidence that a CVE is exploited *somewhere*, not that it was exploited in *this* incident (§6.4).")
    A("- **CVSS** is the CNA/NVD score of the *vulnerability* with its version; it is never used as incident severity. "
      "Incident severity is the report's ordinal **observed** / **potential** rubric.")
    A("- **IBSS** (incident-based severity score; methodology §3.3, \"Scores\") of an entity = the sum of the severity weights of the "
      "records that involve it — Negligible 1 · Low 2 · Medium 4 · High 8 · Critical 16 — computed separately for the observed "
      "(`report.observed_severity`) and the potential severity (`report.potential_severity`). A counted incident adds its weight once per "
      "entity; the sub-threshold records (†) add, per class (AI-written, AI-stack, AI-discovered), only the highest weight among that "
      "class's records, observed and potential separately. It is designed for CWEs, which span many incidents. For CVEs it is computed "
      f"over **in-play** links only and left blank for CVEs that are only `related`/`toolkit`; since {pct_single} % of CVEs occur in a single "
      "record, a CVE's IBSS is usually just that record's weight — see the *IBSS vs CVSS* section. "
      "Incidents — not CVEs — are the unit because a CVE count measures cataloguing practice as much as prevalence: CNA conventions differ (the Linux kernel CNA assigns a CVE per fixing commit; Mozilla issues per-bug CVEs but also rollup CVEs covering many memory-safety bugs at once; ecosystem CNAs often issue one CVE per affected package), so the same underlying flaw can be 1 or 11 CVEs depending on who assigned them — the MCP STDIO transport flaw (DR-2026-059) is eleven. IBSS therefore scores a weakness by the harm of the incidents it was involved in, each counted incident once and each class of sub-threshold records once, and reports prevalence (CVE links, distinct CVEs) beside it rather than folding it in. This is the deliberate inverse of MITRE's CWE Top 25 score (CVE count × average CVSS), which ranks the catalogue.")
    A("- **Segments** used for the CNA-CWE profile (defined over relation × AI role, one per CVE link):")
    for s, desc in SEGMENTS:
        A(f"  - `{s}` — {desc}")
    A(f"- CSV list cells use `{SEP.strip()}` as separator. CVE ids link to CVE.org.")
    A("")
    A("## Summary")
    A("")
    A(f"- **{len(inc)} incidents**; **{n_with}** carry validated CVEs, {len(inc) - n_with} do not "
      f"({len(only_non)} of those have only non-CVE identifiers: {', '.join(only_non)}). "
      f"Beside them **{len(subs)} sub-threshold records** (†), {n_sub_with} of them with validated CVEs.")
    A(f"- **{len(distinct)} distinct CVEs**, {len(links)} record–CVE links ({len(links) - n_sub_links} of counted incidents, {n_sub_links} of "
      f"sub-threshold records). Only {len(multi)} CVEs occur in more than one record (all in exactly two): {', '.join(link(c) for c in multi)}.")
    A("- Links by relation (all live records): " + ", ".join(f"`{lab(r)}` {rel_counts[r]}" for r in RELATION_ORDER if rel_counts[r]) + ".")
    A(f"- **{len(kev)} distinct CVEs on CISA KEV**; {len(expl)} CVE links in the exploited family "
      f"({', '.join(f'{r} {sum(1 for x in expl if x[1] == r)}' for r in EXPLOITED_FAMILY)}).")
    big = sorted(((len(i['validated_cve']), i['id']) for i in lc.records(d) if len(i.get('validated_cve') or []) >= 10), reverse=True)
    A("- Aggregate records (≥10 CVEs): " + ", ".join(f"{mark(i)} ({n})" for n, i in big)
      + ". DR-2026-036 alone holds " + f"{big[0][0]} of {len(distinct)} distinct CVEs — statistics that count CVEs are dominated by it; the segment split below isolates it as `ai-written`.")
    A(f"- {n_non} non-CVE identifiers across {n_non_inc} live records (GHSA, MAL, PYSEC, vendor advisories).")
    removed = cv.get("cves_removed", [])
    still = [c for c in removed if c in distinct]
    gone = [c for c in removed if c not in distinct]
    A("- Removed from the incident that originally cited them during validation: " + ", ".join(gone) + " (non-existent / rejected — never cited here)"
      + (f"; {', '.join(still)} (mis-filed under one incident, re-attributed to another — see Table 2)" if still else "") + ".")
    A("")
    # ---- Findings (computed)
    X0 = T["ibss"]; ALH, AL0 = T["action"]; AL0n = named(ALH, AL0)
    n_live_with = n_with + n_sub_with
    dr_share = sum(1 for i in lc.records(d) if i.get("validated_cve") and i["id"].startswith("DR"))
    expl_links = [l for l in links if l["relation"] == "exploited"]
    expl_all_kev = all(l["cisa_kev"] for l in expl_links)
    fam = [l for l in links if l["relation"] in EXPLOITED_FAMILY and l["cvss_score"] is not None]
    fam_lo, fam_hi = (min(l["cvss_score"] for l in fam), max(l["cvss_score"] for l in fam)) if fam else (None, None)
    adp_rows = sum(1 for r in AL0n if r["cvss_source"] == "CISA-ADP" and r["evidence"] == "self-vulnerability")  # flaws in AI products and AI-written code
    rem_pk = len(group_remove_packages(ALH, AL0))
    top3 = {}
    for seg, _ in SEGMENTS:
        rs = [r for r in named(T["cwe_profile"][0], T["cwe_profile"][1]) if r["segment"] == seg][:3]
        top3[seg] = ", ".join(f"{r['cwe']} ({r['cve_links'] + r['sub_threshold_cve_links']})" for r in rs)
    pi = [i for i in inc if "Prompt injection" in (i["veris"].get("action", {}).get("hacking", {}).get("variety") or [])]
    pi_obs = Counter(i["report"]["observed_severity"] for i in pi); pi_pot = Counter(i["report"]["potential_severity"] for i in pi)
    prof = lambda c: " ".join(f"{s[0]}{c[s]}" for s in SEVERITIES if c[s])
    A("## Findings")
    A("")
    A(f"1. **CVE covers the disclosures, not the breaches.** {ser_without} of the {ser_total} in-scope High/Critical incidents have no CVE; "
      f"{neg_with} of the {n_with} CVE-bearing incidents are observed Negligible (see *Coverage*). The CVE-side tables describe the third of the corpus that is easiest to identify, not the third that hurt most.")
    A(f"2. **The CVE side is deep-research-sourced.** {dr_share} of the {n_live_with} live records with a validated CVE"
      + (f" ({n_with} counted, {n_sub_with} sub-threshold)" if n_sub_with else "") + f" come from the deep-research reports (DR ids), "
      f"{n_live_with - dr_share} from the registers — registers record breaches, not vulnerability disclosures. The CVEs are validated at CVE.org; the *sample* of CVE-bearing incidents is not representative of AI-related incidents.")
    A(f"3. **Exploitation evidence tracked harm; the base score did not.** {'Every' if expl_all_kev else 'Not every'} confirmed-`exploited` CVE is on CISA KEV, "
      f"and the exploited family spans CVSS {fmt(fam_lo)}–{fmt(fam_hi)} — the same range as unexploited disclosures.")
    low_cves = {c for c, _ in X0["low_cvss_high_pot"]}
    low_products = Counter(next(l["product"] for l in links if l["cve"] == c) for c in low_cves)
    low_incs = sorted({l["incident_id"] for l in links if l["cve"] in low_cves and l["relation"] in IN_PLAY and l["potential"] == "Critical"})
    A(f"4. **Medium CVSS ≠ safe.** {len(low_cves)} CVEs rated CVSS < 7.0 sit in potential-Critical incidents "
      f"({', '.join(f'{p} {n}' for p, n in sorted(low_products.items(), key=lambda kv: (-kv[1], kv[0])))}; incidents {', '.join(low_incs)}). "
      f"Per CVSS band, the share of CVEs in a potential-Critical incident is {X0['band_share']['9.0-10.0'][2]:.0%} for 9.0–10.0 against "
      f"{X0['band_share']['7.0-8.9'][2]:.0%} / {X0['band_share']['4.0-6.9'][2]:.0%} for 7.0–8.9 / 4.0–6.9 — CVSS separates the top band, not the middle. "
      f"{len(low_incs)} incidents; a case, not a statistic.")
    A(f"5. **Three populations, three countermeasure programmes.** Top CNA CWEs — AI-written code: {top3['ai-written']}; AI-exploited: {top3['ai-exploited']}; "
      f"AI-discovered: {top3['ai-discovered']}; AI-stack products: {top3['ai-stack-vulnerability']} (CVE links of all live records). The AI-written profile is one external corpus (Radar) and needs a baseline before any \"AI writes X\" claim.")
    A(f"6. **The CVE ecosystem is not yet fit for AI-stack components.** {adp_rows} `self (vulnerability)` CVEs (flaws in AI products and AI-written code) carry no CNA CVSS — the score used here comes from CISA-ADP; "
      f"the MCP STDIO cluster (DR-2026-059) has no CNA CVSS, no CWE and product `n/a` in its records.")
    A(f"7. **Prompt injection: highest potential, least realized harm so far.** {len(pi)} incidents carry VERIS `hacking.variety = Prompt injection`; observed {prof(pi_obs)}, potential {prof(pi_pot)}. "
      f"Most are disclosed PoCs from the deep-research sources.")
    A(f"8. **Malicious releases need removal, not patching.** {sum(1 for r in AL0n if r['action'] == 'remove' and r['scheme'] == 'CVE')} CVEs and {rem_pk} package releases are malware by design "
      f"(CNA CWE-506 / malware advisories); they are separated from the weakness profiles and listed under *remove* in the action list.")
    A("")
    A("Who should read what: vulnerability management → *Action list* and *KEV CVEs*; developers of AI systems → *CNA-assigned CWE profile* (`ai-stack-vulnerability`, `ai-exploited`) and the incident-level CWE ranking of the CWE thread; "
      "researchers → *Coverage*, *CVSS vs observed*, *IBSS vs CVSS*; the CWE validation → *Per-incident CNA CWEs*.")
    A("")
    A("## Files")
    A("")
    A(md_table(["file", "content"], [
        ["`incident_cves.csv`", "Table 1 — one row per live record (counted incidents and sub-threshold records, column `array`): its validated CVEs, grouped by relation"],
        ["`cve_incidents.csv`", "Table 2 — one row per CVE: the records it occurs in, per array; relation, KEV, CVSS, product, CNA CWE"],
        ["`incidents_cve_coverage.csv`", "Coverage — per observed tier: incidents with a validated CVE, without (in scope), without (out of scope)"],
        ["`cvss_vs_observed.csv`", "CVSS band of the CVE vs observed severity of its incident (links of counted incidents); links of sub-threshold records per band"],
        ["`ibss_vs_cvss.csv`", "IBSS (potential) band × CVSS band of the in-play CVEs — the IBSS-vs-CVSS experiment"],
        ["`action_list.csv`", "Action list — patch / remove / watch, one row per identifier, with affected and fixed versions from the cached upstream records"],
        ["`kev_cves.csv`", "Every KEV-listed CVE in the corpus with its action and incident relations"],
        ["`cves_exploited.csv`", "Exploited-family CVEs (exploited / exploited-unconfirmed / attempted / toolkit) — evidence table behind the patch rows"],
        ["`upstream/`", "Raw CVE.org / GitHub Advisory / OSV records cached by `scripts/fetch_upstream.py` (manifest.json, LICENSES.md); never edited"],
        ["`cves_ai_discovered.csv`", "CVEs credited to AI systems / AI-assisted teams, with the CVE record's credits"],
        ["`non_cve_identifiers.csv`", "GHSA / MAL / PYSEC / vendor identifiers per live record"],
        ["`incident_cna_cwes.csv`", "Per live record: CNA CWEs of its in-play CVEs beside the as-cited CWE — input for the CWE validation (Thread B)"],
        ["`cve_cwe_profile_by_segment.csv`, `cve_cwe_segment_totals.csv`", "CNA-assigned CWE frequency of the validated CVEs per segment and array, with IBSS over the records; segment totals"],
        ["`cwe_ibss_cve_path.csv`", "CNA-CWE IBSS via in-play CVEs — the CVE-path baseline the CWE ranking will be compared against"],
        ["`ai_written_radar_profile.csv`", "Vibe Security Radar contribution / cause profile of the `ai-written` CVEs"],
    ]))
    A("")

    # ---- Table 1
    A("## Table 1 — live records and their validated CVEs")
    A("")
    A(f"ID order; † marks a sub-threshold record. Records with more than {LONG_LIST} CVEs are listed in full in the next section. "
      "`non-CVE ids` = count of GHSA/MAL/PYSEC/vendor identifiers (see the non-CVE table).")
    A("")
    long_ones = []
    rows = []
    for r in named(*T["incident_cves"]):
        iid, obs, pot, n, groups, n_non, title = (r[k] for k in ("incident_id", "observed_severity", "potential_severity", "cve_count",
                                                                   "cves_by_relation", "non_cve_identifier_count", "incident_title"))
        if n == 0:
            cell = "—" if not n_non else f"— ({n_non} non-CVE ids)"
        elif n > LONG_LIST:
            cell = f"**{n} CVEs** — see [full list](#{iid.lower()}) below"
            long_ones.append(r)
        else:
            parts = []
            for g in groups.split(" | "):
                rel, cs = g.split(": ", 1)
                parts.append(f"*{lab(rel)}:* " + ", ".join(link(c) for c in cs.split(", ")))
            cell = "; ".join(parts)
            if n_non:
                cell += f" (+{n_non} non-CVE ids)"
        rows.append([mark(iid), title, obs, pot, n, cell])
    A(md_table(["ID", "Incident", "Observed", "Potential", "#", "Validated CVEs (by relation)"], rows))
    A("")
    A("### Full CVE lists of the aggregate records")
    A("")
    for r in long_ones:
        iid, obs, pot, n, groups = (r[k] for k in ("incident_id", "observed_severity", "potential_severity", "cve_count", "cves_by_relation"))
        A(f"<a id=\"{iid.lower()}\"></a>")
        A(f"**{mark(iid)} — {md(r['incident_title'])}** ({n} CVEs; observed {obs}, potential {pot})")
        A("")
        for g in groups.split(" | "):
            rel, cs = g.split(": ", 1)
            A(f"- *{lab(rel)}* ({len(cs.split(', '))}): " + ", ".join(link(c) for c in cs.split(", ")))
        A("")

    # ---- Table 2
    CI = named(*T["cve_incidents"])
    n_nocvss = sum(1 for r in CI if r["cvss_score"] is None)
    A("## Table 2 — CVEs and the records they occur in")
    A("")
    A(f"Only {len(multi)} CVEs recur, all of them twice: {', '.join(link(c) for c in multi)} (bold in the `#` column, where "
      "`n + m†` = n counted incidents and m sub-threshold records). "
      "Since CVSS and KEV are the fields readers triage by, the table is ordered by **CVSS** (the score as published by the CNA; versions are mixed "
      f"and shown), then KEV, then relation; the {n_nocvss} CVEs without a CVSS score follow at the end, ordered by KEV, then relation. "
      "`IBSS obs` / `IBSS pot` are the incident-based severity scores over in-play links, blank for CVEs that are only "
      "`related`/`toolkit` (see *IBSS vs CVSS* below).")
    A("")
    rows = []
    for r in CI:
        n, m, cvss = r["incident_count"], r["sub_threshold_incident_count"], r["cvss_score"]
        rows.append([link(r["cve"]), f"**{nm(n, m)}**" if n + m > 1 else nm(n, m), mark_ids(lab_pairs(r["relations"])).replace(SEP, "<br>"),
                     "**KEV**" if r["cisa_kev"] else "", f"{fmt(cvss)} (v{r['cvss_version']})" if cvss is not None else "",
                     fmt(r["ibss_observed"]), fmt(r["ibss_potential"]), r["cna"], r["published"], r["product"],
                     fmt(r["cna_cwe"]).replace(SEP, ", "), r["title"]])
    A(md_table(["CVE", "#", "Record : relation", "KEV", "CVSS", "IBSS obs", "IBSS pot", "CNA", "Published", "Product", "CNA CWE", "Title"], rows))
    A("")

    # ---- CVSS vs observed
    A("## CVSS of the CVE vs observed severity of its incident (all links)")
    A("")
    A("Each severity cell counts the links of counted incidents by the incident's observed severity (`report.observed_severity`); the last "
      "column counts the links of sub-threshold records (†) per CVSS band. The vulnerability's CVSS and the incident's realized harm are "
      "different things — this table is the empirical form of the methodology's argument (§6.3). It covers all "
      f"{len(links) - n_sub_links} links of counted incidents, whatever their relation, and the {n_sub_links} links of sub-threshold "
      "records; the next section refines the comparison to in-play CVEs and scores them with IBSS.")
    A("")
    h, rows = T["cvss"]
    A(md_table(["CVSS band of CVE"] + SEVERITIES + ["Total", "Sub-threshold links"], rows))
    A("")
    A("Read together with the *Coverage* table at the top: the CVE-bearing incidents are disclosure-heavy, so the Negligible/Low columns are populated partly by construction.")
    A("")

    # ---- IBSS vs CVSS experiment
    X = T["ibss"]; s = X["stats"]
    A("## IBSS vs CVSS — a first experiment")
    A("")
    A(f"IBSS was designed for CWEs, where one weakness spans many incidents. Applying it to CVEs is a first check of two things only: "
      f"whether the tier weights behave sensibly, and how a CVE's technical score relates to the harm its incident realized (observed) or "
      f"could have realized (potential). Three limits apply. **(1)** {s['n_single']} of the {s['n_inplay']} in-play CVEs have a single "
      f"in-play record, so their IBSS is just that record's weight — the summation is barely exercised. **(2)** Each in-play CVE receives the "
      f"*full* weight of every counted incident it is in play in, and per class that of the highest-weighted sub-threshold record (†); "
      f"where several CVEs share an incident (e.g. the Artifactory CVEs of DB-2026-006) the score does not establish per-CVE causation. **(3)** {s['n_036']} of the {s['n_inplay']} in-play CVEs belong to DR-2026-036, and {s['n_036_const']} of those share one observed "
      f"(Medium = 4) and one potential (High = 8) value, so aggregate statistics are dominated by that incident; figures are therefore also "
      f"given without it.")
    A("")
    A(f"- A Spearman rank correlation between CVSS and IBSS is computed by the build script but **not reported at this stage**: "
      f"{s['n_036']} of the {s['n_scored']} scored in-play CVEs share one severity value (DR-2026-036), and the remaining n = {s['n_no036_scored']} "
      f"come from only {s['n_no036_clusters']} incidents or incident sets ({', '.join(s['top_cluster'][0])} alone holds {s['top_cluster'][1]}). "
      f"The CVEs of one incident share its IBSS, so they are not independent observations, and an interval computed as if they were would "
      f"overstate the precision. The corpus is planned to grow (further sources, later years), and the correlation will be "
      f"reported once the in-play CVEs spread over enough incidents for the interval to be informative. Until then the band table below "
      f"carries the comparison.")
    A("- Potential is the fairer comparison — CVSS and potential both describe what *could* happen; observed shows what did.")
    A("")
    A("### IBSS_potential band × CVSS band (in-play CVEs)")
    A("")
    A(md_table(["IBSS pot", "Tier(s)"] + CVSS_BANDS + ["CVEs"], X["band_rows"]))
    A("")
    A("Share of in-play CVEs with at least one **potential-Critical** incident, per CVSS band: "
      + "; ".join(f"{b}: {X['band_share'][b][0]}/{X['band_share'][b][1]} ({X['band_share'][b][2]:.0%})" for b in CVSS_BANDS if X['band_share'][b][1])
      + f". The top band stands out; the middle bands do not differ. The unscored band holds the {s['n_unscored']} in-play CVEs without a CVSS score, "
      f"from {len(s['unscored_incidents'])} incidents ({', '.join(s['unscored_incidents'])}).")
    A("")
    def cve_rows(items):
        return [[link(c), f"{fmt(v['cvss'])} (v{v['cvss_version']})" if v["cvss"] is not None else "—", "**KEV**" if v["kev"] else "",
                 v["obs"], v["pot"], SEP.join(f"{mark(i)}:{lab(r)}" for i, r in zip(v["incidents"], v["relations"]))] for c, v in items]
    H = ["CVE", "CVSS", "KEV", "IBSS obs", "IBSS pot", "Record : relation"]
    A(f"### Top potential band — IBSS_potential ≥ 16 ({len(X['top_band'])} CVEs)")
    A("")
    A(md_table(H, cve_rows(X["top_band"])))
    A("")
    A(f"### Disagreement: CVSS < 7.0 but potential Critical ({len(X['low_cvss_high_pot'])} CVEs)")
    A("")
    A("Context outweighs the component score: chained or privileged use turned medium-rated vulnerabilities into critical potential.")
    A("")
    A(md_table(H, cve_rows(X["low_cvss_high_pot"])) if X["low_cvss_high_pot"] else "none")
    A("")
    A(f"### Disagreement: CVSS ≥ 9.0 but potential ≤ Medium ({len(X['high_cvss_low_pot'])} CVEs)")
    A("")
    A(md_table(H, cve_rows(X["high_cvss_low_pot"])) if X["high_cvss_low_pot"] else "none — every in-play CVE rated Critical by CVSS sits in an incident with potential High or Critical.")
    A("")
    A(f"### Disclosed, not exploited: CVSS ≥ 9.0 but observed ≤ Low ({len(X['high_cvss_low_obs'])} CVEs)")
    A("")
    if X["high_cvss_low_obs"]:
        hl_rel = Counter(max(set(v["relations"]), key=RELATION_WEIGHT.get) for _, v in X["high_cvss_low_obs"])
        A("By strongest in-play relation: " + ", ".join(f"{n} `{lab(r)}`" for r, n in sorted(hl_rel.items(), key=lambda kv: -RELATION_WEIGHT[kv[0]]))
          + ". Severe on paper, no realized harm recorded — the gap the observed/potential split is designed to show.")
        A("")
    A(md_table(H, cve_rows(X["high_cvss_low_obs"])) if X["high_cvss_low_obs"] else "none")
    A("")

    # ---- action list
    AL = AL0n
    n_fetched = sum(1 for r in AL if r["version_data"] != "not fetched")
    fetch_dates = sorted({r["version_data"].split("fetched ")[-1] for r in AL if r["version_data"] != "not fetched"})
    A("## Action list — patch · remove · watch")
    A("")
    A("One row per identifier, derived from the relation vocabulary and the CNA CWE. **patch** = a vulnerability that was exploited, attempted, carried "
      "in an attacker's toolkit, is the disclosed subject of an incident (`self (vulnerability)`), or was found by the AI system the incident is about "
      "(`discovered`); **remove** = a malicious release "
      "(`self (malicious release)`, CNA CWE-506, or a malware-type GHSA / MAL / PYSEC advisory) — purge the listed versions and rotate every credential "
      "they could reach; **watch** = KEV-listed CVEs recorded as `related` context of a campaign, not shown to be used in an incident. "
      f"Version data comes from the cached upstream records (`vulnerabilities/upstream/`, {n_fetched} of {len(AL)} rows; records fetched "
      f"{', '.join(fetch_dates) or 'n/a'}); CVSS is the CNA's, or the CISA-ADP score where the CNA gives none (`cvss_source`). Full table: `action_list.csv`.")
    A("")
    A("Rows are in triage order: KEV-listed first; then by the strongest evidence (exploited > exploited-unconfirmed > attempted > toolkit > "
      "disclosure, where `self (vulnerability)` and `discovered` rank alike, because who found a flaw is no triage signal); then by **IBSS potential** "
      "(`IBSS pot`: the potential severity of the incidents in which the identifier is in play, Negligible 1 … Critical 16); then by CVSS. "
      "A CVE takes the potential of its whole incident, which a different flaw of the same incident may set; the CVSS column shows the CVE's own score.")
    A("")
    def act_rows(items):
        return [[link(r["identifier"]) if r["scheme"] == "CVE" else r["identifier"], lab(r["evidence"]) if r["scheme"] == "CVE" else r["evidence"],
                 "<br>".join(map(mark, r["incidents"] + r["sub_threshold_incidents"])), r["max_observed"], "**KEV**" if r["cisa_kev"] else "",
                 fmt(r["ibss_potential"]), r["cvss"] + (f" ({r['cvss_source']})" if r["cvss_source"] and r["cvss_source"] != "CNA" else ""),
                 r["product_or_package"], r["ecosystem"], r["affected_versions"], r["fixed_or_unaffected"]] for r in items]
    AH = ["ID", "Evidence", "Records", "Max observed", "KEV", "IBSS pot", "CVSS", "Product / package", "Ecosystem", "Affected versions", "Fixed / unaffected"]
    patch = [r for r in AL if r["action"] == "patch"]
    agg = [r for r in patch if "aggregate" in r["scope"]]
    A(f"### patch ({len(patch)} CVEs; {len(patch) - len(agg)} shown, {len(agg)} of the AI-written aggregate corpus DR-2026-036 in the CSV only)")
    A("")
    A(md_table(AH, act_rows([r for r in patch if "aggregate" not in r["scope"]])))
    A("")
    rem = [r for r in AL if r["action"] == "remove"]
    rem_cve = [r for r in rem if r["scheme"] == "CVE"]
    # the same malicious release is often listed by GHSA, MAL and PYSEC -> group by package
    grp = group_remove_packages(ALH, AL0)
    A(f"### remove — {len(rem_cve)} CVEs and {len(grp)} malicious package releases ({len(rem) - len(rem_cve)} GHSA / MAL / PYSEC advisories, grouped by package; one row per advisory in the CSV)")
    A("")
    A("Purge the listed versions, rotate every credential the package could reach (cloud keys, CI tokens, SSH keys), and hunt for the persistence it planted.")
    A("")
    A(md_table(AH, act_rows(rem_cve)))
    A("")
    A(md_table(["Package", "Ecosystem", "Malicious versions", "Advisories", "Records", "Max observed"],
               [[g["name"], g["eco"], ", ".join(sorted(g["versions"], key=lambda s: [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.\-]", s)])), ", ".join(g["ids"]),
                 ", ".join(map(mark, sorted(g["incidents"] | g["sub_threshold_incidents"]))), min(g["obs"], key=SEVERITIES.index)]
                for g in sorted(grp.values(), key=lambda g: (SEVERITIES.index(min(g["obs"], key=SEVERITIES.index)), g["name"].lower()))]))
    A("")
    watch = [r for r in AL if r["action"] == "watch"]
    A(f"### watch ({len(watch)} KEV CVEs related to a campaign)")
    A("")
    A(md_table(AH, act_rows(watch)) if watch else "none")
    A("")

    # ---- KEV
    KV = T["kev"][1]
    A(f"## KEV CVEs in this corpus ({len(KV)})")
    A("")
    A("Every CVE in the corpus that is on CISA's Known Exploited Vulnerabilities catalogue, whatever its relation — KEV means exploited *somewhere*, "
      "not necessarily in these incidents (§6.4). The `action` column links each to the action list above.")
    A("")
    A(md_table(["CVE", "Action", "KEV added", "Incident : relation", "CVSS", "Product", "CNA CWE", "Title"],
               [[link(r[0]), r[1], r[2], mark_ids(lab_pairs(r[3])).replace(SEP, "<br>"), f"{fmt(r[4])} (v{r[5]})" if r[4] is not None else "", r[6], fmt(r[7]).replace(SEP, ", "), r[8]] for r in KV]))
    A("")

    # ---- exploited
    n_expl_links = len(T["exploited"][1]); n_expl_cves = len({r[0] for r in T["exploited"][1]})
    A(f"## Exploited-family CVEs — used, attempted or carried by AI-enabled attackers ({n_expl_links} links, {n_expl_cves} distinct CVEs)")
    A("")
    A("Relation `exploited` / `exploited-unconfirmed` = the CVE was (probably) the way in; `attempted` = tried, not confirmed successful; "
      "`toolkit` = an exploit was present in the attacker's recovered tooling. `lag` = days from CVE publication to the incident date "
      "(only where the incident date is a full ISO date; negative = the incident predates the CVE's publication — zero-day use where the relation is confirmed, otherwise unconfirmed).")
    A("")
    rows = [[link(r[0]), lab(r[1]), mark(r[2]), r[3], r[6], fmt(r[7]), f"{fmt(r[8])} (v{r[9]})" if r[8] is not None else "", "**KEV**" if r[10] else "",
             r[13], fmt(r[14]).replace(SEP, ", "), r[15]] for r in T["exploited"][1]]
    A(md_table(["CVE", "Relation", "Incident", "Observed", "Published", "Lag (d)", "CVSS", "KEV", "Product", "CNA CWE", "Title"], rows))
    A("")

    # ---- discovered
    n_d_links = len(T["discovered"][1]); n_d_cves = len({r[0] for r in T["discovered"][1]})
    A(f"## CVEs discovered by AI systems (register — {n_d_links} links, {n_d_cves} distinct CVEs)")
    A("")
    A("Relation `discovered`: the CVE is credited to the AI system or AI-assisted team the incident is about. "
      "`Credits` lists the discovery credits of the CVE record where the CNA publishes any (methodology §6.7): roles "
      "finder, reporter, analyst and tool, plus credits whose role the record does not state. "
      "`cves_ai_discovered.csv` has every credit with its role, including coordinators and remediation developers.")
    A("")
    cred = {(l["cve"], l["incident_id"]): l["credits"] for l in links}
    rows = [[link(r[0]), mark(r[1]), credits_discovery(cred[(r[0], r[1])]), r[3], r[4], r[5], f"{fmt(r[6])} (v{r[7]})" if r[6] is not None else "", fmt(r[8]).replace(SEP, ", "), r[9]]
            for r in T["discovered"][1]]
    A(md_table(["CVE", "Record", "Credits", "CNA", "Product", "Published", "CVSS", "CNA CWE", "Title"], rows))
    A("")

    # ---- non-CVE
    A("## Non-CVE identifiers")
    A("")
    A("Malicious package releases, account-takeover publishes and vendor-fixed flaws often never receive a CVE (methodology §6.6); "
      "GHSA / MAL / PYSEC / vendor advisory ids are recorded here and never placed in CVE fields.")
    A("")
    A(md_table(["Record", "Identifier", "Scheme", "Kind", "Note"], [[mark(r[0]), r[1], r[2], r[3], r[4]] for r in T["non_cve"][1]]))
    A("")

    # ---- Thread B input
    A("## Per-record CNA CWEs of in-play CVEs (input for the CWE validation)")
    A("")
    A("For every live record with validated CVEs: the CWEs the CNAs assigned to its in-play CVEs, beside the as-cited incident CWE "
      "(`report.weaknesses`, unvalidated). Where the two disagree, the CWE validation decides; nothing is ranked from this table here.")
    A("")
    rows = [[mark(r[0]), r[1], r[2], fmt(r[3]).replace(SEP, ", "),
             fmt(r[4]).replace(SEP, "<br>") if r[1] <= LONG_LIST else f"{r[1]} CVEs — see `incident_cna_cwes.csv`",
             r[5], r[6], r[7]] for r in T["cna_cwes"][1]]
    A(md_table(["Record", "In-play CVEs", "Other CVEs", "CNA CWEs (in-play)", "CVE → CNA CWE", "As-cited CWE", "As-cited basis", "Conf."], rows))
    A("")
    # ---- CWE profile
    A("## CNA-assigned CWE profile of the validated CVEs, per segment")
    A("")
    A("Descriptive CVE statistics: the unit is the **CVE link**, not the incident, and the CWE is the one the CNA assigned to the CVE record. "
      "This is *not* the incident-level CWE ranking (that is built in the CWE thread from the incident layer, where each incident counts once); "
      "it shows what kind of vulnerabilities each population of CVEs consists of.")
    A("")
    TOT = {t["segment"]: t for t in named(T["cwe_profile"][2], T["cwe_profile"][3])}
    A(md_table(["Segment", "CVE links", "Distinct CVEs", "Records", "IBSS obs", "IBSS pot", "Links with CNA CWE", "Distinct CWEs"],
               [[t["segment"], nm(t["cve_links"], t["sub_threshold_cve_links"]), nm(t["distinct_cves"], t["sub_threshold_distinct_cves"]),
                 nm(t["incidents"], t["sub_threshold_incidents"]), t["ibss_observed"], t["ibss_potential"],
                 nm(t["links_with_cna_cwe"], t["sub_threshold_links_with_cna_cwe"]), nm(t["distinct_cwes"], t["sub_threshold_distinct_cwes"])]
                for t in TOT.values()]))
    A("")
    A("How to read the per-segment rows: **CVE links** = number of record–CVE pairs in the segment whose CVE record carries this CWE "
      "(a CVE that occurs in two records counts twice); **Distinct CVEs** = the same without double-counting recurring CVEs; "
      "**Records** = distinct records among those links; `n + m†` = n of counted incidents, m of sub-threshold records; **Share** = CVE links "
      "with this CWE ÷ links in the segment that carry any CNA CWE (the *Links with CNA CWE* column above), per array; **IBSS obs / pot** = "
      "incident-based severity score over those records (Negligible 1 · Low 2 · Medium 4 · High 8 · Critical 16, observed and potential "
      "separately; each counted incident once, the sub-threshold records once per class) — for `related` this attributes an incident's harm to the CWE of a *sibling* CVE, shown as context weight for comparison with the CWE thread (whose Rule 1 excludes `related`), not as the weakness's risk. Shares within a segment add up to more than 100 % because one CVE record can carry several CWEs. "
      "Example: `ai-exploited` / CWE-306 = 4 links (Langflow CVE-2026-33017 and CVE-2025-3248, marimo CVE-2026-39987 in two incidents), "
      "3 distinct CVEs, 4 incidents, 4 ÷ 14 = 29 %. CWEs that the incident record assigns directly (`report.weaknesses`) are **not** counted "
      "here; they appear beside the CNA CWEs in the preceding per-incident table and feed the incident-level CWE ranking of the CWE thread.")
    A("")
    by_seg = defaultdict(list)
    for r in named(T["cwe_profile"][0], T["cwe_profile"][1]):
        by_seg[r["segment"]].append(r)
    for seg, desc in SEGMENTS:
        rs = by_seg.get(seg, [])
        if not rs:
            continue
        A(f"### `{seg}` — top {min(12, len(rs))} of {len(rs)} CWEs")
        A("")
        tot = TOT[seg]
        if tot["incidents"] + tot["sub_threshold_incidents"] == 1:
            one = next(l["incident_id"] for l in links if l["segment"] == seg)
            A(f"All links of this segment stem from one record ({mark(one)}), so IBSS is the same for every row (observed {tot['ibss_observed']}, "
              f"potential {tot['ibss_potential']}) — the column will differentiate once further records join the segment.")
            A("")
        share = lambda r: f"{r['share_of_segment_cwe_tagged_links']:.0%}" + (
            f" + {r['sub_threshold_share_of_segment_cwe_tagged_links']:.0%}†" if r["sub_threshold_cve_links"] else "")
        A(md_table(["CWE", "CVE links", "Distinct CVEs", "Records", "IBSS obs", "IBSS pot", "Share"],
                   [[r["cwe"], nm(r["cve_links"], r["sub_threshold_cve_links"]), nm(r["distinct_cves"], r["sub_threshold_distinct_cves"]),
                     nm(r["incidents"], r["sub_threshold_incidents"]), r["ibss_observed"], r["ibss_potential"], share(r)] for r in rs[:12]]))
        A("")
        if seg == "ai-written":
            rh, rr, n_parsed, n_unparsed = T["radar"]
            A(f"### `ai-written` — Vibe Security Radar profile ({n_parsed} CVE notes parsed, {n_unparsed} unparsed)")
            A("")
            A("Radar's `contribution` type says how the AI tool was involved in the flawed code; `cause` is Radar's coarse cause category. "
              "Per-AI-tool counts are deliberately not tabulated: they reflect Radar's attribution method and tool market share, not defect rates.")
            A("")
            A(md_table(["Dimension", "Value", "CVEs"], [[r[0], r[1], nm(r[2], r[3])] for r in rr]))
            A("")

    # ---- CVE-path CWE IBSS baseline
    CB = named(*T["cwe_ibss"])
    A("## CNA-CWE IBSS via in-play CVEs — the CVE-path baseline for the CWE ranking")
    A("")
    A("For every CNA-assigned CWE of an in-play CVE: the records it reaches through those CVEs (each counted incident once per CWE, the sub-threshold records once per class), their IBSS, and the prevalence behind it. "
      "This is the CVE-path half of the CWE thread's formula (incidents linked to a CWE = analyst mapping ∪ CNA CWE of in-play CVEs): the difference between this table and "
      f"`cwe_priority` will be the contribution of the direct incident-level mapping — which is why analyst-only weaknesses such as CWE-1357 do not appear here at all. "
      f"Sorted by observed IBSS; {len(CB)} CWEs. **Not the CWE ranking.** Full table with ranks: `cwe_ibss_cve_path.csv`.")
    A("")
    A(md_table(["CWE", "Records", "Distinct CVEs", "IBSS obs", "IBSS pot", "Rank pot", "Records (ids)", "Segments"],
               [[r["cwe"], nm(r["incidents"], r["sub_threshold_incidents"]), nm(r["distinct_cves"], r["sub_threshold_distinct_cves"]),
                 r["ibss_observed"], r["ibss_potential"], r["rank_potential"],
                 ", ".join(map(mark, r["incident_ids"] + r["sub_threshold_incident_ids"])), ", ".join(r["segments"])] for r in CB]))
    A("")
    A("## Caveats")
    A("")
    A("- Incident dates are free text for many incidents (e.g. `2026`, `Jun - Jul`), so the exploitation lag is only computed where an ISO date exists.")
    A("- Product strings are as recorded by the CNA (e.g. `BerriAI/litellm` vs `BerriAI/LiteLLM`, `n/a/n/a`); they are not normalised here.")
    A("- CVSS scores come from one source per CVE (usually the CNA); NVD may score differently. No EPSS / SSVC enrichment in this build.")
    A("- The as-cited CWE column is unvalidated and known to be inconsistent in places; see `CWE_validation_handover.md`.")
    A("")
    A("*These tables and this report are licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), as the incident dataset they derive from; "
      "the upstream records they quote keep their own licences (`upstream/LICENSES.md`). Attribution: `README.md` of the repository, section License.*")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = Path(__file__).resolve().parents[1]
    ap.add_argument("--json", default=root / "incidents" / "all_2026_ai_software_security_incidents.json", type=Path)
    ap.add_argument("--out", default=root / "vulnerabilities", type=Path)
    ap.add_argument("--upstream", default=root / "vulnerabilities" / "upstream", type=Path,
                    help="cache written by scripts/fetch_upstream.py (read-only here; missing -> version columns say 'not fetched')")
    a = ap.parse_args()

    d = load(a.json)
    links = build_links(d)
    recs, manifest = load_upstream(a.upstream)
    a.out.mkdir(parents=True, exist_ok=True)

    T = {
        "incident_cves": table_incident_cves(d, links),
        "cve_incidents": table_cve_incidents(links),
        "exploited": table_exploited(links),
        "discovered": table_discovered(links),
        "cwe_profile": table_cwe_profile(links),
        "radar": table_radar(links),
        "non_cve": table_non_cve(d),
        "cvss": table_cvss_vs_observed(d, links),
        "coverage": table_coverage(d),
        "cna_cwes": table_incident_cna_cwes(d, links),
        "ibss": table_ibss_vs_cvss(links),
    }
    T["cwe_ibss"] = table_cwe_ibss_cve_path(links)
    T["action"] = table_action_list(d, links, recs, manifest)
    T["kev"] = table_kev(links, T["action"][1])
    write_csv(a.out / "incident_cves.csv", *T["incident_cves"])
    write_csv(a.out / "cve_incidents.csv", *T["cve_incidents"])
    write_csv(a.out / "ibss_vs_cvss.csv", T["ibss"]["band_headers"], T["ibss"]["band_rows"])
    write_csv(a.out / "action_list.csv", *T["action"])
    write_csv(a.out / "kev_cves.csv", *T["kev"])
    write_csv(a.out / "cves_exploited.csv", *T["exploited"])
    write_csv(a.out / "cves_ai_discovered.csv", *T["discovered"])
    write_csv(a.out / "cve_cwe_profile_by_segment.csv", T["cwe_profile"][0], T["cwe_profile"][1])
    write_csv(a.out / "cve_cwe_segment_totals.csv", T["cwe_profile"][2], T["cwe_profile"][3])
    write_csv(a.out / "cwe_ibss_cve_path.csv", *T["cwe_ibss"])
    write_csv(a.out / "ai_written_radar_profile.csv", T["radar"][0], T["radar"][1])
    write_csv(a.out / "non_cve_identifiers.csv", *T["non_cve"])
    write_csv(a.out / "cvss_vs_observed.csv", *T["cvss"])
    write_csv(a.out / "incidents_cve_coverage.csv", *T["coverage"])
    write_csv(a.out / "incident_cna_cwes.csv", *T["cna_cwes"])
    (a.out / "README.md").write_text(build_report(d, links, T), encoding="utf-8")

    print(f"incidents {len(d['incidents'])} | sub-threshold records {len(d.get(SUB) or [])} | links {len(links)} | distinct CVEs {len({l['cve'] for l in links})} | "
          f"exploited-family {len(T['exploited'][1])} | discovered {len(T['discovered'][1])} | non-CVE ids {len(T['non_cve'][1])} | "
          f"incidents in CNA-CWE table {len(T['cna_cwes'][1])} | action rows {len(T['action'][1])} (upstream records: {sum(len(v) for v in recs.values())}) | "
          f"wrote {len([f for f in a.out.iterdir() if f.is_file()])} files to {a.out}")


if __name__ == "__main__":
    main()
