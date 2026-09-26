#!/usr/bin/env python3
"""Build the derived incident reports from the 2026 AI software-security incident dataset.

Reads  incidents/all_2026_ai_software_security_incidents.json          (source of truth)
Writes incidents/all_2026_ai_software_security_incidents.{csv,md}      (derived; never edited by hand)

Ported from the one-time build_all_csv_md.py of 2026-08-26 (outside this repository). The CSV has the as-cited
`cve` column and the canonical `validated_cve` column; the Markdown shows the as-cited CVEs on the VERIS line and a
**Validated CVEs:** line per entry (methodology §10.2, file map). Offline, standard library only, deterministic.
It fails fast on the checks of scripts/validate_incidents.py core_checks; the full gate is that script.

Usage:  python3 scripts/build_incidents_report.py [--json PATH] [--out-base PATH]
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_corpus as lc  # noqa: E402
from validate_incidents import core_checks  # noqa: E402

XLSX = "incidentdatabase.ai_20260824_ai_incidents_2026.xlsx"
VCDB = "vz-risk/VCDB"
SRC_SHORT = {XLSX: "AIID", VCDB: "VCDB",
             "ChatGPT_DeepResearch_ai_incidents_2026.md": "ChatGPT",
             "ClaudeCode_DeepResearch_ai_incidents_2026.md": "ClaudeCode",
             "Grok_DeepResearch_ai_incidents_2026.md": "Grok"}
MONTHS = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun", 7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"}
TIERS = [("Critical", "CRITICAL"), ("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW"), ("Negligible", "NEGLIGIBLE observed")]
CVE_URL = "https://www.cve.org/CVERecord?id={}"
MAX_CVE_LINKS = 12   # per relation group on the Validated CVEs line
MAX_NON_CVE = 6
CSV_COLS = ["id", "date", "incident", "status", "observed_severity", "potential_severity", "potential_confidence",
            "confidence", "sources", "source_citations", "ai_role", "ai_component", "ai_security_mechanism",
            "actor", "action", "asset", "data_disclosure", "cve", "validated_cve", "cwe", "victim", "industry_naics",
            "observed_severity_rationale", "potential_severity_rationale", "references"]
LINK_NAMES = {
    "anthropic.com": "Anthropic", "openai.com": "OpenAI", "huggingface.co": "Hugging Face", "wiz.io": "Wiz",
    "koi.ai": "Koi Security", "bitdefender.com": "Bitdefender", "thehackernews.com": "The Hacker News",
    "theregister.com": "The Register", "bleepingcomputer.com": "BleepingComputer", "techcrunch.com": "TechCrunch",
    "malwarebytes.com": "Malwarebytes", "darkreading.com": "Dark Reading", "securityweek.com": "SecurityWeek",
    "sysdig.com": "Sysdig", "dragos.com": "Dragos", "varonis.com": "Varonis", "cloud.google.com": "Google Cloud",
    "microsoft.com": "Microsoft", "xbow.com": "XBOW", "nvd.nist.gov": "NVD", "pillar.security": "Pillar Security",
    "research.checkpoint.com": "Check Point", "catonetworks.com": "Cato Networks", "aikido.dev": "Aikido",
    "cybersecuritynews.com": "Cybersecurity News", "stepsecurity.io": "StepSecurity", "elastic.co": "Elastic Security Labs",
    "securitylabs.datadoghq.com": "Datadog Security Labs", "safedep.io": "SafeDep", "flatt.tech": "GMO Flatt Security",
    "orca.security": "Orca Security", "huntress.com": "Huntress", "tanstack.com": "TanStack", "access.redhat.com": "Red Hat",
    "indusface.com": "Indusface", "cybernews.com": "Cybernews", "securitymagazine.com": "Security Magazine",
    "socradar.io": "SoCRadar", "upguard.com": "UpGuard", "aisi.gov.uk": "UK AISI", "ox.security": "OX Security",
    "cline.bot": "Cline", "github.com": "GitHub", "blog.mozilla.org": "Mozilla", "vibesecradar.com": "Vibe Security Radar",
    "incidentdatabase.ai": "AIID", "arstechnica.com": "Ars Technica", "mashable.com": "Mashable", "cyberscoop.com": "CyberScoop",
    "hunt.io": "Hunt.io", "docs.litellm.ai": "LiteLLM", "exposure.cloudsek.com": "CloudSEK", "helpnetsecurity.com": "Help Net Security",
    "rnz.co.nz": "RNZ", "databreaches.net": "DataBreaches.net", "engadget.com": "Engadget", "the-decoder.de": "The Decoder",
    "lluh.org": "Loma Linda UH", "hipaajournal.com": "HIPAA Journal", "nbcnews.com": "NBC News", "procontra-online.de": "procontra",
    "it-boltwise.de": "it-boltwise", "gujaratsamachar.com": "Gujarat Samachar", "ajupress.com": "AJU Press",
    "msn.com": "MSN", "trt4.jus.br": "TRT-4", "thehindu.com": "The Hindu"}


# ----------------------------------------------------------------------------- helpers
def joinlist(x):
    return "; ".join(x) if isinstance(x, list) else (x or "")


def veris_categories(blocks):
    # "category:variety; ..."; a block without variety (actor.partner, action.unknown) renders as its name alone
    return "; ".join(f"{k}:{joinlist(val['variety'])}" if val.get("variety") else k for k, val in blocks.items())


def shortdate(e):
    t = e["veris"]["timeline"]["incident"]
    y, m = t.get("year"), t.get("month")
    return (MONTHS[m] + " " + str(y)) if m else str(y)


def srcshort(e):
    return "+".join(dict.fromkeys(SRC_SHORT.get(c["source"], c["source"]) for c in e["sources"]))


def category(e):
    v, rep = e["veris"], e["report"]
    roles = set(rep["ai_role"])
    mech = " ".join(rep["ai_security_mechanism"]).lower()
    if v["security_incident"] == "False positive":
        return "Not a security event"
    if not roles:
        return "No AI (register context)"
    if "AI model/capability theft" in roles:
        return "Model theft"
    if "AI-discovered vulnerability" in roles or "AI security control" in roles:
        return "AI-discovered vuln"
    if any(k in mech for k in ["worm", "supply-chain", "supply chain", "dependency", "marketplace", "config persistence", "package"]):
        return "AI supply chain"
    if "AI-agent-caused incident" in roles:
        av = v.get("attribute", {}).get("availability", {})
        return "Agent destructive" if av and "Destruction" in av.get("variety", []) else "AI agent incident"
    if "AI-enabled attacker" in roles:
        return "AI-driven attack"
    if "AI-generated weakness" in roles:
        return "Vibe-coded / AI-authored"
    if "AI system/harness attacked" in roles:
        return "Agent harness" if any(k in mech for k in ["prompt injection", "sandbox", "rce", "escape"]) else "AI product breach"
    return "AI-related"


def linkname(u):
    host = re.sub(r"^https?://", "", u).split("/")[0].replace("www.", "")
    return LINK_NAMES.get(host, host)


def cite_md(c):
    s, loc, url = c["source"], c.get("locator"), c.get("url")
    if s == XLSX:
        return f"[{loc or 'AIID'}]({url})" if url else f"`{s}`"
    if s == VCDB:
        if loc and loc.startswith("issues/"):
            label = "VCDB #" + loc.split("/")[1]
        elif loc and "data/json" in loc:
            parts = loc.split("/")
            label = "VCDB " + parts[-2] + "/" + (parts[-1][:8] + "…")
        else:
            label = "VCDB"
        return f"[{label}]({url})" if url else label
    return f"`{s}`"


def reporting_md(e):
    urls = []
    for tok in (x.strip() for x in e["veris"].get("reference", "").split(";")):
        if tok.startswith("http"):
            u = tok.split()[0]
            if u not in urls:
                urls.append(u)
    parts, seen = [], set()
    for u in urls:
        nm = linkname(u)
        if nm in seen:
            continue
        seen.add(nm)
        parts.append(f"[{nm}]({u})")
        if len(parts) >= 3:
            break
    return ", ".join(parts)


def validated_md(e):
    """The **Validated CVEs:** line: relation groups in first-appearance order, then added / non-CVE / removed / note."""
    det = e.get("validated_cve_details") or {}
    groups = {}
    for c in det.get("cves") or []:
        groups.setdefault(c["relation"], []).append(c["cve"])
    parts = []
    for rel, ids in groups.items():
        links = ", ".join(f"[{x}]({CVE_URL.format(x)})" for x in ids[:MAX_CVE_LINKS])
        more = f" … +{len(ids) - MAX_CVE_LINKS} more (full list in JSON)" if len(ids) > MAX_CVE_LINKS else ""
        parts.append(f"*{lc.lab(rel)} ({len(ids)}):* {links}{more}")
    if not parts:
        parts.append("none identified")
    if det.get("added"):
        parts.append(f"{len(det['added'])} added vs. original record")
    non = [n["id"] for n in det.get("non_cve_identifiers") or []]
    if non:
        more = f" … (+{len(non) - MAX_NON_CVE} more in JSON)" if len(non) > MAX_NON_CVE else ""
        parts.append("*non-CVE identifiers:* " + ", ".join(non[:MAX_NON_CVE]) + more)
    if det.get("removed"):
        parts.append("removed: " + "; ".join(f"{r['cve']} ({r.get('state')}: {r.get('reason')})" for r in det["removed"]))
    if det.get("note"):
        parts.append(det["note"])
    return "**Validated CVEs:** " + " · ".join(parts)


# ----------------------------------------------------------------------------- CSV
def render_csv(d):
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for e in d["incidents"]:
        v, rep = e["veris"], e["report"]
        actor = veris_categories(v.get("actor", {}))
        action = veris_categories(v.get("action", {}))
        assets = "; ".join(a.get("variety", "") for a in v.get("asset", {}).get("assets", []))
        dd = v.get("attribute", {}).get("confidentiality", {}).get("data_disclosure", "")
        cve = "; ".join(x.get("cve", "") for x in rep.get("vulnerabilities", []) if x.get("cve"))
        cwe = "; ".join(x.get("cwe", "") for x in rep.get("weaknesses", []) if x.get("cwe"))
        srcs = "; ".join(dict.fromkeys(c["source"] for c in e["sources"]))
        srccit = "; ".join("|".join([c["source"], c.get("locator", ""), c.get("url", "")]).rstrip("|") for c in e["sources"])
        w.writerow([e["id"], e["date"], e["title"], v["security_incident"], rep["observed_severity"],
                    rep["potential_severity"], rep.get("potential_severity_confidence", ""), v.get("confidence", ""),
                    srcs, srccit, joinlist(rep["ai_role"]), joinlist(rep.get("ai_component", [])),
                    joinlist(rep.get("ai_security_mechanism", [])), actor, action, assets, dd, cve,
                    "; ".join(e.get("validated_cve") or []), cwe,
                    v.get("victim", {}).get("victim_id", ""), v.get("victim", {}).get("industry", ""),
                    rep.get("observed_severity_rationale", ""), rep.get("potential_severity_rationale", ""),
                    v.get("reference", "")])
    return buf.getvalue()


# ----------------------------------------------------------------------------- Markdown
def render_md(d):
    inc = d["incidents"]
    num = {e["id"]: lc.incident_number(e["id"]) for e in inc}
    cc, bs, cnt = d["counts"]["by_observed_severity"], d["counts"]["citations_by_source"], d["counts"]
    ids = d["id_scheme"]["counts"]
    n_db_src = cnt["from_ai_software_security_incidents_2026"]
    n_dr_src = cnt["from_merged_incidents_2026_VERIS_described"]
    cv = d["cve_validation"]
    relations = ", ".join(f"*{r}*" for r in lc.RELATION_ORDER)
    n_aligned = len(cv["veris_action_cve_alignment"]["changes"])
    L = ["# All 2026 AI-Related Software-Security Incidents — Consolidated (VERIS-coded)", "",
         "**The full 2026 corpus: every incident from the AIID+VCDB register set and the four deep-research reports, VERIS-coded, with corrected original-source citations. Where AI was a cause, a weapon, a target, the loot, or the tool that found (or wrote) the flaw.**", "",
         f"Compiled {d['generated']}. Union of `ai_software_security_incidents_2026.json` ({n_db_src}) and `merged_incidents_2026_VERIS_described.json` ({n_dr_src}). Ordered highest → lowest **observed** severity (realized harm), with **potential** severity (the bounded counterfactual from the demonstrated attack path) alongside — kept separate per the VERIS methodology, never collapsed. Severity is a report-specific ordinal rubric from VERIS evidence, **not** CVSS/AIRIS.", "",
         f"- **{cc['Critical']} Critical · {cc['High']} High · {cc['Medium']} Medium · {cc['Low']} Low · {cc['Negligible']} Negligible** ({cnt['total_incidents']} incidents; {cnt['by_status']['Near miss']} near-miss, {cnt['by_status']['False positive']} *False positive* as outside the software-security inclusion criterion).",
         f"- **Original sources cited** (per methodology §5/§6): AIID export `{XLSX}` and the VERIS Community Database `{VCDB}` for the register incidents; the three deep-research reports (`ChatGPT`/`ClaudeCode`/`Grok`_DeepResearch_ai_incidents_2026.md) for the rest. Citation counts: VCDB {bs.get(VCDB, 0)} · ClaudeCode {bs.get('ClaudeCode_DeepResearch_ai_incidents_2026.md', 0)} · ChatGPT {bs.get('ChatGPT_DeepResearch_ai_incidents_2026.md', 0)} · AIID {bs.get(XLSX, 0)} · Grok {bs.get('Grok_DeepResearch_ai_incidents_2026.md', 0)}.",
         "", "Full VERIS + report-layer coding is in the companion `all_2026_ai_software_security_incidents.json` / `.csv`.",
         "", "---", "", "## Incident index", "",
         "| # | Incident | Date | Category | AI's role (VERIS) | Source(s) | Observed | Potential |",
         "|---|----------|------|----------|-------------------|-----------|----------|-----------|"]
    for e in inc:
        obs, pot = e["report"]["observed_severity"], e["report"]["potential_severity"]
        obs_s = f"**{obs}**" if obs == "Critical" else obs
        role = ", ".join(e["report"]["ai_role"]) or "—"
        L.append(f"| {num[e['id']]} | {e['title']} | {shortdate(e)} | {category(e)} | {role} | {srcshort(e)} | {obs_s} | {pot} |")
    L += ["", "---", "", "## Incidents in detail", ""]
    for tkey, tlabel in TIERS:
        grp = [e for e in inc if e["report"]["observed_severity"] == tkey]
        if not grp:
            continue
        nums = [num[e["id"]] for e in grp]
        rng = f"{min(nums)}" if len(nums) == 1 else f"{min(nums)}–{max(nums)}"
        L += [f"### {tlabel} tier ({rng})", ""]
        for e in grp:
            v, r = e["veris"], e["report"]
            head = f"**{num[e['id']]}. {e['title']} — {shortdate(e)}.**"
            cve = ""
            cves = [x["cve"] for x in r.get("vulnerabilities") or [] if x.get("cve")]
            if cves:
                cve = " · CVE: " + ", ".join(cves[:4]) + ("…" if len(cves) > 4 else "")
            note = (f"*VERIS: {v['security_incident']} · Observed **{r['observed_severity']}**, Potential **{r['potential_severity']}** "
                    f"(confidence {v.get('confidence', '?')}). {r['potential_severity_rationale']}{cve}*")
            srcline = "**Sources:** " + ", ".join(cite_md(c) for c in e["sources"])
            rep = reporting_md(e)
            if rep:
                srcline += " · **Reporting:** " + rep
            L.append(head + " " + v["summary"])
            if r.get("ai_involvement_note"):
                L.append(f"*AI-involvement: {r['ai_involvement_note']}*")
            L += [note, srcline, validated_md(e), ""]
        L.append("")
    L += ["---", "", "## Method & caveats", "",
          f"- **Incident IDs.** `DB-2026-nnn` (*database*) = at least one register source (AIID export or VCDB; {ids['DB']} incidents), `DR-2026-nnn` (*direct report*) = no register source, found through a deep-research or primary report ({ids['DR']}, all from deep-research reports so far). The number is the position in this report's priority ranking (the `#` column of the index) and is frozen — later re-ranking changes the table, not the ID; new incidents continue from 100.",
          f"- **Scope & union.** {cnt['total_incidents']} incidents = {n_db_src} (from the AIID + VCDB registers) + {n_dr_src} (from the four deep-research reports), with no overlap. Contents are identical to the two source JSONs; only each incident's original-source citations were normalised.",
          "- **Original sources.** Register incidents cite the AIID export (`" + XLSX + "`) and/or the VERIS Community Database (`vz-risk/VCDB`) — the latter at the exact `data/json/{validated,submitted}/<uuid>.json` record or the `issues/<n>` intake. Report incidents cite `ChatGPT`/`ClaudeCode`/`Grok`_DeepResearch_ai_incidents_2026.md. The **Reporting** links are the primary vendor/news/CVE sources from each record.",
          "- **Coding.** Each incident carries a standard VERIS record (Actor/Action/Asset/Attribute, CIA, graded disclosure, scope, timeline, confidence) plus a separate report layer (AI role/component/mechanism, observed & potential severity, CWE/CVE with mapping basis). Where VERIS has no native concept (model extraction, prompt injection, autonomous agent action) the nearest valid coding is used and the AI meaning is carried in the report layer.",
          "- **Ranking.** By **observed** severity, potential as tiebreaker — a report-specific ordinal rubric (Critical > High > Medium > Low > Negligible), **not** CVSS, the ChatGPT report's AIRIS, or the CC report's blended tier. Vulnerability-discovery / coordinated-disclosure PoC items sit at Negligible/Low observed and High/Critical potential.",
          "- **Non-software-security rows.** Five MIT/VCDB register items are `security_incident = False positive` (privacy/likeness/governance harms, not asset compromises); ten conventional VCDB breaches with no AI component are flagged as such. Both are retained for register completeness, each with an AI-involvement note.",
          f"- **CVE validation ({cv['validated_on']}).** Every CVE ID in the original records was resolved against CVE.org/NVD and checked against the incident description; CISA KEV, the GitHub Advisory Database and each incident's primary sources were searched for omitted CVEs. The per-incident **Validated CVEs** line (and the `validated_cve` / `validated_cve_details` attributes in the JSON, `validated_cve` column in the CSV) carries the corrected list, grouped by relation ({relations}), with removed IDs and their reasons. Original title/summary text was left untouched, so a title may still cite an ID that the validation line removes or re-attributes. On {cv['veris_action_cve_alignment']['aligned_on']} the VERIS `action.hacking.cve` / `action.malware.cve` fields in the JSON were aligned to hold only validated *exploited* CVEs ({n_aligned} fields; previous values kept in `validated_cve_details.veris_cve_before`).",
          "- **Granularity note.** The Anthropic July-2026 cyber-evaluation incident (`DB-2026-019`) is coded as one incident under its single disclosure/root cause, though the ChatGPT report enumerated its three sub-incidents separately.",
          "", "---", "",
          f"*Prepared from the AI Incident Database and VERIS Community Database registers plus ChatGPT, Claude Code and Grok deep-research reports, coded per `VERIS_Methodology_for_AI_Security_Incidents_concise.md`, compiled {d['generated']}. Not affiliated with or endorsed by any vendor named herein; all trademarks belong to their owners.*", "",
          "*Licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); adapts material from the VERIS Community Database and the AI Incident Database (both CC BY-SA 4.0). Attribution and changes: `README.md`, section License.*",
          ""]
    return "\n".join(L)


def render(d):
    """(csv_text, md_text) for the corpus; fails fast on the core checks."""
    problems = core_checks(d)
    if problems:
        sys.exit(str(problems[0]))
    return render_csv(d), render_md(d)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default=lc.JSON_PATH, type=Path)
    ap.add_argument("--out-base", default=lc.ROOT / "incidents" / "all_2026_ai_software_security_incidents", type=Path,
                    help="output path without extension; .csv and .md are appended")
    a = ap.parse_args()
    csv_text, md_text = render(lc.load_corpus(a.json))
    a.out_base.with_suffix(".csv").write_text(csv_text, encoding="utf-8", newline="")
    a.out_base.with_suffix(".md").write_text(md_text, encoding="utf-8")
    print(f"wrote {a.out_base}.csv ({csv_text.count(chr(10)) - 1} data rows) and .md ({md_text.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
