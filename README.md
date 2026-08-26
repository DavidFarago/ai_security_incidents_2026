![AISEC 2026 — AI Security Incidents](assets/branding/AISEC2026.png)

# ai_security_incidents_2026

A VERIS-coded catalogue of **2026 software-security incidents in which AI was materially involved** — as a cause, a weapon, a target, the loot, or the tool that found (or wrote) the flaw.

The dataset consolidates five original sources into one consistent, machine-readable corpus, each incident described with the [VERIS](https://verisframework.org/) schema plus a small AI-specific report layer, following the methodology in [`incidents/VERIS_Methodology_for_AI_Security_Incidents_concise.md`](incidents/VERIS_Methodology_for_AI_Security_Incidents_concise.md).

## Why VERIS

Rather than invent a bespoke AI-incident score, this project adopts **VERIS** — the mature, open incident vocabulary behind the Verizon DBIR and the VERIS Community Database — as the single external framework, adding only a thin AI-specific layer on top. It fits better than the obvious alternatives: **CVSS** rates a *vulnerability's* technical severity, not what a realized incident actually did; **NCISS**'s coarse national-response categories discard the details that matter most here (records and credentials exposed, systems touched, confirmed-vs-possible disclosure); and **FAIR / FAIR-MAM** need quantitative loss data that public incident reports seldom provide. Coding to VERIS instead preserves those granular facts, natively separates confirmed breaches from near-misses and mere exposure, and lets these AI incidents be compared and pooled with the tens of thousands already in VCDB — the innovation is applying that established discipline to AI-related software-security incidents. Crucially, VERIS keeps the *incident* layer distinct from the *vulnerability/weakness* layer: exploited CVEs are referenced through VERIS's own `action.hacking.cve` / `action.malware.cve` fields, CVSS is never repurposed as incident severity, and CWE weaknesses are carried in the AI report layer with an explicit mapping basis (authoritative CVE/CNA vs analyst-inferred) rather than silently guessed.

## The dataset

**`incidents/all_2026_ai_software_security_incidents.{json,csv,md}`** — the same 99 incidents in three forms:

| File | What it is |
|---|---|
| `.json` | **Source of truth.** Full nested coding per incident, plus metadata, a source catalogue, and a ranking table. |
| `.csv` | One flattened row per incident (24 columns), including a `source_citations` column with full provenance. |
| `.md` | A severity-ranked field guide: an incident index plus a narrative entry per incident. |

**99 incidents**, severity-ranked by *observed* (realized) harm:

- **2 Critical · 22 High · 31 Medium · 21 Low · 23 Negligible**
- Status: 93 Confirmed · 1 Near miss · 5 False positive
- IDs: `AISEC-2026-*` (35 incidents, sourced from the AIID + VCDB registers) and `MRG-2026-*` (64 incidents, sourced from the three deep-research reports). The two sets are disjoint.

### How each incident is coded

Two layers are kept separate (per the methodology), so the standard security facts stay schema-compliant while the AI-specific judgements remain explicit:

- **`veris`** — canonical VERIS 1.4.1: Actor / Action / Asset / Attribute, CIA with graded `data_disclosure` (Yes / Potentially / No), scope, timeline, victim, confidence, and CVE linkage where applicable.
- **`report`** — AI-specific metadata: `ai_role`, `ai_component`, `ai_security_mechanism`, **Observed** vs **Potential** severity (each with a rationale and confidence), and CWE/CVE with a mapping basis.

**Observed and Potential severity are never collapsed into one score**, and neither is CVSS/AIRIS: severity here is a transparent ordinal rubric (Critical > High > Medium > Low > Negligible) derived from the VERIS evidence. Vulnerability-discovery and coordinated-disclosure PoC items therefore sit at low *observed* / high *potential*.

Non-software-security items carried by the registers (e.g. facial-recognition identification, doxxing, likeness disputes) are marked `security_incident: "False positive"`, and conventional breaches with no AI component are flagged in an `ai_involvement_note`; both are retained for register completeness.

## Repository layout

```
README.md
incidents/
├─ all_2026_ai_software_security_incidents.json   # 99 incidents — source of truth
├─ all_2026_ai_software_security_incidents.csv    # flattened, one row per incident
├─ all_2026_ai_software_security_incidents.md     # severity-ranked field guide
├─ VERIS_Methodology_for_AI_Security_Incidents_concise.md
└─ sources/                                        # the original sources
   ├─ ChatGPT_DeepResearch_ai_incidents_2026.{md,docx,pdf}
   ├─ ClaudeCode_DeepResearch_ai_incidents_2026.{md,html}
   ├─ Grok_DeepResearch_ai_incidents_2026.md
   └─ incidentdatabase.ai_20260824_ai_incidents_2026.xlsx
```

## Sources & provenance

Every incident's `sources` field cites its **original** source(s):

- **`incidentdatabase.ai_20260824_ai_incidents_2026.xlsx`** — AI Incident Database (AIID) export, 2026-08-24 (cited with `AIID <id>` + the cite-page URL).
- **`vz-risk/VCDB`** — the [VERIS Community Database](https://github.com/vz-risk/VCDB), cited at the exact encoded record (`data/json/{validated,submitted}/<uuid>.json`) or the 2026 issue intake (`issues/<n>`). No local VCDB snapshot is bundled; citations point upstream.
- **`ChatGPT_DeepResearch_ai_incidents_2026.md`**, **`ClaudeCode_DeepResearch_ai_incidents_2026.md`**, **`Grok_DeepResearch_ai_incidents_2026.md`** — three independent deep-research incident reviews (kept in `incidents/sources/`).

Each record also carries **`veris.reference`** — the primary vendor/news/CVE reporting behind the incident (surfaced as the "Reporting" links in the `.md`).

Citation counts across the corpus: VCDB 41 · ClaudeCode 36 · ChatGPT 19 · AIID 17 · Grok 9.

## Scope

An event is included when **AI was materially involved** *and* there was an actual, suspected, or near-miss adverse effect on the confidentiality, integrity, availability, or authorization of a software/information asset. Non-security AI controversies (deepfake fraud, disinformation, likeness/IP disputes, autonomous-vehicle safety, harmful model output) are out of scope, except where a register carried them — in which case they are retained and clearly flagged as outside the criterion.

## Caveats

- Several incidents rest on vendor self-disclosure or researcher/attacker claims; per-incident `confidence` reflects this, and "first-of-kind" claims are researcher/vendor assessments. Verify any single figure against the linked primary source.
- Severity ranking is a documented judgement, not a formal aggregate; items near tier boundaries could reasonably be reordered.
- The `.csv` and `.md` are **derived** from the `.json`; treat the JSON as authoritative.
