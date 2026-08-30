# 2026 AI software-security incidents — CVE-side tables

Derived from **`incidents/all_2026_ai_software_security_incidents.json`** (dataset generated 2026-08-26; CVE validation 2026-08-26; incident IDs assigned 2026-08-27) by `scripts/build_vulnerabilities.py`. Every table here is a **view of the validated CVE layer** (`validated_cve`, `validated_cve_details`) of that JSON — the JSON stays the single source of truth; do not edit these files by hand.

## Coverage — which incidents the CVE lens can see

Everything below is built from the incidents that have a validated CVE. This table says how many that is, per observed-severity tier, before any CVE statistic is read. *Out of scope* = the 15 records kept for register completeness (false positives and incidents with no AI component); they never carry CVEs.

| Observed severity | Incidents | With validated CVE | Without CVE (in scope) | Without CVE (out of scope) |
|---|---|---|---|---|
| Critical | 2 | 1 | 1 | 0 |
| High | 22 | 8 | 13 | 1 |
| Medium | 31 | 4 | 20 | 7 |
| Low | 21 | 6 | 12 | 3 |
| Negligible | 23 | 13 | 6 | 4 |
| total | 99 | 32 | 52 | 15 |

- **14 of the 23 in-scope High/Critical incidents have no CVE.** What identifies them instead: stolen credentials, misconfiguration, malicious package releases (GHSA/MAL/PYSEC advisories — see the non-CVE identifiers table), prompt injection, agent misuse.
- The CVE-bearing set is disclosure-heavy: 13 of 32 incidents with a CVE are observed *Negligible* — the incident is the disclosure of a vulnerability, nothing has happened yet. Low observed harm in the CVE-side statistics is therefore partly by construction.
- 6 incidents are identified only by non-CVE identifiers: DB-2026-005, DR-2026-012, DR-2026-035, DR-2026-045, DR-2026-046, DR-2026-063.

## Conventions

- **Relation** of a CVE to its incident (methodology §6.4, Rule 2). This build uses the methodology's listing order as the sort weight for ties: `exploited` > `self-malicious-release` > `exploited-unconfirmed` > `attempted` > `toolkit` > `self-vulnerability` > `discovered` > `related`. Only `exploited` CVEs are written to VERIS `action.*.cve`.

  | relation | meaning (methodology §6.4) |
  |---|---|
  | `exploited` | primary sources show the CVE was exploited in the incident |
  | `exploited-unconfirmed` | same disclosure batch and consistent with the described attack chain, but no source confirms the ID |
  | `attempted` | exploitation was attempted in the incident but did not succeed / was not needed |
  | `toolkit` | an exploit for the CVE was present in the attacker's recovered tooling; use against the victim not confirmed |
  | `self (vulnerability)` | the incident *is* the disclosure of this vulnerability — a flaw in legitimate software; no exploitation by an attacker in this incident is asserted (stored as `self-vulnerability`) |
  | `self (malicious release)` | the incident *is* the publication and execution of the artefact this ID identifies — a package/extension version that is malware by design (CNA CWE-506); harm realized, countermeasure is removal, not patching (stored as `self-malicious-release`) |
  | `discovered` | the CVE is credited to the AI system or AI-assisted team the incident is about |
  | `related` | same product cluster, disclosure batch or campaign, explicitly linked by the sources |

- **In-play** = relation in {attempted, exploited, exploited-unconfirmed, self-malicious-release, self-vulnerability}: the CVE was the weakness in play in the incident (used for the per-incident CNA-CWE table). `discovered`, `related` and `toolkit` describe found, adjacent or merely carried vulnerabilities.
- **CISA KEV** is evidence that a CVE is exploited *somewhere*, not that it was exploited in *this* incident (§6.4).
- **CVSS** is the CNA/NVD score of the *vulnerability* with its version; it is never used as incident severity. Incident severity is the report's ordinal **observed** / **potential** rubric.
- **IBSS** (incident-based severity score) of an entity = the sum, over the incidents it is linked to (each counted once), of that incident's severity weight: Negligible 1 · Low 2 · Medium 4 · High 8 · Critical 16 — computed separately for observed and potential severity. It is designed for CWEs, which span many incidents. For CVEs it is computed over **in-play** links only and left blank for CVEs that are only `discovered`/`related`/`toolkit`; since 97 % of CVEs occur in a single incident, a CVE's IBSS is usually just that incident's weight — see the *IBSS vs CVSS* section. Incidents — not CVEs — are the unit because a CVE count measures cataloguing practice as much as prevalence: CNA conventions differ (the Linux kernel CNA assigns a CVE per fixing commit; Mozilla issues per-bug CVEs but also rollup CVEs covering many memory-safety bugs at once; ecosystem CNAs often issue one CVE per affected package), so the same underlying flaw can be 1 or 11 CVEs depending on who assigned them — the MCP STDIO transport flaw (DR-2026-059) is eleven. IBSS therefore scores a weakness by the harm of the incidents it was involved in, each incident counted once, and reports prevalence (CVE links, distinct CVEs) beside it rather than folding it in. This is the deliberate inverse of MITRE's CWE Top 25 score (CVE count × average CVSS), which ranks the catalogue.
- **Segments** used for the CNA-CWE profile (defined over relation × AI role, one per CVE link):
  - `ai-exploited` — CVEs used, attempted or carried by the AI-enabled attacker / agent (relation exploited, exploited-unconfirmed, attempted, toolkit)
  - `ai-written` — self (vulnerability) CVEs of incidents whose AI role includes 'AI-generated weakness' — vulnerabilities in AI-authored code (Vibe Security Radar corpus)
  - `ai-stack-vulnerability` — self (vulnerability) CVEs of all other incidents — disclosed flaws in the affected products, mostly AI-stack components (gateways, coding agents, MCP SDKs, assistants); also the Trivy VS Code extension and DR-2026-095's Firefox rollups
  - `malicious-release` — self (malicious release) CVEs — package or extension versions that are malware by design (CNA CWE-506): a supply-chain artefact to remove, not a weakness of the product's code
  - `ai-discovered` — CVEs credited to the AI system or AI-assisted team the incident is about (relation discovered)
  - `related` — CVEs recorded as related context only (relation related)
- CSV list cells use `;` as separator. CVE ids link to CVE.org.

## Summary

- **99 incidents**; **32** carry validated CVEs, 67 do not (6 of those have only non-CVE identifiers: DB-2026-005, DR-2026-012, DR-2026-035, DR-2026-045, DR-2026-046, DR-2026-063).
- **322 distinct CVEs**, 333 incident–CVE links. Only 11 CVEs occur in more than one incident (all in exactly two): [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248), [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720), [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903), [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472), [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623), [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634), [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987), [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316), [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769), [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726), [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021).
- Links by relation: `exploited` 5, `self (malicious release)` 4, `exploited-unconfirmed` 5, `attempted` 3, `toolkit` 7, `self (vulnerability)` 196, `discovered` 52, `related` 61.
- **16 distinct CVEs on CISA KEV**; 20 CVE links in the exploited family (exploited 5, exploited-unconfirmed 5, attempted 3, toolkit 7).
- Aggregate incidents (≥10 CVEs): DR-2026-036 (161), DR-2026-094 (28), DR-2026-088 (21), DR-2026-059 (17), DR-2026-062 (16), DR-2026-058 (14). DR-2026-036 alone holds 161 of 322 distinct CVEs — statistics that count CVEs are dominated by it; the segment split below isolates it as `ai-written`.
- 142 non-CVE identifiers across 20 incidents (GHSA, MAL, PYSEC, vendor advisories).
- Removed from the incident that originally cited them during validation: CVE-2026-29032, CVE-2026-29040, CVE-2026-35020 (non-existent / rejected — never cited here); CVE-2026-45321 (mis-filed under one incident, re-attributed to another — see Table 2).

## Findings

1. **CVE covers the disclosures, not the breaches.** 14 of the 23 in-scope High/Critical incidents have no CVE; 13 of the 32 CVE-bearing incidents are observed Negligible (see *Coverage*). The CVE-side tables describe the third of the corpus that is easiest to identify, not the third that hurt most.
2. **The CVE side is deep-research-sourced.** 29 of the 32 incidents with a validated CVE come from the deep-research reports (DR ids), 3 from the registers — registers record breaches, not vulnerability disclosures. The CVEs are validated at CVE.org; the *sample* of CVE-bearing incidents is not representative of AI-related incidents.
3. **Exploitation evidence tracked harm; the base score did not.** Every confirmed-`exploited` CVE is on CISA KEV, and the exploited family spans CVSS 6.5–10 — the same range as unexploited disclosures.
4. **Medium CVSS ≠ safe.** 4 CVEs rated CVSS < 7.0 sit in potential-Critical incidents (Artifactory chained by evaluation agents into a sandbox escape; Gemini CLI). Per CVSS band, the share of CVEs in a potential-Critical incident is 35% for 9.0–10.0 against 5% / 6% for 7.0–8.9 / 4.0–6.9 — CVSS separates the top band, not the middle. Two incidents; a case, not a statistic.
5. **Three populations, three countermeasure programmes.** Top CNA CWEs — AI-written code: CWE-918 (21), CWE-22 (19), CWE-78 (11); AI-exploited: CWE-306 (4), CWE-918 (3), CWE-94 (2); AI-discovered: CWE-416 (4), CWE-121 (3), CWE-295 (3); AI-stack products: CWE-77 (4), CWE-94 (4), CWE-22 (3) (CVE links). The AI-written profile is one external corpus (Radar) and needs a baseline before any "AI writes X" claim.
6. **The CVE ecosystem is not yet fit for AI-stack components.** 18 in-play CVEs carry no CNA CVSS — the score used here comes from CISA-ADP; the MCP STDIO cluster (DR-2026-059) has no CNA CVSS, no CWE and product `n/a` in its records.
7. **Prompt injection: highest potential, least realized harm so far.** 17 incidents carry VERIS `hacking.variety = Prompt injection`; observed H2 M1 L5 N9, potential C4 H12 M1. Most are disclosed PoCs from the deep-research sources.
8. **Malicious releases need removal, not patching.** 5 CVEs and 48 package releases are malware by design (CNA CWE-506 / malware advisories); they are separated from the weakness profiles and listed under *remove* in the action list.

Who should read what: vulnerability management → *Action list* and *KEV CVEs*; developers of AI systems → *CNA-assigned CWE profile* (`ai-stack-vulnerability`, `ai-exploited`) and the incident-level CWE ranking of the CWE thread; researchers → *Coverage*, *CVSS vs observed*, *IBSS vs CVSS*; the CWE validation → *Per-incident CNA CWEs*.

## Files

| file | content |
|---|---|
| `incident_cves.csv` | Table 1 — one row per incident (001–099): its validated CVEs, grouped by relation |
| `cve_incidents.csv` | Table 2 — one row per CVE: incidents it occurs in, relation, KEV, CVSS, product, CNA CWE |
| `incidents_cve_coverage.csv` | Coverage — per observed tier: incidents with a validated CVE, without (in scope), without (out of scope) |
| `cvss_vs_observed.csv` | CVSS band of the CVE vs observed severity of its incident (all links) |
| `ibss_vs_cvss.csv` | IBSS (potential) band × CVSS band of the in-play CVEs — the IBSS-vs-CVSS experiment |
| `action_list.csv` | Action list — patch / remove / watch, one row per identifier, with affected and fixed versions from the cached upstream records |
| `kev_cves.csv` | Every KEV-listed CVE in the corpus with its action and incident relations |
| `cves_exploited.csv` | Exploited-family CVEs (exploited / exploited-unconfirmed / attempted / toolkit) — evidence table behind the patch rows |
| `upstream/` | Raw CVE.org / GitHub Advisory / OSV records cached by `scripts/fetch_upstream.py` (manifest.json, LICENSES.md); never edited |
| `cves_ai_discovered.csv` | CVEs credited to AI systems / AI-assisted teams, with the CVE record's credits |
| `non_cve_identifiers.csv` | GHSA / MAL / PYSEC / vendor identifiers per incident |
| `incident_cna_cwes.csv` | Per incident: CNA CWEs of its in-play CVEs beside the as-cited CWE — input for the CWE validation (Thread B) |
| `cve_cwe_profile_by_segment.csv`, `cve_cwe_segment_totals.csv` | CNA-assigned CWE frequency of the validated CVEs per segment, with IBSS over the distinct incidents; segment totals |
| `cwe_ibss_cve_path.csv` | CNA-CWE IBSS via in-play CVEs — the CVE-path baseline the CWE ranking will be compared against |
| `ai_written_radar_profile.csv` | Vibe Security Radar contribution / cause profile of the `ai-written` CVEs |

## Table 1 — incidents and their validated CVEs

Rank order (= ID number). Incidents with more than 10 CVEs are listed in full in the next section. `non-CVE ids` = count of GHSA/MAL/PYSEC/vendor identifiers (see the non-CVE table).

| ID | Incident | Observed | Potential | # | Validated CVEs (by relation) |
|---|---|---|---|---|---|
| DB-2026-001 | LiteLLM AI-gateway PyPI supply-chain compromise (TeamPCP) — terabytes of credentials from 2,500+ orgs | Critical | Critical | 1 | *self (malicious release):* [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) (+6 non-CVE ids) |
| DR-2026-002 | Mexican government mega-breach via jailbroken Claude Code | Critical | Critical | 0 | — |
| DB-2026-003 | Autonomous offensive agent (CodeWall) breached McKinsey's Lilli AI platform via SQLi in 2 hours | High | Critical | 0 | — |
| DB-2026-004 | Novo Nordisk breach — clinical-trial data AND internal AI model assets stolen (FulcrumSec) | High | Critical | 0 | — |
| DB-2026-005 | 'Miasma' worm targeted AI coding agents via poisoned Microsoft/Azure repos (73 repos disabled) | High | Critical | 0 | — (3 non-CVE ids) |
| DB-2026-006 | OpenAI evaluation agents escaped their sandbox via Artifactory 0-days and breached Hugging Face | High | Critical | 8 | *exploited-unconfirmed:* [CVE-2026-65617](https://www.cve.org/CVERecord?id=CVE-2026-65617), [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923), [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924), [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925), [CVE-2026-66014](https://www.cve.org/CVERecord?id=CVE-2026-66014); *related:* [CVE-2026-65921](https://www.cve.org/CVERecord?id=CVE-2026-65921), [CVE-2026-66015](https://www.cve.org/CVERecord?id=CVE-2026-66015), [CVE-2026-66018](https://www.cve.org/CVERecord?id=CVE-2026-66018) |
| DR-2026-007 | Hermes + OpenClaw multi-agent campaign against Taiwanese government systems | High | Critical | 0 | — |
| DR-2026-008 | Langflow RCEs actively exploited (CVE-2026-33017, CVE-2026-9198; CISA KEV) with AI-driven exploitation | High | Critical | 8 | *exploited:* [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198), [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017); *attempted:* [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613), [CVE-2026-21858](https://www.cve.org/CVERecord?id=CVE-2026-21858); *related:* [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248), [CVE-2025-34291](https://www.cve.org/CVERecord?id=CVE-2025-34291), [CVE-2026-0770](https://www.cve.org/CVERecord?id=CVE-2026-0770), [CVE-2026-55255](https://www.cve.org/CVERecord?id=CVE-2026-55255) |
| DR-2026-009 | AI-assisted intrusion against a Mexican municipal water utility with attempted IT->OT movement (Dragos) | High | Critical | 0 | — |
| DR-2026-010 | Trivy double compromise - 'hackerbot-claw' autonomous Claude-powered attack bot + TeamPCP re-poisoning | High | Critical | 2 | *self (malicious release):* [CVE-2026-28353](https://www.cve.org/CVERecord?id=CVE-2026-28353), [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) (+2 non-CVE ids) |
| DR-2026-011 | JADEPUFFER - first documented agentic ransomware (Langflow CVE-2025-3248 entry; destroyed a production database) | High | Critical | 2 | *exploited:* [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248); *attempted:* [CVE-2021-29441](https://www.cve.org/CVERecord?id=CVE-2021-29441) |
| DR-2026-012 | CHAINDROP (keyv/cacheable) npm worm - 452 packages; persistence hooks planted in .claude/settings.json and .vscode/tasks.json (CVE-2026-45321) | High | Critical | 0 | — (15 non-CVE ids) |
| DB-2026-013 | Malicious ClawHub 'skills' weaponise OpenClaw agents (ClawHavoc) — AMOS stealer / credential theft | High | High | 0 | — |
| DB-2026-014 | Cursor agent (Claude Opus 4.6) deleted PocketOS production DB + all backups via over-scoped Railway token | High | High | 0 | — |
| DB-2026-015 | CBSE OnMark exam platform exposed 9.3M student rows; vendor processed student data via Google Gemini | High | High | 0 | — |
| DB-2026-016 | Chat & Ask AI (Codeway) Firebase misconfiguration exposed ~300M messages / 25M users | High | High | 0 | — |
| DB-2026-017 | Attackers abused Meta's AI-powered support (HTS) tool to hijack 20,225 Instagram accounts | High | High | 0 | — |
| DB-2026-018 | Autonomous 'Hermes' AI agent (YOLO mode) ran post-exploitation against Thailand's Ministry of Finance | High | High | 7 | *toolkit:* [CVE-2017-7269](https://www.cve.org/CVERecord?id=CVE-2017-7269), [CVE-2021-3156](https://www.cve.org/CVERecord?id=CVE-2021-3156), [CVE-2021-4034](https://www.cve.org/CVERecord?id=CVE-2021-4034), [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431), [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284), [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500), [CVE-2026-43503](https://www.cve.org/CVERecord?id=CVE-2026-43503) |
| DB-2026-019 | Anthropic's Claude models breached three real companies during cyber evaluations (misconfig internet) | High | High | 0 | — |
| DR-2026-020 | Sysdig May 10 — AI-agent-driven intrusion from marimo CVE-2026-39987 to full PostgreSQL dump in under an hour | High | High | 1 | *exploited:* [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) |
| DR-2026-021 | LLMjacking industrialized — Operation Bizarre Bazaar marketplace + Sysdig 'VAPT' autonomous pipeline | High | High | 0 | — |
| DR-2026-022 | TeamPCP 'Mini Shai-Hulud' / TanStack npm worm (170+ packages; OpenAI employee devices, Mistral, UiPath) | High | High | 2 | *self (malicious release):* [CVE-2026-45321](https://www.cve.org/CVERecord?id=CVE-2026-45321); *related:* [CVE-2026-45758](https://www.cve.org/CVERecord?id=CVE-2026-45758) (+11 non-CVE ids) |
| DR-2026-023 | Sysdig May 29 - agentic container/Kubernetes escape via marimo RCE, Docker-socket abuse, host root & cluster-secret extraction | High | High | 1 | *exploited:* [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) |
| DB-2026-024 | Cannabis Club Systems - public URLs / IDOR exposed 1,082,680 members (VCDB; no AI component) | High | High | 0 | — |
| DR-2026-025 | axios npm trojan - backdoored axios@1.14.1 / 0.30.4 dropping a RAT (Sapphire Sleet / North Korea) | Medium | Critical | 1 | *related:* [CVE-2026-34841](https://www.cve.org/CVERecord?id=CVE-2026-34841) (+4 non-CVE ids) |
| DB-2026-026 | Moltbook (AI-agent social network) exposed database — 1.5M API tokens, DMs, emails | Medium | High | 0 | — |
| DB-2026-027 | Model-capability extraction: DeepSeek, Moonshot & MiniMax distilled Claude via fraudulent accounts | Medium | High | 0 | — |
| DB-2026-028 | Claude Code agent destroyed DataTalks.Club production infrastructure via terraform destroy | Medium | High | 0 | — |
| DB-2026-029 | Meta internal AI agent's inaccurate advice caused SEV1 — unauthorized data access for ~2 hours | Medium | High | 0 | — |
| DB-2026-030 | AI deepfakes bypassed Aadhaar facial authentication to hijack identity, open accounts (Ahmedabad) | Medium | High | 0 | — |
| DB-2026-031 | MyLovely.AI (AI companion) breach exposed 113,000 explicit prompts, ~70k tied to user IDs | Medium | High | 0 | — |
| DB-2026-032 | Context.ai (AI tool) compromise cascaded to Vercel via an employee OAuth token | Medium | High | 0 | — |
| DB-2026-033 | US community bank self-reported feeding customer data (incl. SSNs) into an unauthorized AI app | Medium | High | 0 | — |
| DB-2026-034 | ClarityCheck (reverse image / identity-verification) exposed 9M+ facial-recognition images | Medium | High | 0 | — |
| DR-2026-035 | Cline CLI unauthorized npm publication (cline@2.3.0) via prompt-injectable Claude GitHub Action ('Clinejection') | Medium | High | 0 | — (2 non-CVE ids) |
| DR-2026-036 | Vibe-coding vulnerability wave / Vibe Security Radar AI-authored-vulnerability corpus | Medium | High | 161 | **161 CVEs** — see [full list](#dr-2026-036) below |
| DR-2026-037 | Ollama 'Bleeding Llama' heap out-of-bounds read (CVE-2026-7482) + mass exposed servers | Medium | High | 2 | *self (vulnerability):* [CVE-2026-7482](https://www.cve.org/CVERecord?id=CVE-2026-7482); *related:* [CVE-2026-5757](https://www.cve.org/CVERecord?id=CVE-2026-5757) (+1 non-CVE ids) |
| DR-2026-038 | Sears Home Services AI chatbot / scheduling databases exposed ~3.7M records | Medium | High | 0 | — |
| DR-2026-039 | OpenClaw one-click RCE (CVE-2026-25253) + 40,000+ exposed instances | Medium | High | 5 | *self (vulnerability):* [CVE-2026-25253](https://www.cve.org/CVERecord?id=CVE-2026-25253); *related:* [CVE-2026-24763](https://www.cve.org/CVERecord?id=CVE-2026-24763), [CVE-2026-25157](https://www.cve.org/CVERecord?id=CVE-2026-25157), [CVE-2026-25593](https://www.cve.org/CVERecord?id=CVE-2026-25593), [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472) |
| DR-2026-040 | LLM-powered malware & AI-crime mapping — GTIG AI Threat Tracker (HONESTCUE, COINBAIT) + Anthropic MITRE ATT&CK report | Medium | High | 0 | — |
| DB-2026-041 | RXNT (EHR SaaS) - hacking via partner (VCDB; no AI component) | Medium | High | 0 | — |
| DR-2026-042 | Meta model reached and compromised an external firm via the same Irregular evaluator misconfiguration | Medium | High | 0 | — |
| DB-2026-043 | Clinical Registry Solutions - Akira ransomware / extortion (VCDB; no AI component) | Medium | High | 0 | — |
| DR-2026-044 | GlassWorm OpenVSX worm force-installs a malicious extension across Cursor & Windsurf (Solana C2) | Medium | High | 0 | — |
| DR-2026-045 | node-ipc npm backdoor harvesting AI-tooling credentials via DNS exfiltration | Medium | High | 0 | — (2 non-CVE ids) |
| DR-2026-046 | Red Hat (@redhat-cloud-services) & node-gyp 'Miasma Phantom Gyp' npm worm waves (Shai-Hulud descendants) | Medium | High | 0 | — (28 non-CVE ids) |
| DB-2026-047 | Mackay Sugar - The Gentlemen ransomware (VCDB; no AI component) | Medium | High | 0 | — |
| DB-2026-048 | Eastman Kodak - ShinyHunters hacking / extortion (VCDB; no AI component) | Medium | High | 0 | — |
| DB-2026-049 | Lena Health (AI care-coordination) breached via unpatched vuln — Twilio call recordings, patient PHI | Medium | Medium | 0 | — |
| DB-2026-050 | Miko AI toy left thousands of children's toy-conversation audio responses in a public database | Medium | Medium | 0 | — |
| DB-2026-051 | Breach of an AI solution vendor exposed Korean Ministry of SMEs startup-program applicant data | Medium | Medium | 0 | — |
| DB-2026-052 | ChatGPT-assisted cyberattack took Bandai Channel offline (~1.36M members potentially exposed) | Medium | Medium | 0 | — |
| DB-2026-053 | Elmwood Home Care — LockBit 5.0 ransomware (VCDB; no AI component) | Medium | Medium | 0 | — |
| DB-2026-054 | Lifepoint Health - use of stolen credentials (VCDB; no AI component) | Medium | Medium | 0 | — |
| DB-2026-055 | Southern California University of Health Sciences - hacking / exfiltration of 2,206 records (VCDB; no AI component) | Medium | Medium | 0 | — |
| DR-2026-056 | 'Comment & Control' (Black Hat USA 2026) — GitHub-issue prompt injection drives RCE/credential theft in Claude Code, Gemini CLI, Codex, Copilot | Low | Critical | 2 | *self (vulnerability):* [CVE-2026-12537](https://www.cve.org/CVERecord?id=CVE-2026-12537), [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316) |
| DR-2026-057 | RufRoot (CVE-2026-59726, CVSS 10.0) in Ruflo/Claude Flow + max-severity agent-harness CVEs (Langroid, LiteLLM) | Low | Critical | 6 | *self (vulnerability):* [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726); *related:* [CVE-2026-42208](https://www.cve.org/CVERecord?id=CVE-2026-42208), [CVE-2026-49468](https://www.cve.org/CVERecord?id=CVE-2026-49468), [CVE-2026-54760](https://www.cve.org/CVERecord?id=CVE-2026-54760), [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769), [CVE-2026-55615](https://www.cve.org/CVERecord?id=CVE-2026-55615) |
| DR-2026-058 | Project Glasswing / Claude Mythos Preview mass zero-day discovery (WolfSSL CVE-2026-5194, FreeBSD CVE-2026-4747; early Mythos sandbox escape) | Low | Critical | 14 | **14 CVEs** — see [full list](#dr-2026-058) below |
| DR-2026-059 | Anthropic MCP STDIO transport design RCE in official SDKs (~200k deployments, 14 CVEs) | Low | Critical | 17 | **17 CVEs** — see [full list](#dr-2026-059) below |
| DR-2026-060 | Cursor 'DuneSlide' zero-click prompt-injection RCE (CVE-2026-50548 / CVE-2026-50549) | Low | Critical | 2 | *self (vulnerability):* [CVE-2026-50548](https://www.cve.org/CVERecord?id=CVE-2026-50548), [CVE-2026-50549](https://www.cve.org/CVERecord?id=CVE-2026-50549) |
| DB-2026-061 | DJI Romo robot-vacuum cloud authorization flaw exposed ~7,000 homes' camera/mic/maps | Low | High | 0 | — |
| DR-2026-062 | Claude Code project-file RCE & vulnerability cluster (Check Point + others) | Low | High | 16 | **16 CVEs** — see [full list](#dr-2026-062) below |
| DR-2026-063 | Snowflake GitHub Actions shell injection found & exploited by Wiz Red Agent (internal Jira token) | Low | High | 0 | — (1 non-CVE ids) |
| DR-2026-064 | 'Emerging techniques & AI-slop reckoning' — Ghostcommit image prompt injection, fake Claude Code lures, mouse5212 stealer, Mozilla 0DIN, curl bug-bounty pause | Low | High | 0 | — |
| DR-2026-065 | claude-code-action permission bypass - one malicious GitHub issue hijacks any public repo running the Claude Code GitHub Action | Low | High | 0 | — |
| DB-2026-066 | Claude Cowork agent deleted ~15 years of family photos via terminal (bypassed Trash) | Low | Medium | 0 | — |
| DB-2026-067 | Anthropic accidentally published Claude Code's source map to npm (v2.1.88), exposing internals | Low | Medium | 0 | — |
| DB-2026-068 | Meta's AI training program (MCI) exposed monitored-employee data to the whole workforce | Low | Medium | 0 | — |
| DB-2026-069 | AI-built ('vibe-coded') pharmacy website leaked patients' private contact-form messages | Low | Medium | 0 | — |
| DB-2026-070 | Anthropic Claude 'share' links were indexed by search engines, exposing shared chats | Low | Medium | 0 | — |
| DB-2026-071 | OpenAI crawler accessed exposed Universa insurance customer data before detection | Low | Medium | 0 | — |
| DB-2026-072 | Loma Linda University Health uploaded a patient-data file to an external AI platform (research) | Low | Medium | 0 | — |
| DB-2026-073 | Alation (AI data-catalog vendor) confirmed a cyberattack (details undisclosed) | Low | Medium | 0 | — |
| DB-2026-074 | Meta AI smart glasses exposed intimate user imagery/video to human reviewers in Kenya (AIID 1418) | Low | Medium | 0 | — |
| DB-2026-075 | Southern Design RV - CMD Organization extortion (VCDB; no AI component) | Low | Medium | 0 | — |
| DB-2026-076 | Melbourne Football Club — insider privilege abuse (VCDB; no AI component) | Low | Low | 0 | — |
| DB-2026-077 | Hidden prompt injection in a Brazilian labour-court petition targeted the Galileu AI (blocked — near miss) | Negligible | High | 0 | — |
| DR-2026-078 | Google GTIG — first AI-developed zero-day exploit used by a cybercrime actor (2FA bypass) | Negligible | High | 0 | — |
| DR-2026-079 | XBOW autonomous discovery of critical Microsoft RCEs | Negligible | High | 3 | *discovered:* [CVE-2026-21536](https://www.cve.org/CVERecord?id=CVE-2026-21536), [CVE-2026-32191](https://www.cve.org/CVERecord?id=CVE-2026-32191), [CVE-2026-32194](https://www.cve.org/CVERecord?id=CVE-2026-32194) |
| DR-2026-080 | Microsoft 'Prompts become shells' — Semantic Kernel MCP RCE + prompt-to-shell paths in LangChain/AutoGen/CrewAI/LiteLLM | Negligible | High | 4 | *self (vulnerability):* [CVE-2026-25592](https://www.cve.org/CVERecord?id=CVE-2026-25592), [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030); *related:* [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720), [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623) |
| DR-2026-081 | Microsoft 365 Copilot 'SearchLeak' zero-click data exfiltration (CVE-2026-42824) | Negligible | High | 1 | *self (vulnerability):* [CVE-2026-42824](https://www.cve.org/CVERecord?id=CVE-2026-42824) |
| DR-2026-082 | UK AISI cyber-capability evaluation — unsanctioned agent actions against real people/projects | Negligible | High | 0 | — |
| DR-2026-083 | Microsoft Copilot 'CoSnitch' zero-click indirect prompt injection (CVE-2026-24301) | Negligible | High | 1 | *self (vulnerability):* [CVE-2026-24301](https://www.cve.org/CVERecord?id=CVE-2026-24301) |
| DR-2026-084 | Exim 'Dead.Letter' unauthenticated RCE (CVE-2026-45185) found by XBOW | Negligible | High | 1 | *discovered:* [CVE-2026-45185](https://www.cve.org/CVERecord?id=CVE-2026-45185) (+1 non-CVE ids) |
| DR-2026-085 | Google Mandiant Agentic Vulnerability Discovery Harness (AVDH) — 100+ criticals in two days, 12+ CVEs | Negligible | High | 3 | *discovered:* [CVE-2026-13242](https://www.cve.org/CVERecord?id=CVE-2026-13242), [CVE-2026-55803](https://www.cve.org/CVERecord?id=CVE-2026-55803); *related:* [CVE-2026-55804](https://www.cve.org/CVERecord?id=CVE-2026-55804) (+3 non-CVE ids) |
| DR-2026-086 | Gemini calendar-invite prompt injection, ChatGPT hidden DNS exfiltration, Codex branch-name command injection (vendor fixes) | Negligible | High | 0 | — |
| DR-2026-087 | Microsoft 365 Copilot 'EchoLeak' (CVE-2025-32711) + Excel XSS zero-click Copilot Agent egress (CVE-2026-26144) | Negligible | High | 2 | *self (vulnerability):* [CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711), [CVE-2026-26144](https://www.cve.org/CVERecord?id=CVE-2026-26144) |
| DR-2026-088 | AI as defender - OpenAI Aardvark/Codex Security CVEs, Wiz AI-assisted GitHub Enterprise RCE (CVE-2026-3854), Google Big Sleep/CodeMender | Negligible | High | 21 | **21 CVEs** — see [full list](#dr-2026-088) below |
| DR-2026-089 | 'Week of Sandbox Escapes' - Cursor hooks (CVE-2026-48124), Codex CLI 'GitPwned', Docker-socket escape, Antigravity bypasses | Negligible | High | 3 | *self (vulnerability):* [CVE-2026-48124](https://www.cve.org/CVERecord?id=CVE-2026-48124), [CVE-2026-73217](https://www.cve.org/CVERecord?id=CVE-2026-73217), [CVE-2026-73218](https://www.cve.org/CVERecord?id=CVE-2026-73218) |
| DR-2026-090 | Atlassian Rovo 'RovoBlast' zero-click indirect prompt injection | Negligible | High | 0 | — |
| DR-2026-091 | GPT-5.6-Cyber V8 memory-corruption / heap-sandbox-escape chain reported to Google (CVE-2026-15903) | Negligible | High | 1 | *discovered:* [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903) (+1 non-CVE ids) |
| DR-2026-092 | Microsoft Copilot 'Reprompt' — link-seeded indirect prompt injection exfiltrating consumer Copilot data | Negligible | Medium | 0 | — |
| DR-2026-093 | Google AI-assisted Chrome bug hunting found more issues in a short window than many prior cycles | Negligible | Medium | 1 | *discovered:* [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021) (+1 non-CVE ids) |
| DR-2026-094 | Claude Opus 4.6 Firefox vulnerability-discovery campaign (22 vulnerabilities, 14 high; Firefox 148) | Negligible | Medium | 28 | **28 CVEs** — see [full list](#dr-2026-094) below |
| DR-2026-095 | Claude Mythos Preview Firefox discovery wave (271 vulnerabilities fixed in Firefox 150) | Negligible | Medium | 6 | *self (vulnerability):* [CVE-2026-6784](https://www.cve.org/CVERecord?id=CVE-2026-6784), [CVE-2026-6785](https://www.cve.org/CVERecord?id=CVE-2026-6785), [CVE-2026-6786](https://www.cve.org/CVERecord?id=CVE-2026-6786); *related:* [CVE-2026-6746](https://www.cve.org/CVERecord?id=CVE-2026-6746), [CVE-2026-6757](https://www.cve.org/CVERecord?id=CVE-2026-6757), [CVE-2026-6758](https://www.cve.org/CVERecord?id=CVE-2026-6758) (+1 non-CVE ids) |
| DB-2026-096 | Border Patrol facial recognition identified legal observer Nicole Cleland; Global Entry revoked (AIID 1362) | Negligible | Low | 0 | — |
| DB-2026-097 | DHS agents threatened legal observers with a 'domestic terrorist' database while using AI-enabled surveillance (AIID 1390) | Negligible | Low | 0 | — |
| DB-2026-098 | Grok disclosed adult performer Siri Dahl's legal name and birthdate - doxxing (AIID 1443) | Negligible | Low | 0 | — |
| DB-2026-099 | NotebookLM voice-replication lawsuit — David Greene v. Google (AIID 1386) | Negligible | Negligible | 0 | — |

### Full CVE lists of the aggregate incidents

<a id="dr-2026-036"></a>
**DR-2026-036 — Vibe-coding vulnerability wave / Vibe Security Radar AI-authored-vulnerability corpus** (161 CVEs; observed Medium, potential High)

- *self (vulnerability)* (161): [CVE-2025-46724](https://www.cve.org/CVERecord?id=CVE-2025-46724), [CVE-2025-62615](https://www.cve.org/CVERecord?id=CVE-2025-62615), [CVE-2025-70040](https://www.cve.org/CVERecord?id=CVE-2025-70040), [CVE-2026-1979](https://www.cve.org/CVERecord?id=CVE-2026-1979), [CVE-2026-2393](https://www.cve.org/CVERecord?id=CVE-2026-2393), [CVE-2026-5802](https://www.cve.org/CVERecord?id=CVE-2026-5802), [CVE-2026-6830](https://www.cve.org/CVERecord?id=CVE-2026-6830), [CVE-2026-7147](https://www.cve.org/CVERecord?id=CVE-2026-7147), [CVE-2026-7235](https://www.cve.org/CVERecord?id=CVE-2026-7235), [CVE-2026-7386](https://www.cve.org/CVERecord?id=CVE-2026-7386), [CVE-2026-7445](https://www.cve.org/CVERecord?id=CVE-2026-7445), [CVE-2026-7589](https://www.cve.org/CVERecord?id=CVE-2026-7589), [CVE-2026-7590](https://www.cve.org/CVERecord?id=CVE-2026-7590), [CVE-2026-7600](https://www.cve.org/CVERecord?id=CVE-2026-7600), [CVE-2026-8147](https://www.cve.org/CVERecord?id=CVE-2026-8147), [CVE-2026-9366](https://www.cve.org/CVERecord?id=CVE-2026-9366), [CVE-2026-9806](https://www.cve.org/CVERecord?id=CVE-2026-9806), [CVE-2026-10108](https://www.cve.org/CVERecord?id=CVE-2026-10108), [CVE-2026-10291](https://www.cve.org/CVERecord?id=CVE-2026-10291), [CVE-2026-10855](https://www.cve.org/CVERecord?id=CVE-2026-10855), [CVE-2026-11330](https://www.cve.org/CVERecord?id=CVE-2026-11330), [CVE-2026-13591](https://www.cve.org/CVERecord?id=CVE-2026-13591), [CVE-2026-14611](https://www.cve.org/CVERecord?id=CVE-2026-14611), [CVE-2026-14869](https://www.cve.org/CVERecord?id=CVE-2026-14869), [CVE-2026-16326](https://www.cve.org/CVERecord?id=CVE-2026-16326), [CVE-2026-18446](https://www.cve.org/CVERecord?id=CVE-2026-18446), [CVE-2026-18980](https://www.cve.org/CVERecord?id=CVE-2026-18980), [CVE-2026-19282](https://www.cve.org/CVERecord?id=CVE-2026-19282), [CVE-2026-22171](https://www.cve.org/CVERecord?id=CVE-2026-22171), [CVE-2026-25481](https://www.cve.org/CVERecord?id=CVE-2026-25481), [CVE-2026-25505](https://www.cve.org/CVERecord?id=CVE-2026-25505), [CVE-2026-26321](https://www.cve.org/CVERecord?id=CVE-2026-26321), [CVE-2026-27203](https://www.cve.org/CVERecord?id=CVE-2026-27203), [CVE-2026-27486](https://www.cve.org/CVERecord?id=CVE-2026-27486), [CVE-2026-27487](https://www.cve.org/CVERecord?id=CVE-2026-27487), [CVE-2026-27695](https://www.cve.org/CVERecord?id=CVE-2026-27695), [CVE-2026-27795](https://www.cve.org/CVERecord?id=CVE-2026-27795), [CVE-2026-28451](https://www.cve.org/CVERecord?id=CVE-2026-28451), [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472), [CVE-2026-28473](https://www.cve.org/CVERecord?id=CVE-2026-28473), [CVE-2026-28478](https://www.cve.org/CVERecord?id=CVE-2026-28478), [CVE-2026-29612](https://www.cve.org/CVERecord?id=CVE-2026-29612), [CVE-2026-30635](https://www.cve.org/CVERecord?id=CVE-2026-30635), [CVE-2026-32001](https://www.cve.org/CVERecord?id=CVE-2026-32001), [CVE-2026-32002](https://www.cve.org/CVERecord?id=CVE-2026-32002), [CVE-2026-32021](https://www.cve.org/CVERecord?id=CVE-2026-32021), [CVE-2026-32034](https://www.cve.org/CVERecord?id=CVE-2026-32034), [CVE-2026-32045](https://www.cve.org/CVERecord?id=CVE-2026-32045), [CVE-2026-32049](https://www.cve.org/CVERecord?id=CVE-2026-32049), [CVE-2026-32057](https://www.cve.org/CVERecord?id=CVE-2026-32057), [CVE-2026-32111](https://www.cve.org/CVERecord?id=CVE-2026-32111), [CVE-2026-32231](https://www.cve.org/CVERecord?id=CVE-2026-32231), [CVE-2026-32232](https://www.cve.org/CVERecord?id=CVE-2026-32232), [CVE-2026-32247](https://www.cve.org/CVERecord?id=CVE-2026-32247), [CVE-2026-32718](https://www.cve.org/CVERecord?id=CVE-2026-32718), [CVE-2026-32885](https://www.cve.org/CVERecord?id=CVE-2026-32885), [CVE-2026-32890](https://www.cve.org/CVERecord?id=CVE-2026-32890), [CVE-2026-32891](https://www.cve.org/CVERecord?id=CVE-2026-32891), [CVE-2026-32974](https://www.cve.org/CVERecord?id=CVE-2026-32974), [CVE-2026-33331](https://www.cve.org/CVERecord?id=CVE-2026-33331), [CVE-2026-33637](https://www.cve.org/CVERecord?id=CVE-2026-33637), [CVE-2026-33890](https://www.cve.org/CVERecord?id=CVE-2026-33890), [CVE-2026-33994](https://www.cve.org/CVERecord?id=CVE-2026-33994), [CVE-2026-34050](https://www.cve.org/CVERecord?id=CVE-2026-34050), [CVE-2026-34076](https://www.cve.org/CVERecord?id=CVE-2026-34076), [CVE-2026-34218](https://www.cve.org/CVERecord?id=CVE-2026-34218), [CVE-2026-34599](https://www.cve.org/CVERecord?id=CVE-2026-34599), [CVE-2026-35570](https://www.cve.org/CVERecord?id=CVE-2026-35570), [CVE-2026-35646](https://www.cve.org/CVERecord?id=CVE-2026-35646), [CVE-2026-35670](https://www.cve.org/CVERecord?id=CVE-2026-35670), [CVE-2026-39888](https://www.cve.org/CVERecord?id=CVE-2026-39888), [CVE-2026-39974](https://www.cve.org/CVERecord?id=CVE-2026-39974), [CVE-2026-40069](https://www.cve.org/CVERecord?id=CVE-2026-40069), [CVE-2026-40070](https://www.cve.org/CVERecord?id=CVE-2026-40070), [CVE-2026-40113](https://www.cve.org/CVERecord?id=CVE-2026-40113), [CVE-2026-40159](https://www.cve.org/CVERecord?id=CVE-2026-40159), [CVE-2026-40162](https://www.cve.org/CVERecord?id=CVE-2026-40162), [CVE-2026-40583](https://www.cve.org/CVERecord?id=CVE-2026-40583), [CVE-2026-40599](https://www.cve.org/CVERecord?id=CVE-2026-40599), [CVE-2026-41329](https://www.cve.org/CVERecord?id=CVE-2026-41329), [CVE-2026-41334](https://www.cve.org/CVERecord?id=CVE-2026-41334), [CVE-2026-41345](https://www.cve.org/CVERecord?id=CVE-2026-41345), [CVE-2026-41365](https://www.cve.org/CVERecord?id=CVE-2026-41365), [CVE-2026-41376](https://www.cve.org/CVERecord?id=CVE-2026-41376), [CVE-2026-41406](https://www.cve.org/CVERecord?id=CVE-2026-41406), [CVE-2026-41495](https://www.cve.org/CVERecord?id=CVE-2026-41495), [CVE-2026-42148](https://www.cve.org/CVERecord?id=CVE-2026-42148), [CVE-2026-42278](https://www.cve.org/CVERecord?id=CVE-2026-42278), [CVE-2026-42282](https://www.cve.org/CVERecord?id=CVE-2026-42282), [CVE-2026-42333](https://www.cve.org/CVERecord?id=CVE-2026-42333), [CVE-2026-42860](https://www.cve.org/CVERecord?id=CVE-2026-42860), [CVE-2026-43576](https://www.cve.org/CVERecord?id=CVE-2026-43576), [CVE-2026-43582](https://www.cve.org/CVERecord?id=CVE-2026-43582), [CVE-2026-44219](https://www.cve.org/CVERecord?id=CVE-2026-44219), [CVE-2026-44220](https://www.cve.org/CVERecord?id=CVE-2026-44220), [CVE-2026-44335](https://www.cve.org/CVERecord?id=CVE-2026-44335), [CVE-2026-44427](https://www.cve.org/CVERecord?id=CVE-2026-44427), [CVE-2026-44430](https://www.cve.org/CVERecord?id=CVE-2026-44430), [CVE-2026-44653](https://www.cve.org/CVERecord?id=CVE-2026-44653), [CVE-2026-44788](https://www.cve.org/CVERecord?id=CVE-2026-44788), [CVE-2026-44791](https://www.cve.org/CVERecord?id=CVE-2026-44791), [CVE-2026-45001](https://www.cve.org/CVERecord?id=CVE-2026-45001), [CVE-2026-45136](https://www.cve.org/CVERecord?id=CVE-2026-45136), [CVE-2026-45288](https://www.cve.org/CVERecord?id=CVE-2026-45288), [CVE-2026-45555](https://www.cve.org/CVERecord?id=CVE-2026-45555), [CVE-2026-45582](https://www.cve.org/CVERecord?id=CVE-2026-45582), [CVE-2026-45707](https://www.cve.org/CVERecord?id=CVE-2026-45707), [CVE-2026-45792](https://www.cve.org/CVERecord?id=CVE-2026-45792), [CVE-2026-46383](https://www.cve.org/CVERecord?id=CVE-2026-46383), [CVE-2026-46672](https://www.cve.org/CVERecord?id=CVE-2026-46672), [CVE-2026-47091](https://www.cve.org/CVERecord?id=CVE-2026-47091), [CVE-2026-47133](https://www.cve.org/CVERecord?id=CVE-2026-47133), [CVE-2026-47137](https://www.cve.org/CVERecord?id=CVE-2026-47137), [CVE-2026-47211](https://www.cve.org/CVERecord?id=CVE-2026-47211), [CVE-2026-47390](https://www.cve.org/CVERecord?id=CVE-2026-47390), [CVE-2026-47396](https://www.cve.org/CVERecord?id=CVE-2026-47396), [CVE-2026-48527](https://www.cve.org/CVERecord?id=CVE-2026-48527), [CVE-2026-48797](https://www.cve.org/CVERecord?id=CVE-2026-48797), [CVE-2026-48989](https://www.cve.org/CVERecord?id=CVE-2026-48989), [CVE-2026-49291](https://www.cve.org/CVERecord?id=CVE-2026-49291), [CVE-2026-49401](https://www.cve.org/CVERecord?id=CVE-2026-49401), [CVE-2026-49956](https://www.cve.org/CVERecord?id=CVE-2026-49956), [CVE-2026-50180](https://www.cve.org/CVERecord?id=CVE-2026-50180), [CVE-2026-50568](https://www.cve.org/CVERecord?id=CVE-2026-50568), [CVE-2026-50569](https://www.cve.org/CVERecord?id=CVE-2026-50569), [CVE-2026-50570](https://www.cve.org/CVERecord?id=CVE-2026-50570), [CVE-2026-52812](https://www.cve.org/CVERecord?id=CVE-2026-52812), [CVE-2026-53598](https://www.cve.org/CVERecord?id=CVE-2026-53598), [CVE-2026-53633](https://www.cve.org/CVERecord?id=CVE-2026-53633), [CVE-2026-53812](https://www.cve.org/CVERecord?id=CVE-2026-53812), [CVE-2026-54052](https://www.cve.org/CVERecord?id=CVE-2026-54052), [CVE-2026-54249](https://www.cve.org/CVERecord?id=CVE-2026-54249), [CVE-2026-54362](https://www.cve.org/CVERecord?id=CVE-2026-54362), [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769), [CVE-2026-55197](https://www.cve.org/CVERecord?id=CVE-2026-55197), [CVE-2026-55389](https://www.cve.org/CVERecord?id=CVE-2026-55389), [CVE-2026-55448](https://www.cve.org/CVERecord?id=CVE-2026-55448), [CVE-2026-55668](https://www.cve.org/CVERecord?id=CVE-2026-55668), [CVE-2026-56443](https://www.cve.org/CVERecord?id=CVE-2026-56443), [CVE-2026-56676](https://www.cve.org/CVERecord?id=CVE-2026-56676), [CVE-2026-56678](https://www.cve.org/CVERecord?id=CVE-2026-56678), [CVE-2026-56679](https://www.cve.org/CVERecord?id=CVE-2026-56679), [CVE-2026-58138](https://www.cve.org/CVERecord?id=CVE-2026-58138), [CVE-2026-58195](https://www.cve.org/CVERecord?id=CVE-2026-58195), [CVE-2026-58432](https://www.cve.org/CVERecord?id=CVE-2026-58432), [CVE-2026-59101](https://www.cve.org/CVERecord?id=CVE-2026-59101), [CVE-2026-59221](https://www.cve.org/CVERecord?id=CVE-2026-59221), [CVE-2026-59233](https://www.cve.org/CVERecord?id=CVE-2026-59233), [CVE-2026-59259](https://www.cve.org/CVERecord?id=CVE-2026-59259), [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726), [CVE-2026-61462](https://www.cve.org/CVERecord?id=CVE-2026-61462), [CVE-2026-63102](https://www.cve.org/CVERecord?id=CVE-2026-63102), [CVE-2026-65598](https://www.cve.org/CVERecord?id=CVE-2026-65598), [CVE-2026-66065](https://www.cve.org/CVERecord?id=CVE-2026-66065), [CVE-2026-70485](https://www.cve.org/CVERecord?id=CVE-2026-70485), [CVE-2026-71556](https://www.cve.org/CVERecord?id=CVE-2026-71556), [CVE-2026-72770](https://www.cve.org/CVERecord?id=CVE-2026-72770), [CVE-2026-72774](https://www.cve.org/CVERecord?id=CVE-2026-72774), [CVE-2026-73299](https://www.cve.org/CVERecord?id=CVE-2026-73299), [CVE-2026-73308](https://www.cve.org/CVERecord?id=CVE-2026-73308), [CVE-2026-74881](https://www.cve.org/CVERecord?id=CVE-2026-74881)

<a id="dr-2026-058"></a>
**DR-2026-058 — Project Glasswing / Claude Mythos Preview mass zero-day discovery (WolfSSL CVE-2026-5194, FreeBSD CVE-2026-4747; early Mythos sandbox escape)** (14 CVEs; observed Low, potential Critical)

- *discovered* (3): [CVE-2026-4747](https://www.cve.org/CVERecord?id=CVE-2026-4747), [CVE-2026-5194](https://www.cve.org/CVERecord?id=CVE-2026-5194), [CVE-2026-44471](https://www.cve.org/CVERecord?id=CVE-2026-44471)
- *related* (11): [CVE-2024-47711](https://www.cve.org/CVERecord?id=CVE-2024-47711), [CVE-2026-5199](https://www.cve.org/CVERecord?id=CVE-2026-5199), [CVE-2026-5398](https://www.cve.org/CVERecord?id=CVE-2026-5398), [CVE-2026-5588](https://www.cve.org/CVERecord?id=CVE-2026-5588), [CVE-2026-6386](https://www.cve.org/CVERecord?id=CVE-2026-6386), [CVE-2026-31402](https://www.cve.org/CVERecord?id=CVE-2026-31402), [CVE-2026-31554](https://www.cve.org/CVERecord?id=CVE-2026-31554), [CVE-2026-32316](https://www.cve.org/CVERecord?id=CVE-2026-32316), [CVE-2026-33721](https://www.cve.org/CVERecord?id=CVE-2026-33721), [CVE-2026-43185](https://www.cve.org/CVERecord?id=CVE-2026-43185), [CVE-2026-64015](https://www.cve.org/CVERecord?id=CVE-2026-64015)

<a id="dr-2026-059"></a>
**DR-2026-059 — Anthropic MCP STDIO transport design RCE in official SDKs (~200k deployments, 14 CVEs)** (17 CVEs; observed Low, potential Critical)

- *self (vulnerability)* (11): [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720), [CVE-2026-26015](https://www.cve.org/CVERecord?id=CVE-2026-26015), [CVE-2026-30615](https://www.cve.org/CVERecord?id=CVE-2026-30615), [CVE-2026-30616](https://www.cve.org/CVERecord?id=CVE-2026-30616), [CVE-2026-30617](https://www.cve.org/CVERecord?id=CVE-2026-30617), [CVE-2026-30618](https://www.cve.org/CVERecord?id=CVE-2026-30618), [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623), [CVE-2026-30624](https://www.cve.org/CVERecord?id=CVE-2026-30624), [CVE-2026-30625](https://www.cve.org/CVERecord?id=CVE-2026-30625), [CVE-2026-40933](https://www.cve.org/CVERecord?id=CVE-2026-40933), [CVE-2026-54449](https://www.cve.org/CVERecord?id=CVE-2026-54449)
- *related* (6): [CVE-2025-49596](https://www.cve.org/CVERecord?id=CVE-2025-49596), [CVE-2025-54136](https://www.cve.org/CVERecord?id=CVE-2025-54136), [CVE-2025-54994](https://www.cve.org/CVERecord?id=CVE-2025-54994), [CVE-2026-22252](https://www.cve.org/CVERecord?id=CVE-2026-22252), [CVE-2026-22688](https://www.cve.org/CVERecord?id=CVE-2026-22688), [CVE-2026-42271](https://www.cve.org/CVERecord?id=CVE-2026-42271)

<a id="dr-2026-062"></a>
**DR-2026-062 — Claude Code project-file RCE & vulnerability cluster (Check Point + others)** (16 CVEs; observed Low, potential High)

- *self (vulnerability)* (5): [CVE-2025-59536](https://www.cve.org/CVERecord?id=CVE-2025-59536), [CVE-2026-21852](https://www.cve.org/CVERecord?id=CVE-2026-21852), [CVE-2026-24887](https://www.cve.org/CVERecord?id=CVE-2026-24887), [CVE-2026-39861](https://www.cve.org/CVERecord?id=CVE-2026-39861), [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316)
- *related* (11): [CVE-2026-24052](https://www.cve.org/CVERecord?id=CVE-2026-24052), [CVE-2026-24053](https://www.cve.org/CVERecord?id=CVE-2026-24053), [CVE-2026-25722](https://www.cve.org/CVERecord?id=CVE-2026-25722), [CVE-2026-25723](https://www.cve.org/CVERecord?id=CVE-2026-25723), [CVE-2026-25724](https://www.cve.org/CVERecord?id=CVE-2026-25724), [CVE-2026-25725](https://www.cve.org/CVERecord?id=CVE-2026-25725), [CVE-2026-33068](https://www.cve.org/CVERecord?id=CVE-2026-33068), [CVE-2026-35603](https://www.cve.org/CVERecord?id=CVE-2026-35603), [CVE-2026-40068](https://www.cve.org/CVERecord?id=CVE-2026-40068), [CVE-2026-46406](https://www.cve.org/CVERecord?id=CVE-2026-46406), [CVE-2026-55607](https://www.cve.org/CVERecord?id=CVE-2026-55607)

<a id="dr-2026-088"></a>
**DR-2026-088 — AI as defender - OpenAI Aardvark/Codex Security CVEs, Wiz AI-assisted GitHub Enterprise RCE (CVE-2026-3854), Google Big Sleep/CodeMender** (21 CVEs; observed Negligible, potential High)

- *discovered* (19): [CVE-2025-32988](https://www.cve.org/CVERecord?id=CVE-2025-32988), [CVE-2025-32989](https://www.cve.org/CVERecord?id=CVE-2025-32989), [CVE-2025-35430](https://www.cve.org/CVERecord?id=CVE-2025-35430), [CVE-2025-35431](https://www.cve.org/CVERecord?id=CVE-2025-35431), [CVE-2025-35432](https://www.cve.org/CVERecord?id=CVE-2025-35432), [CVE-2025-35433](https://www.cve.org/CVERecord?id=CVE-2025-35433), [CVE-2025-35434](https://www.cve.org/CVERecord?id=CVE-2025-35434), [CVE-2025-35435](https://www.cve.org/CVERecord?id=CVE-2025-35435), [CVE-2025-35436](https://www.cve.org/CVERecord?id=CVE-2025-35436), [CVE-2025-64175](https://www.cve.org/CVERecord?id=CVE-2025-64175), [CVE-2026-3854](https://www.cve.org/CVERecord?id=CVE-2026-3854), [CVE-2026-14431](https://www.cve.org/CVERecord?id=CVE-2026-14431), [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903), [CVE-2026-17658](https://www.cve.org/CVERecord?id=CVE-2026-17658), [CVE-2026-19162](https://www.cve.org/CVERecord?id=CVE-2026-19162), [CVE-2026-24881](https://www.cve.org/CVERecord?id=CVE-2026-24881), [CVE-2026-24882](https://www.cve.org/CVERecord?id=CVE-2026-24882), [CVE-2026-25242](https://www.cve.org/CVERecord?id=CVE-2026-25242), [CVE-2026-76045](https://www.cve.org/CVERecord?id=CVE-2026-76045)
- *related* (2): [CVE-2025-32990](https://www.cve.org/CVERecord?id=CVE-2025-32990), [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021)

<a id="dr-2026-094"></a>
**DR-2026-094 — Claude Opus 4.6 Firefox vulnerability-discovery campaign (22 vulnerabilities, 14 high; Firefox 148)** (28 CVEs; observed Negligible, potential Medium)

- *discovered* (22): [CVE-2026-2763](https://www.cve.org/CVERecord?id=CVE-2026-2763), [CVE-2026-2764](https://www.cve.org/CVERecord?id=CVE-2026-2764), [CVE-2026-2765](https://www.cve.org/CVERecord?id=CVE-2026-2765), [CVE-2026-2766](https://www.cve.org/CVERecord?id=CVE-2026-2766), [CVE-2026-2769](https://www.cve.org/CVERecord?id=CVE-2026-2769), [CVE-2026-2770](https://www.cve.org/CVERecord?id=CVE-2026-2770), [CVE-2026-2771](https://www.cve.org/CVERecord?id=CVE-2026-2771), [CVE-2026-2772](https://www.cve.org/CVERecord?id=CVE-2026-2772), [CVE-2026-2773](https://www.cve.org/CVERecord?id=CVE-2026-2773), [CVE-2026-2774](https://www.cve.org/CVERecord?id=CVE-2026-2774), [CVE-2026-2775](https://www.cve.org/CVERecord?id=CVE-2026-2775), [CVE-2026-2785](https://www.cve.org/CVERecord?id=CVE-2026-2785), [CVE-2026-2786](https://www.cve.org/CVERecord?id=CVE-2026-2786), [CVE-2026-2787](https://www.cve.org/CVERecord?id=CVE-2026-2787), [CVE-2026-2788](https://www.cve.org/CVERecord?id=CVE-2026-2788), [CVE-2026-2789](https://www.cve.org/CVERecord?id=CVE-2026-2789), [CVE-2026-2791](https://www.cve.org/CVERecord?id=CVE-2026-2791), [CVE-2026-2796](https://www.cve.org/CVERecord?id=CVE-2026-2796), [CVE-2026-2797](https://www.cve.org/CVERecord?id=CVE-2026-2797), [CVE-2026-2799](https://www.cve.org/CVERecord?id=CVE-2026-2799), [CVE-2026-2804](https://www.cve.org/CVERecord?id=CVE-2026-2804), [CVE-2026-2805](https://www.cve.org/CVERecord?id=CVE-2026-2805)
- *related* (6): [CVE-2026-4702](https://www.cve.org/CVERecord?id=CVE-2026-4702), [CVE-2026-4704](https://www.cve.org/CVERecord?id=CVE-2026-4704), [CVE-2026-4705](https://www.cve.org/CVERecord?id=CVE-2026-4705), [CVE-2026-4718](https://www.cve.org/CVERecord?id=CVE-2026-4718), [CVE-2026-4723](https://www.cve.org/CVERecord?id=CVE-2026-4723), [CVE-2026-4724](https://www.cve.org/CVERecord?id=CVE-2026-4724)

## Table 2 — CVEs and the incidents they occur in

Only 11 CVEs recur, all of them twice: [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248), [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720), [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903), [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472), [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623), [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634), [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987), [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316), [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769), [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726), [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021) (bold **2** in the `#` column). Since CVSS and KEV are the fields readers triage by, the table is ordered by **CVSS** (the score as published by the CNA; versions are mixed and shown), then KEV, then relation; the 62 CVEs without a CVSS score follow at the end, ordered by KEV, then relation. `IBSS obs` / `IBSS pot` are the incident-based severity scores over in-play links, blank for CVEs that are only `discovered`/`related`/`toolkit` (see *IBSS vs CVSS* below).

| CVE | # | Incident : relation | KEV | CVSS | IBSS obs | IBSS pot | CNA | Published | Product | CNA CWE | Title |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613) | 1 | DR-2026-008:attempted | **KEV** | 10 (v3.1) | 8 | 16 | GitHub_M | 2025-12-19 | n8n-io/n8n | CWE-913 | n8n Vulnerable to Remote Code Execution via Expression Injection |
| [CVE-2026-28353](https://www.cve.org/CVERecord?id=CVE-2026-28353) | 1 | DR-2026-010:self (malicious release) |  | 10 (v4.0) | 8 | 16 | GitHub_M | 2026-03-05 | aquasecurity/trivy-vscode-extension | CWE-506 | Trivy Vulnerability Scanner: Unauthorized AI Agent Execution Code Included in OpenVSX Extension Release |
| [CVE-2026-21858](https://www.cve.org/CVERecord?id=CVE-2026-21858) | 1 | DR-2026-008:attempted |  | 10 (v3.1) | 8 | 16 | GitHub_M | 2026-01-07 | n8n-io/n8n | CWE-20 | n8n Vulnerable to Unauthenticated File Access via Improper Webhook Request Handling |
| [CVE-2026-12537](https://www.cve.org/CVERecord?id=CVE-2026-12537) | 1 | DR-2026-056:self (vulnerability) |  | 10 (v4.0) | 2 | 16 | GoogleCloud | 2026-06-24 | Google Cloud/Gemini CLI; Google Cloud/run-gemini-cli GitHub Action | CWE-20 | Unauthenticated Remote Code Execution in Gemini CLI CI/CD Workflows |
| [CVE-2026-16326](https://www.cve.org/CVERecord?id=CVE-2026-16326) | 1 | DR-2026-036:self (vulnerability) |  | 10 (v3.1) | 4 | 8 | HashiCorp | 2026-07-29 | HashiCorp/Tooling | CWE-488 | consul-mcp-server vulnerable to cross-tenant credential reuse in streamable-HTTP stateless mode |
| [CVE-2026-25592](https://www.cve.org/CVERecord?id=CVE-2026-25592) | 1 | DR-2026-080:self (vulnerability) |  | 10 (v3.1) | 1 | 8 | GitHub_M | 2026-02-06 | microsoft/semantic-kernel | CWE-22 | Semantic Kernel has an Arbitrary File Write via AI Agent Function Calling in .NET SDK |
| [CVE-2026-26015](https://www.cve.org/CVERecord?id=CVE-2026-26015) | 1 | DR-2026-059:self (vulnerability) |  | 10 (v4.0) | 2 | 16 | GitHub_M | 2026-04-29 | arc53/DocsGPT | CWE-77 | Unauthenticated RCE in DocsGPT MCP STDIO Configuration |
| [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) | 1 | DR-2026-080:self (vulnerability) |  | 10 (v3.1) | 1 | 8 | GitHub_M | 2026-02-19 | microsoft/semantic-kernel | CWE-94 | Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable to remote code execution |
| [CVE-2026-39888](https://www.cve.org/CVERecord?id=CVE-2026-39888) | 1 | DR-2026-036:self (vulnerability) |  | 10 (v3.1) | 4 | 8 | GitHub_M | 2026-04-08 | MervinPraison/praisonaiagents | CWE-657, CWE-693 | PraisonAIAgents has a sandbox escape via exception frame traversal in `execute_code` (subprocess mode) |
| [CVE-2026-40933](https://www.cve.org/CVERecord?id=CVE-2026-40933) | 1 | DR-2026-059:self (vulnerability) |  | 10 (v3.1) | 2 | 16 | GitHub_M | 2026-04-21 | FlowiseAI/Flowise; FlowiseAI/flowise-components | CWE-78 | Flowise: Authenticated RCE Via MCP Adapters |
| [CVE-2026-47137](https://www.cve.org/CVERecord?id=CVE-2026-47137) | 1 | DR-2026-036:self (vulnerability) |  | 10 (v3.1) | 4 | 8 | GitHub_M | 2026-06-12 | patriksimek/vm2 | CWE-913 | vm2: GHSA-8hg8-63c5-gwmx patch bypass: nesting:true without explicit require still allows full RCE |
| [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769) | **2** | DR-2026-036:self (vulnerability)<br>DR-2026-057:related |  | 10 (v3.1) | 4 | 8 | GitHub_M | 2026-07-09 | langroid/langroid | CWE-94 | Langroid: Sandbox Escape to Remote Code Execution via Incomplete `eval()` Mitigation in TableChatAgent |
| [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726) | **2** | DR-2026-036:self (vulnerability)<br>DR-2026-057:self (vulnerability) |  | 10 (v3.1) | 6 | 24 | GitHub_M | 2026-07-09 | ruvnet/ruflo | CWE-78, CWE-306, CWE-942 | Ruflo: Unauthenticated RCE in MCP bridge default docker-compose deployment |
| [CVE-2026-73299](https://www.cve.org/CVERecord?id=CVE-2026-73299) | 1 | DR-2026-036:self (vulnerability) |  | 10 (v3.1) | 4 | 8 | GitHub_M | 2026-08-12 | microsoft/prompty | CWE-94, CWE-1336 | Prompty: Server-Side Template Injection to Remote Code Execution in the @prompty/core Nunjucks Renderer |
| [CVE-2026-22688](https://www.cve.org/CVERecord?id=CVE-2026-22688) | 1 | DR-2026-059:related |  | 10 (v3.1) |  |  | GitHub_M | 2026-01-10 | Tencent/WeKnora | CWE-77 | WeKnora has Command Injection in MCP stdio test |
| [CVE-2026-41329](https://www.cve.org/CVERecord?id=CVE-2026-41329) | 1 | DR-2026-036:self (vulnerability) |  | 9.9 (v3.1) | 4 | 8 | VulnCheck | 2026-04-20 | OpenClaw/OpenClaw | CWE-648 | OpenClaw < 2026.3.31 - Sandbox Bypass via Heartbeat Context Inheritance and senderIsOwner Escalation |
| [CVE-2026-54052](https://www.cve.org/CVERecord?id=CVE-2026-54052) | 1 | DR-2026-036:self (vulnerability) |  | 9.9 (v3.1) | 4 | 8 | GitHub_M | 2026-07-15 | czlonkowski/n8n-mcp | CWE-639, CWE-862 | n8n-MCP: Cross-tenant access to workflow version backups in multi-tenant HTTP deployments |
| [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248) | **2** | DR-2026-008:related<br>DR-2026-011:exploited | **KEV** | 9.8 (v3.1) | 8 | 16 | VulnCheck | 2025-04-07 | langflow-ai/langflow | CWE-306 | Langflow < 1.3.0 Unauthenticated RCE via /api/v1/validate/code |
| [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198) | 1 | DR-2026-008:exploited | **KEV** | 9.8 (v3.1) | 8 | 16 | ibm | 2026-07-17 | IBM/Langflow OSS | CWE-94 | Unauthenticated Remote Code Execution via Auto-Login Bypass and Code Validation |
| [CVE-2026-0770](https://www.cve.org/CVERecord?id=CVE-2026-0770) | 1 | DR-2026-008:related | **KEV** | 9.8 (v3.0) |  |  | zdi | 2026-01-23 | Langflow/Langflow | CWE-829 | Langflow exec_globals Inclusion of Functionality from Untrusted Control Sphere Remote Code Execution Vulnerability |
| [CVE-2025-46724](https://www.cve.org/CVERecord?id=CVE-2025-46724) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | GitHub_M | 2025-05-20 | langroid/langroid | CWE-94 | Langroid has a Code Injection vulnerability in TableChatAgent |
| [CVE-2026-25505](https://www.cve.org/CVERecord?id=CVE-2026-25505) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | GitHub_M | 2026-02-04 | maziggy/bambuddy | CWE-306, CWE-321 | Bambuddy Uses Hardcoded Secret Key + Many API Endpoints do not Require Authentication |
| [CVE-2026-45288](https://www.cve.org/CVERecord?id=CVE-2026-45288) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | GitHub_M | 2026-05-28 | JasperFx/marten | CWE-89 | Marten has an SQL injection vulnerability in its full-text search regConfig parameter |
| [CVE-2026-47396](https://www.cve.org/CVERecord?id=CVE-2026-47396) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-21 | MervinPraison/PraisonAI | CWE-284, CWE-306 | PraisonAI call server exposes unauthenticated agent listing, invocation, and deletion when CALL_SERVER_TOKEN is unset |
| [CVE-2026-53633](https://www.cve.org/CVERecord?id=CVE-2026-53633) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-14 | vitest-dev/vitest | CWE-749, CWE-862 | Vitest: Exposed Browser Mode API Can Proxy CDP and Overwrite Config Files, Leading to RCE |
| [CVE-2026-58138](https://www.cve.org/CVERecord?id=CVE-2026-58138) | 1 | DR-2026-036:self (vulnerability) |  | 9.8 (v3.1) | 4 | 8 | VulnCheck | 2026-06-30 | conductor-oss/conductor | CWE-94 | Orkes Conductor 3.21.21 < 3.30.2 Unauthenticated RCE via GraalVM Script Evaluators |
| [CVE-2026-21536](https://www.cve.org/CVERecord?id=CVE-2026-21536) | 1 | DR-2026-079:discovered |  | 9.8 (v3.1) |  |  | microsoft | 2026-03-05 | Microsoft/Microsoft Devices Pricing Program | CWE-434 | Microsoft Devices Pricing Program Remote Code Execution Vulnerability |
| [CVE-2026-32191](https://www.cve.org/CVERecord?id=CVE-2026-32191) | 1 | DR-2026-079:discovered |  | 9.8 (v3.1) |  |  | microsoft | 2026-03-19 | Microsoft/Microsoft Bing Images | CWE-78 | Microsoft Bing Images Remote Code Execution Vulnerability |
| [CVE-2026-32194](https://www.cve.org/CVERecord?id=CVE-2026-32194) | 1 | DR-2026-079:discovered |  | 9.8 (v3.1) |  |  | microsoft | 2026-03-19 | Microsoft/Microsoft Bing Images | CWE-77 | Microsoft Bing Images Remote Code Execution Vulnerability |
| [CVE-2026-45185](https://www.cve.org/CVERecord?id=CVE-2026-45185) | 1 | DR-2026-084:discovered |  | 9.8 (v3.1) |  |  | mitre | 2026-05-12 | Exim/Exim | CWE-416 |  |
| [CVE-2026-31402](https://www.cve.org/CVERecord?id=CVE-2026-31402) | 1 | DR-2026-058:related |  | 9.8 (v3.1) |  |  | Linux | 2026-04-03 | Linux/Linux |  | nfsd: fix heap overflow in NFSv4.0 LOCK replay cache |
| [CVE-2026-34841](https://www.cve.org/CVERecord?id=CVE-2026-34841) | 1 | DR-2026-025:related |  | 9.8 (v3.1) |  |  | GitHub_M | 2026-04-06 | usebruno/bruno | CWE-494, CWE-506 | Axios npm Supply Chain Incident Impacting @usebruno/cli |
| [CVE-2026-43185](https://www.cve.org/CVERecord?id=CVE-2026-43185) | 1 | DR-2026-058:related |  | 9.8 (v3.1) |  |  | Linux | 2026-05-06 | Linux/Linux |  | ksmbd: fix signededness bug in smb_direct_prepare_negotiation() |
| [CVE-2026-32890](https://www.cve.org/CVERecord?id=CVE-2026-32890) | 1 | DR-2026-036:self (vulnerability) |  | 9.7 (v3.1) | 4 | 8 | GitHub_M | 2026-03-20 | openVESSL/Anchorr | CWE-79, CWE-200 | Anchorr: Stored XSS in User Mapping dropdown allows unprivileged Discord users to exfiltrate all secrets via /api/config |
| [CVE-2026-45321](https://www.cve.org/CVERecord?id=CVE-2026-45321) | 1 | DR-2026-022:self (malicious release) | **KEV** | 9.6 (v3.1) | 8 | 8 | GitHub_M | 2026-05-12 | @tanstack/arktype-adapter; @tanstack/eslint-plugin-router; @tanstack/eslint-plugin-start; @tanstack/history; @tanstack/nitro-v2-vite-plugin; @tanstack/outer-vite-plugin; @tanstack/react-router; @tanst | CWE-506 | Malware in 42 @tanstack/* packages exfiltrates cloud credentials, GitHub tokens, and SSH keys |
| [CVE-2026-45758](https://www.cve.org/CVERecord?id=CVE-2026-45758) | 1 | DR-2026-022:related |  | 9.6 (v3.1) |  |  | GitHub_M | 2026-06-05 | guardrails-ai/guardrails | CWE-506 | Malicious code in guardrails-ai 0.10.1 (supply chain compromise) |
| [CVE-2026-49468](https://www.cve.org/CVERecord?id=CVE-2026-49468) | 1 | DR-2026-057:related |  | 9.5 (v4.0) |  |  | GitHub_M | 2026-06-22 | BerriAI/litellm | CWE-290 | LiteLLM: Authentication Bypass via Host Header Injection |
| [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) | **2** | DB-2026-001:self (malicious release)<br>DR-2026-010:self (malicious release) | **KEV** | 9.4 (v4.0) | 24 | 32 | GitHub_M | 2026-03-23 | BerriAI/LiteLLM; aquasecurity/setup-trivy; aquasecurity/trivy; aquasecurity/trivy-action; team-telnyx/telnyx | CWE-506 | Trivy ecosystem supply chain briefly compromised |
| [CVE-2025-34291](https://www.cve.org/CVERecord?id=CVE-2025-34291) | 1 | DR-2026-008:related | **KEV** | 9.4 (v4.0) |  |  | VulnCheck | 2025-12-05 | Langflow/Langflow | CWE-346 | Langflow <= 1.6.9 CORS Misconfiguration to Token Hijack & RCE |
| [CVE-2026-25481](https://www.cve.org/CVERecord?id=CVE-2026-25481) | 1 | DR-2026-036:self (vulnerability) |  | 9.4 (v4.0) | 4 | 8 | GitHub_M | 2026-02-04 | langroid/langroid | CWE-94 | Langroid has WAF Bypass Leading to RCE in TableChatAgent |
| [CVE-2026-44791](https://www.cve.org/CVERecord?id=CVE-2026-44791) | 1 | DR-2026-036:self (vulnerability) |  | 9.4 (v4.0) | 4 | 8 | GitHub_M | 2026-06-23 | n8n-io/n8n | CWE-1321 | n8n: XML Node Prototype Pollution Patch Bypass |
| [CVE-2025-49596](https://www.cve.org/CVERecord?id=CVE-2025-49596) | 1 | DR-2026-059:related |  | 9.4 (v4.0) |  |  | GitHub_M | 2025-06-13 | modelcontextprotocol/inspector | CWE-306 | MCP Inspector proxy server lacks authentication between the Inspector client and proxy |
| [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017) | 1 | DR-2026-008:exploited | **KEV** | 9.3 (v4.0) | 8 | 16 | GitHub_M | 2026-03-20 | langflow-ai/langflow | CWE-94, CWE-95, CWE-306 | Langflow has Unauthenticated Remote Code Execution via Public Flow Build Endpoint |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | **2** | DR-2026-020:exploited<br>DR-2026-023:exploited | **KEV** | 9.3 (v4.0) | 16 | 16 | GitHub_M | 2026-04-09 | marimo-team/marimo | CWE-306 | marimo Affected by Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass |
| [CVE-2026-42208](https://www.cve.org/CVERecord?id=CVE-2026-42208) | 1 | DR-2026-057:related | **KEV** | 9.3 (v4.0) |  |  | GitHub_M | 2026-05-08 | BerriAI/litellm | CWE-89 | LiteLLM: SQL injection in Proxy API key verification |
| [CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711) | 1 | DR-2026-087:self (vulnerability) |  | 9.3 (v3.1) | 1 | 8 | microsoft | 2025-06-11 | Microsoft/Microsoft 365 Copilot | CWE-74 | M365 Copilot Information Disclosure Vulnerability |
| [CVE-2025-62615](https://www.cve.org/CVERecord?id=CVE-2025-62615) | 1 | DR-2026-036:self (vulnerability) |  | 9.3 (v4.0) | 4 | 8 | GitHub_M | 2026-02-04 | Significant-Gravitas/AutoGPT | CWE-918 | AutoGPT has SSRF vulnerability in ReadRSSFeedBlock |
| [CVE-2026-48797](https://www.cve.org/CVERecord?id=CVE-2026-48797) | 1 | DR-2026-036:self (vulnerability) |  | 9.3 (v4.0) | 4 | 8 | GitHub_M | 2026-06-16 | mcp-tool-shop-org/@mcptoolshop/backpropagate; mcp-tool-shop-org/backpropagate | CWE-358, CWE-862, CWE-1295 | Backpropagate: backprop ui --auth and backprop ui --share do not enforce authentication |
| [CVE-2026-50548](https://www.cve.org/CVERecord?id=CVE-2026-50548) | 1 | DR-2026-060:self (vulnerability) |  | 9.3 (v4.0) | 2 | 16 | GitHub_M | 2026-06-25 | cursor/cursor | CWE-22 | Cursor Desktop sandbox escape via agent-controlled working directory |
| [CVE-2026-50549](https://www.cve.org/CVERecord?id=CVE-2026-50549) | 1 | DR-2026-060:self (vulnerability) |  | 9.3 (v4.0) | 2 | 16 | GitHub_M | 2026-06-25 | cursor/cursor | CWE-59 | Cursor Desktop sandbox escape via symlink and failed path canonicalization |
| [CVE-2026-5194](https://www.cve.org/CVERecord?id=CVE-2026-5194) | 1 | DR-2026-058:discovered |  | 9.3 (v4.0) |  |  | wolfSSL | 2026-04-09 | wolfSSL/wolfSSL | CWE-295 | wolfSSL ECDSA Certificate Verification |
| [CVE-2025-54994](https://www.cve.org/CVERecord?id=CVE-2025-54994) | 1 | DR-2026-059:related |  | 9.3 (v4.0) |  |  | GitHub_M | 2025-09-08 | akoskm/create-mcp-server-stdio | CWE-78 | @akoskm/create-mcp-server-stdio has Command Injection in MCP Server due to unsafe `exec` API |
| [CVE-2026-54760](https://www.cve.org/CVERecord?id=CVE-2026-54760) | 1 | DR-2026-057:related |  | 9.3 (v4.0) |  |  | GitHub_M | 2026-07-09 | langroid/langroid | CWE-22, CWE-89 | Langroid: SQLChatAgent dangerous-function blocklist can be bypassed with quoted or schema-qualified pg_read_file calls |
| [CVE-2026-55615](https://www.cve.org/CVERecord?id=CVE-2026-55615) | 1 | DR-2026-057:related |  | 9.2 (v4.0) |  |  | GitHub_M | 2026-07-09 | langroid/langroid | CWE-74 | Langroid: Neo4jChatAgent executes LLM-generated Cypher without validation (prompt-to-Cypher injection; config-conditional RCE), mirroring the SQLChatAgent bug fixed in CVE-2026-25879 |
| [CVE-2026-32891](https://www.cve.org/CVERecord?id=CVE-2026-32891) | 1 | DR-2026-036:self (vulnerability) |  | 9.1 (v3.1) | 4 | 8 | GitHub_M | 2026-03-20 | openVESSL/Anchorr | CWE-80, CWE-212, CWE-311 | Anchorr Privilege Escalation: Jellyseerr User → Anchorr Admin via Stored XSS |
| [CVE-2026-22252](https://www.cve.org/CVERecord?id=CVE-2026-22252) | 1 | DR-2026-059:related |  | 9.1 (v3.1) |  |  | GitHub_M | 2026-01-12 | danny-avila/LibreChat | CWE-285 | LibreChat MCP Stdio Remote Command Execution |
| [CVE-2026-33890](https://www.cve.org/CVERecord?id=CVE-2026-33890) | 1 | DR-2026-036:self (vulnerability) |  | 8.9 (v4.0) | 4 | 8 | GitHub_M | 2026-03-27 | franklioxygen/MyTube | CWE-284 | MyTube has an Unauthenticated Admin Privilege Escalation via Passkey Registration |
| [CVE-2026-48989](https://www.cve.org/CVERecord?id=CVE-2026-48989) | 1 | DR-2026-036:self (vulnerability) |  | 8.9 (v4.0) | 4 | 8 | GitHub_M | 2026-06-17 | CursorTouch/Windows-MCP | CWE-306 | Windows-MCP: HTTP transports expose unauthenticated PowerShell control with wildcard CORS |
| [CVE-2026-65598](https://www.cve.org/CVERecord?id=CVE-2026-65598) | 1 | DR-2026-036:self (vulnerability) |  | 8.9 (v4.0) | 4 | 8 | VulnCheck | 2026-07-22 | n8n-io/n8n | CWE-367 | n8n before 1.123.64 Remote Code Execution via Git Clone |
| [CVE-2026-65617](https://www.cve.org/CVERecord?id=CVE-2026-65617) | 1 | DB-2026-006:exploited-unconfirmed |  | 8.8 (v3.1) | 8 | 16 | JFROG | 2026-07-27 | jfrog/artifactory | CWE-502 | Potential remote code execution on an Artifactory package service container. |
| [CVE-2026-66014](https://www.cve.org/CVERecord?id=CVE-2026-66014) | 1 | DB-2026-006:exploited-unconfirmed |  | 8.8 (v3.1) | 8 | 16 | JFROG | 2026-07-27 | jfrog/artifactory | CWE-287 | Potential authentication bypass leading to privilege escalation in Artifactory |
| [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284) | 1 | DB-2026-018:toolkit |  | 8.8 (v3.1) |  |  | Linux | 2026-05-08 | Linux/Linux |  | xfrm: esp: avoid in-place decrypt on shared skb frags |
| [CVE-2026-43503](https://www.cve.org/CVERecord?id=CVE-2026-43503) | 1 | DB-2026-018:toolkit |  | 8.8 (v3.1) |  |  | Linux | 2026-05-23 | Linux/Linux |  | net: skbuff: propagate shared-frag marker through frag-transfer helpers |
| [CVE-2026-7482](https://www.cve.org/CVERecord?id=CVE-2026-7482) | 1 | DR-2026-037:self (vulnerability) |  | 8.8 (v4.0) | 4 | 8 | Echo | 2026-05-04 | ollama/ollama | CWE-125 | Ollama heap out-of-bounds read in GGUF tensor parsing leaks server process memory to unauthenticated remote attackers |
| [CVE-2026-24301](https://www.cve.org/CVERecord?id=CVE-2026-24301) | 1 | DR-2026-083:self (vulnerability) |  | 8.8 (v3.1) | 1 | 8 | microsoft | 2026-08-18 | Microsoft/Copilot Web | CWE-77 | Microsoft Copilot Information Disclosure Vulnerability |
| [CVE-2026-25253](https://www.cve.org/CVERecord?id=CVE-2026-25253) | 1 | DR-2026-039:self (vulnerability) |  | 8.8 (v3.1) | 4 | 8 | mitre | 2026-02-01 | OpenClaw/OpenClaw | CWE-669 |  |
| [CVE-2026-32232](https://www.cve.org/CVERecord?id=CVE-2026-32232) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v4.0) | 4 | 8 | GitHub_M | 2026-03-12 | qhkm/zeptoclaw | CWE-22, CWE-62 | ZeptoClaw: Path boundary checks bypass via symlink, TOCTOU, and hardlink |
| [CVE-2026-32974](https://www.cve.org/CVERecord?id=CVE-2026-32974) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v4.0) | 4 | 8 | VulnCheck | 2026-03-29 | OpenClaw/OpenClaw | CWE-347 | OpenClaw < 2026.3.12 - Forged Event Injection via Feishu Webhook Verification Token |
| [CVE-2026-34599](https://www.cve.org/CVERecord?id=CVE-2026-34599) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-06 | coollabsio/coolify | CWE-78 | Coolify: Authenticated Remote Code Execution in GetLogs Livewire Component |
| [CVE-2026-40583](https://www.cve.org/CVERecord?id=CVE-2026-40583) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v4.0) | 4 | 8 | GitHub_M | 2026-04-21 | UltraDAGcom/core | CWE-460, CWE-696 | UltraDAG: SmartOp Vote Path Triggers Fatal Supply Invariant Halt |
| [CVE-2026-42278](https://www.cve.org/CVERecord?id=CVE-2026-42278) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v4.0) | 4 | 8 | GitHub_M | 2026-05-08 | UltraDAGcom/core | CWE-284, CWE-639 | UltraDAG: Smart Account Spending Policy Bypass via Pockets |
| [CVE-2026-54449](https://www.cve.org/CVERecord?id=CVE-2026-54449) | 1 | DR-2026-059:self (vulnerability) |  | 8.8 (v3.1) | 2 | 16 | GitHub_M | 2026-08-20 | langbot-app/LangBot | CWE-77 | LangBot: Authenticated RCE Via MCP Configuration |
| [CVE-2026-58195](https://www.cve.org/CVERecord?id=CVE-2026-58195) | 1 | DR-2026-036:self (vulnerability) |  | 8.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-17 | ruvnet/agentic-flow | CWE-78 | Agentic-Flow: OS Command Injection in agentic-flow MCP server tools via unsanitized tool-parameter interpolation into execSync |
| [CVE-2026-24763](https://www.cve.org/CVERecord?id=CVE-2026-24763) | 1 | DR-2026-039:related |  | 8.8 (v3.1) |  |  | GitHub_M | 2026-02-02 | clawdbot/clawdbot | CWE-78 | Authenticated Command Injection in OpenClaw Docker Execution via PATH Environment Variable |
| [CVE-2026-65921](https://www.cve.org/CVERecord?id=CVE-2026-65921) | 1 | DB-2026-006:related |  | 8.8 (v3.1) |  |  | JFROG | 2026-07-27 | jfrog/artifactory | CWE-22 | Potential path traversal leading to unauthorized file writes |
| [CVE-2026-42271](https://www.cve.org/CVERecord?id=CVE-2026-42271) | 1 | DR-2026-059:related | **KEV** | 8.7 (v4.0) |  |  | GitHub_M | 2026-05-08 | BerriAI/litellm | CWE-77, CWE-78 | LiteLLM: Authenticated command execution via MCP stdio test endpoints |
| [CVE-2025-59536](https://www.cve.org/CVERecord?id=CVE-2025-59536) | 1 | DR-2026-062:self (vulnerability) |  | 8.7 (v4.0) | 2 | 8 | GitHub_M | 2025-10-03 | anthropics/claude-code | CWE-94 | Claude Code's startup trust dialog could lead to  Command Execution attack |
| [CVE-2026-10108](https://www.cve.org/CVERecord?id=CVE-2026-10108) | 1 | DR-2026-036:self (vulnerability) |  | 8.7 (v4.0) | 4 | 8 | VulnCheck | 2026-05-29 | hanxi/xiaomusic | CWE-22 | xiaomusic 0.5.7 Path Traversal via GET /music endpoint |
| [CVE-2026-48527](https://www.cve.org/CVERecord?id=CVE-2026-48527) | 1 | DR-2026-036:self (vulnerability) |  | 8.7 (v3.1) | 4 | 8 | GitHub_M | 2026-05-29 | haxtheweb/haxcms-nodejs; haxtheweb/haxcms-php | CWE-79 | HaxCMS has a stored Cross-Site Scripting (XSS) bypass in saveNode endpoint |
| [CVE-2026-50180](https://www.cve.org/CVERecord?id=CVE-2026-50180) | 1 | DR-2026-036:self (vulnerability) |  | 8.7 (v4.0) | 4 | 8 | GitHub_M | 2026-07-09 | langroid/langroid | CWE-22, CWE-89 | Langroid: SQLChatAgent _validate_query blocklist misses pg_read_file family enabling arbitrary file read |
| [CVE-2026-56679](https://www.cve.org/CVERecord?id=CVE-2026-56679) | 1 | DR-2026-036:self (vulnerability) |  | 8.7 (v4.0) | 4 | 8 | GitHub_M | 2026-07-15 | decolua/9router | CWE-915 | 9Router: Mass assignment in PATCH /api/settings allows authenticated authorization downgrade |
| [CVE-2026-59233](https://www.cve.org/CVERecord?id=CVE-2026-59233) | 1 | DR-2026-036:self (vulnerability) |  | 8.7 (v4.0) | 4 | 8 | Secur0 | 2026-08-10 | Roskus/Prospero Flow CRM | CWE-639 | Missing Authorization in Prospero Flow CRM permission save endpoint allows privilege escalation |
| [CVE-2026-3854](https://www.cve.org/CVERecord?id=CVE-2026-3854) | 1 | DR-2026-088:discovered |  | 8.7 (v4.0) |  |  | GitHub_P | 2026-03-10 | GitHub/Enterprise Server | CWE-77 | Remote code execution via git push option injection in GitHub Enterprise Server |
| [CVE-2021-29441](https://www.cve.org/CVERecord?id=CVE-2021-29441) | 1 | DR-2026-011:attempted |  | 8.6 (v3.1) | 8 | 16 | GitHub_M | 2021-04-27 | alibaba/nacos | CWE-290 | Authentication bypass |
| [CVE-2026-14869](https://www.cve.org/CVERecord?id=CVE-2026-14869) | 1 | DR-2026-036:self (vulnerability) |  | 8.6 (v3.1) | 4 | 8 | HashiCorp | 2026-07-28 | HashiCorp/Tooling | CWE-918 | terraform-mcp-server vulnerable to server side request forgery leading to token exposure |
| [CVE-2026-45136](https://www.cve.org/CVERecord?id=CVE-2026-45136) | 1 | DR-2026-036:self (vulnerability) |  | 8.6 (v4.0) | 4 | 8 | GitHub_M | 2026-05-27 | cnighswonger/claude-code-cache-fix | CWE-78, CWE-94 | claude-code-cache-fix: Local code execution via Python triple-quote injection in tools/quota-statusline.sh |
| [CVE-2026-61462](https://www.cve.org/CVERecord?id=CVE-2026-61462) | 1 | DR-2026-036:self (vulnerability) |  | 8.6 (v3.1) | 4 | 8 | VulnCheck | 2026-07-13 | zereight/mcp-gitlab | CWE-73 | mcp-gitlab Path Traversal via job_id Parameter |
| [CVE-2026-39974](https://www.cve.org/CVERecord?id=CVE-2026-39974) | 1 | DR-2026-036:self (vulnerability) |  | 8.5 (v3.1) | 4 | 8 | GitHub_M | 2026-04-09 | czlonkowski/n8n-mcp | CWE-918 | n8n-MCP has an Authenticated SSRF via instance-URL header in multi-tenant HTTP mode |
| [CVE-2026-42860](https://www.cve.org/CVERecord?id=CVE-2026-42860) | 1 | DR-2026-036:self (vulnerability) |  | 8.5 (v3.1) | 4 | 8 | GitHub_M | 2026-05-11 | openedx/edx-enterprise | CWE-918 | Open edx Enterprise Service: SSRF via SAML metadata URL in sync_provider_data endpoint |
| [CVE-2026-48124](https://www.cve.org/CVERecord?id=CVE-2026-48124) | 1 | DR-2026-089:self (vulnerability) |  | 8.5 (v4.0) | 1 | 8 | GitHub_M | 2026-06-15 | cursor/cursor | CWE-829, CWE-94 | Cursor Desktop sandbox escape via Claude hook configuration |
| [CVE-2026-50570](https://www.cve.org/CVERecord?id=CVE-2026-50570) | 1 | DR-2026-036:self (vulnerability) |  | 8.5 (v3.1) | 4 | 8 | GitHub_M | 2026-06-10 | fission/fission | CWE-269, CWE-732 | Fission: Incomplete capability denylist in Environment/Function PodSpec validation allows tenant-added CAP_SYS_TIME and cross-tenant node wall-clock corruption |
| [CVE-2026-55255](https://www.cve.org/CVERecord?id=CVE-2026-55255) | 1 | DR-2026-008:related | **KEV** | 8.4 (v3.1) |  |  | GitHub_M | 2026-06-23 | langflow-ai/langflow | CWE-639 | Langflow: IDOR Vulnerability in `/api/v1/responses` Endpoint Allows Authenticated Attackers to Access Another User's Flow |
| [CVE-2026-35570](https://www.cve.org/CVERecord?id=CVE-2026-35570) | 1 | DR-2026-036:self (vulnerability) |  | 8.4 (v3.1) | 4 | 8 | GitHub_M | 2026-04-20 | Gitlawb/openclaude | CWE-22, CWE-284 | OpenClaude has Sandbox Bypass via Early-Exit Logic Flaw that Allows Path Traversal |
| [CVE-2026-40113](https://www.cve.org/CVERecord?id=CVE-2026-40113) | 1 | DR-2026-036:self (vulnerability) |  | 8.4 (v3.1) | 4 | 8 | GitHub_M | 2026-04-09 | MervinPraison/PraisonAI | CWE-88 | PraisonAI has an Argument Injection into Cloud Run Environment Variables via Unsanitized Comma in gcloud --set-env-vars |
| [CVE-2026-40599](https://www.cve.org/CVERecord?id=CVE-2026-40599) | 1 | DR-2026-036:self (vulnerability) |  | 8.4 (v4.0) | 4 | 8 | GitHub_M | 2026-04-21 | craigjbass/clearancekit | CWE-863 | ClearanceKit: Ad-hoc signed binaries can spoof Apple process identities in the global allowlist |
| [CVE-2026-47211](https://www.cve.org/CVERecord?id=CVE-2026-47211) | 1 | DR-2026-036:self (vulnerability) |  | 8.4 (v4.0) | 4 | 8 | GitHub_M | 2026-08-03 | Q00/ouroboros | CWE-426 | Ouroboros: Remote Code Execution via Untrusted Project-Directory .env |
| [CVE-2026-66065](https://www.cve.org/CVERecord?id=CVE-2026-66065) | 1 | DR-2026-036:self (vulnerability) |  | 8.4 (v4.0) | 4 | 8 | GitHub_M | 2026-08-03 | Q00/ouroboros | CWE-15, CWE-94 | Ouroboros: Untrusted project .env can still reach RCE via omitted execution-routing keys (Incomplete fix of CVE-2026-47211) |
| [CVE-2026-24882](https://www.cve.org/CVERecord?id=CVE-2026-24882) | 1 | DR-2026-088:discovered |  | 8.4 (v3.1) |  |  | mitre | 2026-01-27 | GnuPG/GnuPG | CWE-121 |  |
| [CVE-2026-25593](https://www.cve.org/CVERecord?id=CVE-2026-25593) | 1 | DR-2026-039:related |  | 8.4 (v3.1) |  |  | GitHub_M | 2026-02-06 | openclaw/openclaw | CWE-78, CWE-306 | OpenClaw Affected by Unauthenticated Local RCE via WebSocket config.apply |
| [CVE-2026-27203](https://www.cve.org/CVERecord?id=CVE-2026-27203) | 1 | DR-2026-036:self (vulnerability) |  | 8.3 (v3.1) | 4 | 8 | GitHub_M | 2026-02-20 | YosefHayim/ebay-mcp | CWE-15, CWE-74 | eBay API MCP Server Affected by Environment Variable Injection |
| [CVE-2026-28451](https://www.cve.org/CVERecord?id=CVE-2026-28451) | 1 | DR-2026-036:self (vulnerability) |  | 8.3 (v3.1) | 4 | 8 | VulnCheck | 2026-03-05 | OpenClaw/OpenClaw |  | OpenClaw < 2026.2.14 - SSRF via Feishu Extension Media Fetching |
| [CVE-2026-22171](https://www.cve.org/CVERecord?id=CVE-2026-22171) | 1 | DR-2026-036:self (vulnerability) |  | 8.2 (v3.1) | 4 | 8 | VulnCheck | 2026-03-18 | OpenClaw/OpenClaw | CWE-22 | OpenClaw < 2026.2.19 - Path Traversal in Feishu Media Temporary File Naming |
| [CVE-2026-32231](https://www.cve.org/CVERecord?id=CVE-2026-32231) | 1 | DR-2026-036:self (vulnerability) |  | 8.2 (v3.1) | 4 | 8 | GitHub_M | 2026-03-12 | qhkm/zeptoclaw | CWE-306, CWE-345 | ZeptoClaw: Generic webhook channel trusts caller-supplied identity fields; allowlist is checked against untrusted payload data |
| [CVE-2026-33331](https://www.cve.org/CVERecord?id=CVE-2026-33331) | 1 | DR-2026-036:self (vulnerability) |  | 8.2 (v3.1) | 4 | 8 | GitHub_M | 2026-03-24 | middleapi/orpc | CWE-79 | oRPC: Stored XSS in OpenAPI Reference Plugin via unescaped JSON.stringify |
| [CVE-2026-32316](https://www.cve.org/CVERecord?id=CVE-2026-32316) | 1 | DR-2026-058:related |  | 8.2 (v3.1) |  |  | GitHub_M | 2026-04-13 | jqlang/jq | CWE-122, CWE-190 | jq: Integer overflow in jvp_string_append() allows Heap-based Buffer Overflow |
| [CVE-2026-8147](https://www.cve.org/CVERecord?id=CVE-2026-8147) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.0) | 4 | 8 | @huntr_ai | 2026-07-02 | mlflow/mlflow/mlflow | CWE-284 | Authorization Bypass in mlflow/mlflow |
| [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472) | **2** | DR-2026-036:self (vulnerability)<br>DR-2026-039:related |  | 8.1 (v3.1) | 4 | 8 | VulnCheck | 2026-03-05 | OpenClaw/OpenClaw | CWE-306 | OpenClaw < 2026.2.2 - Device Identity Check Bypass in Gateway WebSocket Connect Handshake |
| [CVE-2026-28473](https://www.cve.org/CVERecord?id=CVE-2026-28473) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | VulnCheck | 2026-03-05 | OpenClaw/OpenClaw | CWE-863 | OpenClaw < 2026.2.2 - Authorization Bypass via /approve Chat Command |
| [CVE-2026-32034](https://www.cve.org/CVERecord?id=CVE-2026-32034) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | VulnCheck | 2026-03-19 | OpenClaw/OpenClaw | CWE-78 | OpenClaw < 2026.2.21 - Insecure Control UI Authentication over Plaintext HTTP |
| [CVE-2026-32247](https://www.cve.org/CVERecord?id=CVE-2026-32247) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | GitHub_M | 2026-03-12 | getzep/graphiti | CWE-943 | Graphiti vulnerable to Cypher Injection via unsanitized node_labels in search filters |
| [CVE-2026-40070](https://www.cve.org/CVERecord?id=CVE-2026-40070) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | GitHub_M | 2026-04-09 | sgbett/bsv-ruby-sdk; sgbett/bsv-sdk; sgbett/bsv-wallet | CWE-347 | bsv-sdk and bsv-wallet persist unverified certifier signatures in acquire_certificate (direct and issuance paths) |
| [CVE-2026-45707](https://www.cve.org/CVERecord?id=CVE-2026-45707) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | GitHub_M | 2026-05-29 | czlonkowski/n8n-mcp | CWE-284 | n8n-MCP: Multi-tenant MCP requests fall back to process-level n8n credentials when tenant headers are absent or incomplete |
| [CVE-2026-49291](https://www.cve.org/CVERecord?id=CVE-2026-49291) | 1 | DR-2026-036:self (vulnerability) |  | 8.1 (v3.1) | 4 | 8 | GitHub_M | 2026-06-19 | doobidoo/mcp-memory-service | CWE-862 | mcp-memory-service: OAuth read-only clients can write and delete memories through MCP tools/call |
| [CVE-2026-24881](https://www.cve.org/CVERecord?id=CVE-2026-24881) | 1 | DR-2026-088:discovered |  | 8.1 (v3.1) |  |  | mitre | 2026-01-27 | GnuPG/GnuPG | CWE-121 |  |
| [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431) | 1 | DB-2026-018:toolkit | **KEV** | 7.8 (v3.1) |  |  | Linux | 2026-04-22 | Linux/Linux |  | crypto: algif_aead - Revert to operating out-of-place |
| [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500) | 1 | DB-2026-018:toolkit |  | 7.8 (v3.1) |  |  | Linux | 2026-05-11 | Linux/Linux |  | rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present |
| [CVE-2026-45555](https://www.cve.org/CVERecord?id=CVE-2026-45555) | 1 | DR-2026-036:self (vulnerability) |  | 7.8 (v3.1) | 4 | 8 | GitHub_M | 2026-05-29 | MarcelRoozekrans/roslyn-codelens-mcp | CWE-94 | Roslyn CodeLens MCP Server: Untrusted Roslyn Analyzer Execution via get_diagnostics Leads to Arbitrary Code Execution |
| [CVE-2026-44471](https://www.cve.org/CVERecord?id=CVE-2026-44471) | 1 | DR-2026-058:discovered |  | 7.8 (v3.1) |  |  | GitHub_M | 2026-05-13 | GitoxideLabs/gitoxide | CWE-59 | gitoxide: Symlink prefix-reuse allows worktree escape during checkout |
| [CVE-2024-47711](https://www.cve.org/CVERecord?id=CVE-2024-47711) | 1 | DR-2026-058:related |  | 7.8 (v3.1) |  |  | Linux | 2024-10-21 | Linux/Linux |  | af_unix: Don't return OOB skb in manage_oob(). |
| [CVE-2026-25157](https://www.cve.org/CVERecord?id=CVE-2026-25157) | 1 | DR-2026-039:related |  | 7.8 (v3.1) |  |  | GitHub_M | 2026-02-04 | openclaw/openclaw | CWE-78 | OpenClaw/Clawdbot has OS Command Injection via Project Root Path in sshNodeCommand |
| [CVE-2026-31554](https://www.cve.org/CVERecord?id=CVE-2026-31554) | 1 | DR-2026-058:related |  | 7.8 (v3.1) |  |  | Linux | 2026-04-24 | Linux/Linux |  | futex: Require sys_futex_requeue() to have identical flags |
| [CVE-2026-64015](https://www.cve.org/CVERecord?id=CVE-2026-64015) | 1 | DR-2026-058:related |  | 7.8 (v3.1) |  |  | Linux | 2026-07-19 | Linux/Linux |  | security/keys: fix missed RCU read section on lookup |
| [CVE-2026-24887](https://www.cve.org/CVERecord?id=CVE-2026-24887) | 1 | DR-2026-062:self (vulnerability) |  | 7.7 (v4.0) | 2 | 8 | GitHub_M | 2026-02-03 | anthropics/claude-code | CWE-78, CWE-94 | Claude Code has a Command Injection in find Command Bypasses User Approval Prompt |
| [CVE-2026-39861](https://www.cve.org/CVERecord?id=CVE-2026-39861) | 1 | DR-2026-062:self (vulnerability) |  | 7.7 (v4.0) | 2 | 8 | GitHub_M | 2026-04-21 | anthropics/claude-code | CWE-22, CWE-61 | Claude Code: Sandbox Escape via Symlink Following Allows Arbitrary File Write Outside Workspace |
| [CVE-2026-43576](https://www.cve.org/CVERecord?id=CVE-2026-43576) | 1 | DR-2026-036:self (vulnerability) |  | 7.7 (v3.1) | 4 | 8 | VulnCheck | 2026-05-06 | OpenClaw/OpenClaw | CWE-601, CWE-918 | OpenClaw < 2026.4.5 - Second-hop SSRF via CDP /json/version WebSocket URL |
| [CVE-2026-44335](https://www.cve.org/CVERecord?id=CVE-2026-44335) | 1 | DR-2026-036:self (vulnerability) |  | 7.7 (v4.0) | 4 | 8 | GitHub_M | 2026-05-08 | MervinPraison/PraisonAI | CWE-918 | SSRF bypass in PraisonAI |
| [CVE-2026-53812](https://www.cve.org/CVERecord?id=CVE-2026-53812) | 1 | DR-2026-036:self (vulnerability) |  | 7.7 (v3.1) | 4 | 8 | VulnCheck | 2026-06-11 | OpenClaw/OpenClaw | CWE-918 | OpenClaw < 2026.5.18 - Private-Network Navigation Bypass via Browser Act Interactions |
| [CVE-2026-59221](https://www.cve.org/CVERecord?id=CVE-2026-59221) | 1 | DR-2026-036:self (vulnerability) |  | 7.7 (v3.1) | 4 | 8 | GitHub_M | 2026-07-09 | open-webui/open-webui | CWE-22, CWE-918 | open-webui terminal proxy path traversal guard bypass via 9x encoded traversal |
| [CVE-2026-73217](https://www.cve.org/CVERecord?id=CVE-2026-73217) | 1 | DR-2026-089:self (vulnerability) |  | 7.7 (v4.0) | 1 | 8 | GitHub_M | 2026-08-11 | cursor/cursor | CWE-693 | Cursor: Sandbox escape via tampered Python virtual environments |
| [CVE-2026-73218](https://www.cve.org/CVERecord?id=CVE-2026-73218) | 1 | DR-2026-089:self (vulnerability) |  | 7.7 (v4.0) | 1 | 8 | GitHub_M | 2026-08-11 | cursor/cursor | CWE-269 | Cursor: Sandbox escape via launching privileged containers |
| [CVE-2025-64175](https://www.cve.org/CVERecord?id=CVE-2025-64175) | 1 | DR-2026-088:discovered |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-02-06 | gogs/gogs | CWE-287 | Gogs Vulnerable to 2FA Bypass via Recovery Code |
| [CVE-2026-24053](https://www.cve.org/CVERecord?id=CVE-2026-24053) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-02-03 | anthropics/claude-code | CWE-22, CWE-79 | Cluade Code has a Path Restriction Bypass via ZSH Clobber which Allows Arbitrary File Writes |
| [CVE-2026-25722](https://www.cve.org/CVERecord?id=CVE-2026-25722) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-02-06 | anthropics/claude-code | CWE-20, CWE-78 | Claude Code Vulnerable to Command Injection via Directory Change Bypasses Write Protection |
| [CVE-2026-25723](https://www.cve.org/CVERecord?id=CVE-2026-25723) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-02-06 | anthropics/claude-code | CWE-20, CWE-78 | Claude Code Vulnerable to Command Injection via Piped sed Command Bypasses File Write Restrictions |
| [CVE-2026-25725](https://www.cve.org/CVERecord?id=CVE-2026-25725) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-02-06 | anthropics/claude-code | CWE-501, CWE-668 | Claude Code Has Sandbox Escape via Persistent Configuration Injection in settings.json |
| [CVE-2026-33068](https://www.cve.org/CVERecord?id=CVE-2026-33068) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-03-20 | anthropics/claude-code | CWE-807 | Claude Code has a Workspace Trust Dialog Bypass via Repo-Controlled Settings File |
| [CVE-2026-40068](https://www.cve.org/CVERecord?id=CVE-2026-40068) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-05-05 | anthropics/claude-code | CWE-20, CWE-77 | Claude Code arbitrary code execution via git worktree commondir trust dialog bypass |
| [CVE-2026-55607](https://www.cve.org/CVERecord?id=CVE-2026-55607) | 1 | DR-2026-062:related |  | 7.7 (v4.0) |  |  | GitHub_M | 2026-06-29 | anthropics/claude-code | CWE-22, CWE-59, CWE-78 | Claude Code: Sandbox Escape via Git Worktree Path Confusion Allows Unsandboxed Code Execution |
| [CVE-2026-27487](https://www.cve.org/CVERecord?id=CVE-2026-27487) | 1 | DR-2026-036:self (vulnerability) |  | 7.6 (v3.1) | 4 | 8 | GitHub_M | 2026-02-21 | openclaw/openclaw | CWE-78 | OpenClaw: Prevent shell injection in macOS keychain credential write |
| [CVE-2026-5802](https://www.cve.org/CVERecord?id=CVE-2026-5802) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v2.0) | 4 | 8 | VulDB | 2026-04-08 | idachev/mcp-javadc | CWE-78, CWE-77 | idachev mcp-javadc HTTP os command injection |
| [CVE-2026-7147](https://www.cve.org/CVERecord?id=CVE-2026-7147) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v2.0) | 4 | 8 | VulDB | 2026-04-27 | JoeCastrom/mcp-chat-studio | CWE-918 | JoeCastrom mcp-chat-studio LLM Models API llm.js server-side request forgery |
| [CVE-2026-7386](https://www.cve.org/CVERecord?id=CVE-2026-7386) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v2.0) | 4 | 8 | VulDB | 2026-04-29 | fatbobman/mail-mcp-bridge | CWE-22 | fatbobman mail-mcp-bridge mail_mcp_server.py path traversal |
| [CVE-2026-7590](https://www.cve.org/CVERecord?id=CVE-2026-7590) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v2.0) | 4 | 8 | VulDB | 2026-05-01 | eyal-gor/p_69_branch_monkey_mcp | CWE-78, CWE-77 | eyal-gor p_69_branch_monkey_mcp Preview Endpoint advanced.py os command injection |
| [CVE-2026-9366](https://www.cve.org/CVERecord?id=CVE-2026-9366) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v2.0) | 4 | 8 | VulDB | 2026-05-24 | NousResearch/hermes-agent | CWE-74, CWE-707 | NousResearch hermes-agent prompt_builder.py _scan_context_content injection |
| [CVE-2026-18446](https://www.cve.org/CVERecord?id=CVE-2026-18446) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | openjs | 2026-07-31 | fast-uri/fast-uri | CWE-436 | fast-uri vulnerable to host confusion via backslash authority introducer |
| [CVE-2026-26144](https://www.cve.org/CVERecord?id=CVE-2026-26144) | 1 | DR-2026-087:self (vulnerability) |  | 7.5 (v3.1) | 1 | 8 | microsoft | 2026-03-10 | Microsoft/Microsoft 365 Apps for Enterprise | CWE-79 | Microsoft Excel Information Disclosure Vulnerability |
| [CVE-2026-26321](https://www.cve.org/CVERecord?id=CVE-2026-26321) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | GitHub_M | 2026-02-19 | openclaw/openclaw | CWE-22 | OpenClaw has a local file disclosure via sendMediaFeishu in Feishu extension |
| [CVE-2026-28478](https://www.cve.org/CVERecord?id=CVE-2026-28478) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | VulnCheck | 2026-03-05 | OpenClaw/OpenClaw | CWE-770 | OpenClaw < 2026.2.13 - Denial of Service via Unbounded Webhook Request Body Buffering |
| [CVE-2026-32049](https://www.cve.org/CVERecord?id=CVE-2026-32049) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | VulnCheck | 2026-03-21 | OpenClaw/OpenClaw | CWE-770 | OpenClaw < 2026.2.22 - Denial of Service via Inbound Media Download Byte Limit Bypass |
| [CVE-2026-40069](https://www.cve.org/CVERecord?id=CVE-2026-40069) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | GitHub_M | 2026-04-09 | sgbett/bsv-ruby-sdk | CWE-754 | bsv-sdk ARC broadcaster treats INVALID/MALFORMED/ORPHAN responses as successful broadcasts |
| [CVE-2026-53598](https://www.cve.org/CVERecord?id=CVE-2026-53598) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | GitHub_M | 2026-07-16 | microsoft/prompty | CWE-22, CWE-200 | Prompty: Arbitrary File Read via ${file:path} Reference Expansion |
| [CVE-2026-55389](https://www.cve.org/CVERecord?id=CVE-2026-55389) | 1 | DR-2026-036:self (vulnerability) |  | 7.5 (v3.1) | 4 | 8 | GitHub_M | 2026-07-28 | koxudaxi/datamodel-code-generator | CWE-22, CWE-200, CWE-610 | datamodel-code-generator vulnerable to arbitrary local file read via JSON-Schema `$ref` (`file://` and `../` traversal), bypassing `--no-allow-remote-refs` |
| [CVE-2026-34076](https://www.cve.org/CVERecord?id=CVE-2026-34076) | 1 | DR-2026-036:self (vulnerability) |  | 7.4 (v3.1) | 4 | 8 | GitHub_M | 2026-04-01 | clerk/javascript | CWE-918 | Clerk JavaScript: SSRF in the opt-in clerkFrontendApiProxy feature may leak secret keys to unintended host |
| [CVE-2026-56676](https://www.cve.org/CVERecord?id=CVE-2026-56676) | 1 | DR-2026-036:self (vulnerability) |  | 7.4 (v3.1) | 4 | 8 | GitHub_M | 2026-07-10 | decolua/9router | CWE-367, CWE-918 | 9router: Image prefetch DNS rebinding allows SSRF to internal services |
| [CVE-2026-49401](https://www.cve.org/CVERecord?id=CVE-2026-49401) | 1 | DR-2026-036:self (vulnerability) |  | 7.3 (v3.1) | 4 | 8 | GitHub_M | 2026-06-23 | denoland/deno | CWE-41, CWE-176 | Deno Permission Bypass via Unicode Normalization Mismatch on macOS (APFS) |
| [CVE-2025-54136](https://www.cve.org/CVERecord?id=CVE-2025-54136) | 1 | DR-2026-059:related |  | 7.2 (v3.1) |  |  | GitHub_M | 2025-08-01 | cursor/cursor | CWE-78 | Cursor's Modification of MCP Server Definitions Bypasses Manual Re-approvals |
| [CVE-2026-66015](https://www.cve.org/CVERecord?id=CVE-2026-66015) | 1 | DB-2026-006:related |  | 7.2 (v3.1) |  |  | JFROG | 2026-07-27 | jfrog/artifactory | CWE-269 | JFrog Platform contains an authorization flaw that may allow authenticated privilege escalation. |
| [CVE-2026-2393](https://www.cve.org/CVERecord?id=CVE-2026-2393) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.0) | 4 | 8 | @huntr_ai | 2026-05-11 | mlflow/mlflow/mlflow | CWE-918 | Server-Side Request Forgery (SSRF) in mlflow/mlflow |
| [CVE-2026-32057](https://www.cve.org/CVERecord?id=CVE-2026-32057) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.1) | 4 | 8 | VulnCheck | 2026-03-21 | OpenClaw/OpenClaw | CWE-807 | OpenClaw < 2026.2.25 - Authentication Bypass via Control UI client.id Parameter |
| [CVE-2026-40162](https://www.cve.org/CVERecord?id=CVE-2026-40162) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.1) | 4 | 8 | GitHub_M | 2026-04-10 | bugsink/bugsink | CWE-20 | Bugsink affected by authenticated arbitrary file write in artifactbundle/assemble |
| [CVE-2026-45001](https://www.cve.org/CVERecord?id=CVE-2026-45001) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.1) | 4 | 8 | VulnCheck | 2026-05-11 | OpenClaw/OpenClaw | CWE-862 | OpenClaw < 2026.4.20 - Gateway Config Mutation Guard Bypass via Agent Tool Access |
| [CVE-2026-52812](https://www.cve.org/CVERecord?id=CVE-2026-52812) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v4.0) | 4 | 8 | GitHub_M | 2026-06-24 | gogs/gogs | CWE-345, CWE-639, CWE-862 | Gogs: LFS dedupe path leaks private repo content across tenants |
| [CVE-2026-70485](https://www.cve.org/CVERecord?id=CVE-2026-70485) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.1) | 4 | 8 | GitHub_M | 2026-08-04 | open-webui/open-webui | CWE-918 | Open WebUI: Any authenticated user can reach internal services and cloud metadata via NAT64-encoded URLs |
| [CVE-2026-71556](https://www.cve.org/CVERecord?id=CVE-2026-71556) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v3.1) | 4 | 8 | GitHub_M | 2026-08-07 | go-git/go-git | CWE-59 | go-git: Worktree operations may follow symlinks |
| [CVE-2026-72770](https://www.cve.org/CVERecord?id=CVE-2026-72770) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v4.0) | 4 | 8 | VulnCheck | 2026-08-11 | n8n-io/n8n | CWE-22 | n8n before 1.123.67 Path Traversal via Git Node Operations |
| [CVE-2026-72774](https://www.cve.org/CVERecord?id=CVE-2026-72774) | 1 | DR-2026-036:self (vulnerability) |  | 7.1 (v4.0) | 4 | 8 | VulnCheck | 2026-08-11 | n8n-io/n8n | CWE-639 | n8n before 1.123.67 Authentication Bypass via HTTP Request Node |
| [CVE-2026-24052](https://www.cve.org/CVERecord?id=CVE-2026-24052) | 1 | DR-2026-062:related |  | 7.1 (v4.0) |  |  | GitHub_M | 2026-02-03 | anthropics/claude-code | CWE-601 | Claude Code has a Domain Validation Bypass which Allows Automatic Requests to Attacker-Controlled Domains |
| [CVE-2026-45792](https://www.cve.org/CVERecord?id=CVE-2026-45792) | 1 | DR-2026-036:self (vulnerability) |  | 6.9 (v4.0) | 4 | 8 | GitHub_M | 2026-06-23 | rtk-ai/rtk | CWE-345, CWE-426 | RTK improperly trusts project-local filter configuration, allowing silent tampering of command output shown to LLM |
| [CVE-2026-47133](https://www.cve.org/CVERecord?id=CVE-2026-47133) | 1 | DR-2026-036:self (vulnerability) |  | 6.9 (v4.0) | 4 | 8 | GitHub_M | 2026-07-20 | craigjbass/clearancekit | CWE-294 | ClearanceKit's signed policy tables lack monotonic counter, allowing replay of older legitimately-signed snapshots |
| [CVE-2026-59101](https://www.cve.org/CVERecord?id=CVE-2026-59101) | 1 | DR-2026-036:self (vulnerability) |  | 6.9 (v4.0) | 4 | 8 | VulnCheck | 2026-07-02 | EstrellaXD/Auto_Bangumi | CWE-918 | AutoBangumi < 3.2.8 - SSRF via /api/v1/setup/test-downloader |
| [CVE-2025-35432](https://www.cve.org/CVERecord?id=CVE-2025-35432) | 1 | DR-2026-088:discovered |  | 6.9 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-400 | CISA Thorium does not rate limit account verification email messages |
| [CVE-2025-35436](https://www.cve.org/CVERecord?id=CVE-2025-35436) | 1 | DR-2026-088:discovered |  | 6.9 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-248 | CISA Thorium account verification email error handling |
| [CVE-2026-25242](https://www.cve.org/CVERecord?id=CVE-2026-25242) | 1 | DR-2026-088:discovered |  | 6.9 (v4.0) |  |  | GitHub_M | 2026-02-19 | gogs/gogs | CWE-862 | Gogs allows unauthenticated file uploads |
| [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923) | 1 | DB-2026-006:exploited-unconfirmed |  | 6.8 (v3.1) | 8 | 16 | JFROG | 2026-07-27 | jfrog/artifactory | CWE-918 | Potential server-side request forgery in Artifactory Ansible repository handling |
| [CVE-2026-54249](https://www.cve.org/CVERecord?id=CVE-2026-54249) | 1 | DR-2026-036:self (vulnerability) |  | 6.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-29 | pydantic/pydantic-ai; pydantic/pydantic-ai-slim | CWE-918 | VercelAIAdapter trusts client-controlled `providerMetadata` to construct `UploadedFile` — S3/GCS confused deputy via provider metadata injection |
| [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924) | 1 | DB-2026-006:exploited-unconfirmed |  | 6.5 (v3.1) | 8 | 16 | JFROG | 2026-07-27 | jfrog/artifactory | CWE-918 | Server-Side Request Forgery (SSRF) via Terraform Remote repository |
| [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925) | 1 | DB-2026-006:exploited-unconfirmed |  | 6.5 (v3.1) | 8 | 16 | JFROG | 2026-07-27 | jfrog/artifactory | CWE-918 | Server-Side Request Forgery (SSRF) via JFrog Artifactory Cargo remote repository |
| [CVE-2026-7445](https://www.cve.org/CVERecord?id=CVE-2026-7445) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v2.0) | 4 | 8 | VulDB | 2026-04-29 | ZachHandley/ZMCPTools | CWE-22 | ZachHandley ZMCPTools MCP Log Resource ResourceManager.ts path traversal |
| [CVE-2026-7600](https://www.cve.org/CVERecord?id=CVE-2026-7600) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v2.0) | 4 | 8 | VulDB | 2026-05-02 | ArtMin96/yii2-mcp-server | CWE-78, CWE-77 | ArtMin96 yii2-mcp-server MCP index.ts yii_execute_command os command injection |
| [CVE-2026-18980](https://www.cve.org/CVERecord?id=CVE-2026-18980) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v2.0) | 4 | 8 | VulDB | 2026-08-06 | nearai/ironclaw | CWE-77, CWE-74 | nearai ironclaw shell.rs classify_command_risk command injection |
| [CVE-2026-32021](https://www.cve.org/CVERecord?id=CVE-2026-32021) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | VulnCheck | 2026-03-19 | OpenClaw/OpenClaw | CWE-863 | OpenClaw < 2026.2.22 - Authorization Bypass via Display Name Collision in Feishu allowFrom |
| [CVE-2026-32718](https://www.cve.org/CVERecord?id=CVE-2026-32718) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | GitHub_M | 2026-07-06 | coollabsio/coolify | CWE-863 | Coolify read-scoped API tokens can perform state-changing validation operations |
| [CVE-2026-32885](https://www.cve.org/CVERecord?id=CVE-2026-32885) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | GitHub_M | 2026-04-22 | ddev/ddev | CWE-22 | DDEV has ZipSlip path traversal in tar and zip archive extraction |
| [CVE-2026-34050](https://www.cve.org/CVERecord?id=CVE-2026-34050) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | GitHub_M | 2026-07-06 | coollabsio/coolify | CWE-862 | Coolify Settings/Updates Livewire component missing instance administrator authorization |
| [CVE-2026-41334](https://www.cve.org/CVERecord?id=CVE-2026-41334) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | VulnCheck | 2026-04-23 | OpenClaw/OpenClaw | CWE-636 | OpenClaw < 2026.3.31 - Decompression Bomb Denial of Service via Image Pixel-Limit Guard Bypass |
| [CVE-2026-42824](https://www.cve.org/CVERecord?id=CVE-2026-42824) | 1 | DR-2026-081:self (vulnerability) |  | 6.5 (v3.1) | 1 | 8 | microsoft | 2026-06-04 | Microsoft/Microsoft 365 Copilot | CWE-77 | M365 Copilot Information Disclosure Vulnerability |
| [CVE-2026-44653](https://www.cve.org/CVERecord?id=CVE-2026-44653) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | GitHub_M | 2026-06-02 | danny-avila/LibreChat | CWE-201 | LibreChat Shared MCP Server View Leaks Decrypted Admin Secrets |
| [CVE-2026-45582](https://www.cve.org/CVERecord?id=CVE-2026-45582) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | GitHub_M | 2026-05-29 | czlonkowski/n8n-mcp | CWE-201 | n8n-MCP: Workflow telemetry sanitizer could retain partial values from URL-shaped node parameters |
| [CVE-2026-49956](https://www.cve.org/CVERecord?id=CVE-2026-49956) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | VulnCheck | 2026-06-09 | nesquena/hermes-webui | CWE-862 | Hermes WebUI < 0.51.269 Profile Isolation Bypass via sessions search |
| [CVE-2026-55197](https://www.cve.org/CVERecord?id=CVE-2026-55197) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | VulnCheck | 2026-06-17 | nesquena/hermes-webui | CWE-639 | Hermes WebUI < 0.51.443 - Broken Access Control in /api/session Endpoint |
| [CVE-2026-74881](https://www.cve.org/CVERecord?id=CVE-2026-74881) | 1 | DR-2026-036:self (vulnerability) |  | 6.5 (v3.1) | 4 | 8 | VulnCheck | 2026-08-17 | jahlives/openssl_encrypt | CWE-942 | openssl_encrypt before 1.4.0 CORS Misconfiguration via Wildcard Origins |
| [CVE-2025-32988](https://www.cve.org/CVERecord?id=CVE-2025-32988) | 1 | DR-2026-088:discovered |  | 6.5 (v3.1) |  |  | redhat | 2025-07-10 | ?/?; Red Hat/Red Hat Ceph Storage 7; Red Hat/Red Hat Discovery 2; Red Hat/Red Hat Enterprise Linux 10; Red Hat/Red Hat Enterprise Linux 6; Red Hat/Red Hat Enterprise Linux 7; Red Hat/Red Hat Enterpris | CWE-415 | Gnutls: vulnerability in gnutls othername san export |
| [CVE-2025-32990](https://www.cve.org/CVERecord?id=CVE-2025-32990) | 1 | DR-2026-088:related |  | 6.5 (v3.1) |  |  | redhat | 2025-07-10 | ?/?; Red Hat/Red Hat Ceph Storage 7; Red Hat/Red Hat Discovery 2; Red Hat/Red Hat Enterprise Linux 10; Red Hat/Red Hat Enterprise Linux 6; Red Hat/Red Hat Enterprise Linux 7; Red Hat/Red Hat Enterpris | CWE-122 | Gnutls: vulnerability in gnutls certtool template parsing |
| [CVE-2026-66018](https://www.cve.org/CVERecord?id=CVE-2026-66018) | 1 | DB-2026-006:related |  | 6.5 (v3.1) |  |  | JFROG | 2026-07-27 | jfrog/artifactory | CWE-200 | JFrog Artifactory build environment properties exposure |
| [CVE-2026-56678](https://www.cve.org/CVERecord?id=CVE-2026-56678) | 1 | DR-2026-036:self (vulnerability) |  | 6.4 (v3.1) | 4 | 8 | GitHub_M | 2026-07-15 | decolua/9router | CWE-20, CWE-918 | 9Router: Kiro region injection allows authenticated SSRF with Authorization header forwarding |
| [CVE-2026-9806](https://www.cve.org/CVERecord?id=CVE-2026-9806) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v4.0) | 4 | 8 | CIRCL | 2026-05-28 | misp/cti-transmute | CWE-79 | Stored Cross-Site Scripting (XSS) in CTI Transmute Notification Panel via Malicious Convert Names |
| [CVE-2026-33994](https://www.cve.org/CVERecord?id=CVE-2026-33994) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v4.0) | 4 | 8 | GitHub_M | 2026-03-27 | locutusjs/locutus | CWE-1321 | Locutus Prototype Pollution due to incomplete fix for CVE-2026-25521 |
| [CVE-2026-34218](https://www.cve.org/CVERecord?id=CVE-2026-34218) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v4.0) | 4 | 8 | GitHub_M | 2026-03-31 | craigjbass/clearancekit | CWE-269 | ClearanceKit: Managed and user-defined policy rules not enforced between opfilter start and first policy modification |
| [CVE-2026-42333](https://www.cve.org/CVERecord?id=CVE-2026-42333) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v4.0) | 4 | 8 | GitHub_M | 2026-05-09 | quarkiverse/quarkus-openapi-generator | CWE-200 | quarkus-openapi-generator has overly broad path-parameter matching that sends authentication headers to unintended operations |
| [CVE-2026-43582](https://www.cve.org/CVERecord?id=CVE-2026-43582) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v3.1) | 4 | 8 | VulnCheck | 2026-05-06 | OpenClaw/OpenClaw | CWE-367 | OpenClaw < 2026.4.10 - DNS Rebinding SSRF via Hostname Validation Bypass |
| [CVE-2026-44430](https://www.cve.org/CVERecord?id=CVE-2026-44430) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v4.0) | 4 | 8 | GitHub_M | 2026-05-14 | modelcontextprotocol/registry | CWE-918 | MCP Registry: Unauthenticated SSRF: HTTP namespace verification dials 6to4 / NAT64 / site-local IPv6 addresses, bypassing private-address allowlist |
| [CVE-2026-55448](https://www.cve.org/CVERecord?id=CVE-2026-55448) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v3.1) | 4 | 8 | GitHub_M | 2026-06-26 | jdx/mise | CWE-78 | mise: Local credential_command executes untrusted config |
| [CVE-2026-55668](https://www.cve.org/CVERecord?id=CVE-2026-55668) | 1 | DR-2026-036:self (vulnerability) |  | 6.3 (v3.1) | 4 | 8 | GitHub_M | 2026-07-08 | filebrowser/filebrowser | CWE-22, CWE-59 | File Browser: ScopedFs follows a dangling symlink on write, letting a scoped user create files outside their scope |
| [CVE-2026-5588](https://www.cve.org/CVERecord?id=CVE-2026-5588) | 1 | DR-2026-058:related |  | 6.3 (v4.0) |  |  | bcorg | 2026-04-15 | Legion of the Bouncy Castle Inc./BC-JAVA; Legion of the Bouncy Castle Inc./BCPIX-LTS; Legion of the Bouncy Castle Inc./BCPKIX-FIPS | CWE-327 | PKIX draft CompositeVerifier accepts empty signature sequence as valid. |
| [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316) | **2** | DR-2026-056:self (vulnerability)<br>DR-2026-062:self (vulnerability) |  | 6 (v4.0) | 4 | 24 | GitHub_M | 2026-06-23 | anthropics/claude-code | CWE-183, CWE-200, CWE-515 | Claude Code: Out-of-Band Data Exfiltration via Pre-Approved HuggingFace Domain in WebFetch |
| [CVE-2026-59259](https://www.cve.org/CVERecord?id=CVE-2026-59259) | 1 | DR-2026-036:self (vulnerability) |  | 6 (v4.0) | 4 | 8 | VulnCheck | 2026-07-15 | n8n/n8n | CWE-639 | n8n - Permission Bypass via Expression Parser Mismatch in External Secrets |
| [CVE-2026-32045](https://www.cve.org/CVERecord?id=CVE-2026-32045) | 1 | DR-2026-036:self (vulnerability) |  | 5.9 (v3.1) | 4 | 8 | VulnCheck | 2026-03-21 | OpenClaw/OpenClaw | CWE-290 | OpenClaw < 2026.2.21 - Authentication Bypass in HTTP Gateway Routes via Tokenless Tailscale Auth |
| [CVE-2026-35670](https://www.cve.org/CVERecord?id=CVE-2026-35670) | 1 | DR-2026-036:self (vulnerability) |  | 5.9 (v3.1) | 4 | 8 | VulnCheck | 2026-04-10 | OpenClaw/OpenClaw | CWE-807 | OpenClaw < 2026.3.22 - Webhook Reply Rebinding via Username Resolution in Synology Chat |
| [CVE-2026-44788](https://www.cve.org/CVERecord?id=CVE-2026-44788) | 1 | DR-2026-036:self (vulnerability) |  | 5.9 (v3.1) | 4 | 8 | GitHub_M | 2026-05-26 | adamhathcock/sharpcompress | CWE-22 | SharpCompress: Directory traversal via directory entries in WriteToDirectory (zip slip variant) |
| [CVE-2026-73308](https://www.cve.org/CVERecord?id=CVE-2026-73308) | 1 | DR-2026-036:self (vulnerability) |  | 5.7 (v3.1) | 4 | 8 | GitHub_M | 2026-08-12 | Budibase/budibase | CWE-200 | Budibase: OAuth2 Token Disclosure via Automation Test Results Broadcast to Other Builders |
| [CVE-2026-29612](https://www.cve.org/CVERecord?id=CVE-2026-29612) | 1 | DR-2026-036:self (vulnerability) |  | 5.5 (v3.1) | 4 | 8 | VulnCheck | 2026-03-05 | OpenClaw/OpenClaw | CWE-770 | OpenClaw < 2026.2.14 - Denial of Service via Large Base64 Media File Decoding |
| [CVE-2026-40159](https://www.cve.org/CVERecord?id=CVE-2026-40159) | 1 | DR-2026-036:self (vulnerability) |  | 5.5 (v3.1) | 4 | 8 | GitHub_M | 2026-04-10 | MervinPraison/PraisonAI | CWE-200, CWE-214 | PraisonAI Exposes Sensitive Environment Variable via Untrusted MCP Subprocess Execution |
| [CVE-2026-46383](https://www.cve.org/CVERecord?id=CVE-2026-46383) | 1 | DR-2026-036:self (vulnerability) |  | 5.5 (v3.1) | 4 | 8 | GitHub_M | 2026-05-15 | microsoft/apm | CWE-22, CWE-73 | Microsoft APM: Windows absolute-path tar member overwrite during legacy-bundle probing in `apm install` |
| [CVE-2026-47390](https://www.cve.org/CVERecord?id=CVE-2026-47390) | 1 | DR-2026-036:self (vulnerability) |  | 5.5 (v3.1) | 4 | 8 | GitHub_M | 2026-07-21 | MervinPraison/PraisonAI; MervinPraison/praisonaiagents | CWE-918 | PraisonAI spider_tools SSRF protection bypass via alternate loopback host encodings |
| [CVE-2026-32001](https://www.cve.org/CVERecord?id=CVE-2026-32001) | 1 | DR-2026-036:self (vulnerability) |  | 5.4 (v3.1) | 4 | 8 | VulnCheck | 2026-03-19 | OpenClaw/OpenClaw | CWE-863 | OpenClaw < 2026.2.22 - Node Role Device-Identity Bypass via WebSocket Authentication |
| [CVE-2026-41365](https://www.cve.org/CVERecord?id=CVE-2026-41365) | 1 | DR-2026-036:self (vulnerability) |  | 5.4 (v3.1) | 4 | 8 | VulnCheck | 2026-04-27 | OpenClaw/OpenClaw | CWE-441 | OpenClaw < 2026.3.31 - Sender Allowlist Bypass via Graph API Thread History |
| [CVE-2026-41376](https://www.cve.org/CVERecord?id=CVE-2026-41376) | 1 | DR-2026-036:self (vulnerability) |  | 5.4 (v3.1) | 4 | 8 | VulnCheck | 2026-04-28 | OpenClaw/OpenClaw | CWE-346 | OpenClaw < 2026.3.31 - Matrix Thread Context Allowlist Bypass via Sender Validation |
| [CVE-2026-41406](https://www.cve.org/CVERecord?id=CVE-2026-41406) | 1 | DR-2026-036:self (vulnerability) |  | 5.4 (v3.1) | 4 | 8 | VulnCheck | 2026-04-28 | OpenClaw/OpenClaw | CWE-639 | OpenClaw < 2026.3.31 - Sender Allowlist Bypass via Thread History and Quoted Messages |
| [CVE-2026-63102](https://www.cve.org/CVERecord?id=CVE-2026-63102) | 1 | DR-2026-036:self (vulnerability) |  | 5.4 (v3.1) | 4 | 8 | VulnCheck | 2026-07-20 | rConfig/rConfig v8 Core | CWE-915 | rConfig Core < 8.2.8 Privilege Escalation via Users API role field |
| [CVE-2026-35603](https://www.cve.org/CVERecord?id=CVE-2026-35603) | 1 | DR-2026-062:related |  | 5.4 (v4.0) |  |  | GitHub_M | 2026-04-17 | anthropics/claude-code | CWE-426 | Claude Code: Insecure System-Wide Configuration Loading Enables Local Privilege Escalation on Windows |
| [CVE-2026-21852](https://www.cve.org/CVERecord?id=CVE-2026-21852) | 1 | DR-2026-062:self (vulnerability) |  | 5.3 (v4.0) | 2 | 8 | GitHub_M | 2026-01-21 | anthropics/claude-code | CWE-522 | Claude Code Leaks Data via Malicious Environment Configuration Before Trust Confirmation |
| [CVE-2026-32002](https://www.cve.org/CVERecord?id=CVE-2026-32002) | 1 | DR-2026-036:self (vulnerability) |  | 5.3 (v3.1) | 4 | 8 | VulnCheck | 2026-03-19 | OpenClaw/OpenClaw | CWE-200 | OpenClaw < 2026.2.23 - Sandbox Boundary Bypass via Image Tool workspaceOnly Bypass |
| [CVE-2026-32111](https://www.cve.org/CVERecord?id=CVE-2026-32111) | 1 | DR-2026-036:self (vulnerability) |  | 5.3 (v3.1) | 4 | 8 | GitHub_M | 2026-03-11 | homeassistant-ai/ha-mcp | CWE-918 | ha-mcp OAuth 2.1 DCR mode enables network reconnaissance via an error oracle |
| [CVE-2026-41345](https://www.cve.org/CVERecord?id=CVE-2026-41345) | 1 | DR-2026-036:self (vulnerability) |  | 5.3 (v3.1) | 4 | 8 | VulnCheck | 2026-04-23 | OpenClaw/OpenClaw | CWE-522 | OpenClaw < 2026.3.31 - Authorization Header Leak via Cross-Origin Redirect in Media Download |
| [CVE-2026-41495](https://www.cve.org/CVERecord?id=CVE-2026-41495) | 1 | DR-2026-036:self (vulnerability) |  | 5.3 (v3.1) | 4 | 8 | GitHub_M | 2026-05-08 | czlonkowski/n8n-mcp | CWE-532 | n8n-MCP Logs Sensitive Request Data on Unauthorized /mcp Requests |
| [CVE-2026-54362](https://www.cve.org/CVERecord?id=CVE-2026-54362) | 1 | DR-2026-036:self (vulnerability) |  | 5.3 (v4.0) | 4 | 8 | CIRCL | 2026-06-12 | misp/misp | CWE-863 | MISP template builder exposes non-visible custom galaxies across organisations |
| [CVE-2025-32989](https://www.cve.org/CVERecord?id=CVE-2025-32989) | 1 | DR-2026-088:discovered |  | 5.3 (v3.1) |  |  | redhat | 2025-07-10 | ?/?; Red Hat/Red Hat Ceph Storage 7; Red Hat/Red Hat Discovery 2; Red Hat/Red Hat Enterprise Linux 10; Red Hat/Red Hat Enterprise Linux 6; Red Hat/Red Hat Enterprise Linux 7; Red Hat/Red Hat Enterpris | CWE-295 | Gnutls: vulnerability in gnutls sct extension parsing |
| [CVE-2025-35430](https://www.cve.org/CVERecord?id=CVE-2025-35430) | 1 | DR-2026-088:discovered |  | 5.3 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-22 | CISA Thorium insecure downloaded file path validation |
| [CVE-2025-35431](https://www.cve.org/CVERecord?id=CVE-2025-35431) | 1 | DR-2026-088:discovered |  | 5.3 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-90 | CISA Thorium LDAP injection |
| [CVE-2025-35435](https://www.cve.org/CVERecord?id=CVE-2025-35435) | 1 | DR-2026-088:discovered |  | 5.3 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-369 | CISA Thorium download stream divide by zero |
| [CVE-2026-33721](https://www.cve.org/CVERecord?id=CVE-2026-33721) | 1 | DR-2026-058:related |  | 5.3 (v3.1) |  |  | GitHub_M | 2026-03-27 | MapServer/MapServer | CWE-787 | MapServer has heap buffer overflow in SLD `Categorize` Threshold parsing |
| [CVE-2026-10855](https://www.cve.org/CVERecord?id=CVE-2026-10855) | 1 | DR-2026-036:self (vulnerability) |  | 5.1 (v4.0) | 4 | 8 | CIRCL | 2026-06-04 | misp/misp | CWE-862 | MISP Event template importer authorization bypass |
| [CVE-2026-7235](https://www.cve.org/CVERecord?id=CVE-2026-7235) | 1 | DR-2026-036:self (vulnerability) |  | 5 (v2.0) | 4 | 8 | VulDB | 2026-04-28 | ErlichLiu/claude-agent-sdk-master | CWE-22 | ErlichLiu claude-agent-sdk-master route.ts path traversal |
| [CVE-2026-7589](https://www.cve.org/CVERecord?id=CVE-2026-7589) | 1 | DR-2026-036:self (vulnerability) |  | 5 (v2.0) | 4 | 8 | VulDB | 2026-05-01 | ghantakiran/splunk-mcp-integration | CWE-22 | ghantakiran splunk-mcp-integration CSV Export csv_export.py create_csv_export path traversal |
| [CVE-2026-35646](https://www.cve.org/CVERecord?id=CVE-2026-35646) | 1 | DR-2026-036:self (vulnerability) |  | 4.8 (v3.1) | 4 | 8 | VulnCheck | 2026-04-09 | OpenClaw/OpenClaw | CWE-307 | OpenClaw < 2026.3.25 - Pre-Authentication Rate-Limit Bypass in Webhook Token Validation |
| [CVE-2026-13591](https://www.cve.org/CVERecord?id=CVE-2026-13591) | 1 | DR-2026-036:self (vulnerability) |  | 4.6 (v2.0) | 4 | 8 | VulDB | 2026-06-29 | DeepMyst/Mysti | CWE-285, CWE-266 | DeepMyst Mysti Contact Tracking ChannelBridge.ts _isTrackedConversation improper authorization |
| [CVE-2026-46672](https://www.cve.org/CVERecord?id=CVE-2026-46672) | 1 | DR-2026-036:self (vulnerability) |  | 4.6 (v3.1) | 4 | 8 | GitHub_M | 2026-07-07 | actualbudget/actual | CWE-1236 | Actual: CSV Formula Injection in `@actual-app/cli` `--format csv` Output via Custom `escapeCsv` Helper |
| [CVE-2026-46406](https://www.cve.org/CVERecord?id=CVE-2026-46406) | 1 | DR-2026-062:related |  | 4.4 (v4.0) |  |  | GitHub_M | 2026-06-29 | anthropics/claude-code | CWE-59, CWE-200, CWE-377 | Claude Code: Insecure Temporary File in /copy Command Enables Response Disclosure and Symlink-Based File Write |
| [CVE-2026-1979](https://www.cve.org/CVERecord?id=CVE-2026-1979) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v2.0) | 4 | 8 | VulDB | 2026-02-06 | n/a/mruby | CWE-416, CWE-119 | mruby JMPNOT-to-JMPIF Optimization vm.c mrb_vm_exec use after free |
| [CVE-2026-19282](https://www.cve.org/CVERecord?id=CVE-2026-19282) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v2.0) | 4 | 8 | VulDB | 2026-08-08 | andreahaku/llm_memory_mcp | CWE-77, CWE-74 | andreahaku llm_memory_mcp GitHooksManager.ts auto.capture command injection |
| [CVE-2026-27486](https://www.cve.org/CVERecord?id=CVE-2026-27486) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v4.0) | 4 | 8 | GitHub_M | 2026-02-21 | openclaw/openclaw | CWE-283 | OpenClaw: Process Safety - Unvalidated PID Kill via SIGKILL in Process Cleanup |
| [CVE-2026-27695](https://www.cve.org/CVERecord?id=CVE-2026-27695) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v3.1) | 4 | 8 | GitHub_M | 2026-02-25 | zeroae/zae-limiter | CWE-770 | zae-limiter: DynamoDB hot partition throttling enables per-entity Denial of Service |
| [CVE-2026-42282](https://www.cve.org/CVERecord?id=CVE-2026-42282) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v3.1) | 4 | 8 | GitHub_M | 2026-05-08 | czlonkowski/n8n-mcp | CWE-532 | n8n-MCP: Sensitive MCP tool-call arguments logged on authenticated requests in HTTP mode |
| [CVE-2026-50569](https://www.cve.org/CVERecord?id=CVE-2026-50569) | 1 | DR-2026-036:self (vulnerability) |  | 4.3 (v3.1) | 4 | 8 | GitHub_M | 2026-06-10 | fission/fission | CWE-20 | Fission: HTTPTrigger admission omits RelativeURL / Prefix validation; kubectl apply bypasses CLI checks |
| [CVE-2026-27795](https://www.cve.org/CVERecord?id=CVE-2026-27795) | 1 | DR-2026-036:self (vulnerability) |  | 4.1 (v3.1) | 4 | 8 | GitHub_M | 2026-02-25 | langchain-ai/langchainjs | CWE-918 | LangChain Community: redirect chaining can lead to SSRF bypass via RecursiveUrlLoader |
| [CVE-2026-10291](https://www.cve.org/CVERecord?id=CVE-2026-10291) | 1 | DR-2026-036:self (vulnerability) |  | 4 (v2.0) | 4 | 8 | VulDB | 2026-06-01 | Enderfga/claw-orchestrator | CWE-1333, CWE-400 | Enderfga claw-orchestrator Session Grep Endpoint embedded-server.ts validateRegex redos |
| [CVE-2026-14611](https://www.cve.org/CVERecord?id=CVE-2026-14611) | 1 | DR-2026-036:self (vulnerability) |  | 4 (v2.0) | 4 | 8 | VulDB | 2026-07-03 | DeepMyst/Mysti | CWE-668, CWE-200 | DeepMyst Mysti Per-Project Auto-Memory MemoryManager.ts initProjectMemory exposure of resource |
| [CVE-2026-42148](https://www.cve.org/CVERecord?id=CVE-2026-42148) | 1 | DR-2026-036:self (vulnerability) |  | 3.8 (v3.1) | 4 | 8 | GitHub_M | 2026-07-06 | coollabsio/coolify | CWE-78 | Coolify: Command Injection via Unescaped Version String in Docker Build |
| [CVE-2026-44219](https://www.cve.org/CVERecord?id=CVE-2026-44219) | 1 | DR-2026-036:self (vulnerability) |  | 3.7 (v3.1) | 4 | 8 | GitHub_M | 2026-05-12 | Jo-Jo98/ciguard | CWE-770 | ciguard: SCA HTTP client reads response body without size cap |
| [CVE-2026-50568](https://www.cve.org/CVERecord?id=CVE-2026-50568) | 1 | DR-2026-036:self (vulnerability) |  | 3.6 (v3.1) | 4 | 8 | GitHub_M | 2026-06-10 | fission/fission | CWE-41 | Fission: SanitizeFilePath lexical HasPrefix bypass permits sibling-directory escape |
| [CVE-2026-6830](https://www.cve.org/CVERecord?id=CVE-2026-6830) | 1 | DR-2026-036:self (vulnerability) |  | 3.3 (v3.1) | 4 | 8 | VulnCheck | 2026-04-21 | nesquena/hermes-webui | CWE-668, CWE-459 | Nesquena Hermes WebUI Environment Variable Credential Leakage via Profile Switch |
| [CVE-2026-47091](https://www.cve.org/CVERecord?id=CVE-2026-47091) | 1 | DR-2026-036:self (vulnerability) |  | 3.3 (v3.1) | 4 | 8 | VulnCheck | 2026-05-18 | jarrodwatts/claude-hud | CWE-22 | Claude HUD 0.0.12 Path Traversal via transcript_path |
| [CVE-2026-44220](https://www.cve.org/CVERecord?id=CVE-2026-44220) | 1 | DR-2026-036:self (vulnerability) |  | 3.2 (v3.1) | 4 | 8 | GitHub_M | 2026-05-12 | Jo-Jo98/ciguard | CWE-59 | ciguard: discover_pipeline_files follows symlinks out of scan root |
| [CVE-2026-11330](https://www.cve.org/CVERecord?id=CVE-2026-11330) | 1 | DR-2026-036:self (vulnerability) |  | 2.4 (v2.0) | 4 | 8 | VulDB | 2026-06-05 | thedotmack/claude-mem | CWE-328, CWE-327 | thedotmack claude-mem Observation Content Hash store.ts computeObservationContentHash weak hash |
| [CVE-2025-35433](https://www.cve.org/CVERecord?id=CVE-2025-35433) | 1 | DR-2026-088:discovered |  | 2.3 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-613 | CISA Thorium does not properly invalidate previously used tokens |
| [CVE-2025-35434](https://www.cve.org/CVERecord?id=CVE-2025-35434) | 1 | DR-2026-088:discovered |  | 2.3 (v4.0) |  |  | cisa-cg | 2025-09-17 | CISA/Thorium | CWE-295 | CISA Thorium does not validate TLS connections to Elasticsearch |
| [CVE-2026-5199](https://www.cve.org/CVERecord?id=CVE-2026-5199) | 1 | DR-2026-058:related |  | 2.3 (v4.0) |  |  | Temporal | 2026-04-01 | Temporal Technologies, Inc./temporal | CWE-639 | Cross Namespace Access via Batch Operation |
| [CVE-2026-25724](https://www.cve.org/CVERecord?id=CVE-2026-25724) | 1 | DR-2026-062:related |  | 2.3 (v4.0) |  |  | GitHub_M | 2026-02-06 | anthropics/claude-code | CWE-61, CWE-285 | Claude Code Has Permission Deny Bypass Through Symbolic Links |
| [CVE-2026-33637](https://www.cve.org/CVERecord?id=CVE-2026-33637) | 1 | DR-2026-036:self (vulnerability) |  | 0 (v3.1) | 4 | 8 | GitHub_M | 2026-05-19 | lostisland/faraday | CWE-918 | Faraday: Protocol-relative URI objects still bypass host scoping (possible incomplete fix for GHSA-33mh-2634-fwr2) |
| [CVE-2026-44427](https://www.cve.org/CVERecord?id=CVE-2026-44427) | 1 | DR-2026-036:self (vulnerability) |  | 0 (v4.0) | 4 | 8 | GitHub_M | 2026-05-14 | modelcontextprotocol/registry | CWE-601 | MCP Registry: Open Redirect |
| [CVE-2017-7269](https://www.cve.org/CVERecord?id=CVE-2017-7269) | 1 | DB-2026-018:toolkit | **KEV** |  |  |  | mitre | 2017-03-27 | n/a/n/a |  |  |
| [CVE-2021-3156](https://www.cve.org/CVERecord?id=CVE-2021-3156) | 1 | DB-2026-018:toolkit | **KEV** |  |  |  | mitre | 2021-01-26 | n/a/n/a |  |  |
| [CVE-2021-4034](https://www.cve.org/CVERecord?id=CVE-2021-4034) | 1 | DB-2026-018:toolkit | **KEV** |  |  |  | redhat | 2022-01-28 | n/a/polkit | CWE-787 |  |
| [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720) | **2** | DR-2026-059:self (vulnerability)<br>DR-2026-080:related |  |  | 2 | 16 | mitre | 2026-07-15 | n/a/n/a |  |  |
| [CVE-2025-70040](https://www.cve.org/CVERecord?id=CVE-2025-70040) | 1 | DR-2026-036:self (vulnerability) |  |  | 4 | 8 | mitre | 2026-03-09 | n/a/n/a |  |  |
| [CVE-2026-6784](https://www.cve.org/CVERecord?id=CVE-2026-6784) | 1 | DR-2026-095:self (vulnerability) |  |  | 1 | 4 | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Memory safety bugs fixed in Firefox 150 and Thunderbird 150 |
| [CVE-2026-6785](https://www.cve.org/CVERecord?id=CVE-2026-6785) | 1 | DR-2026-095:self (vulnerability) |  |  | 1 | 4 | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Memory safety bugs fixed in Firefox ESR 115.35, Firefox ESR 140.10, Thunderbird ESR 140.10, Firefox 150 and Thunderbird 150 |
| [CVE-2026-6786](https://www.cve.org/CVERecord?id=CVE-2026-6786) | 1 | DR-2026-095:self (vulnerability) |  |  | 1 | 4 | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Memory safety bugs fixed in Firefox ESR 140.10, Thunderbird ESR 140.10, Firefox 150 and Thunderbird 150 |
| [CVE-2026-30615](https://www.cve.org/CVERecord?id=CVE-2026-30615) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-04-15 | n/a/n/a |  |  |
| [CVE-2026-30616](https://www.cve.org/CVERecord?id=CVE-2026-30616) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-04-15 | n/a/n/a |  |  |
| [CVE-2026-30617](https://www.cve.org/CVERecord?id=CVE-2026-30617) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-04-15 | n/a/n/a |  |  |
| [CVE-2026-30618](https://www.cve.org/CVERecord?id=CVE-2026-30618) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-07-15 | n/a/n/a |  |  |
| [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623) | **2** | DR-2026-059:self (vulnerability)<br>DR-2026-080:related |  |  | 2 | 16 | mitre | 2026-07-15 | n/a/n/a |  |  |
| [CVE-2026-30624](https://www.cve.org/CVERecord?id=CVE-2026-30624) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-04-15 | n/a/n/a |  |  |
| [CVE-2026-30625](https://www.cve.org/CVERecord?id=CVE-2026-30625) | 1 | DR-2026-059:self (vulnerability) |  |  | 2 | 16 | mitre | 2026-04-15 | n/a/n/a |  |  |
| [CVE-2026-30635](https://www.cve.org/CVERecord?id=CVE-2026-30635) | 1 | DR-2026-036:self (vulnerability) |  |  | 4 | 8 | mitre | 2026-05-11 | n/a/n/a |  |  |
| [CVE-2026-56443](https://www.cve.org/CVERecord?id=CVE-2026-56443) | 1 | DR-2026-036:self (vulnerability) |  |  | 4 | 8 | Gitea | 2026-08-13 | Gitea/Gitea Open Source Git Server | CWE-863 | Token public-only scope bypassed on Limited-visibility owners (Repository + Package categories) — residual after CVE-2026-25714 / PR #37118 |
| [CVE-2026-58432](https://www.cve.org/CVERecord?id=CVE-2026-58432) | 1 | DR-2026-036:self (vulnerability) |  |  | 4 | 8 | Gitea | 2026-08-13 | Gitea/Gitea Open Source Git Server | CWE-200, CWE-639, CWE-732, CWE-862 | Missing Authorization and Authorization Bypass Through User-Controlled Key and Incorrect Permission Assignment for Critical Resource and Exposure of Sensitive Information to an Unauthorized Actor in code.gitea.io/gitea |
| [CVE-2026-2763](https://www.cve.org/CVERecord?id=CVE-2026-2763) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2764](https://www.cve.org/CVERecord?id=CVE-2026-2764) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | JIT miscompilation, use-after-free in the JavaScript Engine: JIT component |
| [CVE-2026-2765](https://www.cve.org/CVERecord?id=CVE-2026-2765) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2766](https://www.cve.org/CVERecord?id=CVE-2026-2766) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript Engine: JIT component |
| [CVE-2026-2769](https://www.cve.org/CVERecord?id=CVE-2026-2769) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the Storage: IndexedDB component |
| [CVE-2026-2770](https://www.cve.org/CVERecord?id=CVE-2026-2770) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the DOM: Bindings (WebIDL) component |
| [CVE-2026-2771](https://www.cve.org/CVERecord?id=CVE-2026-2771) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Undefined behavior in the DOM: Core & HTML component |
| [CVE-2026-2772](https://www.cve.org/CVERecord?id=CVE-2026-2772) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the Audio/Video: Playback component |
| [CVE-2026-2773](https://www.cve.org/CVERecord?id=CVE-2026-2773) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Incorrect boundary conditions in the Web Audio component |
| [CVE-2026-2774](https://www.cve.org/CVERecord?id=CVE-2026-2774) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Integer overflow in the Audio/Video component |
| [CVE-2026-2775](https://www.cve.org/CVERecord?id=CVE-2026-2775) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Mitigation bypass in the DOM: HTML Parser component |
| [CVE-2026-2785](https://www.cve.org/CVERecord?id=CVE-2026-2785) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Invalid pointer in the JavaScript Engine component |
| [CVE-2026-2786](https://www.cve.org/CVERecord?id=CVE-2026-2786) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2787](https://www.cve.org/CVERecord?id=CVE-2026-2787) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the DOM: Window and Location component |
| [CVE-2026-2788](https://www.cve.org/CVERecord?id=CVE-2026-2788) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Incorrect boundary conditions in the Audio/Video: GMP component |
| [CVE-2026-2789](https://www.cve.org/CVERecord?id=CVE-2026-2789) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the Graphics: ImageLib component |
| [CVE-2026-2791](https://www.cve.org/CVERecord?id=CVE-2026-2791) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Mitigation bypass in the Networking: Cache component |
| [CVE-2026-2796](https://www.cve.org/CVERecord?id=CVE-2026-2796) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | JIT miscompilation in the JavaScript: WebAssembly component |
| [CVE-2026-2797](https://www.cve.org/CVERecord?id=CVE-2026-2797) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript: GC component |
| [CVE-2026-2799](https://www.cve.org/CVERecord?id=CVE-2026-2799) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the DOM: Core & HTML component |
| [CVE-2026-2804](https://www.cve.org/CVERecord?id=CVE-2026-2804) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript: WebAssembly component |
| [CVE-2026-2805](https://www.cve.org/CVERecord?id=CVE-2026-2805) | 1 | DR-2026-094:discovered |  |  |  |  | mozilla | 2026-02-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Invalid pointer in the DOM: Core & HTML component |
| [CVE-2026-4747](https://www.cve.org/CVERecord?id=CVE-2026-4747) | 1 | DR-2026-058:discovered |  |  |  |  | freebsd | 2026-03-26 | FreeBSD/FreeBSD | CWE-121 | Remote code execution via RPCSEC_GSS packet validation |
| [CVE-2026-13242](https://www.cve.org/CVERecord?id=CVE-2026-13242) | 1 | DR-2026-085:discovered |  |  |  |  | drupal | 2026-07-10 | Drupal/Geolocation Field | CWE-89 | Geolocation Field - Critical - SQL Injection - SA-CONTRIB-2026-062 |
| [CVE-2026-14431](https://www.cve.org/CVERecord?id=CVE-2026-14431) | 1 | DR-2026-088:discovered |  |  |  |  | Chrome | 2026-07-01 | Google/Chrome | CWE-843 |  |
| [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903) | **2** | DR-2026-088:discovered<br>DR-2026-091:discovered |  |  |  |  | Chrome | 2026-07-20 | Google/Chrome |  |  |
| [CVE-2026-17658](https://www.cve.org/CVERecord?id=CVE-2026-17658) | 1 | DR-2026-088:discovered |  |  |  |  | Chrome | 2026-07-30 | Google/Chrome | CWE-416 |  |
| [CVE-2026-19162](https://www.cve.org/CVERecord?id=CVE-2026-19162) | 1 | DR-2026-088:discovered |  |  |  |  | Chrome | 2026-08-06 | Google/Chrome | CWE-787 |  |
| [CVE-2026-55803](https://www.cve.org/CVERecord?id=CVE-2026-55803) | 1 | DR-2026-085:discovered |  |  |  |  | drupal | 2026-07-10 | Drupal/Drupal core | CWE-915 | Drupal core - Critical - PHP object injection - SA-CORE-2026-005 |
| [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021) | **2** | DR-2026-088:related<br>DR-2026-093:discovered |  |  |  |  | Chrome | 2026-08-20 | Google/Chrome | CWE-416 |  |
| [CVE-2026-76045](https://www.cve.org/CVERecord?id=CVE-2026-76045) | 1 | DR-2026-088:discovered |  |  |  |  | Chrome | 2026-08-18 | Google/Chrome | CWE-416 |  |
| [CVE-2026-4702](https://www.cve.org/CVERecord?id=CVE-2026-4702) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | JIT miscompilation in the JavaScript Engine component |
| [CVE-2026-4704](https://www.cve.org/CVERecord?id=CVE-2026-4704) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Denial-of-service in the WebRTC: Signaling component |
| [CVE-2026-4705](https://www.cve.org/CVERecord?id=CVE-2026-4705) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Undefined behavior in the WebRTC: Signaling component |
| [CVE-2026-4718](https://www.cve.org/CVERecord?id=CVE-2026-4718) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Undefined behavior in the WebRTC: Signaling component |
| [CVE-2026-4723](https://www.cve.org/CVERecord?id=CVE-2026-4723) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-4724](https://www.cve.org/CVERecord?id=CVE-2026-4724) | 1 | DR-2026-094:related |  |  |  |  | mozilla | 2026-03-24 | Mozilla/Firefox; Mozilla/Thunderbird |  | Undefined behavior in the Audio/Video component |
| [CVE-2026-5398](https://www.cve.org/CVERecord?id=CVE-2026-5398) | 1 | DR-2026-058:related |  |  |  |  | freebsd | 2026-04-22 | FreeBSD/FreeBSD | CWE-416 | Kernel use-after-free bug in the TIOCNOTTY handler |
| [CVE-2026-5757](https://www.cve.org/CVERecord?id=CVE-2026-5757) | 1 | DR-2026-037:related |  |  |  |  | certcc | 2026-06-26 | Ollama AI/Ollama |  | There exists an unauthenticated remote information disclosure vulnerability in Ollama's model quantization engine |
| [CVE-2026-6386](https://www.cve.org/CVERecord?id=CVE-2026-6386) | 1 | DR-2026-058:related |  |  |  |  | freebsd | 2026-04-22 | FreeBSD/FreeBSD | CWE-269, CWE-732 | Missing large page handling in pmap_pkru_update_range() |
| [CVE-2026-6746](https://www.cve.org/CVERecord?id=CVE-2026-6746) | 1 | DR-2026-095:related |  |  |  |  | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the DOM: Core & HTML component |
| [CVE-2026-6757](https://www.cve.org/CVERecord?id=CVE-2026-6757) | 1 | DR-2026-095:related |  |  |  |  | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Invalid pointer in the JavaScript: WebAssembly component |
| [CVE-2026-6758](https://www.cve.org/CVERecord?id=CVE-2026-6758) | 1 | DR-2026-095:related |  |  |  |  | mozilla | 2026-04-21 | Mozilla/Firefox; Mozilla/Thunderbird |  | Use-after-free in the JavaScript: WebAssembly component |
| [CVE-2026-55804](https://www.cve.org/CVERecord?id=CVE-2026-55804) | 1 | DR-2026-085:related |  |  |  |  | drupal | 2026-07-10 | Drupal/Drupal core | CWE-915 | Drupal core - Moderately critical - Gadget chain - SA-CORE-2026-006 |

## CVSS of the CVE vs observed severity of its incident (all links)

Each cell counts incident–CVE links. The vulnerability's CVSS and the incident's realized harm are different things — this table is the empirical form of the methodology's argument (§6.3). It covers all 333 links, whatever their relation; the next section refines the comparison to in-play CVEs and scores them with IBSS.

| CVSS band of CVE | Critical | High | Medium | Low | Negligible | Total |
|---|---|---|---|---|---|---|
| Critical 9.0-10.0 | 1 | 14 | 21 | 18 | 7 | 61 |
| High 7.0-8.9 | 0 | 10 | 74 | 19 | 9 | 112 |
| Medium 4.0-6.9 | 0 | 4 | 60 | 7 | 10 | 81 |
| Low 0.1-3.9 | 0 | 0 | 9 | 2 | 2 | 13 |
| no CVSS | 0 | 3 | 5 | 11 | 47 | 66 |

Read together with the *Coverage* table at the top: the CVE-bearing incidents are disclosure-heavy, so the Negligible/Low columns are populated partly by construction.

## IBSS vs CVSS — a first experiment

IBSS was designed for CWEs, where one weakness spans many incidents. Applying it to CVEs is a first check of two things only: whether the tier weights behave sensibly, and how a CVE's technical score relates to the harm its incident realized (observed) or could have realized (potential). Three limits apply. **(1)** 205 of the 209 in-play CVEs have a single in-play incident, so their IBSS is just that incident's weight — the summation is barely exercised. **(2)** Each in-play CVE receives the *full* weight of its incident; where several CVEs share an incident (e.g. the Artifactory CVEs of DB-2026-006) the score does not establish per-CVE causation. **(3)** 161 of the 209 in-play CVEs belong to DR-2026-036, and 160 of those share one observed (Medium = 4) and one potential (High = 8) value, so aggregate statistics are dominated by that incident; figures are therefore also given without it.

- A Spearman rank correlation between CVSS and IBSS is computed by the build script but **not reported at this stage**: 161 of the 194 scored in-play CVEs share one severity value (DR-2026-036), and the remaining n = 37 yields confidence intervals that span zero to a moderate correlation — the coefficient would carry no information either way and would invite the reading "CVSS is unrelated to harm". The corpus is planned to grow (further sources, later years), and the correlation will be reported once the in-play CVE population is large and varied enough for the interval to be informative. Until then the band table below carries the comparison.
- Potential is the fairer comparison — CVSS and potential both describe what *could* happen; observed shows what did.

### IBSS_potential band × CVSS band (in-play CVEs)

| IBSS pot | Tier(s) | 9.0-10.0 | 7.0-8.9 | 4.0-6.9 | 0.1-3.9 | no CVSS | CVEs |
|---|---|---|---|---|---|---|---|
| 32 | Critical + Critical | 1 | 0 | 0 | 0 | 0 | 1 |
| 24 | Critical + High | 1 | 0 | 1 | 0 | 0 | 2 |
| 16 | Critical / High + High | 12 | 4 | 3 | 0 | 8 | 27 |
| 8 | High | 23 | 78 | 62 | 9 | 4 | 176 |
| 4 | Medium | 0 | 0 | 0 | 0 | 3 | 3 |

Share of in-play CVEs with at least one **potential-Critical** incident, per CVSS band: 9.0-10.0: 13/37 (35%); 7.0-8.9: 4/82 (5%); 4.0-6.9: 4/66 (6%); 0.1-3.9: 0/9 (0%); no CVSS: 8/15 (53%). The top band stands out; the middle bands do not differ — and the unscored band is the MCP STDIO cluster.

### Top potential band — IBSS_potential ≥ 16 (30 CVEs)

| CVE | CVSS | KEV | IBSS obs | IBSS pot | Incident : relation |
|---|---|---|---|---|---|
| [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) | 9.4 (v4.0) | **KEV** | 24 | 32 | DB-2026-001:self (malicious release); DR-2026-010:self (malicious release) |
| [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726) | 10 (v3.1) |  | 6 | 24 | DR-2026-036:self (vulnerability); DR-2026-057:self (vulnerability) |
| [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316) | 6 (v4.0) |  | 4 | 24 | DR-2026-056:self (vulnerability); DR-2026-062:self (vulnerability) |
| [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613) | 10 (v3.1) | **KEV** | 8 | 16 | DR-2026-008:attempted |
| [CVE-2026-12537](https://www.cve.org/CVERecord?id=CVE-2026-12537) | 10 (v4.0) |  | 2 | 16 | DR-2026-056:self (vulnerability) |
| [CVE-2026-21858](https://www.cve.org/CVERecord?id=CVE-2026-21858) | 10 (v3.1) |  | 8 | 16 | DR-2026-008:attempted |
| [CVE-2026-26015](https://www.cve.org/CVERecord?id=CVE-2026-26015) | 10 (v4.0) |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-28353](https://www.cve.org/CVERecord?id=CVE-2026-28353) | 10 (v4.0) |  | 8 | 16 | DR-2026-010:self (malicious release) |
| [CVE-2026-40933](https://www.cve.org/CVERecord?id=CVE-2026-40933) | 10 (v3.1) |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248) | 9.8 (v3.1) | **KEV** | 8 | 16 | DR-2026-011:exploited |
| [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198) | 9.8 (v3.1) | **KEV** | 8 | 16 | DR-2026-008:exploited |
| [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017) | 9.3 (v4.0) | **KEV** | 8 | 16 | DR-2026-008:exploited |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | 9.3 (v4.0) | **KEV** | 16 | 16 | DR-2026-020:exploited; DR-2026-023:exploited |
| [CVE-2026-50548](https://www.cve.org/CVERecord?id=CVE-2026-50548) | 9.3 (v4.0) |  | 2 | 16 | DR-2026-060:self (vulnerability) |
| [CVE-2026-50549](https://www.cve.org/CVERecord?id=CVE-2026-50549) | 9.3 (v4.0) |  | 2 | 16 | DR-2026-060:self (vulnerability) |
| [CVE-2026-54449](https://www.cve.org/CVERecord?id=CVE-2026-54449) | 8.8 (v3.1) |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-65617](https://www.cve.org/CVERecord?id=CVE-2026-65617) | 8.8 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2026-66014](https://www.cve.org/CVERecord?id=CVE-2026-66014) | 8.8 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2021-29441](https://www.cve.org/CVERecord?id=CVE-2021-29441) | 8.6 (v3.1) |  | 8 | 16 | DR-2026-011:attempted |
| [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923) | 6.8 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924) | 6.5 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925) | 6.5 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30615](https://www.cve.org/CVERecord?id=CVE-2026-30615) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30616](https://www.cve.org/CVERecord?id=CVE-2026-30616) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30617](https://www.cve.org/CVERecord?id=CVE-2026-30617) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30618](https://www.cve.org/CVERecord?id=CVE-2026-30618) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30624](https://www.cve.org/CVERecord?id=CVE-2026-30624) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-30625](https://www.cve.org/CVERecord?id=CVE-2026-30625) | — |  | 2 | 16 | DR-2026-059:self (vulnerability) |

### Disagreement: CVSS < 7.0 but potential Critical (4 CVEs)

Context outweighs the component score: chained or privileged use turned medium-rated vulnerabilities into critical potential.

| CVE | CVSS | KEV | IBSS obs | IBSS pot | Incident : relation |
|---|---|---|---|---|---|
| [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316) | 6 (v4.0) |  | 4 | 24 | DR-2026-056:self (vulnerability); DR-2026-062:self (vulnerability) |
| [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923) | 6.8 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924) | 6.5 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |
| [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925) | 6.5 (v3.1) |  | 8 | 16 | DB-2026-006:exploited-unconfirmed |

### Disagreement: CVSS ≥ 9.0 but potential ≤ Medium (0 CVEs)

none — every in-play CVE rated Critical by CVSS sits in an incident with potential High or Critical.

### Disclosed, not exploited: CVSS ≥ 9.0 but observed ≤ Low (8 CVEs)

These are mostly `self (vulnerability)` disclosures of AI-product vulnerabilities: severe on paper, no realized harm recorded — the gap the observed/potential split is designed to show.

| CVE | CVSS | KEV | IBSS obs | IBSS pot | Incident : relation |
|---|---|---|---|---|---|
| [CVE-2026-12537](https://www.cve.org/CVERecord?id=CVE-2026-12537) | 10 (v4.0) |  | 2 | 16 | DR-2026-056:self (vulnerability) |
| [CVE-2026-26015](https://www.cve.org/CVERecord?id=CVE-2026-26015) | 10 (v4.0) |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-40933](https://www.cve.org/CVERecord?id=CVE-2026-40933) | 10 (v3.1) |  | 2 | 16 | DR-2026-059:self (vulnerability) |
| [CVE-2026-50548](https://www.cve.org/CVERecord?id=CVE-2026-50548) | 9.3 (v4.0) |  | 2 | 16 | DR-2026-060:self (vulnerability) |
| [CVE-2026-50549](https://www.cve.org/CVERecord?id=CVE-2026-50549) | 9.3 (v4.0) |  | 2 | 16 | DR-2026-060:self (vulnerability) |
| [CVE-2026-25592](https://www.cve.org/CVERecord?id=CVE-2026-25592) | 10 (v3.1) |  | 1 | 8 | DR-2026-080:self (vulnerability) |
| [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) | 10 (v3.1) |  | 1 | 8 | DR-2026-080:self (vulnerability) |
| [CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711) | 9.3 (v3.1) |  | 1 | 8 | DR-2026-087:self (vulnerability) |

## Action list — patch · remove · watch

One row per identifier, derived from the relation vocabulary and the CNA CWE. **patch** = a vulnerability that was exploited, attempted, carried in an attacker's toolkit, or is the disclosed subject of an incident (`self (vulnerability)`); **remove** = a malicious release (`self (malicious release)`, CNA CWE-506, or a malware-type GHSA / MAL / PYSEC advisory) — purge the listed versions and rotate every credential they could reach; **watch** = KEV-listed CVEs recorded as `related` context of a campaign, not shown to be used in an incident. Version data comes from the cached upstream records (`vulnerabilities/upstream/`, 286 of 286 rows; records fetched 2026-08-29); CVSS is the CNA's, or the CISA-ADP score where the CNA gives none (`cvss_source`). Full table: `action_list.csv`.

### patch (213 CVEs; 55 shown, 158 of the AI-written aggregate corpus DR-2026-036 in the CSV only)

| ID | Evidence | Incidents | Max observed | KEV | CVSS | Product / package | Ecosystem | Affected versions | Fixed / unaffected |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248) | exploited | DR-2026-008<br>DR-2026-011 | High | **KEV** | 9.8 (v3.1) | langflow-ai/langflow |  | langflow-ai/langflow: < 1.3.0 | langflow-ai/langflow 1.3.0 |
| [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198) | exploited | DR-2026-008 | High | **KEV** | 9.8 (v3.1) | IBM/Langflow OSS |  | IBM/Langflow OSS: >= 1.0.0, <= 1.10.0 |  |
| [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017) | exploited | DR-2026-008 | High | **KEV** | 9.3 (v4.0) | langflow-ai/langflow |  | langflow-ai/langflow: < 1.9.0 | langflow-ai/langflow 1.9.0 |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | exploited | DR-2026-020<br>DR-2026-023 | High | **KEV** | 9.3 (v4.0) | marimo-team/marimo |  | marimo-team/marimo: < 0.23.0 | marimo-team/marimo 0.23.0 |
| [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613) | attempted | DR-2026-008 | High | **KEV** | 10 (v3.1) | n8n-io/n8n |  | n8n-io/n8n: >= 0.211.0, < 1.120.4; = 1.121.0 |  |
| [CVE-2017-7269](https://www.cve.org/CVERecord?id=CVE-2017-7269) | toolkit | DB-2026-018 | High | **KEV** | 9.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2021-3156](https://www.cve.org/CVERecord?id=CVE-2021-3156) | toolkit | DB-2026-018 | High | **KEV** | 7.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2021-4034](https://www.cve.org/CVERecord?id=CVE-2021-4034) | toolkit | DB-2026-018 | High | **KEV** | 7.8 (v3.1) (CISA-ADP) | n/a/polkit |  | polkit: all |  |
| [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431) | toolkit | DB-2026-018 | High | **KEV** | 7.8 (v3.1) | Linux/Linux |  | Linux/Linux: >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < 893d22e0135fa394db81df88697fba6032747667; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < 19d43105a97be0810edbda875f2cd03f30dc130c; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < 961cfa271a918ad4ae452420e7c303149002875b; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < 3115af9644c342b356f3f07a4dd1c8905cd9a6fc; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < 8b88d99341f139e23bdeb1027a2a3ae10d341d82; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < ce42ee423e58dffa5ec03524054c9d8bfd4f6237; >= 72548b093ee38a6d4f2a19e6ef1948ae05c181f7, < a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5 \| Linux/Linux: 4.14 | Linux/Linux 893d22e0135fa394db81df88697fba6032747667; Linux/Linux 19d43105a97be0810edbda875f2cd03f30dc130c; Linux/Linux 961cfa271a918ad4ae452420e7c303149002875b; Linux/Linux 3115af9644c342b356f3f07a4dd1c8905cd9a6fc; Linux/Linux 8b88d99341f139e23bdeb1027a2a3ae10d341d82; Linux/Linux fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8; Linux/Linux ce42ee423e58dffa5ec03524054c9d8bfd4f6237; Linux/Linux a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5; Linux/Linux 0; Linux/Linux 5.10.254; Linux/Linux 5.15.204; Linux/Linux 6.1.170; Linux/Linux 6.6.137; Linux/Linux 6.12.85; Linux/Linux 6.18.22; Linux/Linux 6.19.12; Linux/Linux 7.0 |
| [CVE-2026-65617](https://www.cve.org/CVERecord?id=CVE-2026-65617) | exploited-unconfirmed | DB-2026-006 | High |  | 8.8 (v3.1) | jfrog/artifactory |  | jfrog/artifactory: < 7.111.18; >= 7.117.0, < 7.117.25; >= 7.125.0, < 7.125.18; >= 7.133.0, < 7.133.27; >= 7.146.0, < 7.146.34; >= 7.161.0, < 7.161.15 | jfrog/artifactory 7.111.18; jfrog/artifactory 7.117.25; jfrog/artifactory 7.125.18; jfrog/artifactory 7.133.27; jfrog/artifactory 7.146.34; jfrog/artifactory 7.161.15 |
| [CVE-2026-66014](https://www.cve.org/CVERecord?id=CVE-2026-66014) | exploited-unconfirmed | DB-2026-006 | High |  | 8.8 (v3.1) | jfrog/artifactory |  | jfrog/artifactory: < 7.111.18; >= 7.117.0, < 7.117.25; >= 7.125.0, < 7.125.18; >= 7.133.0, < 7.133.27; >= 7.146.0, < 7.146.34; >= 7.161.0, < 7.161.15 | jfrog/artifactory 7.111.18; jfrog/artifactory 7.117.25; jfrog/artifactory 7.125.18; jfrog/artifactory 7.133.27; jfrog/artifactory 7.146.34; jfrog/artifactory 7.161.15 |
| [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923) | exploited-unconfirmed | DB-2026-006 | High |  | 6.8 (v3.1) | jfrog/artifactory |  | jfrog/artifactory: < 7.111.18; >= 7.117.0, < 7.117.25; >= 7.125.0, < 7.125.18; >= 7.133.0, < 7.133.27; >= 7.146.0, < 7.146.34; >= 7.161.0, < 7.161.15 | jfrog/artifactory 7.111.18; jfrog/artifactory 7.117.25; jfrog/artifactory 7.125.18; jfrog/artifactory 7.133.27; jfrog/artifactory 7.146.34; jfrog/artifactory 7.161.15 |
| [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924) | exploited-unconfirmed | DB-2026-006 | High |  | 6.5 (v3.1) | jfrog/artifactory |  | jfrog/artifactory: < 7.111.18; >= 7.117.0, < 7.117.25; >= 7.125.0, < 7.125.18; >= 7.133.0, < 7.133.27; >= 7.146.0, < 7.146.34; >= 7.161.0, < 7.161.15 | jfrog/artifactory 7.111.18; jfrog/artifactory 7.117.25; jfrog/artifactory 7.125.18; jfrog/artifactory 7.133.27; jfrog/artifactory 7.146.34; jfrog/artifactory 7.161.15 |
| [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925) | exploited-unconfirmed | DB-2026-006 | High |  | 6.5 (v3.1) | jfrog/artifactory |  | jfrog/artifactory: < 7.111.18; >= 7.117.0, < 7.117.25; >= 7.125.0, < 7.125.18; >= 7.133.0, < 7.133.27; >= 7.146.0, < 7.146.34; >= 7.161.0, < 7.161.15 | jfrog/artifactory 7.111.18; jfrog/artifactory 7.117.25; jfrog/artifactory 7.125.18; jfrog/artifactory 7.133.27; jfrog/artifactory 7.146.34; jfrog/artifactory 7.161.15 |
| [CVE-2026-21858](https://www.cve.org/CVERecord?id=CVE-2026-21858) | attempted | DR-2026-008 | High |  | 10 (v3.1) | n8n-io/n8n |  | n8n-io/n8n: >= 1.65.0, < 1.121.0 |  |
| [CVE-2021-29441](https://www.cve.org/CVERecord?id=CVE-2021-29441) | attempted | DR-2026-011 | High |  | 8.6 (v3.1) | alibaba/nacos |  | alibaba/nacos: < 1.4.1 | alibaba/nacos 1.4.1 |
| [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284) | toolkit | DB-2026-018 | High |  | 8.8 (v3.1) | Linux/Linux |  | Linux/Linux: >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < a6cb440f274a22456ef3e86b457344f1678f38f9; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < ab8b995323e5237041472d07e5055f5f7dcdf15b; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < fe785bb3a8096dffcc4048a85cd0c83337eeecad; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < 5d55c7336f8032d434adcc5fab987ccc93a44aec; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < 8253aab4659ca16116b522203c2a6b18dccacea7; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < 50ed1e7873100f77abad20fd31c51029bc49cd03; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < b54edf1e9a3fd3491bdcb82a21f8d21315271e0d; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < 71a1d9d985d26716f74d21f18ee8cac821b06e97; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < 52646cbd00e765a6db9c3afe9535f26218276034; >= cac2661c53f35cbe651bef9b07026a5a05ab8ce0, < f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4 \| Linux/Linux: 4.11 | Linux/Linux a6cb440f274a22456ef3e86b457344f1678f38f9; Linux/Linux ab8b995323e5237041472d07e5055f5f7dcdf15b; Linux/Linux fe785bb3a8096dffcc4048a85cd0c83337eeecad; Linux/Linux 5d55c7336f8032d434adcc5fab987ccc93a44aec; Linux/Linux 8253aab4659ca16116b522203c2a6b18dccacea7; Linux/Linux 50ed1e7873100f77abad20fd31c51029bc49cd03; Linux/Linux b54edf1e9a3fd3491bdcb82a21f8d21315271e0d; Linux/Linux 71a1d9d985d26716f74d21f18ee8cac821b06e97; Linux/Linux 52646cbd00e765a6db9c3afe9535f26218276034; Linux/Linux f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4; Linux/Linux 0; Linux/Linux 5.10.255; Linux/Linux 5.15.205; Linux/Linux 5.15.206; Linux/Linux 6.1.171; Linux/Linux 6.1.172; Linux/Linux 6.6.138; Linux/Linux 6.12.87; Linux/Linux 6.18.28; Linux/Linux 7.0.5; Linux/Linux 7.1 |
| [CVE-2026-43503](https://www.cve.org/CVERecord?id=CVE-2026-43503) | toolkit | DB-2026-018 | High |  | 8.8 (v3.1) | Linux/Linux |  | Linux/Linux: >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < fbeab9555564a1b98e8582cd106dfe46c4606991; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < 179f1852bdedc300e373e807cc102cd81feff196; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < 12401fcfb01f53ccc63ab0a3246570fe8f3105ee; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < 989214c66884d70716d83dc1d0bf5e16287bf349; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < fc6eb39c55e97df2f94ad974b8a5bbcd019da2c8; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < ff375cc75f9167168db38e0464a482d5fbc8d81d; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < 9bc9d6d6967a2239aa57af2aa53554eddd640d20; >= cef401de7be8c4e155c6746bfccf721a4fa5fab9, < 48f6a5356a33dd78e7144ae1faef95ffc990aae0 \| Linux/Linux: 3.9 | Linux/Linux fbeab9555564a1b98e8582cd106dfe46c4606991; Linux/Linux 179f1852bdedc300e373e807cc102cd81feff196; Linux/Linux 12401fcfb01f53ccc63ab0a3246570fe8f3105ee; Linux/Linux 989214c66884d70716d83dc1d0bf5e16287bf349; Linux/Linux fc6eb39c55e97df2f94ad974b8a5bbcd019da2c8; Linux/Linux ff375cc75f9167168db38e0464a482d5fbc8d81d; Linux/Linux 9bc9d6d6967a2239aa57af2aa53554eddd640d20; Linux/Linux 48f6a5356a33dd78e7144ae1faef95ffc990aae0; Linux/Linux 0; Linux/Linux 5.10.257; Linux/Linux 5.15.208; Linux/Linux 6.1.174; Linux/Linux 6.6.141; Linux/Linux 6.12.91; Linux/Linux 6.18.33; Linux/Linux 7.0.10; Linux/Linux 7.1 |
| [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500) | toolkit | DB-2026-018 | High |  | 7.8 (v3.1) | Linux/Linux |  | Linux/Linux: >= d0d5c0cd1e711c98703f3544c1e6fc1372898de5, < 7c504ffab3efce8f7e4f463b314ae31030bdf18b; >= d0d5c0cd1e711c98703f3544c1e6fc1372898de5, < 3711382a77342a9a1c3d2e7330dcfc7ea927f568; >= d0d5c0cd1e711c98703f3544c1e6fc1372898de5, < 3eae0f4f9f7206a4801efa5e0235c25bbd5a412c; >= d0d5c0cd1e711c98703f3544c1e6fc1372898de5, < d45179f8795222ce858770dc619abe51f9d24411; >= d0d5c0cd1e711c98703f3544c1e6fc1372898de5, < aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71 \| Linux/Linux: 5.3 | Linux/Linux 7c504ffab3efce8f7e4f463b314ae31030bdf18b; Linux/Linux 3711382a77342a9a1c3d2e7330dcfc7ea927f568; Linux/Linux 3eae0f4f9f7206a4801efa5e0235c25bbd5a412c; Linux/Linux d45179f8795222ce858770dc619abe51f9d24411; Linux/Linux aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71; Linux/Linux 0; Linux/Linux 6.6.140; Linux/Linux 6.12.88; Linux/Linux 6.18.29; Linux/Linux 7.0.6; Linux/Linux 7.1 |
| [CVE-2026-12537](https://www.cve.org/CVERecord?id=CVE-2026-12537) | self (vulnerability) | DR-2026-056 | Low |  | 10 (v4.0) | Google Cloud/Gemini CLI; Google Cloud/run-gemini-cli GitHub Action |  | Google Cloud/Gemini CLI: < 0.39.1 \| Google Cloud/run-gemini-cli GitHub Action: < 0.1.22 | Google Cloud/Gemini CLI 0.39.1; Google Cloud/run-gemini-cli GitHub Action 0.1.22 |
| [CVE-2026-25592](https://www.cve.org/CVERecord?id=CVE-2026-25592) | self (vulnerability) | DR-2026-080 | Negligible |  | 10 (v3.1) | microsoft/semantic-kernel |  | microsoft/semantic-kernel: < 1.71.0 | microsoft/semantic-kernel 1.71.0 |
| [CVE-2026-26015](https://www.cve.org/CVERecord?id=CVE-2026-26015) | self (vulnerability) | DR-2026-059 | Low |  | 10 (v4.0) | arc53/DocsGPT |  | arc53/DocsGPT: >= 0.15.0, < 0.16.0 |  |
| [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) | self (vulnerability) | DR-2026-080 | Negligible |  | 10 (v3.1) | microsoft/semantic-kernel |  | microsoft/semantic-kernel: < 1.39.4 | microsoft/semantic-kernel 1.39.4 |
| [CVE-2026-40933](https://www.cve.org/CVERecord?id=CVE-2026-40933) | self (vulnerability) | DR-2026-059 | Low |  | 10 (v3.1) | FlowiseAI/Flowise; FlowiseAI/flowise-components |  | FlowiseAI/Flowise: < 3.1.0 \| FlowiseAI/flowise-components: < 3.1.0 | FlowiseAI/Flowise 3.1.0; FlowiseAI/flowise-components 3.1.0 |
| [CVE-2026-54769](https://www.cve.org/CVERecord?id=CVE-2026-54769) | self (vulnerability) | DR-2026-036<br>DR-2026-057 | Medium |  | 10 (v3.1) | langroid/langroid |  | langroid/langroid: < 0.65.2 | langroid/langroid 0.65.2 |
| [CVE-2026-59726](https://www.cve.org/CVERecord?id=CVE-2026-59726) | self (vulnerability) | DR-2026-036<br>DR-2026-057 | Medium |  | 10 (v3.1) | ruvnet/ruflo |  | ruvnet/ruflo: < 3.16.3 | ruvnet/ruflo 3.16.3 |
| [CVE-2025-65720](https://www.cve.org/CVERecord?id=CVE-2025-65720) | self (vulnerability) | DR-2026-059<br>DR-2026-080 | Low |  | 9.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-30618](https://www.cve.org/CVERecord?id=CVE-2026-30618) | self (vulnerability) | DR-2026-059 | Low |  | 9.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-30623](https://www.cve.org/CVERecord?id=CVE-2026-30623) | self (vulnerability) | DR-2026-059<br>DR-2026-080 | Low |  | 9.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-30625](https://www.cve.org/CVERecord?id=CVE-2026-30625) | self (vulnerability) | DR-2026-059 | Low |  | 9.8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711) | self (vulnerability) | DR-2026-087 | Negligible |  | 9.3 (v3.1) | Microsoft/Microsoft 365 Copilot |  | Microsoft/Microsoft 365 Copilot: - |  |
| [CVE-2026-50548](https://www.cve.org/CVERecord?id=CVE-2026-50548) | self (vulnerability) | DR-2026-060 | Low |  | 9.3 (v4.0) | cursor/cursor |  | cursor/cursor: < 3.0 | cursor/cursor 3.0 |
| [CVE-2026-50549](https://www.cve.org/CVERecord?id=CVE-2026-50549) | self (vulnerability) | DR-2026-060 | Low |  | 9.3 (v4.0) | cursor/cursor |  | cursor/cursor: < 3.0 | cursor/cursor 3.0 |
| [CVE-2026-24301](https://www.cve.org/CVERecord?id=CVE-2026-24301) | self (vulnerability) | DR-2026-083 | Negligible |  | 8.8 (v3.1) | Microsoft/Copilot Web |  | Microsoft/Copilot Web: - |  |
| [CVE-2026-25253](https://www.cve.org/CVERecord?id=CVE-2026-25253) | self (vulnerability) | DR-2026-039 | Medium |  | 8.8 (v3.1) | OpenClaw/OpenClaw |  | OpenClaw/OpenClaw: < 2026.1.29 | OpenClaw/OpenClaw 2026.1.29 |
| [CVE-2026-54449](https://www.cve.org/CVERecord?id=CVE-2026-54449) | self (vulnerability) | DR-2026-059 | Low |  | 8.8 (v3.1) | langbot-app/LangBot |  | langbot-app/LangBot: <= 4.10.7 |  |
| [CVE-2026-7482](https://www.cve.org/CVERecord?id=CVE-2026-7482) | self (vulnerability) | DR-2026-037 | Medium |  | 8.8 (v4.0) | ollama/ollama | GitHub | ollama/ollama: < 0.17.1 | ollama/ollama 0.17.1 |
| [CVE-2025-59536](https://www.cve.org/CVERecord?id=CVE-2025-59536) | self (vulnerability) | DR-2026-062 | Low |  | 8.7 (v4.0) | anthropics/claude-code |  | anthropics/claude-code: < 1.0.111 | anthropics/claude-code 1.0.111 |
| [CVE-2026-30617](https://www.cve.org/CVERecord?id=CVE-2026-30617) | self (vulnerability) | DR-2026-059 | Low |  | 8.6 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-30624](https://www.cve.org/CVERecord?id=CVE-2026-30624) | self (vulnerability) | DR-2026-059 | Low |  | 8.6 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-48124](https://www.cve.org/CVERecord?id=CVE-2026-48124) | self (vulnerability) | DR-2026-089 | Negligible |  | 8.5 (v4.0) | cursor/cursor |  | cursor/cursor: < 3.0.0 | cursor/cursor 3.0.0 |
| [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472) | self (vulnerability) | DR-2026-036<br>DR-2026-039 | Medium |  | 8.1 (v3.1) | OpenClaw/OpenClaw |  | OpenClaw/OpenClaw: < 2026.2.2 | OpenClaw/OpenClaw 2026.2.2 |
| [CVE-2026-30615](https://www.cve.org/CVERecord?id=CVE-2026-30615) | self (vulnerability) | DR-2026-059 | Low |  | 8 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-24887](https://www.cve.org/CVERecord?id=CVE-2026-24887) | self (vulnerability) | DR-2026-062 | Low |  | 7.7 (v4.0) | anthropics/claude-code |  | anthropics/claude-code: < 2.0.72 | anthropics/claude-code 2.0.72 |
| [CVE-2026-39861](https://www.cve.org/CVERecord?id=CVE-2026-39861) | self (vulnerability) | DR-2026-062 | Low |  | 7.7 (v4.0) | anthropics/claude-code |  | anthropics/claude-code: < 2.1.64 | anthropics/claude-code 2.1.64 |
| [CVE-2026-73217](https://www.cve.org/CVERecord?id=CVE-2026-73217) | self (vulnerability) | DR-2026-089 | Negligible |  | 7.7 (v4.0) | cursor/cursor |  | cursor/cursor: < 3.1.2 | cursor/cursor 3.1.2 |
| [CVE-2026-73218](https://www.cve.org/CVERecord?id=CVE-2026-73218) | self (vulnerability) | DR-2026-089 | Negligible |  | 7.7 (v4.0) | cursor/cursor |  | cursor/cursor: < 3.0.0 | cursor/cursor 3.0.0 |
| [CVE-2026-26144](https://www.cve.org/CVERecord?id=CVE-2026-26144) | self (vulnerability) | DR-2026-087 | Negligible |  | 7.5 (v3.1) | Microsoft/Microsoft 365 Apps for Enterprise |  | Microsoft/Microsoft 365 Apps for Enterprise: >= 16.0.1, < https://aka.ms/OfficeSecurityReleases | Microsoft/Microsoft 365 Apps for Enterprise https://aka.ms/OfficeSecurityReleases |
| [CVE-2026-6784](https://www.cve.org/CVERecord?id=CVE-2026-6784) | self (vulnerability) | DR-2026-095 | Negligible |  | 7.5 (v3.1) (CISA-ADP) | Mozilla/Firefox; Mozilla/Thunderbird |  | Mozilla/Firefox: versions not specified \| Mozilla/Thunderbird: versions not specified | Mozilla/Firefox 150; Mozilla/Thunderbird 150 |
| [CVE-2026-6785](https://www.cve.org/CVERecord?id=CVE-2026-6785) | self (vulnerability) | DR-2026-095 | Negligible |  | 7.5 (v3.1) (CISA-ADP) | Mozilla/Firefox; Mozilla/Thunderbird |  | Mozilla/Firefox: versions not specified \| Mozilla/Thunderbird: versions not specified | Mozilla/Firefox 115.35; Mozilla/Firefox 140.10; Mozilla/Firefox 150; Mozilla/Thunderbird 140.10; Mozilla/Thunderbird 150 |
| [CVE-2026-6786](https://www.cve.org/CVERecord?id=CVE-2026-6786) | self (vulnerability) | DR-2026-095 | Negligible |  | 7.5 (v3.1) (CISA-ADP) | Mozilla/Firefox; Mozilla/Thunderbird |  | Mozilla/Firefox: versions not specified \| Mozilla/Thunderbird: versions not specified | Mozilla/Firefox 140.10; Mozilla/Firefox 150; Mozilla/Thunderbird 140.10; Mozilla/Thunderbird 150 |
| [CVE-2026-30616](https://www.cve.org/CVERecord?id=CVE-2026-30616) | self (vulnerability) | DR-2026-059 | Low |  | 7.3 (v3.1) (CISA-ADP) | n/a/n/a |  | not structured in the CVE record |  |
| [CVE-2026-42824](https://www.cve.org/CVERecord?id=CVE-2026-42824) | self (vulnerability) | DR-2026-081 | Negligible |  | 6.5 (v3.1) | Microsoft/Microsoft 365 Copilot |  | Microsoft/Microsoft 365 Copilot: - |  |
| [CVE-2026-54316](https://www.cve.org/CVERecord?id=CVE-2026-54316) | self (vulnerability) | DR-2026-056<br>DR-2026-062 | Low |  | 6 (v4.0) | anthropics/claude-code |  | anthropics/claude-code: >= 0.2.54, < 2.1.163 |  |
| [CVE-2026-21852](https://www.cve.org/CVERecord?id=CVE-2026-21852) | self (vulnerability) | DR-2026-062 | Low |  | 5.3 (v4.0) | anthropics/claude-code |  | anthropics/claude-code: < 2.0.65 | anthropics/claude-code 2.0.65 |

### remove — 5 CVEs and 48 malicious package releases (63 GHSA / MAL / PYSEC advisories, grouped by package; one row per advisory in the CSV)

Purge the listed versions, rotate every credential the package could reach (cloud keys, CI tokens, SSH keys), and hunt for the persistence it planted.

| ID | Evidence | Incidents | Max observed | KEV | CVSS | Product / package | Ecosystem | Affected versions | Fixed / unaffected |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-45321](https://www.cve.org/CVERecord?id=CVE-2026-45321) | self (malicious release) | DR-2026-022 | High | **KEV** | 9.6 (v3.1) | @tanstack/arktype-adapter; @tanstack/eslint-plugin-router; @tanstack/eslint-plugin-start; @tanstack/history; @tanstack/nitro-v2-vite-plugin; @tanstack/outer-vite-plugin; @tanstack/react-router; @tanst |  | @tanstack/arktype-adapter: 1.166.12; 1.166.15 \| @tanstack/eslint-plugin-router: 1.161.9; 1.161.12 \| @tanstack/eslint-plugin-start: 0.0.4; 0.0.7 \| @tanstack/history: 1.161.9; 1.161.12 \| @tanstack/nitro-v2-vite-plugin: 1.154.12; 1.154.15 \| @tanstack/react-router: 1.169.5; 1.169.8 \| @tanstack/react-router-devtools: 1.166.16; 1.166.19 \| @tanstack/react-router-ssr-query: 1.166.15; 1.166.18 \| @tanstack/react-start: 1.167.68; 1.167.71 \| @tanstack/react-start-client: 1.166.51; 1.166.54 \| @tanstack/react-start-rsc: 0.0.47; 0.0.50 \| @tanstack/react-start-server: 1.166.55; 1.166.58 \| @tanstack/router-cli: 1.166.46; 1.166.49 \| @tanstack/router-core: 1.169.5; 1.169.8 \| @tanstack/router-devtools: 1.166.16; 1.166.19 \| @tanstack/router-devtools-core: 1.167.6; 1.167.9 \| @tanstack/router-generator: 1.166.45; 1.166.48 \| @tanstack/router-plugin: 1.167.38; 1.167.41 \| @tanstack/router-ssr-query-core: 1.168.3; 1.168.6 \| @tanstack/router-utils: 1.161.11; 1.161.14 \| @tanstack/outer-vite-plugin: 1.166.53; 1.166.56 \| @tanstack/solid-router: 1.169.5; 1.169.8 \| @tanstack/solid-router-devtools: 1.166.16; 1.166.19 \| @tanstack/solid-router-ssr-query: 1.166.15; 1.166.18 \| @tanstack/solid-start: 1.167.65; 1.167.68 \| @tanstack/solid-start-client: 1.166.50; 1.166.53 \| @tanstack/solid-start-server: 1.166.54; 1.166.57 \| @tanstack/start-client-core: 1.168.5; 1.168.8 \| @tanstack/start-fn-stubs: 1.161.9; 1.161.12 \| @tanstack/start-plugin-core: 1.169.23; 1.169.26 \| @tanstack/start-server-core: 1.167.33; 1.167.36 \| @tanstack/start-static-server-functions: 1.166.44; 1.166.47 \| @tanstack/start-storage-context: 1.166.38; 1.166.41 \| @tanstack/valibot-adapter: 1.166.12; 1.166.15 \| @tanstack/virtual-file-routes: 1.161.10; 1.161.13 \| @tanstack/vue-router: 1.169.5; 1.169.8 \| @tanstack/vue-router-devtools: 1.166.16; 1.166.19 \| @tanstack/vue-router-ssr-query: 1.166.15; 1.166.18 \| @tanstack/vue-start: 1.167.61; 1.167.64 \| @tanstack/vue-start-client: 1.166.46; 1.166.49 \| @tanstack/vue-start-server: 1.166.50; 1.166.53 \| @tanstack/zod-adapter: 1.166.12; 1.166.15 |  |
| [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) | self (malicious release) | DB-2026-001<br>DR-2026-010 | Critical | **KEV** | 9.4 (v4.0) | BerriAI/LiteLLM; aquasecurity/setup-trivy; aquasecurity/trivy; aquasecurity/trivy-action; team-telnyx/telnyx |  | aquasecurity/setup-trivy: < 0.2.6 \| aquasecurity/trivy-action: < 0.35.0 \| aquasecurity/trivy: = 0.69.4 \| BerriAI/LiteLLM: >= 1.82.7, <= 1.82.8 \| team-telnyx/telnyx: >= 4.87.1, <= 4.87.2 | aquasecurity/setup-trivy 0.2.6; aquasecurity/trivy-action 0.35.0 |
| [CVE-2026-28353](https://www.cve.org/CVERecord?id=CVE-2026-28353) | self (malicious release) | DR-2026-010 | High |  | 10 (v4.0) | aquasecurity/trivy-vscode-extension |  | aquasecurity/trivy-vscode-extension: = 1.8.12 |  |
| [CVE-2026-34841](https://www.cve.org/CVERecord?id=CVE-2026-34841) | related | DR-2026-025 | Medium |  | 9.8 (v3.1) | usebruno/bruno |  | usebruno/bruno: < 3.2.1 | usebruno/bruno 3.2.1 |
| [CVE-2026-45758](https://www.cve.org/CVERecord?id=CVE-2026-45758) | related | DR-2026-022 | High |  | 9.6 (v3.1) | guardrails-ai/guardrails |  | guardrails-ai/guardrails: = 0.10.1 |  |

| Package | Ecosystem | Malicious versions | Advisories | Incidents | Max observed |
|---|---|---|---|---|---|
| litellm | PyPI | 1.82.7, 1.82.8 | GHSA-92x9-889m-jgmw, MAL-2026-2144, PYSEC-2026-2 | DB-2026-001 | Critical |
| telnyx | PyPI | 4.87.1, 4.87.2 | MAL-2026-2254 | DB-2026-001 | Critical |
| @cacheable/memory | npm | 2.2.1 | GHSA-583f-9h76-9fx2 | DR-2026-012 | High |
| @cacheable/node-cache | npm | 3.1.2 | GHSA-7pv9-q9wh-jqc3 | DR-2026-012 | High |
| @keyv/compress-gzip | npm | 6.0.0 | GHSA-c7r2-p8ff-5ffp | DR-2026-012 | High |
| @keyv/mongo | npm | 6.0.0 | GHSA-h8h5-wqhj-grm7 | DR-2026-012 | High |
| @keyv/postgres | npm | 6.0.0 | GHSA-cgpm-wvpq-73p3 | DR-2026-012 | High |
| @keyv/redis | npm | 6.0.0 | GHSA-q99r-cjmf-3xrf | DR-2026-012 | High |
| @keyv/sqlite | npm | 6.0.0 | GHSA-4wfp-qcf3-mgqp | DR-2026-012 | High |
| @mistralai/mistralai | npm | 2.2.2, 2.2.3, 2.2.4 | MAL-2026-3432 | DR-2026-022 | High |
| @opensearch-project/opensearch | npm | 3.5.3, 3.6.2, 3.7.0, 3.8.0 | GHSA-298w-vvm4-ww55 | DR-2026-022 | High |
| @uipath/agent.sdk | npm | 0.0.18 | GHSA-9hfm-w6gw-qc7c | DR-2026-022 | High |
| @uipath/apollo-core | npm | 5.9.2 | GHSA-j36c-8r88-423c | DR-2026-022 | High |
| @uipath/cli | npm | 1.0.1 | GHSA-r62p-98fh-6qv4 | DR-2026-022 | High |
| @uipath/robot | npm | 1.3.4 | GHSA-cx9h-9vrc-7393 | DR-2026-022 | High |
| cache-manager | npm | 7.2.10 | GHSA-p7m5-96hg-gppj | DR-2026-012 | High |
| cacheable | npm | 2.5.1 | GHSA-jpjx-r3gh-v5pf, MAL-2026-11963 | DR-2026-012 | High |
| cacheable-request | npm | 13.0.20 | GHSA-mxgw-gq2g-4fq9 | DR-2026-012 | High |
| durabletask | PyPI | 1.4.1, 1.4.2, 1.4.3 | GHSA-3qf7-886j-9wrc, MAL-2026-4174, PYSEC-2026-207 | DB-2026-005 | High |
| file-entry-cache | npm | 11.1.6 | GHSA-qp89-2g43-jg8j | DR-2026-012 | High |
| flat-cache | npm | 6.1.24 | GHSA-8jxr-wprf-45g8 | DR-2026-012 | High |
| keyv | npm | 6.0.0 | GHSA-3p9h-f68w-m6fx, MAL-2026-11524 | DR-2026-012 | High |
| mistralai | PyPI | 2.4.6 | MAL-2026-3608 | DR-2026-022 | High |
| @redhat-cloud-services/chrome | npm | 2.3.1, 2.3.2, 2.3.4 | GHSA-942v-f47r-w9c3 | DR-2026-046 | Medium |
| @redhat-cloud-services/compliance-client | npm | 4.0.3, 4.0.4, 4.0.6 | GHSA-x4x7-xp58-wjrh | DR-2026-046 | Medium |
| @redhat-cloud-services/entitlements-client | npm | 4.0.12, 4.0.14 | GHSA-28hc-2275-h287 | DR-2026-046 | Medium |
| @redhat-cloud-services/eslint-config-redhat-cloud-services | npm | 3.2.1 | GHSA-c3mv-fjj4-2542 | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components | npm | 7.7.2 | GHSA-mrgj-mcjh-5mf2 | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-advisor-components | npm | 3.8.2, 3.8.4, 3.8.6 | GHSA-873j-vjwp-88w8 | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-config | npm | 6.11.3, 6.11.4, 6.11.6 | GHSA-h43w-g623-gfmv, GHSA-r28x-h6v7-8rjj | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-config-utilities | npm | 4.11.2, 4.11.3, 4.11.5 | GHSA-cxfw-p322-rfrv | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-notifications | npm | 6.9.2, 6.9.3, 6.9.5 | GHSA-ghcf-x8cx-89q8, GHSA-vvm2-35w3-pp39 | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-remediations | npm | 4.9.3, 4.9.5 | GHSA-4rjr-7qhx-vjwg | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-translations | npm | 4.4.1, 4.4.2, 4.4.4 | GHSA-h5c9-cj46-7p79 | DR-2026-046 | Medium |
| @redhat-cloud-services/frontend-components-utilities | npm | 7.4.1, 7.4.2, 7.4.4 | GHSA-r9mp-ff22-jhrr | DR-2026-046 | Medium |
| @redhat-cloud-services/host-inventory-client | npm | 5.0.3, 5.0.4, 5.0.6 | GHSA-4hcm-2c2r-2rhm | DR-2026-046 | Medium |
| @redhat-cloud-services/javascript-clients-shared | npm | 2.0.8, 2.0.9, 2.0.11 | GHSA-wfwj-j63c-gg6h | DR-2026-046 | Medium |
| @redhat-cloud-services/rbac-client | npm | 9.0.3, 9.0.4, 9.0.6 | GHSA-2p99-xvqh-j893 | DR-2026-046 | Medium |
| @redhat-cloud-services/sources-client | npm | 3.0.11, 3.0.13 | GHSA-vp9c-9mjm-2f7w | DR-2026-046 | Medium |
| @redhat-cloud-services/tsc-transform-imports | npm | 1.2.2, 1.2.4, 1.2.6 | GHSA-4p47-xv4r-786w, GHSA-8gf7-gc4w-pwh7 | DR-2026-046 | Medium |
| @redhat-cloud-services/types | npm | 3.6.1, 3.6.2, 3.6.4 | GHSA-4qj4-x996-qvgw, GHSA-8xj2-9c64-m64h | DR-2026-046 | Medium |
| @redhat-cloud-services/vulnerabilities-client | npm | 2.1.8, 2.1.9, 2.1.11 | GHSA-p4vp-xg44-93v7 | DR-2026-046 | Medium |
| @vapi-ai/server-sdk | npm | 0.11.1, 0.11.2, 1.2.1, 1.2.2 | GHSA-8m2w-rq7p-jw7q, MAL-2026-5209 | DR-2026-046 | Medium |
| ai-sdk-ollama | npm | 0.13.1, 1.1.1, 2.2.1, 3.8.5 | GHSA-m9j7-x8ww-5jwr, MAL-2026-5210 | DR-2026-046 | Medium |
| axios | npm | 0.30.4, 1.14.1 | GHSA-fw8c-xr5c-95f9, MAL-2026-2307 | DR-2026-025 | Medium |
| cline | npm | 2.3.0 | MAL-2026-1380 | DR-2026-035 | Medium |
| node-ipc | npm | 9.1.6, 9.2.3, 12.0.1 | GHSA-pvh2-rg5g-69v7, MAL-2026-3744 | DR-2026-045 | Medium |
| plain-crypto-js | npm | 0.0.1-security, 4.2.0, 4.2.1, >= 0 | GHSA-2x9r-6wxq-hrr7, MAL-2026-2306 | DR-2026-025 | Medium |

### watch (5 KEV CVEs related to a campaign)

| ID | Evidence | Incidents | Max observed | KEV | CVSS | Product / package | Ecosystem | Affected versions | Fixed / unaffected |
|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-0770](https://www.cve.org/CVERecord?id=CVE-2026-0770) | related | DR-2026-008 | High | **KEV** | 9.8 (v3.0) | Langflow/Langflow |  | Langflow/Langflow: 1.4.2 |  |
| [CVE-2025-34291](https://www.cve.org/CVERecord?id=CVE-2025-34291) | related | DR-2026-008 | High | **KEV** | 9.4 (v4.0) | Langflow/Langflow |  | Langflow/Langflow: <= 1.6.9 |  |
| [CVE-2026-42208](https://www.cve.org/CVERecord?id=CVE-2026-42208) | related | DR-2026-057 | Low | **KEV** | 9.3 (v4.0) | BerriAI/litellm |  | BerriAI/litellm: >= 1.81.16, < 1.83.7 |  |
| [CVE-2026-42271](https://www.cve.org/CVERecord?id=CVE-2026-42271) | related | DR-2026-059 | Low | **KEV** | 8.7 (v4.0) | BerriAI/litellm |  | BerriAI/litellm: >= 1.74.2, < 1.83.7 |  |
| [CVE-2026-55255](https://www.cve.org/CVERecord?id=CVE-2026-55255) | related | DR-2026-008 | High | **KEV** | 8.4 (v3.1) | langflow-ai/langflow |  | langflow-ai/langflow: < 1.9.1 | langflow-ai/langflow 1.9.1 |

## KEV CVEs in this corpus (16)

Every CVE in the corpus that is on CISA's Known Exploited Vulnerabilities catalogue, whatever its relation — KEV means exploited *somewhere*, not necessarily in these incidents (§6.4). The `action` column links each to the action list above.

| CVE | Action | KEV added | Incident : relation | CVSS | Product | CNA CWE | Title |
|---|---|---|---|---|---|---|---|
| [CVE-2017-7269](https://www.cve.org/CVERecord?id=CVE-2017-7269) | patch | 2021-11-03 | DB-2026-018:toolkit |  | n/a/n/a |  |  |
| [CVE-2021-3156](https://www.cve.org/CVERecord?id=CVE-2021-3156) | patch | 2022-04-06 | DB-2026-018:toolkit |  | n/a/n/a |  |  |
| [CVE-2021-4034](https://www.cve.org/CVERecord?id=CVE-2021-4034) | patch | 2022-06-27 | DB-2026-018:toolkit |  | n/a/polkit | CWE-787 |  |
| [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248) | patch | 2025-05-05 | DR-2026-008:related<br>DR-2026-011:exploited | 9.8 (v3.1) | langflow-ai/langflow | CWE-306 | Langflow < 1.3.0 Unauthenticated RCE via /api/v1/validate/code |
| [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613) | patch | 2026-03-11 | DR-2026-008:attempted | 10 (v3.1) | n8n-io/n8n | CWE-913 | n8n Vulnerable to Remote Code Execution via Expression Injection |
| [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017) | patch | 2026-03-25 | DR-2026-008:exploited | 9.3 (v4.0) | langflow-ai/langflow | CWE-94, CWE-95, CWE-306 | Langflow has Unauthenticated Remote Code Execution via Public Flow Build Endpoint |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | patch | 2026-04-23 | DR-2026-020:exploited<br>DR-2026-023:exploited | 9.3 (v4.0) | marimo-team/marimo | CWE-306 | marimo Affected by Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass |
| [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431) | patch | 2026-05-01 | DB-2026-018:toolkit | 7.8 (v3.1) | Linux/Linux |  | crypto: algif_aead - Revert to operating out-of-place |
| [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198) | patch | 2026-08-04 | DR-2026-008:exploited | 9.8 (v3.1) | IBM/Langflow OSS | CWE-94 | Unauthenticated Remote Code Execution via Auto-Login Bypass and Code Validation |
| [CVE-2026-33634](https://www.cve.org/CVERecord?id=CVE-2026-33634) | remove | 2026-03-26 | DB-2026-001:self (malicious release)<br>DR-2026-010:self (malicious release) | 9.4 (v4.0) | BerriAI/LiteLLM; aquasecurity/setup-trivy; aquasecurity/trivy; aquasecurity/trivy-action; team-telnyx/telnyx | CWE-506 | Trivy ecosystem supply chain briefly compromised |
| [CVE-2026-45321](https://www.cve.org/CVERecord?id=CVE-2026-45321) | remove | 2026-05-27 | DR-2026-022:self (malicious release) | 9.6 (v3.1) | @tanstack/arktype-adapter; @tanstack/eslint-plugin-router; @tanstack/eslint-plugin-start; @tanstack/history; @tanstack/nitro-v2-vite-plugin; @tanstack/outer-vite-plugin; @tanstack/react-router; @tanst | CWE-506 | Malware in 42 @tanstack/* packages exfiltrates cloud credentials, GitHub tokens, and SSH keys |
| [CVE-2026-42208](https://www.cve.org/CVERecord?id=CVE-2026-42208) | watch | 2026-05-08 | DR-2026-057:related | 9.3 (v4.0) | BerriAI/litellm | CWE-89 | LiteLLM: SQL injection in Proxy API key verification |
| [CVE-2025-34291](https://www.cve.org/CVERecord?id=CVE-2025-34291) | watch | 2026-05-21 | DR-2026-008:related | 9.4 (v4.0) | Langflow/Langflow | CWE-346 | Langflow <= 1.6.9 CORS Misconfiguration to Token Hijack & RCE |
| [CVE-2026-42271](https://www.cve.org/CVERecord?id=CVE-2026-42271) | watch | 2026-06-08 | DR-2026-059:related | 8.7 (v4.0) | BerriAI/litellm | CWE-77, CWE-78 | LiteLLM: Authenticated command execution via MCP stdio test endpoints |
| [CVE-2026-55255](https://www.cve.org/CVERecord?id=CVE-2026-55255) | watch | 2026-07-07 | DR-2026-008:related | 8.4 (v3.1) | langflow-ai/langflow | CWE-639 | Langflow: IDOR Vulnerability in `/api/v1/responses` Endpoint Allows Authenticated Attackers to Access Another User's Flow |
| [CVE-2026-0770](https://www.cve.org/CVERecord?id=CVE-2026-0770) | watch | 2026-07-21 | DR-2026-008:related | 9.8 (v3.0) | Langflow/Langflow | CWE-829 | Langflow exec_globals Inclusion of Functionality from Untrusted Control Sphere Remote Code Execution Vulnerability |

## Exploited-family CVEs — used, attempted or carried by AI-enabled attackers (20 links, 19 distinct CVEs)

Relation `exploited` / `exploited-unconfirmed` = the CVE was (probably) the way in; `attempted` = tried, not confirmed successful; `toolkit` = an exploit was present in the attacker's recovered tooling. `lag` = days from CVE publication to the incident date (only where the incident date is a full ISO date; negative = the incident predates the CVE's publication — zero-day use where the relation is confirmed, otherwise unconfirmed).

| CVE | Relation | Incident | Observed | Published | Lag (d) | CVSS | KEV | Product | CNA CWE | Title |
|---|---|---|---|---|---|---|---|---|---|---|
| [CVE-2026-9198](https://www.cve.org/CVERecord?id=CVE-2026-9198) | exploited | DR-2026-008 | High | 2026-07-17 |  | 9.8 (v3.1) | **KEV** | IBM/Langflow OSS | CWE-94 | Unauthenticated Remote Code Execution via Auto-Login Bypass and Code Validation |
| [CVE-2026-33017](https://www.cve.org/CVERecord?id=CVE-2026-33017) | exploited | DR-2026-008 | High | 2026-03-20 |  | 9.3 (v4.0) | **KEV** | langflow-ai/langflow | CWE-94, CWE-95, CWE-306 | Langflow has Unauthenticated Remote Code Execution via Public Flow Build Endpoint |
| [CVE-2025-3248](https://www.cve.org/CVERecord?id=CVE-2025-3248) | exploited | DR-2026-011 | High | 2025-04-07 |  | 9.8 (v3.1) | **KEV** | langflow-ai/langflow | CWE-306 | Langflow < 1.3.0 Unauthenticated RCE via /api/v1/validate/code |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | exploited | DR-2026-020 | High | 2026-04-09 |  | 9.3 (v4.0) | **KEV** | marimo-team/marimo | CWE-306 | marimo Affected by Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass |
| [CVE-2026-39987](https://www.cve.org/CVERecord?id=CVE-2026-39987) | exploited | DR-2026-023 | High | 2026-04-09 |  | 9.3 (v4.0) | **KEV** | marimo-team/marimo | CWE-306 | marimo Affected by Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass |
| [CVE-2026-65617](https://www.cve.org/CVERecord?id=CVE-2026-65617) | exploited-unconfirmed | DB-2026-006 | High | 2026-07-27 | -18 | 8.8 (v3.1) |  | jfrog/artifactory | CWE-502 | Potential remote code execution on an Artifactory package service container. |
| [CVE-2026-65923](https://www.cve.org/CVERecord?id=CVE-2026-65923) | exploited-unconfirmed | DB-2026-006 | High | 2026-07-27 | -18 | 6.8 (v3.1) |  | jfrog/artifactory | CWE-918 | Potential server-side request forgery in Artifactory Ansible repository handling |
| [CVE-2026-65924](https://www.cve.org/CVERecord?id=CVE-2026-65924) | exploited-unconfirmed | DB-2026-006 | High | 2026-07-27 | -18 | 6.5 (v3.1) |  | jfrog/artifactory | CWE-918 | Server-Side Request Forgery (SSRF) via Terraform Remote repository |
| [CVE-2026-65925](https://www.cve.org/CVERecord?id=CVE-2026-65925) | exploited-unconfirmed | DB-2026-006 | High | 2026-07-27 | -18 | 6.5 (v3.1) |  | jfrog/artifactory | CWE-918 | Server-Side Request Forgery (SSRF) via JFrog Artifactory Cargo remote repository |
| [CVE-2026-66014](https://www.cve.org/CVERecord?id=CVE-2026-66014) | exploited-unconfirmed | DB-2026-006 | High | 2026-07-27 | -18 | 8.8 (v3.1) |  | jfrog/artifactory | CWE-287 | Potential authentication bypass leading to privilege escalation in Artifactory |
| [CVE-2025-68613](https://www.cve.org/CVERecord?id=CVE-2025-68613) | attempted | DR-2026-008 | High | 2025-12-19 |  | 10 (v3.1) | **KEV** | n8n-io/n8n | CWE-913 | n8n Vulnerable to Remote Code Execution via Expression Injection |
| [CVE-2026-21858](https://www.cve.org/CVERecord?id=CVE-2026-21858) | attempted | DR-2026-008 | High | 2026-01-07 |  | 10 (v3.1) |  | n8n-io/n8n | CWE-20 | n8n Vulnerable to Unauthenticated File Access via Improper Webhook Request Handling |
| [CVE-2021-29441](https://www.cve.org/CVERecord?id=CVE-2021-29441) | attempted | DR-2026-011 | High | 2021-04-27 |  | 8.6 (v3.1) |  | alibaba/nacos | CWE-290 | Authentication bypass |
| [CVE-2017-7269](https://www.cve.org/CVERecord?id=CVE-2017-7269) | toolkit | DB-2026-018 | High | 2017-03-27 | 3367 |  | **KEV** | n/a/n/a |  |  |
| [CVE-2021-3156](https://www.cve.org/CVERecord?id=CVE-2021-3156) | toolkit | DB-2026-018 | High | 2021-01-26 | 1966 |  | **KEV** | n/a/n/a |  |  |
| [CVE-2021-4034](https://www.cve.org/CVERecord?id=CVE-2021-4034) | toolkit | DB-2026-018 | High | 2022-01-28 | 1599 |  | **KEV** | n/a/polkit | CWE-787 |  |
| [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431) | toolkit | DB-2026-018 | High | 2026-04-22 | 54 | 7.8 (v3.1) | **KEV** | Linux/Linux |  | crypto: algif_aead - Revert to operating out-of-place |
| [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284) | toolkit | DB-2026-018 | High | 2026-05-08 | 38 | 8.8 (v3.1) |  | Linux/Linux |  | xfrm: esp: avoid in-place decrypt on shared skb frags |
| [CVE-2026-43500](https://www.cve.org/CVERecord?id=CVE-2026-43500) | toolkit | DB-2026-018 | High | 2026-05-11 | 35 | 7.8 (v3.1) |  | Linux/Linux |  | rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present |
| [CVE-2026-43503](https://www.cve.org/CVERecord?id=CVE-2026-43503) | toolkit | DB-2026-018 | High | 2026-05-23 | 23 | 8.8 (v3.1) |  | Linux/Linux |  | net: skbuff: propagate shared-frag marker through frag-transfer helpers |

## CVEs discovered by AI systems (register — 52 links, 51 distinct CVEs)

Relation `discovered`: the CVE is credited to the AI system or AI-assisted team the incident is about. `Credits` is the CVE record's own credit line where the CNA publishes one (methodology §6.7).

| CVE | Incident | Credits | CNA | Product | Published | CVSS | CNA CWE | Title |
|---|---|---|---|---|---|---|---|---|
| [CVE-2026-4747](https://www.cve.org/CVERecord?id=CVE-2026-4747) | DR-2026-058 | Nicholas Carlini using Claude, Anthropic | freebsd | FreeBSD/FreeBSD | 2026-03-26 |  | CWE-121 | Remote code execution via RPCSEC_GSS packet validation |
| [CVE-2026-5194](https://www.cve.org/CVERecord?id=CVE-2026-5194) | DR-2026-058 | Nicholas Carlini from Anthropic | wolfSSL | wolfSSL/wolfSSL | 2026-04-09 | 9.3 (v4.0) | CWE-295 | wolfSSL ECDSA Certificate Verification |
| [CVE-2026-44471](https://www.cve.org/CVERecord?id=CVE-2026-44471) | DR-2026-058 |  | GitHub_M | GitoxideLabs/gitoxide | 2026-05-13 | 7.8 (v3.1) | CWE-59 | gitoxide: Symlink prefix-reuse allows worktree escape during checkout |
| [CVE-2026-21536](https://www.cve.org/CVERecord?id=CVE-2026-21536) | DR-2026-079 |  | microsoft | Microsoft/Microsoft Devices Pricing Program | 2026-03-05 | 9.8 (v3.1) | CWE-434 | Microsoft Devices Pricing Program Remote Code Execution Vulnerability |
| [CVE-2026-32191](https://www.cve.org/CVERecord?id=CVE-2026-32191) | DR-2026-079 |  | microsoft | Microsoft/Microsoft Bing Images | 2026-03-19 | 9.8 (v3.1) | CWE-78 | Microsoft Bing Images Remote Code Execution Vulnerability |
| [CVE-2026-32194](https://www.cve.org/CVERecord?id=CVE-2026-32194) | DR-2026-079 |  | microsoft | Microsoft/Microsoft Bing Images | 2026-03-19 | 9.8 (v3.1) | CWE-77 | Microsoft Bing Images Remote Code Execution Vulnerability |
| [CVE-2026-45185](https://www.cve.org/CVERecord?id=CVE-2026-45185) | DR-2026-084 |  | mitre | Exim/Exim | 2026-05-12 | 9.8 (v3.1) | CWE-416 |  |
| [CVE-2026-13242](https://www.cve.org/CVERecord?id=CVE-2026-13242) | DR-2026-085 | Michael Maturi (michaelmaturi); Michael Maturi (michaelmaturi); Christian Adamski (christianadamski); cilefen  (cilefen); Neil Drumm (drumm); Greg Knaddison (greggles); Drew Webber (mcdruid); Juraj Nemec (poker10) | drupal | Drupal/Geolocation Field | 2026-07-10 |  | CWE-89 | Geolocation Field - Critical - SQL Injection - SA-CONTRIB-2026-062 |
| [CVE-2026-55803](https://www.cve.org/CVERecord?id=CVE-2026-55803) | DR-2026-085 | Michael Maturi (michaelmaturi); BjÃ¶rn Brala (bbrala); Sascha Grossenbacher (berdir); Lee Rowlands (larowlan); Dave Long (longwave); Drew Webber (mcdruid); Anna Kalata (akalata); Benji Fisher (benjifisher); Damien McKenna (damienmckenna); David Strauss (david strauss); Neil Drumm (drumm); Greg Knadd | drupal | Drupal/Drupal core | 2026-07-10 |  | CWE-915 | Drupal core - Critical - PHP object injection - SA-CORE-2026-005 |
| [CVE-2025-32988](https://www.cve.org/CVERecord?id=CVE-2025-32988) | DR-2026-088 |  | redhat | ?/?; Red Hat/Red Hat Ceph Storage 7; Red Hat/Red Hat Discovery 2; Red Hat/Red Hat Enterprise Linux 10; Red Hat/Red Hat Enterprise Linux 6; Red Hat/Red Hat Enterprise Linux 7; Red Hat/Red Hat Enterpris | 2025-07-10 | 6.5 (v3.1) | CWE-415 | Gnutls: vulnerability in gnutls othername san export |
| [CVE-2025-32989](https://www.cve.org/CVERecord?id=CVE-2025-32989) | DR-2026-088 |  | redhat | ?/?; Red Hat/Red Hat Ceph Storage 7; Red Hat/Red Hat Discovery 2; Red Hat/Red Hat Enterprise Linux 10; Red Hat/Red Hat Enterprise Linux 6; Red Hat/Red Hat Enterprise Linux 7; Red Hat/Red Hat Enterpris | 2025-07-10 | 5.3 (v3.1) | CWE-295 | Gnutls: vulnerability in gnutls sct extension parsing |
| [CVE-2025-35430](https://www.cve.org/CVERecord?id=CVE-2025-35430) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 5.3 (v4.0) | CWE-22 | CISA Thorium insecure downloaded file path validation |
| [CVE-2025-35431](https://www.cve.org/CVERecord?id=CVE-2025-35431) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 5.3 (v4.0) | CWE-90 | CISA Thorium LDAP injection |
| [CVE-2025-35432](https://www.cve.org/CVERecord?id=CVE-2025-35432) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 6.9 (v4.0) | CWE-400 | CISA Thorium does not rate limit account verification email messages |
| [CVE-2025-35433](https://www.cve.org/CVERecord?id=CVE-2025-35433) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 2.3 (v4.0) | CWE-613 | CISA Thorium does not properly invalidate previously used tokens |
| [CVE-2025-35434](https://www.cve.org/CVERecord?id=CVE-2025-35434) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 2.3 (v4.0) | CWE-295 | CISA Thorium does not validate TLS connections to Elasticsearch |
| [CVE-2025-35435](https://www.cve.org/CVERecord?id=CVE-2025-35435) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 5.3 (v4.0) | CWE-369 | CISA Thorium download stream divide by zero |
| [CVE-2025-35436](https://www.cve.org/CVERecord?id=CVE-2025-35436) | DR-2026-088 | , OpenAI Security Research | cisa-cg | CISA/Thorium | 2025-09-17 | 6.9 (v4.0) | CWE-248 | CISA Thorium account verification email error handling |
| [CVE-2025-64175](https://www.cve.org/CVERecord?id=CVE-2025-64175) | DR-2026-088 |  | GitHub_M | gogs/gogs | 2026-02-06 | 7.7 (v4.0) | CWE-287 | Gogs Vulnerable to 2FA Bypass via Recovery Code |
| [CVE-2026-3854](https://www.cve.org/CVERecord?id=CVE-2026-3854) | DR-2026-088 | Sagi Tzadik @ Wiz.io | GitHub_P | GitHub/Enterprise Server | 2026-03-10 | 8.7 (v4.0) | CWE-77 | Remote code execution via git push option injection in GitHub Enterprise Server |
| [CVE-2026-14431](https://www.cve.org/CVERecord?id=CVE-2026-14431) | DR-2026-088 |  | Chrome | Google/Chrome | 2026-07-01 |  | CWE-843 |  |
| [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903) | DR-2026-088 |  | Chrome | Google/Chrome | 2026-07-20 |  |  |  |
| [CVE-2026-17658](https://www.cve.org/CVERecord?id=CVE-2026-17658) | DR-2026-088 |  | Chrome | Google/Chrome | 2026-07-30 |  | CWE-416 |  |
| [CVE-2026-19162](https://www.cve.org/CVERecord?id=CVE-2026-19162) | DR-2026-088 |  | Chrome | Google/Chrome | 2026-08-06 |  | CWE-787 |  |
| [CVE-2026-24881](https://www.cve.org/CVERecord?id=CVE-2026-24881) | DR-2026-088 |  | mitre | GnuPG/GnuPG | 2026-01-27 | 8.1 (v3.1) | CWE-121 |  |
| [CVE-2026-24882](https://www.cve.org/CVERecord?id=CVE-2026-24882) | DR-2026-088 |  | mitre | GnuPG/GnuPG | 2026-01-27 | 8.4 (v3.1) | CWE-121 |  |
| [CVE-2026-25242](https://www.cve.org/CVERecord?id=CVE-2026-25242) | DR-2026-088 |  | GitHub_M | gogs/gogs | 2026-02-19 | 6.9 (v4.0) | CWE-862 | Gogs allows unauthenticated file uploads |
| [CVE-2026-76045](https://www.cve.org/CVERecord?id=CVE-2026-76045) | DR-2026-088 |  | Chrome | Google/Chrome | 2026-08-18 |  | CWE-416 |  |
| [CVE-2026-15903](https://www.cve.org/CVERecord?id=CVE-2026-15903) | DR-2026-091 |  | Chrome | Google/Chrome | 2026-07-20 |  |  |  |
| [CVE-2026-76021](https://www.cve.org/CVERecord?id=CVE-2026-76021) | DR-2026-093 |  | Chrome | Google/Chrome | 2026-08-20 |  | CWE-416 |  |
| [CVE-2026-2763](https://www.cve.org/CVERecord?id=CVE-2026-2763) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2764](https://www.cve.org/CVERecord?id=CVE-2026-2764) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | JIT miscompilation, use-after-free in the JavaScript Engine: JIT component |
| [CVE-2026-2765](https://www.cve.org/CVERecord?id=CVE-2026-2765) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2766](https://www.cve.org/CVERecord?id=CVE-2026-2766) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript Engine: JIT component |
| [CVE-2026-2769](https://www.cve.org/CVERecord?id=CVE-2026-2769) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the Storage: IndexedDB component |
| [CVE-2026-2770](https://www.cve.org/CVERecord?id=CVE-2026-2770) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the DOM: Bindings (WebIDL) component |
| [CVE-2026-2771](https://www.cve.org/CVERecord?id=CVE-2026-2771) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Undefined behavior in the DOM: Core & HTML component |
| [CVE-2026-2772](https://www.cve.org/CVERecord?id=CVE-2026-2772) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the Audio/Video: Playback component |
| [CVE-2026-2773](https://www.cve.org/CVERecord?id=CVE-2026-2773) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Incorrect boundary conditions in the Web Audio component |
| [CVE-2026-2774](https://www.cve.org/CVERecord?id=CVE-2026-2774) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Integer overflow in the Audio/Video component |
| [CVE-2026-2775](https://www.cve.org/CVERecord?id=CVE-2026-2775) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Mitigation bypass in the DOM: HTML Parser component |
| [CVE-2026-2785](https://www.cve.org/CVERecord?id=CVE-2026-2785) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Invalid pointer in the JavaScript Engine component |
| [CVE-2026-2786](https://www.cve.org/CVERecord?id=CVE-2026-2786) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript Engine component |
| [CVE-2026-2787](https://www.cve.org/CVERecord?id=CVE-2026-2787) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the DOM: Window and Location component |
| [CVE-2026-2788](https://www.cve.org/CVERecord?id=CVE-2026-2788) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Incorrect boundary conditions in the Audio/Video: GMP component |
| [CVE-2026-2789](https://www.cve.org/CVERecord?id=CVE-2026-2789) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the Graphics: ImageLib component |
| [CVE-2026-2791](https://www.cve.org/CVERecord?id=CVE-2026-2791) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Mitigation bypass in the Networking: Cache component |
| [CVE-2026-2796](https://www.cve.org/CVERecord?id=CVE-2026-2796) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | JIT miscompilation in the JavaScript: WebAssembly component |
| [CVE-2026-2797](https://www.cve.org/CVERecord?id=CVE-2026-2797) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript: GC component |
| [CVE-2026-2799](https://www.cve.org/CVERecord?id=CVE-2026-2799) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the DOM: Core & HTML component |
| [CVE-2026-2804](https://www.cve.org/CVERecord?id=CVE-2026-2804) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Use-after-free in the JavaScript: WebAssembly component |
| [CVE-2026-2805](https://www.cve.org/CVERecord?id=CVE-2026-2805) | DR-2026-094 | Evyatar Ben Asher, Keane Lucas, Nicholas Carlini, Newton Cheng, Daniel Freeman, Alex Gaynor, and Joel Weinberger using Claude from Anthropic | mozilla | Mozilla/Firefox; Mozilla/Thunderbird | 2026-02-24 |  |  | Invalid pointer in the DOM: Core & HTML component |

## Non-CVE identifiers

Malicious package releases, account-takeover publishes and vendor-fixed flaws often never receive a CVE (methodology §6.6); GHSA / MAL / PYSEC / vendor advisory ids are recorded here and never placed in CVE fields.

| Incident | Identifier | Scheme | Kind | Note |
|---|---|---|---|---|
| DB-2026-001 | GHSA-5mg7-485q-xm76 | GHSA | GHSA (reviewed, critical) | Two LiteLLM versions (1.82.7, 1.82.8) published containing credential-harvesting malware; no CVE of its own |
| DB-2026-001 | GHSA-92x9-889m-jgmw | GHSA | GHSA (malware) | OSSF malware entry for litellm 1.82.7/1.82.8 |
| DB-2026-001 | PYSEC-2026-2 | PYSEC | PyPA advisory | litellm 1.82.7/1.82.8 malicious releases |
| DB-2026-001 | MAL-2026-2144 | MAL | OSV malware | litellm 1.82.7/1.82.8 |
| DB-2026-001 | GHSA-955r-262c-33jc | GHSA | GHSA (reviewed, critical) | telnyx 4.87.1/4.87.2 malicious PyPI releases (same TeamPCP campaign) |
| DB-2026-001 | MAL-2026-2254 | MAL | OSV malware | telnyx 4.87.1/4.87.2 |
| DB-2026-005 | GHSA-3qf7-886j-9wrc | GHSA | GHSA (malware) | durabletask 1.4.1-1.4.3 PyPI account takeover, 19 May 2026 - the Miasma/TeamPCP precursor; the 5 Jun GitHub-repo wave itself has no advisory ID |
| DB-2026-005 | MAL-2026-4174 | MAL | OSV malware | durabletask 1.4.1-1.4.3 |
| DB-2026-005 | PYSEC-2026-207 | PYSEC | PyPA advisory | durabletask 1.4.1-1.4.3 |
| DR-2026-010 | GHSA-69fq-xp46-6x23 | GHSA | GHSA | Trivy ecosystem compromise advisory (= CVE-2026-33634) |
| DR-2026-010 | GHSA-8mr6-gf9x-j8qg | GHSA | GHSA (repo-level) | Malicious Trivy VS Code extension 1.8.12 (= CVE-2026-28353) |
| DR-2026-012 | GHSA-3p9h-f68w-m6fx | GHSA | GHSA (malware) | keyv 6.0.0 - CHAINDROP initial vector |
| DR-2026-012 | MAL-2026-11524 | MAL | OSV malware | keyv 6.0.0 |
| DR-2026-012 | GHSA-jpjx-r3gh-v5pf | GHSA | GHSA (malware) | cacheable 2.5.1 |
| DR-2026-012 | MAL-2026-11963 | MAL | OSV malware | cacheable 2.5.1 |
| DR-2026-012 | GHSA-q99r-cjmf-3xrf | GHSA | GHSA (malware) | @keyv/redis 6.0.0 |
| DR-2026-012 | GHSA-4wfp-qcf3-mgqp | GHSA | GHSA (malware) | @keyv/sqlite 6.0.0 |
| DR-2026-012 | GHSA-cgpm-wvpq-73p3 | GHSA | GHSA (malware) | @keyv/postgres 6.0.0 |
| DR-2026-012 | GHSA-h8h5-wqhj-grm7 | GHSA | GHSA (malware) | @keyv/mongo 6.0.0 |
| DR-2026-012 | GHSA-c7r2-p8ff-5ffp | GHSA | GHSA (malware) | @keyv/compress-gzip 6.0.0 |
| DR-2026-012 | GHSA-mxgw-gq2g-4fq9 | GHSA | GHSA (malware) | cacheable-request 13.0.20 |
| DR-2026-012 | GHSA-7pv9-q9wh-jqc3 | GHSA | GHSA (malware) | @cacheable/node-cache 3.1.2 |
| DR-2026-012 | GHSA-583f-9h76-9fx2 | GHSA | GHSA (malware) | @cacheable/memory 2.2.1 |
| DR-2026-012 | GHSA-8jxr-wprf-45g8 | GHSA | GHSA (malware) | flat-cache 6.1.24 |
| DR-2026-012 | GHSA-qp89-2g43-jg8j | GHSA | GHSA (malware) | file-entry-cache 11.1.6 |
| DR-2026-012 | GHSA-p7m5-96hg-gppj | GHSA | GHSA (malware) | cache-manager 7.2.10 |
| DR-2026-022 | GHSA-g7cv-rxg3-hmpx | GHSA | GHSA (reviewed, critical) | 42 @tanstack/* packages (= CVE-2026-45321) |
| DR-2026-022 | GHSA-wx9m-wx4f-4cmg | GHSA | GHSA (reviewed, critical, vendor-authored) | mistralai 2.4.6 PyPI malicious dropper |
| DR-2026-022 | MAL-2026-3608 | MAL | OSV malware | mistralai 2.4.6 |
| DR-2026-022 | GHSA-jgg6-4rpr-wfh7 | GHSA | GHSA (reviewed, low) | @mistralai/mistralai 2.2.2-2.2.4, -azure/-gcp 1.7.1-1.7.3 (broken dropper) |
| DR-2026-022 | MAL-2026-3432 | MAL | OSV malware | @mistralai/* npm |
| DR-2026-022 | GHSA-r62p-98fh-6qv4 | GHSA | GHSA (malware) | @uipath/cli 1.0.1 |
| DR-2026-022 | GHSA-cx9h-9vrc-7393 | GHSA | GHSA (malware) | @uipath/robot 1.3.4 |
| DR-2026-022 | GHSA-j36c-8r88-423c | GHSA | GHSA (malware) | @uipath/apollo-core 5.9.2 |
| DR-2026-022 | GHSA-9hfm-w6gw-qc7c | GHSA | GHSA (malware) | @uipath/agent.sdk 0.0.18 |
| DR-2026-022 | GHSA-298w-vvm4-ww55 | GHSA | GHSA (malware) | @opensearch-project/opensearch 3.5.3/3.6.2/3.7.0/3.8.0 |
| DR-2026-022 | GHSA-xmpw-2vmm-p4p6 | GHSA | GHSA | guardrails-ai 0.10.1 (= CVE-2026-45758) |
| DR-2026-025 | GHSA-fw8c-xr5c-95f9 | GHSA | GHSA (malware, critical) | Malware in axios 1.14.1 / 0.30.4 |
| DR-2026-025 | MAL-2026-2307 | MAL | OSV malware | axios 1.14.1 / 0.30.4 |
| DR-2026-025 | GHSA-2x9r-6wxq-hrr7 | GHSA | GHSA (malware) | plain-crypto-js 4.2.0/4.2.1 - the phantom dependency carrying the RAT |
| DR-2026-025 | MAL-2026-2306 | MAL | OSV malware | plain-crypto-js |
| DR-2026-035 | GHSA-9ppg-jx86-fqw7 | GHSA | GHSA (reviewed, low) | Unauthorized npm publish of cline@2.3.0 with modified postinstall (cve_id null) |
| DR-2026-035 | MAL-2026-1380 | MAL | OSV malware | cline 2.3.0 |
| DR-2026-036 | GHSA-5WP8-Q9MX-8JX8 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-5WP8-Q9MX-8JX8: qhkm/zeptoclaw (Rust); AI tool: Claude; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-03-05 |
| DR-2026-036 | GHSA-HHJV-JQ77-CMVX | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-HHJV-JQ77-CMVX: qhkm/zeptoclaw (n/a); AI tool: GitHub Copilot; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-03-05 |
| DR-2026-036 | GHSA-F67F-HCR6-94MF | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-F67F-HCR6-94MF: shadd0wtaka/zen-ai-pentest (n/a); AI tool: ChatGPT/Codex; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-03-20 |
| DR-2026-036 | GHSA-C875-H985-HVRC | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-C875-H985-HVRC: scriban/scriban (n/a); AI tool: unspecified; contribution: AI_CODE_FLAWED; cause: injection; advisory published 2026-03-24 |
| DR-2026-036 | GHSA-P6Q4-FGR8-VX4P | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-P6Q4-FGR8-VX4P: scriban/scriban (n/a); AI tool: GitHub Copilot; contribution: AI_CODE_FLAWED; cause: resource_abuse; advisory published 2026-03-24 |
| DR-2026-036 | GHSA-3MJM-X6GW-2X42 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-3MJM-X6GW-2X42: nick-pape/grackle (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-03-25 |
| DR-2026-036 | GHSA-8X4M-QW58-3PCX | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-8X4M-QW58-3PCX: wevm/mppx (n/a); AI tool: unspecified; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-03-29 |
| DR-2026-036 | GHSA-425G-FJHQ-5H92 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-425G-FJHQ-5H92: jahlives/openssl_encrypt (Python); AI tool: Claude; contribution: AI_INCOMPLETE_REMEDIATION; cause: validation_fail_open; advisory published 2026-03-31 |
| DR-2026-036 | GHSA-H45M-MGCP-Q388 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-H45M-MGCP-Q388: jahlives/openssl_encrypt (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: resource_abuse; advisory published 2026-03-31 |
| DR-2026-036 | GHSA-J48Q-4C78-RHF9 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-J48Q-4C78-RHF9: jahlives/openssl_encrypt (Python); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: other_ambiguous; advisory published 2026-03-31 |
| DR-2026-036 | GHSA-VFGX-5Q85-58Q3 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-VFGX-5Q85-58Q3: jahlives/openssl_encrypt (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: other_ambiguous; advisory published 2026-03-31 |
| DR-2026-036 | GHSA-4RH7-JWG9-M28M | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-4RH7-JWG9-M28M: jahlives/openssl_encrypt (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: other_ambiguous; advisory published 2026-04-01 |
| DR-2026-036 | GHSA-8H88-GXP3-J7PG | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-8H88-GXP3-J7PG: jahlives/openssl_encrypt (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-04-01 |
| DR-2026-036 | GHSA-75HX-XJ24-MQRW | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-75HX-XJ24-MQRW: czlonkowski/n8n-mcp (JavaScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: auth_access; advisory published 2026-04-10 |
| DR-2026-036 | GHSA-HM2H-WWWH-G49X | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-HM2H-WWWH-G49X: lin-snow/ech0 (n/a); AI tool: Cursor; contribution: AI_DIRECT_ROOT; cause: auth_access; advisory published 2026-04-10 |
| DR-2026-036 | GHSA-P4H8-56QP-HPGV | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-P4H8-56QP-HPGV: aiondadotcom/mcp-ssh (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-04-14 |
| DR-2026-036 | GHSA-GQQJ-85QM-8QHF | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-GQQJ-85QM-8QHF: paperclipai/paperclip (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: validation_fail_open; advisory published 2026-04-16 |
| DR-2026-036 | GHSA-P7MM-R948-4Q3Q | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-P7MM-R948-4Q3Q: paperclipai/paperclip (n/a); AI tool: Claude; contribution: AI_CODE_FLAWED; cause: auth_access; advisory published 2026-04-16 |
| DR-2026-036 | GHSA-XFQJ-R5QW-8G4J | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-XFQJ-R5QW-8G4J: paperclipai/paperclip (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: auth_access; advisory published 2026-04-16 |
| DR-2026-036 | GHSA-2R2P-4CGF-HV7H | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-2R2P-4CGF-HV7H: nickcirv/engram (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-04-22 |
| DR-2026-036 | GHSA-7JM2-G593-4QRC | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-7JM2-G593-4QRC: openclaw/openclaw (JavaScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: other_ambiguous; advisory published 2026-04-25 |
| DR-2026-036 | GHSA-R27J-894H-3W3P | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-R27J-894H-3W3P: amannn/next-intl (n/a); AI tool: Cursor; contribution: AI_DIRECT_ROOT; cause: resource_abuse; advisory published 2026-05-06 |
| DR-2026-036 | GHSA-8G7G-HMWM-6RV2 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-8G7G-HMWM-6RV2: czlonkowski/n8n-mcp (JavaScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: ssrf_network; advisory published 2026-05-08 |
| DR-2026-036 | GHSA-88Q9-CMP2-C2VQ | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-88Q9-CMP2-C2VQ: bzsanti/oxidizepdf (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: resource_abuse; advisory published 2026-05-11 |
| DR-2026-036 | GHSA-G39V-CVJH-8FPF | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-G39V-CVJH-8FPF: homeassistant-ai/ha-mcp (Python); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: auth_access; advisory published 2026-05-14 |
| DR-2026-036 | GHSA-7CWM-FPFH-RRCH | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-7CWM-FPFH-RRCH: metal3-io/ironic-standalone-operator (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-05-29 |
| DR-2026-036 | GHSA-2C85-RFCC-G74J | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-2C85-RFCC-G74J: karatelabs/karate (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-06-18 |
| DR-2026-036 | GHSA-V52W-28XH-V562 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-V52W-28XH-V562: kozou-dev/kozou (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: other_ambiguous; advisory published 2026-06-19 |
| DR-2026-036 | GHSA-6Q7J-XR26-3H2C | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-6Q7J-XR26-3H2C: scriban/scriban (C#); AI tool: GitHub Copilot; contribution: AI_INCOMPLETE_REMEDIATION; cause: resource_abuse; advisory published 2026-06-26 |
| DR-2026-036 | GHSA-72W7-MF9G-733P | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-72W7-MF9G-733P: nolabs-ai/nono-py (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-06-26 |
| DR-2026-036 | GHSA-Q6RR-FM2G-G5X8 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-Q6RR-FM2G-G5X8: scriban/scriban (C#); AI tool: GitHub Copilot; contribution: AI_INCOMPLETE_REMEDIATION; cause: resource_abuse; advisory published 2026-06-26 |
| DR-2026-036 | GHSA-RP72-5V5Q-2446 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-RP72-5V5Q-2446: morganoncode/cardano402 (n/a); AI tool: Claude; contribution: AI_CODE_FLAWED; cause: ssrf_network; advisory published 2026-06-26 |
| DR-2026-036 | GHSA-9C3V-684M-579C | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-9C3V-684M-579C: openclaw/openclaw (JavaScript); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: auth_access; advisory published 2026-07-01 |
| DR-2026-036 | GHSA-2944-57XV-2682 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-2944-57XV-2682: asymmetric-effort/specifyjs (TypeScript); AI tool: Claude; contribution: AI_INCOMPLETE_REMEDIATION; cause: resource_abuse; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-322X-V876-G883 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-322X-V876-G883: asymmetric-effort/nogginlessdom (TypeScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: path_link; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-3WQP-PRF6-2M72 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-3WQP-PRF6-2M72: openclaw/openclaw (n/a); AI tool: Claude; contribution: AI_CODE_FLAWED; cause: other_ambiguous; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-5C7W-4WM3-85VW | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-5C7W-4WM3-85VW: asymmetric-effort/specifyjs (TypeScript); AI tool: Claude; contribution: AI_INCOMPLETE_REMEDIATION; cause: validation_fail_open; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-J5QP-P44G-2M49 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-J5QP-P44G-2M49: asymmetric-effort/specifyjs (TypeScript); AI tool: Claude; contribution: AI_INCOMPLETE_REMEDIATION; cause: ssrf_network; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-QCR8-X557-7CP3 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-QCR8-X557-7CP3: asymmetric-effort/specifyjs (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: resource_abuse; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-VV65-F55V-XM6G | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-VV65-F55V-XM6G: nick-pape/grackle (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-WV26-J37Q-2G7P | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-WV26-J37Q-2G7P: openclaw/openclaw (n/a); AI tool: Claude; contribution: AI_CODE_FLAWED; cause: injection; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-X4HG-HFWF-P9MW | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-X4HG-HFWF-P9MW: asymmetric-effort/nogginlessdom (TypeScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: resource_abuse; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-XW57-23P8-9WC5 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-XW57-23P8-9WC5: asymmetric-effort/specifyjs (n/a); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: ssrf_network; advisory published 2026-07-02 |
| DR-2026-036 | GHSA-Q855-8RH5-JFGQ | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-Q855-8RH5-JFGQ: homeassistant-ai/ha-mcp (Python); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: auth_access; advisory published 2026-07-07 |
| DR-2026-036 | GHSA-3RP5-JJMW-4WV2 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-3RP5-JJMW-4WV2: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-07-24 |
| DR-2026-036 | GHSA-P5RM-JG5C-8C77 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-P5RM-JG5C-8C77: microsoft/kiota (C#); AI tool: GitHub Copilot; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-07-24 |
| DR-2026-036 | GHSA-R9MR-M37C-5FR3 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-R9MR-M37C-5FR3: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-07-24 |
| DR-2026-036 | GHSA-RFR2-MQ9M-X2QX | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-RFR2-MQ9M-X2QX: koxudaxi/datamodel-code-generator (n/a); AI tool: Claude; contribution: AI_CODE_FLAWED; cause: ssrf_network; advisory published 2026-07-28 |
| DR-2026-036 | GHSA-8JQH-598V-RFXC | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-8JQH-598V-RFXC: arnasdon/wacrm (TypeScript); AI tool: Claude; contribution: AI_DIRECT_ROOT; cause: validation_fail_open; advisory published 2026-07-30 |
| DR-2026-036 | GHSA-PQH8-P93P-2RX7 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-PQH8-P93P-2RX7: dynatrace-oss/dynatrace-mcp (n/a); AI tool: GitHub Copilot; contribution: AI_NEW_SURFACE_CONTRIBUTOR; cause: injection; advisory published 2026-07-31 |
| DR-2026-036 | GHSA-539M-9XH6-Q6RR | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-539M-9XH6-Q6RR: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-08-03 |
| DR-2026-036 | GHSA-WVPP-8HX9-P66J | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-WVPP-8HX9-P66J: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_DIRECT_ROOT; cause: injection; advisory published 2026-08-07 |
| DR-2026-036 | GHSA-3WXW-XV34-2FRG | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-3WXW-XV34-2FRG: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: path_link; advisory published 2026-08-10 |
| DR-2026-036 | GHSA-5XXX-QHH7-9287 | GHSA | GHSA (no CVE) | Vibe Security Radar case GHSA-5XXX-QHH7-9287: gitpython-developers/gitpython (Python); AI tool: ChatGPT/Codex; contribution: AI_INCOMPLETE_REMEDIATION; cause: injection; advisory published 2026-08-10 |
| DR-2026-037 | VU#518910 | VU | CERT/CC note | = CVE-2026-5757 |
| DR-2026-045 | GHSA-pvh2-rg5g-69v7 | GHSA | GHSA (malware) | Malware in node-ipc (GitHub lists 9.1.6 only) |
| DR-2026-045 | MAL-2026-3744 | MAL | OSV malware | node-ipc 9.1.6 / 9.2.3 / 12.0.1 |
| DR-2026-046 | RHSB-2026-006 | RHSB | Red Hat security bulletin | @redhat-cloud-services npm compromise (32 packages); lists no CVE |
| DR-2026-046 | GHSA-8m2w-rq7p-jw7q | GHSA | GHSA (malware) | @vapi-ai/server-sdk 0.11.1/0.11.2/1.2.1/1.2.2 - Miasma Phantom Gyp |
| DR-2026-046 | MAL-2026-5209 | MAL | OSV malware | @vapi-ai/server-sdk |
| DR-2026-046 | GHSA-m9j7-x8ww-5jwr | GHSA | GHSA (malware) | ai-sdk-ollama 0.13.1/1.1.1/2.2.1/3.8.5 - Miasma Phantom Gyp |
| DR-2026-046 | MAL-2026-5210 | MAL | OSV malware | ai-sdk-ollama |
| DR-2026-046 | GHSA-mrgj-mcjh-5mf2 | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components 7.7.2 |
| DR-2026-046 | GHSA-r9mp-ff22-jhrr | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-utilities 7.4.1/7.4.2/7.4.4 |
| DR-2026-046 | GHSA-ghcf-x8cx-89q8 | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-notifications 6.9.2/6.9.3/6.9.5 |
| DR-2026-046 | GHSA-vvm2-35w3-pp39 | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-notifications |
| DR-2026-046 | GHSA-r28x-h6v7-8rjj | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-config 6.11.3/6.11.4/6.11.6 |
| DR-2026-046 | GHSA-h43w-g623-gfmv | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-config |
| DR-2026-046 | GHSA-cxfw-p322-rfrv | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-config-utilities 4.11.2/4.11.3/4.11.5 |
| DR-2026-046 | GHSA-h5c9-cj46-7p79 | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-translations 4.4.1/4.4.2/4.4.4 |
| DR-2026-046 | GHSA-873j-vjwp-88w8 | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-advisor-components 3.8.2/3.8.4/3.8.6 |
| DR-2026-046 | GHSA-4rjr-7qhx-vjwg | GHSA | GHSA (malware) | @redhat-cloud-services/frontend-components-remediations 4.9.3/4.9.5 |
| DR-2026-046 | GHSA-4p47-xv4r-786w | GHSA | GHSA (malware) | @redhat-cloud-services/tsc-transform-imports 1.2.2/1.2.4/1.2.6 |
| DR-2026-046 | GHSA-8gf7-gc4w-pwh7 | GHSA | GHSA (malware) | @redhat-cloud-services/tsc-transform-imports |
| DR-2026-046 | GHSA-4qj4-x996-qvgw | GHSA | GHSA (malware) | @redhat-cloud-services/types 3.6.1/3.6.2/3.6.4 |
| DR-2026-046 | GHSA-8xj2-9c64-m64h | GHSA | GHSA (malware) | @redhat-cloud-services/types |
| DR-2026-046 | GHSA-4hcm-2c2r-2rhm | GHSA | GHSA (malware) | @redhat-cloud-services/host-inventory-client 5.0.3/5.0.4/5.0.6 |
| DR-2026-046 | GHSA-p4vp-xg44-93v7 | GHSA | GHSA (malware) | @redhat-cloud-services/vulnerabilities-client 2.1.8/2.1.9/2.1.11 |
| DR-2026-046 | GHSA-wfwj-j63c-gg6h | GHSA | GHSA (malware) | @redhat-cloud-services/javascript-clients-shared 2.0.8/2.0.9/2.0.11 |
| DR-2026-046 | GHSA-x4x7-xp58-wjrh | GHSA | GHSA (malware) | @redhat-cloud-services/compliance-client 4.0.3/4.0.4/4.0.6 |
| DR-2026-046 | GHSA-vp9c-9mjm-2f7w | GHSA | GHSA (malware) | @redhat-cloud-services/sources-client 3.0.11/3.0.13 |
| DR-2026-046 | GHSA-28hc-2275-h287 | GHSA | GHSA (malware) | @redhat-cloud-services/entitlements-client 4.0.12/4.0.14 |
| DR-2026-046 | GHSA-2p99-xvqh-j893 | GHSA | GHSA (malware) | @redhat-cloud-services/rbac-client 9.0.3/9.0.4/9.0.6 |
| DR-2026-046 | GHSA-942v-f47r-w9c3 | GHSA | GHSA (malware) | @redhat-cloud-services/chrome 2.3.1/2.3.2/2.3.4 |
| DR-2026-046 | GHSA-c3mv-fjj4-2542 | GHSA | GHSA (malware) | @redhat-cloud-services/eslint-config-redhat-cloud-services 3.2.1 |
| DR-2026-058 | OpenBSD 7.8 errata 025 | OpenBSD | vendor errata | 27-year TCP SACK kernel crash found by Mythos; no CVE |
| DR-2026-058 | FreeBSD-SA-26:08.rpcsec_gss | FreeBSD | vendor advisory | = CVE-2026-4747 |
| DR-2026-058 | GHSA-f89h-2fjh-2r9q | GHSA | GHSA | gitoxide (= CVE-2026-44471) |
| DR-2026-059 | OX Security MCP-STDIO advisory (15 Apr 2026) | OX | vendor research advisory | umbrella advisory for the wave; LangFlow, LettaAI and three undisclosed products listed without any ID |
| DR-2026-063 | HackerOne #3819931 | HackerOne | bug-bounty report | Wiz Red Agent report to Snowflake, 23 Jun 2026 (no CVE/GHSA assigned) |
| DR-2026-084 | EXIM-Security-2026-05-01.1 | EXIM | vendor advisory | = CVE-2026-45185 |
| DR-2026-085 | SA-CONTRIB-2026-062 | SA | Drupal advisory | = CVE-2026-13242 |
| DR-2026-085 | SA-CORE-2026-005 | SA | Drupal advisory | = CVE-2026-55803 |
| DR-2026-085 | SA-CORE-2026-006 | SA | Drupal advisory | = CVE-2026-55804 |
| DR-2026-091 | Chromium issue 531503216 | Chromium | vendor bug | = CVE-2026-15903 |
| DR-2026-093 | Chromium issue 541854084 | Chromium | vendor bug | = CVE-2026-76021 |
| DR-2026-094 | MFSA 2026-13 | MFSA | Mozilla advisory | Firefox 148 - the 22 Anthropic-credited CVEs |
| DR-2026-094 | MFSA 2026-20 | MFSA | Mozilla advisory | Firefox 149 - 6 further Anthropic-credited CVEs |
| DR-2026-095 | MFSA 2026-30 | MFSA | Mozilla advisory | Firefox 150 (43 CVEs incl. the three rollups carrying the Mythos findings) |

## Per-incident CNA CWEs of in-play CVEs (input for the CWE validation)

For every incident with validated CVEs: the CWEs the CNAs assigned to its in-play CVEs, beside the as-cited incident CWE (`report.weaknesses`, unvalidated). Where the two disagree, the CWE validation decides; nothing is ranked from this table here.

| Incident | In-play CVEs | Other CVEs | CNA CWEs (in-play) | CVE → CNA CWE | As-cited CWE | As-cited basis | Conf. |
|---|---|---|---|---|---|---|---|
| DB-2026-001 | 1 | 0 | CWE-506 | CVE-2026-33634:CWE-506 | CWE-1357 / CWE-506 / CWE-522 | Analyst inference (reliance on compromised component; embedded malicious code; credential exposure) | High |
| DB-2026-006 | 5 | 3 | CWE-287, CWE-502, CWE-918 | CVE-2026-65617:CWE-502<br>CVE-2026-65923:CWE-918<br>CVE-2026-65924:CWE-918<br>CVE-2026-65925:CWE-918<br>CVE-2026-66014:CWE-287 | CWE-22 / CWE-918 / CWE-94 | CVE/CNA (JFrog) + demonstrated dataset-loader RCE / template injection | High |
| DR-2026-008 | 4 | 4 | CWE-20, CWE-94, CWE-95, CWE-306, CWE-913 | CVE-2025-68613:CWE-913<br>CVE-2026-9198:CWE-94<br>CVE-2026-21858:CWE-20<br>CVE-2026-33017:CWE-94,CWE-95,CWE-306 | CWE-94 | CVE/CNA (Langflow) | High |
| DR-2026-010 | 2 | 0 | CWE-506 | CVE-2026-28353:CWE-506<br>CVE-2026-33634:CWE-506 | CWE-269 / CWE-829 | Analyst inference (pull_request_target privilege; poisoned dependency) | High |
| DR-2026-011 | 2 | 0 | CWE-290, CWE-306 | CVE-2021-29441:CWE-290<br>CVE-2025-3248:CWE-306 | CWE-94 | CVE/CNA (Langflow) | High |
| DB-2026-018 | 0 | 7 |  |  | CWE-noinfo | Multiple exploited but unspecified; not inferred | Low |
| DR-2026-020 | 1 | 0 | CWE-306 | CVE-2026-39987:CWE-306 | CWE-94 / CWE-522 | CVE/CNA (marimo) + credential reuse | High |
| DR-2026-022 | 1 | 1 | CWE-506 | CVE-2026-45321:CWE-506 | CWE-1357 / CWE-506 | Analyst inference (compromised components; worm) | High |
| DR-2026-023 | 1 | 0 | CWE-306 | CVE-2026-39987:CWE-306 | CWE-94 / CWE-668 / CWE-522 | CVE/CNA (marimo) + Docker-socket exposure + credential reuse | High |
| DR-2026-025 | 0 | 1 |  |  | CWE-506 / CWE-1357 | Analyst inference (embedded backdoor; compromised dependency) | High |
| DR-2026-036 | 161 | 0 | CWE-15, CWE-20, CWE-22, CWE-41, CWE-59, CWE-62, CWE-73, CWE-74, CWE-77, CWE-78, CWE-79, CWE-80, CWE-88, CWE-89, CWE-94, CWE-119, CWE-176, CWE-200, CWE-201, CWE-212, CWE-214, CWE-266, CWE-269, CWE-283, CWE-284, CWE-285, CWE-290, CWE-294, CWE-306, CWE-307, CWE-311, CWE-321, CWE-327, CWE-328, CWE-345, CWE-346, CWE-347, CWE-358, CWE-367, CWE-400, CWE-416, CWE-426, CWE-436, CWE-441, CWE-459, CWE-460, CWE-488, CWE-522, CWE-532, CWE-601, CWE-610, CWE-636, CWE-639, CWE-648, CWE-657, CWE-668, CWE-693, CWE-696, CWE-707, CWE-732, CWE-749, CWE-754, CWE-770, CWE-807, CWE-862, CWE-863, CWE-913, CWE-915, CWE-918, CWE-942, CWE-943, CWE-1236, CWE-1295, CWE-1321, CWE-1333, CWE-1336 | 161 CVEs — see `incident_cna_cwes.csv` | CWE-1188 / CWE-284 / CWE-798 | Analyst inference (insecure defaults, missing access control, hardcoded creds) | Medium |
| DR-2026-037 | 1 | 1 | CWE-125 | CVE-2026-7482:CWE-125 | CWE-125 / CWE-306 | CVE/CNA (Ollama) + missing auth | High |
| DR-2026-039 | 1 | 4 | CWE-669 | CVE-2026-25253:CWE-669 | CWE-346 / CWE-1385 | CVE/CNA (OpenClaw) — origin validation / WebSocket hijacking | High |
| DR-2026-056 | 2 | 0 | CWE-20, CWE-183, CWE-200, CWE-515 | CVE-2026-12537:CWE-20<br>CVE-2026-54316:CWE-183,CWE-200,CWE-515 | CWE-77 / CWE-78 | CVE/CNA (Gemini CLI) + demonstrated injection | High |
| DR-2026-057 | 1 | 5 | CWE-78, CWE-306, CWE-942 | CVE-2026-59726:CWE-78,CWE-306,CWE-942 | CWE-306 / CWE-862 | CVE/CNA (Ruflo) | Medium |
| DR-2026-058 | 0 | 14 |  |  | CWE-295 / CWE-noinfo | CVE/CNA (WolfSSL cert forgery) + others | High |
| DR-2026-059 | 11 | 6 | CWE-77, CWE-78 | 11 CVEs — see `incident_cna_cwes.csv` | CWE-78 | CVE/CNA (MCP SDK CVEs) | High |
| DR-2026-060 | 2 | 0 | CWE-22, CWE-59 | CVE-2026-50548:CWE-22<br>CVE-2026-50549:CWE-59 | CWE-77 / CWE-59 | CVE/CNA (Cato/Cursor) - injection; symlink resolution | High |
| DR-2026-062 | 5 | 11 | CWE-22, CWE-61, CWE-78, CWE-94, CWE-183, CWE-200, CWE-515, CWE-522 | CVE-2025-59536:CWE-94<br>CVE-2026-21852:CWE-522<br>CVE-2026-24887:CWE-78,CWE-94<br>CVE-2026-39861:CWE-22,CWE-61<br>CVE-2026-54316:CWE-183,CWE-200,CWE-515 | CWE-94 / CWE-77 \| CWE-200 | CVE/CNA (Check Point / Anthropic advisories) \| Analyst inference (API-key exfiltration) | High \| High |
| DR-2026-079 | 0 | 3 |  |  | CWE-434 / CWE-78 | CVE/CNA (Microsoft) | High |
| DR-2026-080 | 2 | 2 | CWE-22, CWE-94 | CVE-2026-25592:CWE-22<br>CVE-2026-26030:CWE-94 | CWE-77 / CWE-94 | CVE/CNA (Microsoft / CERT-CC) | High |
| DR-2026-081 | 1 | 0 | CWE-77 | CVE-2026-42824:CWE-77 | CWE-77 / CWE-918 | CVE/CNA (Varonis/Microsoft) | High |
| DR-2026-083 | 1 | 0 | CWE-77 | CVE-2026-24301:CWE-77 | CWE-77 | CVE/CNA (Varonis/Microsoft) | High |
| DR-2026-084 | 0 | 1 |  |  | CWE-noinfo | CVE/CNA (Exim) | Medium |
| DR-2026-085 | 0 | 3 |  |  | CWE-noinfo | CVE/CNA (assorted) | Medium |
| DR-2026-087 | 2 | 0 | CWE-74, CWE-79 | CVE-2025-32711:CWE-74<br>CVE-2026-26144:CWE-79 | CWE-77 / CWE-79 | CVE/CNA (Microsoft) | High |
| DR-2026-088 | 0 | 21 |  |  | CWE-noinfo | CVE/CNA (assorted) | Medium |
| DR-2026-089 | 3 | 0 | CWE-94, CWE-269, CWE-693, CWE-829 | CVE-2026-48124:CWE-829,CWE-94<br>CVE-2026-73217:CWE-693<br>CVE-2026-73218:CWE-269 | CWE-668 / CWE-693 | CVE/CNA (Cursor) + Pillar research - trust handoff | High |
| DR-2026-091 | 0 | 1 |  |  | CWE-787 / CWE-noinfo | CVE/CNA (Google V8) | Medium |
| DR-2026-093 | 0 | 1 |  |  | CWE-noinfo | Defensive discovery; various | Low |
| DR-2026-094 | 0 | 28 |  |  | CWE-noinfo | Defensive discovery; various | Low |
| DR-2026-095 | 3 | 3 |  | CVE-2026-6784:-<br>CVE-2026-6785:-<br>CVE-2026-6786:- | CWE-noinfo | Defensive discovery; various | Low |

## CNA-assigned CWE profile of the validated CVEs, per segment

Descriptive CVE statistics: the unit is the **CVE link**, not the incident, and the CWE is the one the CNA assigned to the CVE record. This is *not* the incident-level CWE ranking (that is built in the CWE thread from the incident layer, where each incident counts once); it shows what kind of vulnerabilities each population of CVEs consists of.

| Segment | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Links with CNA CWE | Distinct CWEs |
|---|---|---|---|---|---|---|---|
| ai-exploited | 20 | 19 | 6 | 48 | 72 | 14 | 10 |
| ai-written | 161 | 161 | 1 | 4 | 8 | 158 | 76 |
| ai-stack-vulnerability | 35 | 34 | 13 | 24 | 132 | 24 | 20 |
| malicious-release | 4 | 3 | 3 | 32 | 40 | 4 | 1 |
| ai-discovered | 52 | 51 | 8 | 9 | 64 | 28 | 20 |
| related | 61 | 61 | 15 | 49 | 160 | 44 | 33 |

How to read the per-segment rows: **CVE links** = number of incident–CVE pairs in the segment whose CVE record carries this CWE (a CVE that occurs in two incidents counts twice); **Distinct CVEs** = the same without double-counting recurring CVEs; **Incidents** = distinct incidents among those links; **Share** = CVE links with this CWE ÷ links in the segment that carry any CNA CWE (the *Links with CNA CWE* column above); **IBSS obs / pot** = incident-based severity score over those incidents, each counted once (Negligible 1 · Low 2 · Medium 4 · High 8 · Critical 16, observed and potential separately) — for `related` and `ai-discovered` this attributes an incident's harm to the CWE of a *sibling* or *found* CVE, shown as context weight for comparison with the CWE thread (whose Rule 1 excludes those relations), not as the weakness's risk. Shares within a segment add up to more than 100 % because one CVE record can carry several CWEs. Example: `ai-exploited` / CWE-306 = 4 links (Langflow CVE-2026-33017 and CVE-2025-3248, marimo CVE-2026-39987 in two incidents), 3 distinct CVEs, 4 incidents, 4 ÷ 14 = 29 %. CWEs that the incident record assigns directly (`report.weaknesses`) are **not** counted here; they appear beside the CNA CWEs in the preceding per-incident table and feed the incident-level CWE ranking of the CWE thread.

### `ai-exploited` — top 10 of 10 CWEs

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-306 | 4 | 3 | 4 | 32 | 48 | 29% |
| CWE-918 | 3 | 3 | 1 | 8 | 16 | 21% |
| CWE-94 | 2 | 2 | 1 | 8 | 16 | 14% |
| CWE-20 | 1 | 1 | 1 | 8 | 16 | 7% |
| CWE-95 | 1 | 1 | 1 | 8 | 16 | 7% |
| CWE-287 | 1 | 1 | 1 | 8 | 16 | 7% |
| CWE-290 | 1 | 1 | 1 | 8 | 16 | 7% |
| CWE-502 | 1 | 1 | 1 | 8 | 16 | 7% |
| CWE-787 | 1 | 1 | 1 | 8 | 8 | 7% |
| CWE-913 | 1 | 1 | 1 | 8 | 16 | 7% |

### `ai-written` — top 12 of 76 CWEs

All links of this segment stem from one incident (DR-2026-036), so IBSS is the same for every row (observed 4, potential 8) — the column will differentiate once further incidents join the segment.

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-918 | 21 | 21 | 1 | 4 | 8 | 13% |
| CWE-22 | 19 | 19 | 1 | 4 | 8 | 12% |
| CWE-78 | 11 | 11 | 1 | 4 | 8 | 7% |
| CWE-862 | 10 | 10 | 1 | 4 | 8 | 6% |
| CWE-200 | 9 | 9 | 1 | 4 | 8 | 6% |
| CWE-639 | 9 | 9 | 1 | 4 | 8 | 6% |
| CWE-94 | 8 | 8 | 1 | 4 | 8 | 5% |
| CWE-863 | 7 | 7 | 1 | 4 | 8 | 4% |
| CWE-284 | 6 | 6 | 1 | 4 | 8 | 4% |
| CWE-306 | 6 | 6 | 1 | 4 | 8 | 4% |
| CWE-77 | 5 | 5 | 1 | 4 | 8 | 3% |
| CWE-770 | 5 | 5 | 1 | 4 | 8 | 3% |

### `ai-written` — Vibe Security Radar profile (161 CVE notes parsed, 0 unparsed)

Radar's `contribution` type says how the AI tool was involved in the flawed code; `cause` is Radar's coarse cause category. Per-AI-tool counts are deliberately not tabulated: they reflect Radar's attribution method and tool market share, not defect rates.

| Dimension | Value | CVEs |
|---|---|---|
| contribution | AI_DIRECT_ROOT | 93 |
| contribution | AI_NEW_SURFACE_CONTRIBUTOR | 30 |
| contribution | AI_CODE_FLAWED | 21 |
| contribution | AI_INCOMPLETE_REMEDIATION | 15 |
| contribution | AI_CAUSAL_CONTRIBUTOR | 2 |
| cause | injection | 46 |
| cause | auth_access | 37 |
| cause | ssrf_network | 22 |
| cause | other_ambiguous | 18 |
| cause | validation_fail_open | 17 |
| cause | path_link | 15 |
| cause | resource_abuse | 6 |

### `ai-stack-vulnerability` — top 12 of 20 CWEs

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-77 | 4 | 4 | 3 | 4 | 32 | 17% |
| CWE-94 | 4 | 4 | 3 | 4 | 24 | 17% |
| CWE-22 | 3 | 3 | 3 | 5 | 32 | 12% |
| CWE-78 | 3 | 3 | 3 | 6 | 40 | 12% |
| CWE-183 | 2 | 1 | 2 | 4 | 24 | 8% |
| CWE-200 | 2 | 1 | 2 | 4 | 24 | 8% |
| CWE-515 | 2 | 1 | 2 | 4 | 24 | 8% |
| CWE-20 | 1 | 1 | 1 | 2 | 16 | 4% |
| CWE-59 | 1 | 1 | 1 | 2 | 16 | 4% |
| CWE-61 | 1 | 1 | 1 | 2 | 8 | 4% |
| CWE-74 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-79 | 1 | 1 | 1 | 1 | 8 | 4% |

### `malicious-release` — top 1 of 1 CWEs

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-506 | 4 | 3 | 3 | 32 | 40 | 100% |

### `ai-discovered` — top 12 of 20 CWEs

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-416 | 4 | 4 | 3 | 3 | 20 | 14% |
| CWE-121 | 3 | 3 | 2 | 3 | 24 | 11% |
| CWE-295 | 3 | 3 | 2 | 3 | 24 | 11% |
| CWE-77 | 2 | 2 | 2 | 2 | 16 | 7% |
| CWE-22 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-59 | 1 | 1 | 1 | 2 | 16 | 4% |
| CWE-78 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-89 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-90 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-248 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-287 | 1 | 1 | 1 | 1 | 8 | 4% |
| CWE-369 | 1 | 1 | 1 | 1 | 8 | 4% |

### `related` — top 12 of 33 CWEs

| CWE | CVE links | Distinct CVEs | Incidents | IBSS obs | IBSS pot | Share |
|---|---|---|---|---|---|---|
| CWE-78 | 9 | 9 | 3 | 8 | 32 | 20% |
| CWE-22 | 4 | 4 | 3 | 12 | 40 | 9% |
| CWE-306 | 4 | 4 | 3 | 14 | 40 | 9% |
| CWE-20 | 3 | 3 | 1 | 2 | 8 | 7% |
| CWE-77 | 3 | 3 | 2 | 4 | 24 | 7% |
| CWE-59 | 2 | 2 | 1 | 2 | 8 | 4% |
| CWE-89 | 2 | 2 | 1 | 2 | 16 | 4% |
| CWE-122 | 2 | 2 | 2 | 3 | 24 | 4% |
| CWE-200 | 2 | 2 | 2 | 10 | 24 | 4% |
| CWE-269 | 2 | 2 | 2 | 10 | 32 | 4% |
| CWE-285 | 2 | 2 | 2 | 4 | 24 | 4% |
| CWE-416 | 2 | 2 | 2 | 3 | 24 | 4% |

## CNA-CWE IBSS via in-play CVEs — the CVE-path baseline for the CWE ranking

For every CNA-assigned CWE of an in-play CVE: the incidents it reaches through those CVEs (each incident counted once per CWE), their IBSS, and the prevalence behind it. This is the CVE-path half of the CWE thread's formula (incidents linked to a CWE = analyst mapping ∪ CNA CWE of in-play CVEs): the difference between this table and `cwe_priority` will be the contribution of the direct incident-level mapping — which is why analyst-only weaknesses such as CWE-1357 do not appear here at all. Sorted by observed IBSS; 86 CWEs. **Not the CWE ranking.** Full table with ranks: `cwe_ibss_cve_path.csv`.

| CWE | Incidents | Distinct CVEs | IBSS obs | IBSS pot | Rank pot | Incidents (ids) | Segments |
|---|---|---|---|---|---|---|---|
| CWE-306 | 6 | 9 | 38 | 72 | 1 | DR-2026-008, DR-2026-011, DR-2026-020, DR-2026-023, DR-2026-036, DR-2026-057 | ai-exploited, ai-written, ai-stack-vulnerability |
| CWE-506 | 3 | 3 | 32 | 40 | 4 | DB-2026-001, DR-2026-010, DR-2026-022 | malicious-release |
| CWE-94 | 5 | 14 | 16 | 48 | 2 | DR-2026-008, DR-2026-036, DR-2026-062, DR-2026-080, DR-2026-089 | ai-exploited, ai-written, ai-stack-vulnerability |
| CWE-20 | 3 | 5 | 14 | 40 | 5 | DR-2026-008, DR-2026-036, DR-2026-056 | ai-exploited, ai-written, ai-stack-vulnerability |
| CWE-290 | 2 | 2 | 12 | 24 | 9 | DR-2026-011, DR-2026-036 | ai-exploited, ai-written |
| CWE-913 | 2 | 2 | 12 | 24 | 10 | DR-2026-008, DR-2026-036 | ai-exploited, ai-written |
| CWE-918 | 2 | 24 | 12 | 24 | 11 | DB-2026-006, DR-2026-036 | ai-exploited, ai-written |
| CWE-78 | 4 | 13 | 10 | 48 | 3 | DR-2026-036, DR-2026-057, DR-2026-059, DR-2026-062 | ai-written, ai-stack-vulnerability |
| CWE-22 | 4 | 22 | 9 | 40 | 6 | DR-2026-036, DR-2026-060, DR-2026-062, DR-2026-080 | ai-written, ai-stack-vulnerability |
| CWE-77 | 4 | 9 | 8 | 40 | 7 | DR-2026-036, DR-2026-059, DR-2026-081, DR-2026-083 | ai-written, ai-stack-vulnerability |
| CWE-200 | 3 | 10 | 8 | 32 | 8 | DR-2026-036, DR-2026-056, DR-2026-062 | ai-written, ai-stack-vulnerability |
| CWE-95 | 1 | 1 | 8 | 16 | 16 | DR-2026-008 | ai-exploited |
| CWE-287 | 1 | 1 | 8 | 16 | 17 | DB-2026-006 | ai-exploited |
| CWE-502 | 1 | 1 | 8 | 16 | 18 | DB-2026-006 | ai-exploited |
| CWE-59 | 2 | 4 | 6 | 24 | 12 | DR-2026-036, DR-2026-060 | ai-written, ai-stack-vulnerability |
| CWE-942 | 2 | 2 | 6 | 24 | 13 | DR-2026-036, DR-2026-057 | ai-written, ai-stack-vulnerability |
| CWE-522 | 2 | 2 | 6 | 16 | 19 | DR-2026-036, DR-2026-062 | ai-written, ai-stack-vulnerability |
| CWE-74 | 2 | 5 | 5 | 16 | 20 | DR-2026-036, DR-2026-087 | ai-written, ai-stack-vulnerability |
| CWE-79 | 2 | 5 | 5 | 16 | 21 | DR-2026-036, DR-2026-087 | ai-written, ai-stack-vulnerability |
| CWE-269 | 2 | 3 | 5 | 16 | 22 | DR-2026-036, DR-2026-089 | ai-written, ai-stack-vulnerability |
| CWE-693 | 2 | 2 | 5 | 16 | 23 | DR-2026-036, DR-2026-089 | ai-written, ai-stack-vulnerability |
| CWE-183 | 2 | 1 | 4 | 24 | 14 | DR-2026-056, DR-2026-062 | ai-stack-vulnerability |
| CWE-515 | 2 | 1 | 4 | 24 | 15 | DR-2026-056, DR-2026-062 | ai-stack-vulnerability |
| CWE-15 | 1 | 2 | 4 | 8 | 24 | DR-2026-036 | ai-written |
| CWE-41 | 1 | 2 | 4 | 8 | 25 | DR-2026-036 | ai-written |
| CWE-62 | 1 | 1 | 4 | 8 | 26 | DR-2026-036 | ai-written |
| CWE-73 | 1 | 2 | 4 | 8 | 27 | DR-2026-036 | ai-written |
| CWE-80 | 1 | 1 | 4 | 8 | 28 | DR-2026-036 | ai-written |
| CWE-88 | 1 | 1 | 4 | 8 | 29 | DR-2026-036 | ai-written |
| CWE-89 | 1 | 2 | 4 | 8 | 30 | DR-2026-036 | ai-written |
| CWE-119 | 1 | 1 | 4 | 8 | 31 | DR-2026-036 | ai-written |
| CWE-125 | 1 | 1 | 4 | 8 | 32 | DR-2026-037 | ai-stack-vulnerability |
| CWE-176 | 1 | 1 | 4 | 8 | 33 | DR-2026-036 | ai-written |
| CWE-201 | 1 | 2 | 4 | 8 | 34 | DR-2026-036 | ai-written |
| CWE-212 | 1 | 1 | 4 | 8 | 35 | DR-2026-036 | ai-written |
| CWE-214 | 1 | 1 | 4 | 8 | 36 | DR-2026-036 | ai-written |
| CWE-266 | 1 | 1 | 4 | 8 | 37 | DR-2026-036 | ai-written |
| CWE-283 | 1 | 1 | 4 | 8 | 38 | DR-2026-036 | ai-written |
| CWE-284 | 1 | 6 | 4 | 8 | 39 | DR-2026-036 | ai-written |
| CWE-285 | 1 | 1 | 4 | 8 | 40 | DR-2026-036 | ai-written |
| CWE-294 | 1 | 1 | 4 | 8 | 41 | DR-2026-036 | ai-written |
| CWE-307 | 1 | 1 | 4 | 8 | 42 | DR-2026-036 | ai-written |
| CWE-311 | 1 | 1 | 4 | 8 | 43 | DR-2026-036 | ai-written |
| CWE-321 | 1 | 1 | 4 | 8 | 44 | DR-2026-036 | ai-written |
| CWE-327 | 1 | 1 | 4 | 8 | 45 | DR-2026-036 | ai-written |
| CWE-328 | 1 | 1 | 4 | 8 | 46 | DR-2026-036 | ai-written |
| CWE-345 | 1 | 3 | 4 | 8 | 47 | DR-2026-036 | ai-written |
| CWE-346 | 1 | 1 | 4 | 8 | 48 | DR-2026-036 | ai-written |
| CWE-347 | 1 | 2 | 4 | 8 | 49 | DR-2026-036 | ai-written |
| CWE-358 | 1 | 1 | 4 | 8 | 50 | DR-2026-036 | ai-written |
| CWE-367 | 1 | 3 | 4 | 8 | 51 | DR-2026-036 | ai-written |
| CWE-400 | 1 | 1 | 4 | 8 | 52 | DR-2026-036 | ai-written |
| CWE-416 | 1 | 1 | 4 | 8 | 53 | DR-2026-036 | ai-written |
| CWE-426 | 1 | 2 | 4 | 8 | 54 | DR-2026-036 | ai-written |
| CWE-436 | 1 | 1 | 4 | 8 | 55 | DR-2026-036 | ai-written |
| CWE-441 | 1 | 1 | 4 | 8 | 56 | DR-2026-036 | ai-written |
| CWE-459 | 1 | 1 | 4 | 8 | 57 | DR-2026-036 | ai-written |
| CWE-460 | 1 | 1 | 4 | 8 | 58 | DR-2026-036 | ai-written |
| CWE-488 | 1 | 1 | 4 | 8 | 59 | DR-2026-036 | ai-written |
| CWE-532 | 1 | 2 | 4 | 8 | 60 | DR-2026-036 | ai-written |
| CWE-601 | 1 | 2 | 4 | 8 | 61 | DR-2026-036 | ai-written |
| CWE-610 | 1 | 1 | 4 | 8 | 62 | DR-2026-036 | ai-written |
| CWE-636 | 1 | 1 | 4 | 8 | 63 | DR-2026-036 | ai-written |
| CWE-639 | 1 | 9 | 4 | 8 | 64 | DR-2026-036 | ai-written |
| CWE-648 | 1 | 1 | 4 | 8 | 65 | DR-2026-036 | ai-written |
| CWE-657 | 1 | 1 | 4 | 8 | 66 | DR-2026-036 | ai-written |
| CWE-668 | 1 | 2 | 4 | 8 | 67 | DR-2026-036 | ai-written |
| CWE-669 | 1 | 1 | 4 | 8 | 68 | DR-2026-039 | ai-stack-vulnerability |
| CWE-696 | 1 | 1 | 4 | 8 | 69 | DR-2026-036 | ai-written |
| CWE-707 | 1 | 1 | 4 | 8 | 70 | DR-2026-036 | ai-written |
| CWE-732 | 1 | 2 | 4 | 8 | 71 | DR-2026-036 | ai-written |
| CWE-749 | 1 | 1 | 4 | 8 | 72 | DR-2026-036 | ai-written |
| CWE-754 | 1 | 1 | 4 | 8 | 73 | DR-2026-036 | ai-written |
| CWE-770 | 1 | 5 | 4 | 8 | 74 | DR-2026-036 | ai-written |
| CWE-807 | 1 | 2 | 4 | 8 | 75 | DR-2026-036 | ai-written |
| CWE-862 | 1 | 10 | 4 | 8 | 76 | DR-2026-036 | ai-written |
| CWE-863 | 1 | 7 | 4 | 8 | 77 | DR-2026-036 | ai-written |
| CWE-915 | 1 | 2 | 4 | 8 | 78 | DR-2026-036 | ai-written |
| CWE-943 | 1 | 1 | 4 | 8 | 79 | DR-2026-036 | ai-written |
| CWE-1236 | 1 | 1 | 4 | 8 | 80 | DR-2026-036 | ai-written |
| CWE-1295 | 1 | 1 | 4 | 8 | 81 | DR-2026-036 | ai-written |
| CWE-1321 | 1 | 2 | 4 | 8 | 82 | DR-2026-036 | ai-written |
| CWE-1333 | 1 | 1 | 4 | 8 | 83 | DR-2026-036 | ai-written |
| CWE-1336 | 1 | 1 | 4 | 8 | 84 | DR-2026-036 | ai-written |
| CWE-61 | 1 | 1 | 2 | 8 | 85 | DR-2026-062 | ai-stack-vulnerability |
| CWE-829 | 1 | 1 | 1 | 8 | 86 | DR-2026-089 | ai-stack-vulnerability |

## Caveats

- Incident dates are free text for many incidents (e.g. `2026`, `Jun - Jul`), so the exploitation lag is only computed where an ISO date exists.
- Product strings are as recorded by the CNA (e.g. `BerriAI/litellm` vs `BerriAI/LiteLLM`, `n/a/n/a`); they are not normalised here.
- CVSS scores come from one source per CVE (usually the CNA); NVD may score differently. No EPSS / SSVC enrichment in this build.
- The as-cited CWE column is unvalidated and known to be inconsistent in places; see `CWE_validation_handover.md`.
