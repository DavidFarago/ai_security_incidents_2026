# VERIS Methodology for AI-Related Software Security Incidents

*© 2026 Dave Farago. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). VERIS is the Vocabulary for Event Recording and Incident Sharing of the vz-risk project (https://github.com/vz-risk/veris); this document uses its vocabulary and quotes none of its text.*

## 1. Purpose and methodological decision

This document defines a methodology for describing, evaluating, and ranking **AI-related software security incidents** using **VERIS (Vocabulary for Event Recording and Incident Sharing)** as the primary external framework.

The methodology is intended for a report on AI-related software security incidents in 2026, but should remain reusable for future incident collections.

The main goals are to:

1. describe incidents consistently using a mature cybersecurity incident vocabulary;
2. distinguish **what actually happened** from **what could plausibly have happened**;
3. handle confirmed incidents, suspected incidents, vulnerabilities/exposures, and near-misses;
4. preserve important technical details such as confidentiality, integrity, availability, affected scope, credentials, and recovery;
5. link incidents to **CVE**, **CWE**, and **CVSS** information where available;
6. describe the role of AI without distorting standard VERIS semantics;
7. rank incidents transparently without pretending that a universally accepted incident-severity score exists.

The core decision is:

> **Use VERIS as the single mandatory external framework for incident description. Add only a small report-specific layer for AI-specific metadata, observed severity, potential severity, and CWE provenance.**

Two alternatives were considered and rejected as mandatory ranking layers:

- **NCISS** was rejected because its national-response/critical-infrastructure orientation and coarse impact categories fit these incidents poorly and can discard important information such as affected record or credential counts.
- **FAIR / FAIR-MAM** were rejected as mandatory layers because they add substantial quantitative-loss modeling complexity and assumptions that public incident reports usually do not support. They remain useful optional tools when reliable financial-loss data exists.

Do **not** use CVSS as incident severity. CVSS measures vulnerability severity, not the realized impact of a security incident.

---

## 2. VERIS in a nutshell

VERIS is an open schema and vocabulary for recording cybersecurity incidents consistently.

Its central incident model is often summarized as the **A4 model**:

- **Actor** — who or what was responsible?
- **Action** — what happened?
- **Asset** — what was affected?
- **Attribute** — what security property was affected?

The attribute layer is based on an expanded CIA model:

- Confidentiality / Possession
- Integrity / Authenticity
- Availability / Utility

VERIS also records information such as:

- incident status;
- discovery and response;
- timelines;
- victim information;
- confidence;
- affected data and record counts;
- impact/loss categories;
- monetary loss estimates and ranges;
- an overall qualitative impact rating.

As of August 2026, the public VERIS Community Schema identifies itself as **VERIS Community Schema 1.4.1**.

VERIS is attractive for this report because it is specifically designed for security incidents, is open and machine-readable, is used in the Verizon DBIR ecosystem, and has an associated public incident corpus in the **VERIS Community Database (VCDB)**.

Most importantly, VERIS preserves details that coarse severity scores often discard, including:

- how many records were affected;
- what type of data was affected;
- whether disclosure was confirmed or only possible;
- how many systems/assets were affected;
- how long availability was lost;
- whether integrity was modified;
- what categories of loss occurred.

It also supports **confirmed incidents, suspected incidents, and near-misses**, which is especially useful for AI-security research.

---

## 3. Which AI-security events belong in the report

The AI Incident Database's `Privacy & Security` category is broader than software security. Some privacy or governance incidents do not involve a security compromise at all.

A useful inclusion criterion is:

> **Include an event if AI was materially involved and there was an actual, suspected, or near-miss adverse effect on the confidentiality, possession/control, integrity, authenticity, availability, utility, authorization, or another security-relevant property of a software or information asset.**

This includes cases such as:

- prompt injection;
- agent compromise;
- data or credential exposure;
- malicious agent skills;
- model extraction;
- AI-generated vulnerabilities;
- AI-agent destructive actions;
- unauthorized read/write access;
- security failures caught before exploitation.

This naturally excludes many AI-policy or privacy controversies where no meaningful software-security failure is established.

### 3.1 Event status

VERIS supports:

- **Confirmed**
- **Suspected**
- **Near miss**
- **False positive**

Near-misses are particularly important in this report. A blocked prompt injection or a demonstrated authorization flaw may have negligible realized harm while still being highly security-relevant.

**`Confirmed` requires an affected asset.** Use `Confirmed` or `Suspected` only when the `attribute` section records an effect on the victim's asset: `data_disclosure` Yes, Potentially or Unknown, or an integrity or availability variety. Everything else that meets the inclusion criterion is a `Near miss`, however high its potential severity:

- a flaw demonstrated on the finder's own setup (own installation, test tenant or account);
- a vulnerability disclosure without evidence of exploitation;
- an attack stopped before it affected an asset.

`scripts/validate_incidents.py` fails on a `Confirmed` or `Suspected` record without such an effect.

### 3.2 Confidentiality: compromise vs. exposure

VERIS explicitly distinguishes actual disclosure from possible exposure with:

`attribute.confidentiality.data_disclosure`

Important values include:

- **Yes** — evidence indicates unauthorized access/viewing occurred;
- **Potentially** — data was exposed or endangered, but unauthorized access has not been demonstrated;
- **No** — no disclosure.

This distinction should be preserved exactly.

For example, a publicly reachable database containing private data may be `Potentially` disclosed if no evidence shows that unauthorized parties accessed it. If logs or attacker behavior demonstrate access, use `Yes`.

### 3.3 Vulnerability disclosures: own record or aggregate

A vulnerability disclosure meets the inclusion criterion as a near miss or a demonstrated flaw, but disclosures of AI-related vulnerabilities are far more numerous than incidents with harm (an NVD keyword probe found about 600 AI-related CVEs published in the first eight months of 2026). Without a rule, the disclosure class would dominate every count and every ranking.

A vulnerability disclosure gets **its own incident record** only if at least one of these conditions holds:

- **(a) KEV:** at least one validated CVE of the disclosure is listed in the CISA KEV catalog;
- **(b) exploitation:** a primary source reports that the vulnerability was exploited;
- **(c) realized harm:** the incident has status `Confirmed` (which requires an affected asset, §3.1) and observed severity Low or higher.

Otherwise the disclosure goes into **one aggregate incident per class**. The aggregate's validated CVE layer holds the CVEs of its class, enumerated under §6.7. A ranking or score counts the aggregate once, so a flood of disclosures weighs as one incident, and the aggregate's potential severity still records what the class could cause.

The classes are derived mechanically from the CVE's `relation` (§6.4) and the incident's `ai_role` (§5.1):

| class | derivation | example |
|---|---|---|
| AI-written vulnerabilities | `self-vulnerability`, `ai_role` contains *AI-generated weakness* | flaws in code written by AI coding tools |
| AI-stack vulnerabilities | `self-vulnerability`, any other `ai_role` | flaws in agents, agent harnesses, MCP servers, LLM gateways and other AI products |
| AI-discovered vulnerabilities | `discovered` | flaws found by an AI system or an AI-assisted team |

Finer distinctions, such as the product type or the AI vendor and tool, are recorded as per-CVE attributes, not as further classes. Each class adds one incident's weight to a ranking, so finer classes would make the ranking depend on how finely the classes are cut. A split by vendor would also measure disclosure practice (credit lines, commit markers) rather than risk.

**Realized harm.** Condition (c) also defines the ranking variant **IBSS-observed with realized harm**: the observed incident-based severity score over `Confirmed` incidents with observed severity Low or higher only. It is reported beside IBSS-observed and IBSS-potential.

**Scope.** The rule applies to every incident, including those recorded before the rule was written (2026-09-24). Folding an existing incident into an aggregate removes its record, so §4.1 must first state what happens to the ID of a removed incident.

---

## 4. Minimal VERIS encoding for this project

Do not try to populate every VERIS field merely because it exists. Use the fields that support the report's decisions.

### 4.1 Identification and evidence

Capture at least:

- `incident_id`
- `reference`
- `summary`
- `timeline.incident`
- `security_incident`
- `confidence`

VERIS has a native `confidence` field. Use it rather than inventing a separate generic evidence-confidence field.

**Incident ID scheme (2026 corpus).** `incident_id` is `DB-2026-nnn` (*database*) when at least one source is an incident register (AI Incident Database, VERIS Community Database) and `DR-2026-nnn` (*direct report*) when no source is a register: the incident was found by reading a report directly, a deep-research report or a primary report. The prefix records the discovery channel only, not the quality of the sources. `nnn` is the incident's position in the priority ranking at the time IDs were assigned (2026-08-27) and is unique across both prefixes; it is frozen — later re-ranking changes the ranking table, not the ID, and new incidents continue the sequence. Register record locators (e.g. VCDB UUIDs) belong in `sources`, not in `incident_id`.

### 4.2 Actor

Identify who or what caused the event where possible:

- external attacker;
- internal employee;
- partner;
- unknown.

For accidental AI-agent behavior, the conventional actor taxonomy may not perfectly describe the proximate cause. Do not force an automated system into an inappropriate human-attacker category; use the closest valid VERIS representation and explain the AI-specific role separately.

**Finder vs. actor.** The actor is whoever performed the action, not whoever found it. `Security researcher` is a value of `discovery_method`, not of `actor`.

- A researcher, red team or AI system that **demonstrates** a flaw (a hacking action) is the actor: `external` `Unaffiliated` when outside the victim organization, `internal` `Other` when inside it (a vendor auditing its own product). Name the finder in the actor's `notes`.
- For an **error**, the actor is the party that made the error: the victim's own administrator or developer (`internal`), or the vendor that ran the system (`partner`). The finder appears only in `discovery_method`.
- Motive `NA` means an unintentional action. It fits errors; a deliberate demonstration gets `Other` unless a source states the motive.

### 4.3 Action

Relevant VERIS action varieties include security concepts such as:

- Prompt injection
- Exploit vuln
- Exploit misconfig
- Abuse of functionality
- Use of stolen creds
- OS commanding
- SQLi
- XSS
- malware activity
- error
- misuse

For accidental AI behavior, `action.error` may be more appropriate than forcing the incident into hacking.

**False positives.** The VERIS schema requires an action, but a `False positive` (§3.1) has no security action. Code it as `action.unknown` with result `NA` and a note that says why.

### 4.4 Asset

Capture:

- affected asset type;
- number of affected systems/assets;
- hosted/cloud context where relevant.

### 4.5 Attribute and consequence

Capture the affected security properties:

- confidentiality / possession;
- integrity / authenticity;
- availability / utility.

Where relevant, also record:

- confidentiality data variety;
- confidentiality data amount;
- disclosure status;
- integrity variety;
- availability variety;
- availability duration;
- impact/loss categories;
- monetary impact or ranges when reliably known;
- VERIS overall impact rating when it can be meaningfully assessed.

---

## 5. AI-specific metadata

VERIS was not designed specifically for modern AI-agent systems, so some important concepts do not have perfect native fields.

Examples include:

- model extraction / distillation;
- agent tool authority;
- prompt injection into agent memory/context;
- autonomous destructive action;
- AI-generated vulnerable code;
- poisoned agent skills;
- retrieval/context manipulation;
- model or agent-harness compromise.

Do not distort VERIS semantics to make these concepts fit.

Instead keep:

1. a canonical, valid VERIS record for the cybersecurity facts; and
2. a separate report-specific metadata layer for AI-specific semantics.

Recommended fields:

- `ai_role`
- `ai_component`
- `ai_security_mechanism`
- `ai_involvement_note` (optional; explains borderline or absent AI involvement)
- `observed_severity`
- `observed_severity_rationale`
- `potential_severity`
- `potential_severity_rationale`
- `potential_severity_confidence`
- `cwe`
- `cwe_mapping_basis`

### 5.1 Recommended AI role taxonomy

An incident may have multiple roles:

1. **AI-generated weakness**  
   AI generated or materially contributed to insecure code, configuration, or design.

2. **AI-agent-caused incident**  
   An autonomous or semi-autonomous agent performed a harmful security-relevant action.

3. **AI system/harness attacked**  
   Prompt injection, agent compromise, malicious skill, tool abuse, RAG poisoning, etc.

4. **AI-enabled attacker**  
   AI materially assisted exploitation, social engineering, vulnerability discovery, malware generation, or attack operations.

5. **AI-discovered vulnerability**  
   AI found or helped validate a vulnerability.

6. **AI model/capability theft**  
   Model extraction, distillation, theft of model artifacts, or proprietary capability extraction.

7. **AI security control**  
   AI detected, blocked, mitigated, or otherwise materially affected the security outcome.

These are **report metadata**, not VERIS categories.

### 5.2 Schema note

The current strict VERIS Community Schema 1.4.1 uses `additionalProperties: false` in its schema structure and does not expose a generic top-level `plus.*` namespace in the current public schema.

Therefore:

> **Keep custom AI/report fields outside the canonical VERIS object, or define a separate explicit extension schema.**

---

## 6. Weaknesses, vulnerabilities, CVE, CWE, and CVSS

The incident layer and the vulnerability/weakness layer should remain distinct.

### 6.1 CWE

**CWE (Common Weakness Enumeration)** describes classes of software and hardware weaknesses.

It answers:

> **What kind of underlying weakness was involved?**

Examples include injection, improper authorization, path traversal, improper access control, and command-execution weaknesses.

CWE is not an incident database.

### 6.2 CVE

**CVE (Common Vulnerabilities and Exposures)** identifies individual publicly disclosed vulnerabilities.

It answers:

> **Which specific vulnerability was involved?**

### 6.3 CVSS

CVSS rates the technical severity of a vulnerability.

It answers:

> **How technically severe is this vulnerability?**

It does **not** answer:

> How severe was the real-world incident?

Therefore:

> **Never substitute CVSS for incident severity.**

### 6.4 VERIS and CVE

Current VERIS contains first-class CVE fields, including:

- `action.hacking.cve`
- `action.malware.cve`

**Their meaning is narrow:** a CVE placed there asserts that the vulnerability was *exploited* in the incident through hacking or malware. Many CVEs that legitimately belong to an incident record do not satisfy that: the incident may *be* the disclosure of a vulnerability, an AI system may have *found* it, or an exploit for it may merely have been present in the attacker's toolkit. Putting such CVEs into the VERIS action fields misstates what happened.

Two rules therefore apply.

**Rule 1 — validate every CVE ID before citing it.** Resolve the ID against the CVE.org record (`https://cveawg.mitre.org/api/cve/<ID>`; NVD as a secondary source). Only IDs in state `PUBLISHED` are cited. IDs that do not exist, are `REJECTED` by their CNA, or are still `RESERVED` are not used (a RESERVED ID may be noted as pending). Check that the record's product and description match the incident: an ID copied from a secondary source may belong to a different incident. In the 2026 corpus, 4 of the 46 originally cited IDs failed this check (one non-existent, two rejected, one belonging to another incident).

*Scope of Rule 1 — two layers, kept for every incident.* CVE information is recorded in two layers. The **as-cited layer** (`report.vulnerabilities`, prose in `title` / `summary` / `reference`) holds the IDs exactly as the sources give them and is never edited, so source errors stay visible. The **validated layer** (`validated_cve`, `validated_cve_details`) is produced by applying Rules 1 and 2 to the as-cited IDs plus a search for omitted ones, and is the canonical list. The VERIS fields `action.hacking.cve` / `action.malware.cve` are **derived** from the validated layer: together they hold exactly the incident's CVEs with relation `exploited` (Rule 2), no more and no fewer. Each block lists the CVEs exploited through that action: `action.hacking.cve` for CVEs exploited by the operator or agent (the usual case, including the entry vector of a later ransomware deployment), `action.malware.cve` only for CVEs the malware itself exploited (e.g. a worm's propagation exploit). A CVE appears in both blocks only when it was exploited by both actions.

**Rule 2 — record how each CVE relates to the incident.** Every validated CVE carries one `relation` value:

| relation | meaning | written to VERIS `action.*.cve`? |
|---|---|---|
| `exploited` | primary sources show the CVE was exploited in the incident | yes |
| `exploited-unconfirmed` | same disclosure batch and consistent with the described attack chain, but no source confirms the ID | no |
| `attempted` | exploitation was attempted in the incident but did not succeed / was not needed | no |
| `toolkit` | an exploit for the CVE was present in the attacker's recovered tooling; use against the victim not confirmed | no |
| `self-vulnerability` | the incident *is* the disclosure of this vulnerability — a flaw in legitimate software; no exploitation by an attacker in this incident is asserted (displayed as *self (vulnerability)*) | no |
| `self-malicious-release` | the incident *is* the publication and execution of the artefact this ID identifies — a package or extension version that is malware by design (CNA CWE-506, advisory type *malware*); harm is realized, the countermeasure is removal and credential rotation, not patching (displayed as *self (malicious release)*) | no |
| `discovered` | the CVE is credited to the AI system or AI-assisted team the incident is about | no |
| `related` | same product cluster, disclosure batch or campaign, explicitly linked by the sources | no |

`action.hacking.cve` and `action.malware.cve` together hold exactly the `exploited` CVEs. This restricts only these two fields: CVEs with every other relation are recorded in the validated layer (`validated_cve`, `validated_cve_details`; §10.2), and the as-cited layer keeps whatever the sources cite. Where a single ordering of relations is needed (sorting, tie-breaking), use: exploited > self-malicious-release > exploited-unconfirmed > attempted > toolkit > self-vulnerability > discovered > related.

**Evidence signals.** A CISA KEV listing is recorded as a per-CVE flag: it is evidence that the CVE is exploited *somewhere*, not that it was exploited in *this* incident. CVSS is recorded together with its version, because CNA scores (often v4.0) and NVD scores (often v3.1) differ.

The natural relationship remains:

> **VERIS incident → CVE vulnerability → CVSS**

One incident may involve multiple CVEs, one CVE may cause many incidents, and many incidents have no CVE at all (see §6.6 for what to record instead).

### 6.5 VERIS and CWE

VERIS does not provide a general first-class CWE field comparable to its CVE fields.

Therefore:

1. use the CWE listed by the CVE/CNA/NVD when available;
2. if no CVE exists, assign a CWE only when the evidence supports a defensible mapping;
3. distinguish authoritative CWE mappings from analyst-inferred mappings.

Example:

```yaml
weaknesses:
  - cwe: "CWE-..."
    mapping_basis: "CVE/CNA"
    confidence: "High"
```

or:

```yaml
weaknesses:
  - cwe: "CWE-..."
    mapping_basis: "Analyst inference from demonstrated authorization flaw"
    confidence: "Medium"
```

Do not silently infer CWE.

### 6.6 Non-CVE identifiers

CVE covers vulnerabilities in legitimate software. It does **not** cover malicious package releases, account-takeover publishes, or server-side flaws that a vendor fixes without assigning an ID. A large share of AI supply-chain incidents therefore never receive a CVE and are identified only by:

| identifier | issuer | typical use |
|---|---|---|
| `GHSA-xxxx-xxxx-xxxx` | GitHub Advisory Database. GitHub is a CVE Numbering Authority: a *reviewed* GHSA usually aliases a CVE; a `malware`-type GHSA usually does not | malicious npm/PyPI releases; repository advisories |
| `MAL-YYYY-NNNN` | OpenSSF malicious-packages repository, served via OSV.dev | malicious package versions |
| `PYSEC-YYYY-N` | PyPA advisory database | Python packages |
| vendor / CERT advisories (`MFSA`, `RHSB`, `SA-CORE`, `FreeBSD-SA`, `VU#`, `ZDI`, `EXIM-Security`) | the vendor or CERT | usually alias a CVE; occasionally the only ID |

Record these in `non_cve_identifiers` (id, kind, note). Never place them in a CVE field, and never conclude "no identifier exists" without checking the GitHub Advisory Database and OSV.dev. GHSA and OSV are complementary to CVE, not competing schemes; genuinely separate numbering schemes (GCVE, EUVD) exist but are not used in this report.

### 6.7 AI-discovered vulnerabilities and aggregate incidents

For incidents whose AI role is *AI-discovered vulnerability*, the CVE list is the set of CVEs credited to the AI system or AI-assisted team. Evidence, in order of strength: the `credits` field of the CVE record, where the discovery roles are `finder`, `reporter`, `analyst` and `tool` (other roles, such as `coordinator` or `remediation developer`, are not evidence of discovery); the vendor advisory's reporter line (Mozilla MFSA, MSRC CVRF acknowledgements, FreeBSD-SA); the discoverer's own publication. Some CNAs (Linux kernel, Chrome) carry no credit field, so attribution there rests on release notes or commit trailers and must be marked as such. A vendor claim of "N vulnerabilities found" rarely maps to N CVEs: fixes may be bundled into rollup CVEs or receive none.

For aggregate incidents (a wave of vulnerabilities rather than one event; §3.3 says when a disclosure becomes part of one), enumerate constituent CVEs only from a named curated corpus, scope them to the report year, exclude RESERVED IDs, and record the corpus and its cut-off date in the note. A curated corpus is either an external list maintained with its own inclusion checks (e.g. Vibe Security Radar) or a frozen sweep output of this project: a file under `incidents/sources/` that records the script, the query, the run date, and the screening of every hit against the §3 criterion. A sweep output is frozen once cited; a later run produces a new file.

---

## 7. Observed vs. potential impact

This distinction is central to the methodology.

### 7.1 Observed impact

**Observed impact** is the harm supported by evidence as having actually occurred.

Examples:

- data was actually accessed;
- credentials were actually stolen;
- files were modified;
- production systems were unavailable;
- an agent deleted data;
- unauthorized access occurred;
- financial losses were reported.

The report's **Observed Severity** summarizes this realized impact.

### 7.2 Potential impact

**Potential impact** is the plausible consequence if the **demonstrated security failure or attack path** had successfully realized its documented capability.

Examples:

- a prompt injection was blocked before modifying data;
- an authorization flaw exposed thousands of reachable devices but no exploitation was demonstrated;
- credentials were publicly exposed but no evidence shows they were used;
- an AI agent obtained dangerous permissions but was stopped before a destructive action.

The report's **Potential Severity** summarizes this bounded counterfactual impact.

### 7.3 Potential does not mean worst imaginable

Do not ask:

> What is the worst possible thing that could theoretically follow?

Instead ask:

> **Given the capability, access, scope, and attack path actually demonstrated by the evidence, what harm could reasonably have resulted if that demonstrated path had successfully completed?**

Guardrails:

- do not assume unrelated vulnerabilities;
- do not assume privilege escalation unless supported;
- bound scope by documented reachable systems/users/data;
- respect controls that demonstrably remained effective;
- state material assumptions;
- lower confidence when the counterfactual depends on uncertain facts.

### 7.4 Do not confuse two meanings of “potential”

VERIS `data_disclosure = Potentially` means:

> confidential data may have been exposed, but actual unauthorized access is unproven.

Report `potential_severity` means:

> how severe the incident could reasonably have become if the demonstrated failure had realized.

These are different concepts and must remain separate.

---

## 8. Severity rubric and ranking

There is no universally accepted CVSS-like score for historical software-security incidents.

Use a transparent ordinal scale:

1. **Critical**
2. **High**
3. **Medium**
4. **Low**
5. **Negligible**

This is a **report-specific rubric derived from VERIS evidence**, not an official VERIS score.

### 8.1 Inputs

Observed and Potential Severity should consider:

- **Confidentiality / possession:** sensitivity, actual vs. potential disclosure, affected record count, credentials/tokens and their privilege, number of users/organizations affected.
- **Integrity / authenticity:** unauthorized modification, read/write authority, code/configuration manipulation, impersonation, persistence, affected scope.
- **Availability / utility:** interruption, destruction, deletion, duration, number of users/systems, service criticality, reversibility.
- **Direct/indirect impact:** financial loss, recovery effort, business interruption, legal/regulatory impact, safety/physical effects.
- **Recoverability/persistence:** reversible changes versus permanent disclosure, irreversible deletion, persistent credential compromise, or unrecoverable IP/model loss.
- **Scale:** number of records, credentials, systems, users, or organizations affected.

Do not mechanically sum points. Use a **dominant-consequence assessment**:

1. identify the strongest substantiated consequence;
2. interpret it in light of scale, sensitivity, duration, privilege, and recoverability;
3. document the rationale;
4. record confidence.

### 8.2 Severity anchors

**Critical**  
Realized or plausibly realizable catastrophic/systemic consequences, such as destructive loss of critical production systems, very large-scale compromise of highly sensitive data or privileged credentials, major supply-chain compromise, major critical-service outage, or serious physical/safety consequences.

**High**  
Major material security harm, such as large-scale sensitive-data exposure, significant credential/token compromise, unauthorized privileged or production read/write access, substantial integrity compromise, prolonged/widespread outage, or meaningful multi-organization compromise.

**Medium**  
Material but contained impact, such as limited sensitive-data exposure, compromise of a bounded number of systems/accounts, recoverable production impact, or significant but contained integrity/availability loss.

**Low**  
Limited realized impact, such as small-scope low-sensitivity disclosure, quickly reversible unauthorized changes, short non-critical service interruption, or limited exposure with little downstream harm.

**Negligible**  
Little or no realized security harm.

Near-misses often have **Negligible Observed Severity** but **High or Critical Potential Severity**. A near miss compromised no asset of its victim, so rate it Negligible unless the rationale names another realized effect (for example, an AI agent escaping its test sandbox).

### 8.3 Examples

**Blocked prompt injection**

- VERIS status: Near miss
- Observed Severity: Negligible
- Potential Severity: High

**Vulnerability demonstrated on the finder's own setup, disclosed and fixed**

- VERIS status: Near miss
- disclosure: No
- Observed Severity: Negligible
- Potential Severity: High

**Authorization flaw affecting thousands of devices, with no demonstrated exploitation**

- disclosure: Potentially
- Observed Severity: Low
- Potential Severity: High

**Large credential exposure with broad privilege**

- Observed Severity: High
- Potential Severity: Critical

### 8.4 VERIS overall impact vs. report severity

Do not discard `impact.overall_rating`, but keep it conceptually distinct.

VERIS overall impact asks roughly:

> How badly did this incident hurt the affected organization?

The report severity scale is intended for **cross-incident comparison**.

Therefore this is possible:

```text
VERIS overall impact: Painful
Report Observed Severity: High
Report Potential Severity: Critical
```

A large organization may absorb a technically serious incident without the event becoming existential to the organization.

---

## 9. Confidence, workflow, and ranking

### 9.1 Confidence

Use VERIS's native `confidence` field.

Confidence is **not severity**.

Do not increase severity because many articles covered an incident, and do not reduce severity merely because one high-quality primary source is the only source.

Prefer evidence roughly in this order:

1. primary technical advisory, postmortem, or incident report;
2. affected vendor/operator statement;
3. security-researcher report with reproducible evidence;
4. regulator, law-enforcement, or court documentation;
5. high-quality independent reporting;
6. secondary summaries or social media.

For every important claim, distinguish:

- directly documented fact;
- reasonable inference;
- unknown.

Potential severity may need a separate confidence value because the counterfactual can be more uncertain than the underlying VERIS record.

### 9.2 Recommended workflow

For each candidate event:

1. **Establish inclusion.**
2. **Collect primary evidence and references.**
3. **Set event status:** Confirmed / Suspected / Near miss / False positive; `Confirmed` and `Suspected` require an effect recorded in step 4 (§3.1).
4. **Encode Actor, Action, Asset, Attribute.**
5. **Encode realized consequences:** disclosure, record counts, credentials, integrity changes, downtime, affected assets, losses.
6. **Identify candidate CVEs and CWE where supported.**
7. **Validate and classify CVEs:** resolve each ID at CVE.org, assign a `relation` (§6.4), and search CISA KEV, the GitHub Advisory Database, OSV.dev and the incident's primary sources for omitted CVEs and non-CVE identifiers (§6.6).
8. **Record AI role/mechanism.**
9. **Rate Observed Severity from realized evidence.**
10. **Construct a bounded potential scenario from demonstrated capability and scope.**
11. **Rate Potential Severity.**
12. **Record confidence and assumptions.**
13. **Re-review difficult/borderline cases.**

### 9.3 Ranking

Do not collapse Observed and Potential Severity into one score.

Recommended opening-table columns:

| Incident | Status | Observed | Potential | Confidence | CVE/CWE | AI role |
|---|---|---|---|---|---|---|

If the report is ordered by the severity of what actually happened:

1. **Observed Severity** descending;
2. **Potential Severity** as a tiebreaker;
3. realized scope/impact;
4. confidence as an interpretive signal, not a harm multiplier.

Do not rank a near-miss above a catastrophic realized breach merely because its hypothetical potential was greater.

---

## 10. Recommended data model

Use two layers.

### 10.1 Canonical VERIS layer

```yaml
veris:
  schema_version: "1.4.1"
  incident_id: "..."
  security_incident: "Confirmed | Suspected | Near miss | False positive"
  confidence: "High | Medium | Low | None"
  reference:
    - "..."
  summary: "..."

  actor:
    ...

  action:
    ...

  asset:
    ...

  attribute:
    confidentiality:
      data_disclosure: "Yes | Potentially | No | Unknown"
      data:
        - variety: "..."
          amount: 0
    integrity:
      ...
    availability:
      ...

  impact:
    loss:
      ...
    overall_rating: "..."
```

The exact JSON must follow the current VERIS schema; this YAML is illustrative only.

### 10.2 Report metadata layer

```yaml
report:
  ai_role:
    - "AI-agent-caused incident"

  ai_component:
    - "coding agent"
    - "tool harness"

  ai_security_mechanism:
    - "prompt injection"

  ai_involvement_note: "..."                 # optional; explains borderline or absent AI involvement

  observed_severity: "High"
  observed_severity_rationale: "..."

  potential_severity: "Critical"
  potential_severity_rationale: "..."
  potential_severity_confidence: "Medium"

  # as-cited layer: IDs exactly as the sources give them; never edited
  vulnerabilities:
    - cve: "CVE-2026-..."
      cvss_version: "4.0"
      cvss_score: 9.3

  weaknesses:
    - cwe: "CWE-..."
      mapping_basis: "CVE/CNA"
      confidence: "High"

# validated layer (canonical; see 6.4, 6.6): a sibling of `veris` and `report` at the incident's top level.
# VERIS action.*.cve is derived from it (relation exploited only)
validated_cve:
  - "CVE-2026-..."
validated_cve_details:
  validated_on: "2026-08-26"
  method_ref: "see top-level cve_validation.method"
  original_cve_mentions: ["CVE-2026-..."]   # every ID cited anywhere in the original record
  added: ["CVE-2026-..."]
  removed:
    - cve: "CVE-2026-..."
      state: "REJECTED"
      reason: "..."
  cves:
    - cve: "CVE-2026-..."
      relation: "exploited"                  # vocabulary of 6.4
      in_original: true
      state: "PUBLISHED"
      cna: "GitHub_M"
      published: "2026-04-09"
      title: "..."                           # from the CVE record
      product: "vendor/product"
      cvss_version: "4.0"
      cvss_score: 9.3
      cwe: ["CWE-306"]
      cisa_kev: true
      kev_date_added: "2026-04-23"
      credits:                               # every CNA credit, with its role
        - value: "..."
          type: "finder"                     # finder | reporter | analyst | coordinator | remediation developer | ... | null
      record_url: "https://www.cve.org/CVERecord?id=CVE-2026-..."
      note: "..."
  non_cve_identifiers:
    - id: "GHSA-xxxx-xxxx-xxxx"
      kind: "GHSA (malware)"
      note: "..."
  note: "..."
```

`validated_cve` and `validated_cve_details` are siblings of `veris` and `report` at the incident's top level, not
children of `report`. The table gives their paths.

Where the CVE information lives in the 2026 corpus files:

| layer | JSON (`all_2026_ai_software_security_incidents.json`) | CSV | MD |
|---|---|---|---|
| as cited (never edited) | `report.vulnerabilities[].cve`; free text in `title`, `veris.summary`, `veris.reference`; `ranking_table[].cve_cwe` | `cve` column | title text; `· CVE:` on the VERIS line |
| validated (canonical) | `validated_cve`; `validated_cve_details`; `ranking_table[].validated_cve`; top-level `cve_validation` | `validated_cve` column | `**Validated CVEs:**` line per entry |
| VERIS (derived) | `veris.action.hacking.cve` / `veris.action.malware.cve` = validated CVEs with relation `exploited` only | — | — |

The as-cited fields are retained unchanged for provenance; the validated fields are canonical; the VERIS action fields are derived from them. Only CVEs were validated: the CWE fields (`report.weaknesses`, `cwe`, the CWE part of `cve_cwe`) are as cited.

**Copied CVE metadata.** The following fields of `validated_cve_details.cves[]` are copies of upstream records. `scripts/validate_incidents.py` re-derives each one from the records cached under `vulnerabilities/upstream/` and fails on any difference:

| field | rule |
|---|---|
| `state`, `cna`, `published` | `cveMetadata.state`, `.assignerShortName`, date part of `.datePublished`; `state` must be `PUBLISHED` |
| `product` | the distinct `vendor/product` pairs of `containers.cna.affected[]`, sorted, joined with `; ` (a missing part is `?`) |
| `title` | the first that exists: `containers.cna.title`; the CISA KEV `vulnerabilityName`; the `summary` of a reviewed GitHub advisory for the CVE; the `summary` of an OSV record aliasing the CVE; the first sentence of the CNA's English description. ADP `title` values name the container (e.g. "CISA ADP Vulnrichment"), not the vulnerability, and are never used |
| `cvss_version`, `cvss_score` | one (version, base score) pair from any metrics entry of the CNA or an ADP container; empty only if no container has one |
| `cwe` | a subset of the CWE IDs of one container (CNA or ADP) |
| `credits` | a list with one object per entry of `containers.cna.credits[]`, in record order, duplicates kept: `value`, `type` (the role; `null` where the record gives none — the CVE schema defines no default), and `user` (CVE User Registry UUID) where present; `lang` is not kept. Values are verbatim, including encoding errors of the CNA. Where the CNA has no credits the field is absent, and attribution evidence per §6.7 goes into the `note` |
| `cisa_kev`, `kev_date_added` | listed in the cached CISA KEV catalog; its `dateAdded` |
| `record_url` | `https://www.cve.org/CVERecord?id=<CVE>` |

A difference that is correct on purpose is recorded on the `cves[]` entry as `overrides: {"<field>": "<reason>"}`; the verifier prints every override on every run.

**Change logs in the data.** The JSON records a reason only where its data deliberately differs from an external source: a value copied from an upstream record (`overrides`, above) or a VERIS coding adopted from a register record. A fix of this project's own coding, including a value copied wrongly and then restored, gets no log in the data; git history records it, and §14 records any rule it changes.

This keeps:

- canonical VERIS data standard-compliant;
- CVE citations verifiable, with their relation to the incident explicit;
- AI-specific methodology explicit;
- weakness/vulnerability information easy to analyze;
- observed and potential severity clearly separated.

---

## 11. Common mistakes to avoid

- **Do not use CVSS as incident severity.**
- **Do not treat exposure as confirmed disclosure.** Use VERIS `Potentially` where appropriate.
- **Do not code a demonstrated flaw as `Confirmed`.** Without an affected asset it is a `Near miss` (§3.1).
- **Do not rank by article count or media attention.**
- **Do not present potential harm as realized harm.**
- **Do not use unconstrained worst-case scenarios.**
- **Do not force non-security AI controversies into the corpus.**
- **Do not invent pseudo-precise 0–100 scores from incomplete public data.**
- **Do not silently infer CWE.**
- **Do not cite a CVE ID without resolving it.** Non-existent, REJECTED and RESERVED IDs are not cited; an ID taken from a secondary source may belong to another incident (§6.4).
- **Do not put a discovered, related or toolkit CVE into a VERIS action field.** Those fields hold exactly the `exploited` CVEs (§6.4).
- **Do not treat GHSA / OSV / vendor advisory IDs as CVEs,** and do not conclude "no identifier" without checking those databases (§6.6).
- **Do not modify VERIS semantics to fit AI.** Keep custom AI/report fields separate.

---

## 12. Final methodological summary

The recommended methodology is:

> **VERIS is the single mandatory external framework for describing AI-related software-security incidents.**

Use VERIS for:

- incident status;
- Actor / Action / Asset / Attribute;
- confidentiality / integrity / availability;
- confirmed vs. potential disclosure;
- affected scope;
- impact/loss;
- confidence;
- CVE linkage where applicable.

Add a small report-specific layer for:

- AI role and mechanism;
- Observed Severity;
- Potential Severity;
- bounded potential-impact rationale;
- CWE mapping and provenance;
- validated CVEs with their relation to the incident, plus non-CVE identifiers.

Do not use:

- **NCISS** as the ranking layer;
- **FAIR / FAIR-MAM** as a mandatory layer;
- **CVSS** as incident severity.

FAIR/FAIR-MAM remain optional for incidents where detailed quantitative financial-loss analysis is justified by sufficient data.

Conceptually:

```text
Public evidence / AIID / vendor reports / advisories
                    |
                    v
             Inclusion decision
                    |
                    v
              VERIS incident
  status + A4 + CIA + scope + impact + confidence
                    |
          +---------+----------+
          |                    |
          v                    v
   CVE -> CVSS            CWE weakness
          |
          v
     AI-specific metadata
          |
          v
   Observed Severity
          +
   Potential Severity
          |
          v
       Report ranking
```

This preserves standardization where a mature framework exists and makes the genuinely report-specific judgments explicit rather than disguising them as an industry-standard score.

---

## 13. References

### VERIS

- VERIS home: https://verisframework.org/
- VERIS GitHub repository: https://github.com/vz-risk/veris
- Current community schema: https://github.com/vz-risk/veris/blob/master/verisc-merged.json
- VERIS attributes: https://verisframework.org/attributes.html
- VERIS impact assessment: https://verisframework.org/impact.html
- Getting started with VERIS: https://verisframework.org/howto.html
- VERIS Community Database: https://verisframework.org/vcdb.html

### Vulnerabilities and weaknesses

- CVE: https://www.cve.org/
- CVE record API (MITRE): https://cveawg.mitre.org/api/cve/
- NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- GitHub Advisory Database: https://github.com/advisories
- OSV.dev (incl. OpenSSF malicious packages): https://osv.dev/
- CWE: https://cwe.mitre.org/
- CVSS / FIRST: https://www.first.org/cvss/

### Optional quantitative risk/loss analysis

- Open FAIR: https://www.opengroup.org/open-fair
- FAIR Institute: https://www.fairinstitute.org/

---

## 14. Revision history

- **2026-08-27** — After validating every CVE citation in the 2026 corpus: added CVE validation rules and the `relation` vocabulary (§6.4), non-CVE identifiers (§6.6), guidance for AI-discovered and aggregate incidents (§6.7), workflow step 7 (§9.2), the validated CVE layer and the file map of as-cited vs. validated fields (§10.2), three further mistakes (§11) and vulnerability-database references (§13). VERIS core, severity rubric and observed/potential model unchanged.
- **2026-08-27 (b)** — Made the two-layer structure (as-cited / validated) the standing rule for all incidents, with the VERIS `action.*.cve` fields derived from the validated layer (§6.4, §10.2). The 2026 corpus's VERIS action fields were aligned accordingly (10 fields; previous values kept in `validated_cve_details.veris_cve_before`).
- **2026-08-27 (c)** — Documented the incident ID scheme (§4.1): `DB-`/`DR-` prefix by provenance, frozen rank number.
- **2026-08-29** — §6.4 Rule 2: relation `primary` split into `self-vulnerability` / `self-malicious-release`; relevance order stated. Applied to the 2026 corpus (196 / 4 links); recorded in `cve_validation.relation_revision`.
- **2026-09-24** — §4.1: `DR` redefined as *direct report* (no register source; found through a deep-research or a primary report); the prefix records the discovery channel, not source quality. §5 and §10.2 aligned with the JSON data model.
- **2026-09-25** — §3.3: rule for vulnerability disclosures (own record only with a KEV listing, a primary exploitation report or realized harm; otherwise one aggregate per class: AI-written, AI-stack, AI-discovered), the definition of IBSS-observed with realized harm, and its scope (all incidents). §6.7: a frozen sweep output counts as a curated corpus. §10.2: transcription rules for copied CVE metadata, per-field `overrides`, and the `cve_validation.metadata_corrections` log.
- **2026-09-25 (b)** — §10.2: `credits` is a list of typed credits (`value`, `type`, `user` where present) instead of one joined string, so the credit role is kept; §6.7 names the discovery roles. Applied to the 2026 corpus (127 links); recorded in `cve_validation.credits_revision`.
- **2026-09-26** — §4.2: finder vs. actor (the finder goes into `discovery_method`; the actor of an error is the party that made it; a deliberate demonstration has motive `Other`, not `NA`). §4.3: a `False positive` is coded `action.unknown`. Applied to the 2026 corpus, which fixes its 36 errors against the VCDB schema (29 actor codings, 5 missing actions, 1 misplaced `confidentiality.amount`, 1 invalid NAICS code); the verifier now passes.
- **2026-09-26 (b)** — §3.1: `Confirmed` and `Suspected` require an effect in the VERIS `attribute` section; a demonstrated flaw, an unexploited disclosure or a stopped attack is a `Near miss`. The verifier checks it. §3.3 (c), §8.2, §8.3 (new example), §9.2 step 3 and §11 point to the rule. Applied to the 2026 corpus: 22 records `Confirmed` → `Near miss` (21 vulnerability disclosures and one stopped attack); 4 of them observed Low → Negligible under §8.2. The verifier's disclosure measurement, which sees only disclosures with a CVE, rises from 13 to 17; counting the disclosures without a CVE (DR-2026-065, 086, 090, 092), 21 fail §3.3 (a) and (c), up from 16.
- **2026-09-27** — §10.2: change logs in the data are kept only where the data deliberately differs from an external source (an upstream record, via `overrides`, or a VERIS coding adopted from a register record); fixes of this project's own coding are recorded by git and §14. Removed from the 2026 corpus accordingly, all of them records of our own fixes: `cve_validation.veris_action_cve_alignment` with the per-incident `veris_cve_field` / `veris_cve_before` / `veris_cve_after` (10 incidents; §6.4 and §10.2 no longer mention them), `cve_validation.relation_revision`, `cve_validation.credits_revision`, `cve_validation.metadata_corrections` (with its §10.2 rule) and `source_corrections`. Git holds them (commits `f04247c`, `7d850e8`, `473c073`, `ecb3ccd`). The rules they applied (§6.4, §10.2) are unchanged.
