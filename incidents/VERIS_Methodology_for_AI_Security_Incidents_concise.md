# VERIS Methodology for AI-Related Software Security Incidents

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

### 3.2 Confidentiality: compromise vs. exposure

VERIS explicitly distinguishes actual disclosure from possible exposure with:

`attribute.confidentiality.data_disclosure`

Important values include:

- **Yes** — evidence indicates unauthorized access/viewing occurred;
- **Potentially** — data was exposed or endangered, but unauthorized access has not been demonstrated;
- **No** — no disclosure.

This distinction should be preserved exactly.

For example, a publicly reachable database containing private data may be `Potentially` disclosed if no evidence shows that unauthorized parties accessed it. If logs or attacker behavior demonstrate access, use `Yes`.

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

### 4.2 Actor

Identify who or what caused the event where possible:

- external attacker;
- internal employee;
- partner;
- unknown.

For accidental AI-agent behavior, the conventional actor taxonomy may not perfectly describe the proximate cause. Do not force an automated system into an inappropriate human-attacker category; use the closest valid VERIS representation and explain the AI-specific role separately.

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

These can identify CVEs exploited through hacking or malware.

The natural relationship is therefore:

> **VERIS incident → CVE vulnerability → CVSS**

One incident may involve multiple CVEs, one CVE may cause many incidents, and many incidents have no CVE at all.

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

Near-misses often have **Negligible Observed Severity** but **High or Critical Potential Severity**.

### 8.3 Examples

**Blocked prompt injection**

- VERIS status: Near miss
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
3. **Set event status:** Confirmed / Suspected / Near miss / False positive.
4. **Encode Actor, Action, Asset, Attribute.**
5. **Encode realized consequences:** disclosure, record counts, credentials, integrity changes, downtime, affected assets, losses.
6. **Identify CVE/CVSS and CWE where supported.**
7. **Record AI role/mechanism.**
8. **Rate Observed Severity from realized evidence.**
9. **Construct a bounded potential scenario from demonstrated capability and scope.**
10. **Rate Potential Severity.**
11. **Record confidence and assumptions.**
12. **Re-review difficult/borderline cases.**

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

  observed_severity: "High"
  observed_severity_rationale: "..."

  potential_severity: "Critical"
  potential_severity_rationale: "..."
  potential_severity_confidence: "Medium"

  vulnerabilities:
    - cve: "CVE-2026-..."
      cvss_version: "4.0"
      cvss_score: 9.3

  weaknesses:
    - cwe: "CWE-..."
      mapping_basis: "CVE/CNA"
      confidence: "High"
```

This keeps:

- canonical VERIS data standard-compliant;
- AI-specific methodology explicit;
- weakness/vulnerability information easy to analyze;
- observed and potential severity clearly separated.

---

## 11. Common mistakes to avoid

- **Do not use CVSS as incident severity.**
- **Do not treat exposure as confirmed disclosure.** Use VERIS `Potentially` where appropriate.
- **Do not rank by article count or media attention.**
- **Do not present potential harm as realized harm.**
- **Do not use unconstrained worst-case scenarios.**
- **Do not force non-security AI controversies into the corpus.**
- **Do not invent pseudo-precise 0–100 scores from incomplete public data.**
- **Do not silently infer CWE.**
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
- CWE mapping and provenance.

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
- CWE: https://cwe.mitre.org/
- CVSS / FIRST: https://www.first.org/cvss/

### Optional quantitative risk/loss analysis

- Open FAIR: https://www.opengroup.org/open-fair
- FAIR Institute: https://www.fairinstitute.org/
