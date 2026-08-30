# Upstream records — provenance and terms

Raw vulnerability records cached verbatim by `scripts/fetch_upstream.py`; never edited. `manifest.json` records source, fetch date, HTTP status and the record's own update stamp for every file. Re-fetch with `--refresh`.

| directory | source | terms |
|---|---|---|
| `cve.org/` | CVE Program records (CVE Record Format 5.x, incl. CISA-ADP containers) via https://cveawg.mitre.org/api/cve/ | CVE® is sponsored by CISA and operated by The MITRE Corporation. Redistribution of CVE records is permitted under the **CVE Terms of Use** (https://www.cve.org/Legal/TermsOfUse), which require that this notice accompany any copy: *"CVE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA). Copyright © 1999–2026, The MITRE Corporation. CVE and the CVE logo are registered trademarks of The MITRE Corporation."* Verify the current wording at the URL above before publication. |
| `ghsa/` | GitHub Advisory Database via https://api.github.com/advisories/ | Advisory data is licensed **CC-BY-4.0** (https://github.com/github/advisory-database#license); attribution: GitHub Advisory Database. Malware-type advisories originate from the OpenSSF malicious-packages project (Apache-2.0). |
| `osv/` | OSV.dev records (MAL-, PYSEC- ids) via https://api.osv.dev/v1/vulns/ | Aggregated by OSV under the source databases' licences: OpenSSF malicious-packages (Apache-2.0), PyPA advisory-db (CC-BY-4.0). |

Nothing here is a statement by CISA, MITRE, GitHub or OSV about this project; the records are reproduced for validation and enrichment of the incident dataset only.
