# Upstream records — provenance and terms

Raw records cached verbatim by `scripts/fetch_upstream.py`; never edited. `manifest.json` records source, fetch date, HTTP status and the record's own update stamp for every file. Re-fetch with `--refresh`.

Terms verified on 2026-09-25 at the URLs given. No record in this directory has been modified.

| directory | source | licence | what redistribution requires |
|---|---|---|---|
| `cve.org/` | CVE Program records (CVE Record Format 5.x, incl. CISA-ADP containers) via https://cveawg.mitre.org/api/cve/ | CVE Terms of Use, https://www.cve.org/Legal/TermsOfUse (text in the website source `CVEProject/cve-website`, `src/views/Legal/TermsOfUse.vue`, last changed 2026-03-18) | Reproduce MITRE's copyright designation and the licence in every copy: both are below. |
| `osv-by-cve/` | OSV.dev records for CVE ids via https://api.osv.dev/v1/vulns/<CVE>; each is generated from the CVE Program's `cvelistV5` record (`database_specific.osv_generated_from`) | as `cve.org/` (OSV passes each source's licence through: https://google.github.io/osv.dev/data/) | as `cve.org/` |
| `ghsa/`, `ghsa-by-cve/` | GitHub Advisory Database via https://api.github.com/advisories/ | CC BY 4.0, https://github.com/github/advisory-database/blob/main/LICENSE.md | Attribution "GitHub Advisory Database", a link to the licence, and a statement that the records are unmodified. |
| `osv/` (MAL- ids) | OpenSSF Malicious Packages via OSV.dev | Apache License 2.0, https://github.com/ossf/malicious-packages/blob/main/LICENSE | A copy of the licence: `LICENSE-Apache-2.0.txt` in this directory. The records are unmodified. |
| `osv/` (PYSEC- ids) | PyPA Advisory Database via OSV.dev | CC BY 4.0, https://github.com/pypa/advisory-database/blob/main/LICENSE | Attribution "PyPA Advisory Database", a link to the licence, unmodified. |
| `cisa-kev/` | CISA Known Exploited Vulnerabilities catalog, https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CC0 1.0, as stated in the catalog's repository `cisagov/kev-data` (`LICENSE`) | Nothing. CISA adds: third-party links in the catalog keep their own terms, and use does not authorize the CISA logo or DHS seal, nor imply endorsement by CISA or DHS. |
| `veris/` | `vcdb-merged.json`, the VERIS JSON schema as merged for the VERIS Community Database, https://github.com/vz-risk/VCDB (branch `master`) | CC BY-SA 4.0, https://github.com/vz-risk/VCDB/blob/master/LICENSE.txt | Attribution "VERIS Community Database (VCDB), vz-risk", a link to the licence, unmodified. ShareAlike applies only to adapted versions; this copy is verbatim. |

### CVE: MITRE's copyright designation and licence

*"CVE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA). Copyright © 1999–2026, The MITRE Corporation. CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation."* (cve.org website footer)

*"CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy."*

*"Disclaimers: ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE."*

Nothing here is a statement by CISA, MITRE, GitHub, OpenSSF, PyPA, OSV or Verizon about this project; the records are reproduced for validation and enrichment of the incident dataset only.
