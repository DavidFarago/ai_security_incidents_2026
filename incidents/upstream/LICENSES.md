# Incident-side upstream records — provenance and terms

Records cached by `scripts/fetch_upstream.py` and never edited: no value is changed. `manifest.json` records source,
fetch date, HTTP status and the record's own update stamp for every file. Re-fetch with `--refresh`.

`scripts/validate_incidents.py` compares the incidents JSON with these records: every `veris` block with the VERIS
schema, and the VERIS coding of a record that adopts a VCDB record with that VCDB record (methodology §10.2). The
records of the dataset cite VCDB at VCDB's own URLs, pinned to a commit, not at these copies.

| directory | source | licence | what redistribution requires |
|---|---|---|---|
| `veris/` | `vcdb-merged.json`, the VERIS JSON schema as merged for the VERIS Community Database, https://github.com/vz-risk/VCDB (VERIS 1.4.2: branch `1_4_2`, commit `1adb272404b5ccac15e1dc1ff420661ac2ee3752`) | CC BY-SA 4.0, https://github.com/vz-risk/VCDB/blob/master/LICENSE.txt | Attribution "VERIS Community Database (VCDB), vz-risk", a link to the licence, unmodified. ShareAlike applies only to adapted versions; this copy is unmodified. |
| `vcdb/<commit>/<path>` | Each VCDB record whose VERIS coding a record of the dataset adopts, at the VCDB commit that the record's citation pins: https://github.com/vz-risk/VCDB/blob/<commit>/<path> | CC BY-SA 4.0, as `veris/` | As `veris/`. |

Nothing here is a statement by Verizon or the VCDB project about this project; the records are reproduced to verify
the incident dataset only.
