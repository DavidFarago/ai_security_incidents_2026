#!/usr/bin/env python3
"""Fetch the upstream vulnerability records cited by the incidents JSON into vulnerabilities/upstream/.

Sources (raw records stored verbatim, never edited):
  cve.org  https://cveawg.mitre.org/api/cve/<CVE>          -> upstream/cve.org/<CVE>.json   (CVE 5.x record, incl. CISA-ADP)
  ghsa     https://api.github.com/advisories/<GHSA>        -> upstream/ghsa/<GHSA>.json     (GitHub Advisory Database)
  osv      https://api.osv.dev/v1/vulns/<MAL|PYSEC id>     -> upstream/osv/<id>.json        (OSV; malicious-package entries)
  cisa-kev CISA KEV catalog (whole feed)                    -> upstream/cisa-kev/known_exploited_vulnerabilities.json
  veris    vz-risk/VCDB vcdb-merged.json (VERIS JSON schema) -> upstream/veris/vcdb-merged.json
For CVEs whose cached CVE record has no CNA title (title fallback chain, methodology §10.2), two alias lookups:
  ghsa-by-cve  https://api.github.com/advisories?cve_id=<CVE> -> upstream/ghsa-by-cve/<CVE>.json (list, may be empty)
  osv-by-cve   https://api.osv.dev/v1/vulns/<CVE>             -> upstream/osv-by-cve/<CVE>.json  (404 = no record)
A manifest (upstream/manifest.json) records per id: source, fetched_on, http_status, the record's own update stamp.
Keys are the plain id for cve.org/ghsa/osv, and "<source>:<id>" for the other sources. A 404 is recorded too, so the
verifier can tell "looked up, nothing found" from "never looked up".
Idempotent: existing records are kept unless --refresh. The builders and the verifier read only this cache.

Usage: python3 scripts/fetch_upstream.py [--refresh] [--only cve.org|ghsa|osv|cisa-kev|veris|ghsa-by-cve|osv-by-cve]
GitHub token: $GITHUB_TOKEN or `gh auth token` (unauthenticated calls are limited to 60/h).
"""
from __future__ import annotations
import argparse, datetime as dt, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ROOT / "incidents" / "all_2026_ai_software_security_incidents.json"
UP = ROOT / "vulnerabilities" / "upstream"
UA = "ai_security_incidents_2026/fetch_upstream (https://github.com/) python-urllib"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VERIS_URL = "https://raw.githubusercontent.com/vz-risk/VCDB/master/vcdb-merged.json"
SOURCES = ["cve.org", "ghsa", "osv", "cisa-kev", "veris", "ghsa-by-cve", "osv-by-cve"]


def github_token():
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10).stdout.strip() or None
    except Exception:
        return None


def get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8")), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, None, dict(e.headers or {})
    except Exception as e:  # network error
        return -1, {"_error": str(e)[:200]}, {}


def ids_from_json():
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    cves, ghsa, osv = set(), set(), set()
    for i in d["incidents"]:
        det = i.get("validated_cve_details") or {}
        for c in det.get("cves") or []:
            cves.add(c["cve"])
        for n in det.get("non_cve_identifiers") or []:
            x = n["id"]
            if x.startswith("GHSA-"):
                ghsa.add(x)
            elif x.startswith(("MAL-", "PYSEC-")):
                osv.add(x)
    return sorted(cves), sorted(ghsa), sorted(osv)


def titleless_cves(cves):
    """CVEs whose cached CVE record has no CNA title: they need the alias lookups of the title chain."""
    out = []
    for x in cves:
        f = UP / "cve.org" / f"{x}.json"
        if f.exists() and not ((json.loads(f.read_text(encoding="utf-8")).get("containers") or {}).get("cna") or {}).get("title"):
            out.append(x)
    return out


def run(plan, manifest, mpath, refresh, today):
    done = skipped = failed = 0
    for src, key, out, url, hdr, pause, stamp in plan:
        if key in manifest and (out.exists() or manifest[key].get("http_status") == 404) and not refresh:
            skipped += 1
            continue
        status, rec, rh = get(url, hdr)
        if status == 404 and src == "ghsa" and key != key.lower():   # GitHub's API is case-sensitive; Radar ids are upper-case
            status, rec, rh = get(url.replace(key, "GHSA-" + key[5:].lower()), hdr)
        entry = {"source": src, "file": str(out.relative_to(ROOT)), "fetched_on": today, "http_status": status, "url": url}
        if status == 200 and rec is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rec, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
            entry["updated"] = stamp(rec)
            done += 1
        elif status == 404 and src in ("ghsa-by-cve", "osv-by-cve"):
            entry["file"] = None   # looked up, no record exists
            done += 1
        else:
            failed += 1
            entry["error"] = (rec or {}).get("_error") if isinstance(rec, dict) else None
            print(f"  {src} {key}: HTTP {status} {entry['error'] or ''}", file=sys.stderr)
            if status in (403, 429):
                reset = rh.get("x-ratelimit-reset") or rh.get("X-RateLimit-Reset")
                wait = max(5, int(reset) - int(time.time())) if reset and reset.isdigit() else 60
                print(f"  rate limited; sleeping {wait}s", file=sys.stderr)
                time.sleep(min(wait, 900))
        manifest[key] = entry
        mpath.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        time.sleep(pause)
    return done, skipped, failed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="re-fetch records that are already cached")
    ap.add_argument("--only", choices=SOURCES, help="fetch one source only")
    a = ap.parse_args()
    today = dt.date.today().isoformat()
    UP.mkdir(parents=True, exist_ok=True)
    mpath = UP / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else {}
    cves, ghsa, osv = ids_from_json()
    tok = github_token()
    gh_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if tok:
        gh_headers["Authorization"] = f"Bearer {tok}"
    gh_pause = 0.25 if tok else 61.0
    want = lambda src: a.only in (None, src)
    # Phase 1: records keyed by the corpus's own identifiers, plus the two whole-file sources.
    plan = []
    if want("cve.org"):
        plan += [("cve.org", x, UP / "cve.org" / f"{x}.json", f"https://cveawg.mitre.org/api/cve/{x}", {}, 0.15, lambda r: (r.get("cveMetadata") or {}).get("dateUpdated")) for x in cves]
    if want("ghsa"):
        plan += [("ghsa", x, UP / "ghsa" / f"{x}.json", f"https://api.github.com/advisories/{x}", gh_headers, gh_pause, lambda r: r.get("updated_at")) for x in ghsa]
    if want("osv"):
        plan += [("osv", x, UP / "osv" / f"{x}.json", f"https://api.osv.dev/v1/vulns/{x}", {}, 0.2, lambda r: r.get("modified")) for x in osv]
    if want("cisa-kev"):
        plan.append(("cisa-kev", "cisa-kev", UP / "cisa-kev" / "known_exploited_vulnerabilities.json", KEV_URL, {}, 0, lambda r: r.get("catalogVersion")))
    if want("veris"):
        plan.append(("veris", "veris:vcdb-merged", UP / "veris" / "vcdb-merged.json", VERIS_URL, {}, 0, lambda r: None))
    r1 = run(plan, manifest, mpath, a.refresh, today)
    # Phase 2: alias lookups, only for CVEs that phase 1 left without a CNA title.
    plan = []
    bare = titleless_cves(cves)
    if want("ghsa-by-cve"):
        plan += [("ghsa-by-cve", f"ghsa-by-cve:{x}", UP / "ghsa-by-cve" / f"{x}.json", f"https://api.github.com/advisories?cve_id={x}", gh_headers, gh_pause, lambda r: None) for x in bare]
    if want("osv-by-cve"):
        plan += [("osv-by-cve", f"osv-by-cve:{x}", UP / "osv-by-cve" / f"{x}.json", f"https://api.osv.dev/v1/vulns/{x}", {}, 0.2, lambda r: r.get("modified")) for x in bare]
    r2 = run(plan, manifest, mpath, a.refresh, today)
    done, skipped, failed = (r1[k] + r2[k] for k in range(3))
    print(f"ids: {len(cves)} CVE ({len(bare)} without CNA title), {len(ghsa)} GHSA, {len(osv)} OSV; github token: {'yes' if tok else 'NO (60 req/h)'}")
    print(f"fetched {done}, skipped (cached) {skipped}, failed {failed}; manifest entries {len(manifest)} -> {UP}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
