#!/usr/bin/env python3
"""Fetch the upstream vulnerability records cited by the incidents JSON into vulnerabilities/upstream/.

Sources (raw records stored verbatim, never edited):
  cve.org  https://cveawg.mitre.org/api/cve/<CVE>          -> upstream/cve.org/<CVE>.json   (CVE 5.x record, incl. CISA-ADP)
  ghsa     https://api.github.com/advisories/<GHSA>        -> upstream/ghsa/<GHSA>.json     (GitHub Advisory Database)
  osv      https://api.osv.dev/v1/vulns/<MAL|PYSEC id>     -> upstream/osv/<id>.json        (OSV; malicious-package entries)
A manifest (upstream/manifest.json) records per id: source, fetched_on, http_status, the record's own update stamp.
Idempotent: existing records are kept unless --refresh. The builder (build_vulnerabilities.py) reads only this cache.

Usage: python3 scripts/fetch_upstream.py [--refresh] [--only cve.org|ghsa|osv]
GitHub token: $GITHUB_TOKEN or `gh auth token` (unauthenticated calls are limited to 60/h).
"""
from __future__ import annotations
import argparse, datetime as dt, json, os, re, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ROOT / "incidents" / "all_2026_ai_software_security_incidents.json"
UP = ROOT / "vulnerabilities" / "upstream"
UA = "ai_security_incidents_2026/fetch_upstream (https://github.com/) python-urllib"


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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="re-fetch records that are already cached")
    ap.add_argument("--only", choices=["cve.org", "ghsa", "osv"], help="fetch one source only")
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
    plan = []
    if a.only in (None, "cve.org"):
        plan += [("cve.org", x, f"https://cveawg.mitre.org/api/cve/{x}", {}, 0.15, lambda r: (r.get("cveMetadata") or {}).get("dateUpdated")) for x in cves]
    if a.only in (None, "ghsa"):
        plan += [("ghsa", x, f"https://api.github.com/advisories/{x}", gh_headers, 0.25 if tok else 61.0, lambda r: r.get("updated_at")) for x in ghsa]
    if a.only in (None, "osv"):
        plan += [("osv", x, f"https://api.osv.dev/v1/vulns/{x}", {}, 0.2, lambda r: r.get("modified")) for x in osv]
    print(f"plan: {len(plan)} records ({len(cves)} CVE, {len(ghsa)} GHSA, {len(osv)} OSV); github token: {'yes' if tok else 'NO (60 req/h)'}")
    done = skipped = failed = 0
    for src, x, url, hdr, pause, stamp in plan:
        out = UP / src / f"{x}.json"
        if out.exists() and not a.refresh:
            skipped += 1
            continue
        status, rec, rh = get(url, hdr)
        if status == 404 and src == "ghsa" and x != x.lower():   # GitHub's API is case-sensitive; Radar ids are upper-case
            status, rec, rh = get(url.replace(x, "GHSA-" + x[5:].lower()), hdr)
        entry = {"source": src, "file": str(out.relative_to(ROOT)), "fetched_on": today, "http_status": status, "url": url}
        if status == 200 and rec is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rec, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
            entry["updated"] = stamp(rec)
            done += 1
        else:
            failed += 1
            entry["error"] = (rec or {}).get("_error") if isinstance(rec, dict) else None
            print(f"  {src} {x}: HTTP {status} {entry['error'] or ''}", file=sys.stderr)
            if status in (403, 429):
                reset = rh.get("x-ratelimit-reset") or rh.get("X-RateLimit-Reset")
                wait = max(5, int(reset) - int(time.time())) if reset and reset.isdigit() else 60
                print(f"  rate limited; sleeping {wait}s", file=sys.stderr)
                time.sleep(min(wait, 900))
        manifest[x] = entry
        mpath.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        time.sleep(pause)
    print(f"fetched {done}, skipped (cached) {skipped}, failed {failed}; manifest entries {len(manifest)} -> {UP}")


if __name__ == "__main__":
    main()
