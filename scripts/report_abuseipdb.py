#!/usr/bin/env python3
"""Report new honeypot attacker IPs to AbuseIPDB (bulk-report endpoint).

Reads the latest data/snapshot-*.json, builds a bulk-report CSV for IPs not
yet reported (tracked in data/abuseipdb-reported.json), and POSTs it to
https://api.abuseipdb.com/api/v2/bulk-report.

- Report comments are generic; nothing identifies the sensor setup.
- Each IP is reported once (dedupe via the state file).
- Rows are capped per run to stay under the free-tier daily quota; the
  remainder is picked up on the next run (worst offenders first).
- AbuseIPDB rejects ReportDates older than two months, so stale IPs are
  skipped.

Env:
    ABUSEIPDB_API_KEY  required; if unset the script exits 0 doing nothing.

Usage:
    python scripts/report_abuseipdb.py [--dry-run]
"""

import csv
import glob
import io
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
STATE_PATH = os.path.join(DATA, "abuseipdb-reported.json")

API_URL = "https://api.abuseipdb.com/api/v2/bulk-report"
# Free tier allows 1,000 reports/day; stay comfortably under it.
MAX_ROWS_PER_RUN = 900
# AbuseIPDB rejects ReportDates older than two months; keep a safety margin.
MAX_AGE_DAYS = 55

# service/flag -> (abuseipdb categories, generic comment)
ACTIVITY = {
    "ssh": ([18, 22], "SSH brute-force login attempts observed."),
    "http": ([21], "Automated web-application probing observed."),
    "jenkins": ([21], "Automated Jenkins probing observed."),
    "misc": ([15], "Probing of exposed network services observed."),
    "flag:env": ([15], "Attempts to retrieve environment files observed."),
    "flag:wp": ([18, 21], "WordPress login brute-force attempts observed."),
}


def latest_snapshot():
    files = sorted(glob.glob(os.path.join(DATA, "snapshot-*.json")))
    if not files:
        print("no snapshots found, nothing to do")
        sys.exit(0)
    with open(files[-1]) as fh:
        return json.load(fh)


def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as fh:
            return json.load(fh)
    return {}


def save_state(state):
    with open(STATE_PATH, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)


def build_rows(snapshot, reported):
    now = time.time()
    cutoff = now - MAX_AGE_DAYS * 86400
    rows = []
    for ip, rec in snapshot.get("ips", {}).items():
        if ip in reported:
            continue
        last = rec.get("last", 0)
        if last < cutoff:
            continue  # too stale; AbuseIPDB would reject it
        cats, comments = set(), []
        for svc in rec.get("services", {}):
            if svc in ACTIVITY:
                c, msg = ACTIVITY[svc]
                cats.update(c)
                comments.append(msg)
        for flag in rec.get("flags", []):
            key = "flag:" + flag
            if key in ACTIVITY:
                c, msg = ACTIVITY[key]
                cats.update(c)
                comments.append(msg)
        if not cats:
            continue
        # de-dupe comments, keep stable order
        seen, uniq = set(), []
        for m in comments:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        comment = " ".join(uniq)[:1000]
        report_date = datetime.fromtimestamp(last, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00")
        rows.append({
            "ip": ip,
            "categories": ",".join(str(c) for c in sorted(cats)),
            "report_date": report_date,
            "comment": comment,
            "hits": rec.get("hits", 0),
        })
    rows.sort(key=lambda r: r["hits"], reverse=True)
    return rows[:MAX_ROWS_PER_RUN]


def to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow(["IP", "Categories", "ReportDate", "Comment"])
    for r in rows:
        w.writerow([r["ip"], r["categories"], r["report_date"], r["comment"]])
    return buf.getvalue()


def main():
    dry_run = "--dry-run" in sys.argv
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    snapshot = latest_snapshot()
    reported = load_state()
    rows = build_rows(snapshot, reported)
    print("snapshot %s: %d unreported IPs, submitting %d"
          % (snapshot.get("date"), len(rows) if rows else 0, len(rows)))
    if not rows:
        return 0
    csv_text = to_csv(rows)
    if dry_run or not api_key:
        if not api_key:
            print("ABUSEIPDB_API_KEY not set; skipping submission")
        print("--- dry run: first 5 rows ---")
        for line in csv_text.splitlines()[:6]:
            print(line)
        return 0
    try:
        resp = requests.post(
            API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            files={"csv": ("report.csv", csv_text, "text/csv")},
            timeout=90,
        )
    except requests.RequestException as exc:
        print("bulk-report request failed: %s" % exc)
        return 1
    if resp.status_code == 429:
        retry = resp.headers.get("Retry-After", "?")
        print("rate limited (429); retry after %s seconds" % retry)
        return 1
    if resp.status_code != 200:
        print("bulk-report HTTP %d: %s" % (resp.status_code, resp.text[:500]))
        return 1
    try:
        data = resp.json()["data"]
    except (ValueError, KeyError):
        print("unexpected response: %s" % resp.text[:500])
        return 1
    invalid = {e.get("rowNumber"): e for e in data.get("invalidReports", [])}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    saved, failed = 0, 0
    for i, r in enumerate(rows):
        row_number = i + 2  # 1-based, header is row 1
        err = invalid.get(row_number)
        if err:
            failed += 1
            print("row %d (%s) rejected: %s"
                  % (row_number, r["ip"], err.get("error")))
        else:
            reported[r["ip"]] = today
            saved += 1
    save_state(reported)
    print("saved=%d rejected=%d (api reported savedReports=%s)"
          % (saved, failed, data.get("savedReports")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
