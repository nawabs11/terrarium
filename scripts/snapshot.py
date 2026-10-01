#!/usr/bin/env python3
"""Terrarium snapshot builder — runs on the log collector (Pi).

Streams every deception-grid *.jsonl log, aggregates per-IP activity and
SSH command counts, scrubs non-routable / own infrastructure addresses,
and writes data/snapshot-YYYY-MM-DD.json (cumulative from retained logs).

Nothing credential-bearing is exported: no usernames, no passwords.
"""
import glob
import ipaddress
import json
import os
import sys
import time
from collections import Counter, defaultdict

LOG_ROOT = os.path.expanduser("~/deception-logs")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

# Addresses that must never appear in a public feed.
OWN_IPS = {"98.45.159.69"}  # operator's own egress IP (seen in logs via self-tests)

# Service classification: (log filename prefix) -> service bucket
SERVICE_OF = (
    ("ssh", "ssh"),
    ("http", "http"),
    ("jenkins", "jenkins"),
    ("redis", "misc"),
    ("docker", "misc"),
    ("es", "misc"),
    ("vpn", "misc"),
)


def service_for(filename):
    base = os.path.basename(filename).lower()
    for prefix, svc in SERVICE_OF:
        if base.startswith(prefix):
            return svc
    return None


def publishable(ip_str):
    """True if this address may appear in the public feed."""
    if not ip_str or ip_str in OWN_IPS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return False
    return True


def main():
    ips = {}
    ssh_commands = Counter()
    files_seen = 0
    events_seen = 0

    for path in sorted(glob.glob(os.path.join(LOG_ROOT, "*", "*.jsonl"))):
        svc = service_for(path)
        if not svc:
            continue
        files_seen += 1
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                events_seen += 1
                event = ev.get("event", "")
                src = ev.get("src", "")
                if not src or not publishable(src):
                    continue
                ts = ev.get("ts", 0)
                rec = ips.get(src)
                if rec is None:
                    rec = ips[src] = {"hits": 0, "first": ts, "last": ts,
                                      "services": defaultdict(int), "flags": set()}
                rec["hits"] += 1
                rec["services"][svc] += 1
                if ts:
                    if ts < rec["first"]:
                        rec["first"] = ts
                    if ts > rec["last"]:
                        rec["last"] = ts
                # behavior flags (HTTP-family services)
                rp = ev.get("req_path", "") or ""
                if ".env" in rp:
                    rec["flags"].add("env")
                if "wp-login" in rp:
                    rec["flags"].add("wp")
                # SSH command tally (raw; render step filters to generic-only)
                if event == "command" and ev.get("command"):
                    cmd = " ".join(str(ev["command"]).split())
                    if cmd:
                        ssh_commands[cmd[:200]] += 1

    date = time.strftime("%Y-%m-%d", time.gmtime())
    snapshot = {
        "date": date,
        "generated_ts": int(time.time()),
        "meta": {"log_files": files_seen, "events": events_seen,
                 "unique_ips": len(ips)},
        "ips": {ip: {"hits": r["hits"], "first": r["first"], "last": r["last"],
                      "services": dict(r["services"]), "flags": sorted(r["flags"])}
                for ip, r in ips.items()},
        # cap the long tail; render keeps top 100 after filtering
        "ssh_commands": dict(ssh_commands.most_common(20000)),
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "snapshot-%s.json" % date)
    with open(out, "w") as fh:
        json.dump(snapshot, fh)
    print("wrote %s (%d ips, %d events)" % (out, len(ips), events_seen))


if __name__ == "__main__":
    sys.exit(main())
