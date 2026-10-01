#!/usr/bin/env python3
"""Terrarium feed renderer — runs in GitHub Actions.

Reads the latest data/snapshot-*.json, enriches IPs with reverse DNS
(cached) and geolocation (cached, via ip-api.com batch), then renders
every public feed file, the daily attack map, MAP.md and the README
stats block. The workflow commits whatever changed.
"""
import concurrent.futures
import glob
import json
import os
import socket
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
ASSETS = os.path.join(ROOT, "assets")
SCRIPTS = os.path.join(ROOT, "scripts")

RDNS_CACHE = os.path.join(DATA, "rdns-cache.json")
GEO_CACHE = os.path.join(DATA, "geo-cache.json")

REPO_URL = "https://github.com/nawabs11/terrarium"

# Command fragments that would fingerprint the honeypot's custom layout.
# Anything containing these never leaves the building.
COMMAND_DENY = ("sree", "balaji", "decept", "honeypot", "canary",
                "/opt/", "/root/.ssh/ship", "ntfy")
COMMAND_MAXLEN = 120

IPAPI_BATCH = "http://ip-api.com/batch"


def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)


def latest_snapshot():
    snaps = sorted(glob.glob(os.path.join(DATA, "snapshot-*.json")))
    if not snaps:
        raise SystemExit("no snapshot found in data/")
    with open(snaps[-1]) as fh:
        return json.load(fh), os.path.basename(snaps[-1])


def resolve_rdns(ips, cache):
    missing = [ip for ip in ips if ip not in cache]
    if not missing:
        return cache
    socket.setdefaulttimeout(5)

    def lookup(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0].rstrip(".")
        except Exception:
            return ip, "-"

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for ip, host in ex.map(lookup, missing):
            cache[ip] = host if host else "-"
    return cache


def resolve_geo(ips, cache):
    missing = [ip for ip in ips if ip not in cache]
    for i in range(0, len(missing), 100):
        batch = missing[i:i + 100]
        results = []
        for attempt in range(3):
            req = urllib.request.Request(
                IPAPI_BATCH + "?fields=status,query,lat,lon,countryCode",
                data=json.dumps([{"query": ip} for ip in batch]).encode(),
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    results = json.loads(resp.read().decode())
                break
            except Exception as e:
                print("geo batch attempt %d failed: %r" % (attempt + 1, e))
                time.sleep(3)
        if not results:
            print("geo batch gave up for %d ips; will retry tomorrow" % len(batch))
        for r in results:
            if r.get("status") == "success":
                cache[r["query"]] = {"lat": r["lat"], "lon": r["lon"],
                                     "cc": r.get("countryCode") or "--"}
            else:
                cache[r["query"]] = None
        time.sleep(1.5)  # respect the free tier
    return cache


def generic_command(cmd):
    low = cmd.lower()
    if any(d in low for d in COMMAND_DENY):
        return None
    if len(cmd) > COMMAND_MAXLEN:
        return None
    return cmd


def feed_header(name, desc, count, date):
    return ("# terrarium — %s\n"
            "# %s\n"
            "# updated: %s (daily)\n"
            "# source: %s\n"
            "# entries: %d\n" % (name, desc, date, REPO_URL, count))


def write_feed(path, header, lines):
    with open(path, "w") as fh:
        fh.write(header)
        for line in lines:
            fh.write(line + "\n")


def main():
    snap, snap_name = latest_snapshot()
    date = snap.get("date", time.strftime("%Y-%m-%d", time.gmtime()))
    ips = snap.get("ips", {})

    rdns = load_json(RDNS_CACHE, {})
    geo = load_json(GEO_CACHE, {})
    ip_list = sorted(ips)
    rdns = resolve_rdns(ip_list, rdns)
    geo = resolve_geo(ip_list, geo)
    save_json(RDNS_CACHE, rdns)
    save_json(GEO_CACHE, geo)

    def has(svc):
        return sorted(ip for ip, r in ips.items()
                      if r.get("services", {}).get(svc, 0) > 0)

    ssh_ips = has("ssh")
    http_ips = sorted(set(has("http")) | set(has("misc")))
    jenkins_ips = has("jenkins")
    env_ips = sorted(ip for ip, r in ips.items() if "env" in r.get("flags", []))
    wp_ips = sorted(ip for ip, r in ips.items() if "wp" in r.get("flags", []))

    write_feed("all.txt",
               feed_header("all.txt", "Every attacker IP observed by the grid.",
                           len(ip_list), date), ip_list)
    write_feed("ssh-bruteforce.txt",
               feed_header("ssh-bruteforce.txt",
                           "IPs that attempted SSH logins or ran commands.", len(ssh_ips), date),
               ssh_ips)
    write_feed("http-probers.txt",
               feed_header("http-probers.txt",
                           "IPs that probed HTTP(S) services (web, api, misc).",
                           len(http_ips), date), http_ips)
    write_feed("jenkins-probers.txt",
               feed_header("jenkins-probers.txt",
                           "IPs that probed the Jenkins login/console.", len(jenkins_ips), date),
               jenkins_ips)
    write_feed("env-grabbers.txt",
               feed_header("env-grabbers.txt",
                           "IPs that requested /.env or similar secret files.",
                           len(env_ips), date), env_ips)
    write_feed("wp-login.txt",
               feed_header("wp-login.txt",
                           "IPs that hit wp-login.php / WordPress paths.",
                           len(wp_ips), date), wp_ips)

    ranked = sorted(ips.items(), key=lambda kv: (-kv[1]["hits"], kv[0]))
    write_feed("top-attackers.txt",
               feed_header("top-attackers.txt",
                           "Attackers ranked by total events. Columns: events IP reverse-DNS "
                           "('-' = no PTR record).", len(ranked), date) +
               "#\n",
               ["%-8d %-40s %s" % (r["hits"], ip, rdns.get(ip, "-"))
                for ip, r in ranked])

    cmds = ((c, n) for c, n in snap.get("ssh_commands", {}).items())
    cmds = [(c, n) for c, n in cmds if generic_command(c)]
    cmds.sort(key=lambda x: -x[1])
    write_feed("top-ssh-commands.txt",
               feed_header("top-ssh-commands.txt",
                           "Most-run SSH commands (generic only — nothing identifying "
                           "the honeypot internals). Columns: runs command.", len(cmds[:100]), date) +
               "#\n",
               ["%-8d %s" % (n, c) for c, n in cmds[:100]])

    render_map(ranked, geo, date)
    render_map_md(ranked, geo, date, len(ip_list), len(ssh_ips), len(http_ips), len(jenkins_ips))
    render_readme_stats(date, len(ip_list), ranked[:5], rdns)
    print("rendered %d ips from %s" % (len(ip_list), snap_name))


def render_map(ranked, geo, date):
    from PIL import Image, ImageDraw
    base = Image.open(os.path.join(ASSETS, "world.png")).convert("RGB")
    W, H = base.size
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    import math
    plotted = 0
    for ip, r in ranked:
        g = geo.get(ip)
        if not g:
            continue
        x = int((g["lon"] + 180.0) / 360.0 * W)
        y = int((90.0 - g["lat"]) / 180.0 * H)
        rad = 2 + min(9, int(math.log10(1 + r["hits"]) * 3))
        # hotter = more events
        heat = min(1.0, math.log10(1 + r["hits"]) / 3.0)
        col = (int(255), int(120 - 60 * heat), int(60 - 40 * heat), 200)
        draw.ellipse([x - rad, y - rad, x + rad, y + rad], fill=col)
        plotted += 1

    img = Image.alpha_composite(base.convert("RGBA"), overlay).convert("RGB")
    d = ImageDraw.Draw(img)
    d.text((14, 10), "TERRARIUM - attack origins", fill=(235, 240, 250))
    d.text((14, 28), "%s · %d unique attacker IPs plotted: %d"
           % (date, len(ranked), plotted), fill=(150, 160, 175))
    img.save(os.path.join(ASSETS, "map.png"))
    print("map plotted %d/%d" % (plotted, len(ranked)))


def render_map_md(ranked, geo, date, n_ips, n_ssh, n_http, n_jenkins):
    from collections import Counter
    cc = Counter()
    for ip, r in ranked:
        g = geo.get(ip)
        if g and g.get("cc"):
            cc[g["cc"]] += r["hits"]
    top_cc = cc.most_common(8)
    rows = "\n".join("| %s | %d |" % (c, n) for c, n in top_cc) or "| — | — |"
    md = """# Attack map

![Attack origins](assets/map.png)

Updated daily from the deception grid.

| Metric | Count |
|---|---|
| Unique attacker IPs | {n_ips} |
| SSH brute-forcers | {n_ssh} |
| HTTP probers | {n_http} |
| Jenkins probers | {n_jenkins} |

## Top origin countries (by events)

| Country | Events |
|---|---|
{rows}

_Last updated: {date} UTC_
""".format(n_ips=n_ips, n_ssh=n_ssh, n_http=n_http, n_jenkins=n_jenkins,
           rows=rows, date=date)
    with open(os.path.join(ROOT, "MAP.md"), "w") as fh:
        fh.write(md)


def render_readme_stats(date, n_ips, top5, rdns):
    path = os.path.join(ROOT, "README.md")
    with open(path) as fh:
        content = fh.read()
    lines = ["", "## Live stats", "",
             "_Last updated: %s UTC · %d unique attacker IPs_"
             % (date, n_ips), "",
             "| # | Events | IP | Reverse DNS |",
             "|---|---|---|---|"]
    for i, (ip, r) in enumerate(top5, 1):
        lines.append("| %d | %d | `%s` | %s |"
                     % (i, r["hits"], ip, rdns.get(ip, "-")))
    lines += ["", "_Full ranking: [top-attackers.txt](top-attackers.txt)_", ""]
    block = "\n".join(lines)
    start, end = "<!-- STATS:START -->", "<!-- STATS:END -->"
    before, _, rest = content.partition(start)
    _, _, after = rest.partition(end)
    content = before + start + "\n" + block + "\n" + end + after
    with open(path, "w") as fh:
        fh.write(content)


if __name__ == "__main__":
    main()
