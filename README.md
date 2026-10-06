# Terrarium

![updated daily](https://img.shields.io/badge/updated-daily-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

**Terrarium** is a daily-updated threat-intelligence feed drawn from a live
deception grid — a network of honeypot services (SSH, HTTP, Jenkins, Redis,
Docker, Elasticsearch, VPN) that records every unsolicited connection attempt
in real time. Think of it as an ant farm for attackers: they come in, we watch,
and the observations are published here for the whole community.

Inspired by [ipsum](https://github.com/stamparm/ipsum).

<!-- STATS:START -->

## Live stats

_Last updated: 2026-10-06 UTC · 3443 unique attacker IPs_

| # | Events | IP | Reverse DNS |
|---|---|---|---|
| 1 | 65672 | `109.160.32.149` | - |
| 2 | 64489 | `109.160.32.110` | - |
| 3 | 59421 | `109.160.32.106` | - |
| 4 | 59109 | `109.160.32.105` | - |
| 5 | 47210 | `109.160.32.31` | - |

_Full ranking: [top-attackers.txt](top-attackers.txt)_

<!-- STATS:END -->

## Methodology

Unsolicited traffic hitting the deception grid is logged per service. Each day
a snapshot is taken of the retained logs and this repository is regenerated:

1. **Collect** — connection, authentication, command-execution and
   request events are aggregated per source IP.
2. **Scrub** — non-routable addresses (private, loopback, link-local,
   multicast, reserved) and the operator's own infrastructure are removed.
   Nothing credential-bearing is ever published: no usernames, no passwords.
3. **Classify** — each IP is bucketed by what it actually did
   (SSH brute-forcing, HTTP probing, Jenkins probing, `.env` grabbing …).
4. **Enrich** — reverse DNS is resolved for every IP (cached; `-` means no
   PTR record). Geolocation powers the daily attack map.
5. **Publish** — feeds, rankings and the map are regenerated and committed.

Counts are cumulative over the currently retained logs. IPs are **observed**,
not convicted — see the disclaimer below.

## Files

| File | Format | Description |
|---|---|---|
| `all.txt` | one IP per line | Every attacker IP observed by the grid. The simplest feed: drop it into a firewall blocklist or SIEM watchlist. |
| `ssh-bruteforce.txt` | one IP per line | IPs that attempted SSH logins or executed commands over SSH. |
| `http-probers.txt` | one IP per line | IPs that probed HTTP(S) services — web paths, APIs, and misc service probes. |
| `jenkins-probers.txt` | one IP per line | IPs that probed the Jenkins login and console endpoints. |
| `env-grabbers.txt` | one IP per line | IPs that requested `/.env` or similar secret files — a strong opportunistic-exploitation signal. |
| `wp-login.txt` | one IP per line | IPs that hit `wp-login.php` / WordPress paths. |
| `top-attackers.txt` | `events IP reverse-DNS` | All attackers ranked by total events, most active first. The second column is the PTR record (`-` when none exists) — handy for spotting repeat offenders and for telling benign scanners (e.g. `*.shodan.io`, `*.censys.io`) apart from real threats. |
| `top-ssh-commands.txt` | `runs command` | The 100 most-executed SSH commands, generic only. Anything that could fingerprint the honeypot's internals is filtered out before publishing. |
| `MAP.md` | markdown + PNG | Daily world map of attack origins plus top origin countries. |
| `data/snapshot-YYYY-MM-DD.json` | JSON | The raw daily snapshot this release was built from (per-IP hits, first/last seen, per-service counts). For researchers who want to do their own analysis. |
| `data/rdns-cache.json`, `data/geo-cache.json` | JSON | Lookup caches so daily rebuilds stay fast and polite to free APIs. |

Example `top-attackers.txt`:

```
# terrarium — top-attackers.txt
# updated: 2026-10-01 (daily)
# entries: 560
#
452      109.160.32.158                         -
318      87.81.235.79                           87-81-235-79.example.net
```

## Download & usage

Grab a single feed with curl:

```bash
curl -sL https://raw.githubusercontent.com/nawabs11/terrarium/main/all.txt -o terrarium-ips.txt
```

…or with wget:

```bash
wget -q https://raw.githubusercontent.com/nawabs11/terrarium/main/ssh-bruteforce.txt
```

…or clone the whole thing:

```bash
git clone https://github.com/nawabs11/terrarium.git
cd terrarium
wc -l all.txt
```

**Blocklist use (example, iptables):**

```bash
while read -r ip; do
  case "$ip" in \#*|"") continue;; esac
  iptables -A INPUT -s "$ip" -j DROP
done < ssh-bruteforce.txt
```

**SIEM use:** ingest `all.txt` as a watchlist / threat-intel indicator list and
alert on matches in firewall or IDS logs.

Feeds refresh daily around 07:00 UTC, plus on every new data snapshot.

## AbuseIPDB reporting

New attacker IPs are also reported to [AbuseIPDB](https://www.abuseipdb.com)
once per day via the bulk-report API, so the observations feed back into the
shared community blocklist. Each IP is reported exactly once, with categories
mapped from the observed activity (SSH brute-force → Brute-Force/SSH, web
probing → Web App Attack, and so on) and a generic description of the
behavior. Reporting runs inside the daily workflow and never blocks the feed
update if the API is unreachable.

## Disclaimer — read this

- These IPs were **observed interacting with a honeypot**. That is evidence of
  unsolicited scanning or attack attempts, not proof of malice and not an
  accusation against whoever operates the address today. IPs get reassigned;
  today's attacker IP can be tomorrow's coffee shop.
- Known benign scanners (Shodan, Censys, BinaryEdge, …) appear in these feeds
  when they scan the grid. Check the reverse-DNS column in `top-attackers.txt`
  before treating an entry as hostile.
- Use these feeds as **one signal among many**, not as a sole basis for
  blocking decisions on production systems. The authors accept no liability
  for blocks, false positives, or hurt feelings.

## Contributing

Spotted a misclassified scanner, or have an idea for a new feed slice? Open an
issue or a pull request. Be kind.

## Credits

- Feed concept inspired by Miroslav Stampar's
  [ipsum](https://github.com/stamparm/ipsum).
- Base map imagery: Solar System Scope / NASA Blue Marble
  (via Wikimedia Commons, CC BY).
- Geolocation: [ip-api.com](https://ip-api.com) free tier.

## License

MIT — see [LICENSE](LICENSE).
