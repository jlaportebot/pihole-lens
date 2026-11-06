# Pi-hole Lens

**A per-device DNS analytics dashboard that reads your existing [Pi-hole](https://pi-hole.net) query log — no extra agents, no packet capture, one small Python file with zero dependencies.**

Pi-hole already records every DNS lookup on your network. Its built-in admin UI is excellent for *network-wide* stats and managing blocklists, but answering "**what is _this specific device_ actually doing, and how do I make sense of thousands of raw domains?**" means a lot of scrolling and filtering. Pi-hole Lens is a read-only companion view built for exactly that: it classifies every domain into human-readable categories and gives each device its own profile.

> **Scope, stated plainly:** Lens shows the **domain names** devices look up (`api.example.com`), because that is what a DNS resolver sees. It does **not** show full URLs, page content, messages, or anything inside HTTPS — none of that reaches your DNS server. It is a traffic-category lens, not a content monitor.

---

## Why add it on top of Pi-hole?

| | Stock Pi-hole admin | Pi-hole Lens |
|---|---|---|
| Network-wide stats | ✅ Excellent | ✅ Overview tab |
| **Per-device deep-dive** | Filter the query log by client | ✅ Dedicated profile per device (master-detail) |
| **Domain classification** | — | ✅ Every domain sorted into 16 categories (Ads & Tracking, Streaming, Social, Gaming, AI, OS Telemetry, …) |
| **Device identity** | IP / basic client list | ✅ IP + MAC + hardware vendor + first/last seen + lifetime count |
| Blocklist management | ✅ Full control | ❌ Read-only (by design — it never writes) |
| Install footprint | The whole Pi-hole stack | One `.py` file, Python standard library only |

Lens doesn't replace Pi-hole's admin page — it sits beside it and answers a different question. It opens the databases **read-only** and runs as the unprivileged `pihole` user, so it can't change your configuration, your blocklists, or your data.

---

## Features

**Network Overview tab**
- Headline tiles: total queries, blocked, block rate, active devices, unique domains, cache-hit rate, average lookup latency, blocklist size.
- Queries-over-time line chart (allowed vs. blocked) with real time and count axes, a hover crosshair and tooltip, arrow-key navigation, and a "show as table" view. Bucket size adapts to the window (1 minute for the last hour, 10 minutes for a day, 2 hours for a week), and empty buckets are plotted as zero so the time axis stays linear.
- **Traffic by category** across the whole network.
- Top domains, top blocked domains, query-type and reply-type breakdowns, and which upstream resolvers answered.
- Live host health (CPU load, RAM, temperature, uptime) read from `/proc` and the thermal sensor.

**Devices tab** (master-detail — click a device for its full profile)
- Device list with name, IP, vendor, query count, block %, top category, and an activity sparkline.
- Per-device: identity block, its own stat tiles, activity timeline, **category breakdown ("what it's doing")**, top domains, top blocked, query/reply types.
- A **live recent-lookups feed**: timestamp, domain, category, record type, allow/block status, and response time.

**Shared**
- Time-window switch: 1 hour / 24 hours / 7 days / all.
- Auto-refreshes every 30 seconds. Dark theme. No external fonts, CDNs, or JS libraries — the entire UI ships inside `server.py`.

---

## Requirements

- A working **Pi-hole v6** install (FTL's SQLite databases at `/etc/pihole/pihole-FTL.db` and `/etc/pihole/gravity.db`).
- **Python 3.9+** (already present on a standard Pi-hole host). No `pip install` — standard library only.

## Quick start

```bash
git clone https://github.com/jlaportebot/pihole-lens.git
cd pihole-lens

# Run as the pihole user so it can read FTL's databases (read-only):
sudo -u pihole python3 server.py
```

Then open **`http://<your-pi-hole-ip>:8053`** from any device on your LAN.

## Configuration (environment variables)

All optional — the defaults work on a standard Pi-hole host.

| Variable | Default | Purpose |
|---|---|---|
| `LENS_PORT` | `8053` | Port to listen on |
| `LENS_HOST` | `0.0.0.0` | Bind address (`127.0.0.1` = this host only) |
| `LENS_SUBNET` | *(auto)* | LIKE prefix for "local" clients, e.g. `10.0.0.`. Unset = auto-match all RFC1918 private ranges |
| `LENS_FTL_DB` | `/etc/pihole/pihole-FTL.db` | Path to FTL database |
| `LENS_GRAVITY_DB` | `/etc/pihole/gravity.db` | Path to gravity database |

## Run it as a service (optional)

```bash
# Install the code where the service expects it, then enable the unit:
sudo mkdir -p /opt/pihole-lens
sudo cp server.py /opt/pihole-lens/
sudo cp systemd/pihole-lens.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-lens
```

The unit runs Lens as the `pihole` user and restarts it on failure. See [`systemd/pihole-lens.service`](systemd/pihole-lens.service).

---

## Device names

Lens labels devices using Pi-hole's own client comments. Add a comment to a client in the Pi-hole admin UI (**Groups → Clients**), or run:

```bash
pihole arp  # see known devices
```

Devices without a comment show as *Unlabelled device* with their vendor from the MAC prefix.

## Security notes

- **Read-only.** Lens only ever opens the databases in read-only mode and never writes to disk.
- **No authentication is built in.** Anyone who can reach the port can view the dashboard. Keep it on a trusted LAN, bind it to `127.0.0.1` and reach it over an SSH tunnel, or put it behind a reverse proxy with auth if you need access control.
- It exposes the same DNS metadata Pi-hole already stores — nothing more.

## Responsible use

Run Pi-hole Lens only on a network you own or administer. DNS query logs reveal which services the people on your network use; if others share the network, be transparent that DNS activity is being monitored. This is a tool for understanding and securing *your own* network, not for surveilling people without their knowledge. Follow the laws that apply to you.

## How it works

Pi-hole's FTL engine logs every query to a SQLite database. Lens opens that database (plus `gravity.db` for client labels) read-only, runs a handful of aggregate queries per view, classifies domains with an ordered set of substring rules, and serves a single self-contained HTML page plus a small JSON API (`/api/overview`, `/api/devices`, `/api/device?ip=…`). That's the whole thing.

## Contributing

The domain classifier (`CLASSIFY_RULES` in `server.py`) is a best-effort heuristic — PRs that improve category coverage are very welcome. Keep it dependency-free.

Run the tests (standard library only) with:

```bash
python3 -m unittest discover -s tests
```

## License

[MIT](LICENSE)
