#!/usr/bin/env python3
"""Pi-hole Lens -- in-depth per-device DNS analytics dashboard for Pi-hole.

Runs as the `pihole` user (read-only on both FTL and gravity databases) and
serves a self-contained single-page dashboard on the LAN. It reports only
DNS metadata that the resolver already logs -- domains, not URLs or content.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FTL_DB = os.environ.get("LENS_FTL_DB", "/etc/pihole/pihole-FTL.db")
GRAVITY_DB = os.environ.get("LENS_GRAVITY_DB", "/etc/pihole/gravity.db")
# Optional LIKE prefix selecting which clients count as "local", e.g.
# LENS_SUBNET=10.0.0.  Left unset, Lens matches every RFC1918 private range,
# so no site-specific subnet is baked into the code.
LAN_PREFIX = os.environ.get("LENS_SUBNET", "").strip()
if LAN_PREFIX and not re.fullmatch(r"[0-9.]+", LAN_PREFIX):
    LAN_PREFIX = ""
LISTEN_HOST = os.environ.get("LENS_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LENS_PORT", "8053"))

TOP_DOMAINS = 20
RECENT_QUERIES = 150
QUERY_TIMEOUT_SECONDS = 20
MILLISECONDS = 1000

BLOCKED_STATUSES = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 17)
_blocked_sql = ",".join(str(code) for code in BLOCKED_STATUSES)


def _lan_filter(column: str) -> str:
    """SQL boolean selecting local clients for `column` (no bind params)."""
    if LAN_PREFIX:
        return f"{column} LIKE '{LAN_PREFIX}%'"
    return (f"({column} GLOB '192.168.*' OR {column} GLOB '10.*' "
            f"OR {column} GLOB '172.1[6-9].*' OR {column} GLOB '172.2[0-9].*' "
            f"OR {column} GLOB '172.3[01].*')")


CLIENT_WHERE = _lan_filter("q.client")
ADDR_WHERE = _lan_filter("na.ip")

WINDOWS = {"1h": 3600, "24h": 86400, "7d": 604800, "all": 0}
DEFAULT_WINDOW = "24h"

QUERY_TYPE_NAMES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}

REPLY_TYPE_NAMES = {
    0: "UNKNOWN", 1: "NODATA", 2: "NXDOMAIN", 3: "CNAME", 4: "IP",
    5: "DOMAIN", 6: "RRNAME", 7: "SERVFAIL", 8: "REFUSED", 9: "NOTIMP",
    10: "OTHER", 11: "DNSSEC", 12: "NONE", 13: "BLOB",
}

STATUS_NAMES = {
    0: "Unknown", 1: "Blocked (gravity)", 2: "OK (forwarded)",
    3: "OK (cached)", 4: "Blocked (regex)", 5: "Blocked (denylist)",
    6: "Blocked (upstream)", 7: "Blocked (upstream)", 8: "Blocked (upstream)",
    9: "Blocked (gravity CNAME)", 10: "Blocked (regex CNAME)",
    11: "Blocked (denylist CNAME)", 12: "OK (retried)",
    13: "OK (retried)", 14: "OK (forwarded)", 15: "Blocked (busy)",
    16: "OK (special)", 17: "Blocked (special)",
}

# Ordered classification rules: first category whose substrings match wins.
# Brand-specific analytics is matched before the brand itself on purpose.
CLASSIFY_RULES = [
    ("Adult", ["pornhub", "xvideos", "xnxx", "xhamster", "redtube",
               "onlyfans", "youporn", ".xxx", "brazzers"]),
    ("Security & Antivirus", ["mcafee", "avast", "norton", "kaspersky",
                              "malwarebytes", "bitdefender", "phantom.app",
                              "blowfish-blocklist"]),
    ("Ads & Tracking", ["doubleclick", "googlesyndication", "googleadservices",
                        "google-analytics", "analytics.google", "adservice",
                        "adsystem", "pagead", "scorecardresearch", "adnxs",
                        "criteo", "taboola", "outbrain", "bluekai", "demdex",
                        "rubiconproject", "pubmatic", "moatads", "amplitude",
                        "mixpanel", "segment.io", "sentry.io", "bugsnag",
                        "app-measurement", "app-analytics", "appsflyer",
                        "adjust.com", "branch.io", "crashlytics", "adsrvr",
                        "analytics", "telemetry", "metric", "tracking"]),
    ("AI Assistants", ["openai", "chatgpt", "oaistatic", "anthropic", "claude",
                       "gemini", "perplexity", "copilot", "x.ai"]),
    ("Social & Messaging", ["facebook", "fbcdn", "instagram", "cdninstagram",
                            "snapchat", "sc-cdn", "sc-gw", "tiktok", "twitter",
                            "twimg", "reddit", "pinterest", "linkedin",
                            "discord", "whatsapp", "telegram", "signal",
                            "messenger", "threads.net"]),
    ("Streaming & Media", ["netflix", "nflx", "spotify", "scdn.co",
                           "primevideo", "aiv-delivery", "amazonvideo", "hulu",
                           "disney", "hbomax", "max.com", "roku", "twitch",
                           "ttvnw", "soundcloud", "vimeo", "plex", "tidal",
                           "deezer", "crunchyroll", "tmdb", "themoviedb",
                           "ravm.tv", "iptv"]),
    ("Gaming", ["steam", "steampowered", "steamserver", "epicgames",
                "xboxlive", "playstation", "nintendo", "riotgames",
                "battle.net", "blizzard", "ea.com", "ubisoft", "roblox",
                "minecraft"]),
    ("Shopping", ["amazon.com", "ebay", "etsy", "walmart", "aliexpress",
                  "shopify", "bestbuy", "unagi-na.amazon"]),
    ("Finance & Crypto", ["paypal", "stripe", "revenuecat", "coinbase",
                          "binance", "chase.com", "wellsfargo", "venmo"]),
    ("Education & Work", ["perusall", "piazza", "zoom.us", "slack", "dropbox",
                          "notion", "atlassian", "github", "gitlab",
                          "instructure", "canvas", "blackboard", "coursera",
                          "udemy", "khanacademy"]),
    ("Software Updates", ["gvt2.com", "gvt3.com", "windowsupdate",
                          "update.microsoft", "swscan.apple", "mesu.apple",
                          "osx.apple", "dl.google", "edgedl", "ctldl",
                          "data.microsoft", "beacons"]),
    ("Apple Services", ["apple.com", "icloud", "apple-dns", "aaplimg",
                        "cdn-apple", "itunes", "mzstatic", "apple-cloudkit",
                        "gsa.apple", "apple-dns.net"]),
    ("Google Services", ["google.com", "gstatic", "googleapis", "ggpht",
                         "googleusercontent", "gvt1", "youtube", "ytimg",
                         "googlevideo", "android.clients", "play.google",
                         "gmail", "clients6.google", "clients3.google"]),
    ("Microsoft Services", ["microsoft", "msftncsi", "office365", "office.com",
                            "sharepoint", "outlook", "live.com", "msn.com",
                            "bing", "windows.net", "azure", "msedge",
                            "skype", "teams"]),
    ("DNS & Network", ["in-addr.arpa", "resolver.arpa", "_dns", "dns.google",
                       "ntp", "pool.ntp", "time.apple", "tplinkcloud",
                       "tp-link", "deco", "connectivitycheck", "captive",
                       "gateway"]),
    ("Cloud & CDN", ["akamai", "cloudfront", "cloudflare", "fastly",
                     "amazonaws", "aws.", "azureedge", "edgekey", "edgesuite",
                     "gcp", "digitalocean", "herokuapp", "gstatic", "cdn"]),
]


def classify(domain: str) -> str:
    low = domain.lower()
    for category, needles in CLASSIFY_RULES:
        if any(needle in low for needle in needles):
            return category
    return "Other"


def open_readonly() -> sqlite3.Connection:
    conn = sqlite3.connect(
        f"file:{FTL_DB}?mode=ro", uri=True, timeout=QUERY_TIMEOUT_SECONDS
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"ATTACH DATABASE 'file:{GRAVITY_DB}?mode=ro' AS g")
    return conn


def since_clause(window_seconds: int) -> tuple[str, list]:
    if window_seconds <= 0:
        return "", []
    return "AND q.timestamp >= ?", [int(time.time()) - window_seconds]


def bucket_seconds(window_seconds: int) -> int:
    if 0 < window_seconds <= 3600:
        return 300
    if window_seconds <= 86400:
        return 3600
    if window_seconds <= 604800:
        return 21600
    return 86400


def local_time(epoch) -> str | None:
    if not epoch:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(epoch)))


def device_identity(conn: sqlite3.Connection) -> dict:
    """Map each LAN IP to MAC, vendor, interface, first-seen, label."""
    rows = conn.execute(
        """
        SELECT na.ip AS ip, n.hwaddr AS mac, n.macVendor AS vendor,
               n.interface AS iface, n.firstSeen AS first_seen,
               n.numQueries AS lifetime, cl.comment AS label
        FROM network n
        JOIN network_addresses na ON na.network_id = n.id
        LEFT JOIN g.client cl ON cl.ip = n.hwaddr COLLATE NOCASE
        WHERE {ADDR_WHERE}
        """.format(ADDR_WHERE=ADDR_WHERE),
    ).fetchall()
    out = {}
    for r in rows:
        out[r["ip"]] = {
            "mac": r["mac"], "vendor": r["vendor"] or "Unknown vendor",
            "iface": r["iface"], "first_seen": local_time(r["first_seen"]),
            "lifetime": r["lifetime"],
            "label": r["label"] or "Unlabelled device",
        }
    return out


def system_health() -> dict:
    load1, load5, load15 = (float(x) for x in
                            open("/proc/loadavg").read().split()[:3])
    mem = {}
    for line in open("/proc/meminfo"):
        key, _, rest = line.partition(":")
        mem[key] = int(rest.strip().split()[0])
    total_kb = mem.get("MemTotal", 1)
    avail_kb = mem.get("MemAvailable", 0)
    uptime = float(open("/proc/uptime").read().split()[0])
    temp_c = None
    try:
        temp_c = round(int(open(
            "/sys/class/thermal/thermal_zone0/temp").read()) / MILLISECONDS, 1)
    except OSError:
        pass
    return {
        "load1": load1, "load5": load5, "load15": load15,
        "cpus": os.cpu_count(),
        "mem_used_pct": round(100 * (total_kb - avail_kb) / total_kb, 1),
        "mem_total_gb": round(total_kb / (1024 * 1024), 1),
        "temp_c": temp_c,
        "uptime_h": round(uptime / 3600, 1),
    }


def _counts_by(conn, column, where, params, extra=""):
    sql = f"""
        SELECT {column} AS k, COUNT(*) AS n FROM queries q
        WHERE {CLIENT_WHERE} {where} {extra}
        GROUP BY {column} ORDER BY n DESC
    """
    return conn.execute(sql, [*params]).fetchall()


def overview(conn, window_seconds) -> dict:
    where, params = since_clause(window_seconds)
    agg = conn.execute(
        f"""SELECT COUNT(*) total,
                   SUM(q.status IN ({_blocked_sql})) blocked,
                   SUM(q.status=3) cached, SUM(q.status IN (2,14)) forwarded,
                   ROUND(AVG(q.reply_time)*1000,2) avg_ms,
                   COUNT(DISTINCT q.client) devices,
                   COUNT(DISTINCT q.domain) domains
            FROM queries q WHERE {CLIENT_WHERE} {where}""", list(params)
    ).fetchone()
    total = agg["total"] or 0
    blocked = int(agg["blocked"] or 0)
    served = (agg["cached"] or 0) + (agg["forwarded"] or 0)
    gravity = conn.execute("SELECT COUNT(*) n FROM g.gravity").fetchone()["n"]
    return {
        "total": total, "blocked": blocked, "allowed": total - blocked,
        "block_pct": round(100 * blocked / total, 1) if total else 0.0,
        "cache_hit_pct": round(100 * (agg["cached"] or 0) / served, 1)
        if served else 0.0,
        "avg_ms": agg["avg_ms"] or 0, "devices": agg["devices"] or 0,
        "unique_domains": agg["domains"] or 0, "gravity_domains": gravity,
        "query_types": _named_counts(_counts_by(conn, "q.type", where, params),
                                     QUERY_TYPE_NAMES),
        "reply_types": _named_counts(
            _counts_by(conn, "q.reply_type", where, params), REPLY_TYPE_NAMES),
        "upstreams": [{"name": r["k"], "count": r["n"]} for r in _counts_by(
            conn, "q.forward", where, params, "AND q.forward IS NOT NULL")],
        "categories": category_counts(conn, where, params),
        "timeline": timeline(conn, where, params, window_seconds),
        "top_domains": top_domains(conn, where, params, blocked_only=False),
        "top_blocked": top_domains(conn, where, params, blocked_only=True),
        "health": system_health(),
    }


def _named_counts(rows, names) -> list:
    return [{"name": names.get(r["k"], f"#{r['k']}"), "count": r["n"]}
            for r in rows]


def category_counts(conn, where, params, client_ip=None) -> list:
    sql = f"""SELECT q.domain AS domain, COUNT(*) AS n,
                     SUM(q.status IN ({_blocked_sql})) AS blocked
              FROM queries q WHERE {CLIENT_WHERE} {where}
              {"AND q.client = ?" if client_ip else ""}
              GROUP BY q.domain"""
    args = list(params) + ([client_ip] if client_ip else [])
    buckets: dict[str, dict] = {}
    for r in conn.execute(sql, args):
        cat = classify(r["domain"])
        b = buckets.setdefault(cat, {"category": cat, "count": 0, "blocked": 0})
        b["count"] += r["n"]
        b["blocked"] += int(r["blocked"] or 0)
    return sorted(buckets.values(), key=lambda b: b["count"], reverse=True)


def timeline(conn, where, params, window_seconds, client_ip=None) -> list:
    bucket = bucket_seconds(window_seconds or 604800)
    sql = f"""SELECT (CAST(q.timestamp AS INTEGER)/{bucket})*{bucket} AS slot,
                     COUNT(*) AS total,
                     SUM(q.status IN ({_blocked_sql})) AS blocked
              FROM queries q WHERE {CLIENT_WHERE} {where}
              {"AND q.client = ?" if client_ip else ""}
              GROUP BY slot ORDER BY slot"""
    args = list(params) + ([client_ip] if client_ip else [])
    out = []
    for r in conn.execute(sql, args):
        blk = int(r["blocked"] or 0)
        out.append({"t": local_time(r["slot"]), "blocked": blk,
                    "allowed": r["total"] - blk})
    return out


def top_domains(conn, where, params, blocked_only, client_ip=None) -> list:
    cond = f"AND q.status IN ({_blocked_sql})" if blocked_only else ""
    sql = f"""SELECT q.domain AS domain, COUNT(*) AS n,
                     SUM(q.status IN ({_blocked_sql})) AS blocked
              FROM queries q WHERE {CLIENT_WHERE} {where} {cond}
              {"AND q.client = ?" if client_ip else ""}
              GROUP BY q.domain ORDER BY n DESC LIMIT {TOP_DOMAINS}"""
    args = list(params) + ([client_ip] if client_ip else [])
    return [{"domain": r["domain"], "count": r["n"],
             "blocked": int(r["blocked"] or 0),
             "category": classify(r["domain"])}
            for r in conn.execute(sql, args)]


def device_list(conn, window_seconds) -> list:
    where, params = since_clause(window_seconds)
    ident = device_identity(conn)
    rows = conn.execute(
        f"""SELECT q.client AS ip, COUNT(*) total,
                   SUM(q.status IN ({_blocked_sql})) blocked,
                   MAX(q.timestamp) last_seen,
                   ROUND(AVG(q.reply_time)*1000,2) avg_ms
            FROM queries q WHERE {CLIENT_WHERE} {where}
            GROUP BY q.client ORDER BY total DESC""",
        list(params)).fetchall()
    spark = _spark_map(conn, where, params, window_seconds)
    devices = []
    for r in rows:
        ip = r["ip"]
        info = ident.get(ip, {})
        total = r["total"] or 0
        blocked = int(r["blocked"] or 0)
        cats = category_counts(conn, where, params, client_ip=ip)
        devices.append({
            "ip": ip, "label": info.get("label", "Unlabelled device"),
            "mac": info.get("mac"), "vendor": info.get("vendor"),
            "total": total, "blocked": blocked,
            "block_pct": round(100 * blocked / total, 1) if total else 0.0,
            "avg_ms": r["avg_ms"] or 0, "last_seen": local_time(r["last_seen"]),
            "top_category": cats[0]["category"] if cats else "-",
            "spark": spark.get(ip, []),
        })
    return devices


def _spark_map(conn, where, params, window_seconds) -> dict:
    bucket = bucket_seconds(window_seconds or 604800)
    rows = conn.execute(
        f"""SELECT q.client AS ip, (CAST(q.timestamp AS INTEGER)/{bucket})*{bucket} AS slot,
                   COUNT(*) n FROM queries q WHERE {CLIENT_WHERE} {where}
            GROUP BY q.client, slot ORDER BY slot""",
        list(params)).fetchall()
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r["ip"], []).append(r["n"])
    return out


def device_detail(conn, ip, window_seconds) -> dict:
    where, params = since_clause(window_seconds)
    ident = device_identity(conn).get(ip, {})
    agg = conn.execute(
        f"""SELECT COUNT(*) total, SUM(q.status IN ({_blocked_sql})) blocked,
                   SUM(q.status=3) cached, SUM(q.status IN (2,14)) forwarded,
                   ROUND(AVG(q.reply_time)*1000,2) avg_ms,
                   MAX(q.reply_time)*1000 max_ms,
                   MIN(q.timestamp) first, MAX(q.timestamp) last,
                   COUNT(DISTINCT q.domain) domains
            FROM queries q WHERE q.client = ? {where}""",
        [ip, *params]).fetchone()
    total = agg["total"] or 0
    blocked = int(agg["blocked"] or 0)
    served = (agg["cached"] or 0) + (agg["forwarded"] or 0)
    recent = conn.execute(
        f"""SELECT q.timestamp ts, q.domain domain, q.type type,
                   q.status status, q.reply_type reply, q.forward forward,
                   ROUND(q.reply_time*1000,2) ms
            FROM queries q WHERE q.client = ? {where}
            ORDER BY q.timestamp DESC LIMIT {RECENT_QUERIES}""",
        [ip, *params]).fetchall()
    return {
        "ip": ip, "identity": ident,
        "total": total, "blocked": blocked, "allowed": total - blocked,
        "block_pct": round(100 * blocked / total, 1) if total else 0.0,
        "cache_hit_pct": round(100 * (agg["cached"] or 0) / served, 1)
        if served else 0.0,
        "avg_ms": agg["avg_ms"] or 0, "max_ms": round(agg["max_ms"] or 0, 1),
        "unique_domains": agg["domains"] or 0,
        "first_seen": local_time(agg["first"]),
        "last_seen": local_time(agg["last"]),
        "categories": category_counts(conn, where, params, client_ip=ip),
        "timeline": timeline(conn, where, params, window_seconds, client_ip=ip),
        "query_types": _named_counts(
            _counts_by(conn, "q.type", where + " AND q.client = ?",
                       [*params, ip]), QUERY_TYPE_NAMES),
        "reply_types": _named_counts(
            _counts_by(conn, "q.reply_type", where + " AND q.client = ?",
                       [*params, ip]), REPLY_TYPE_NAMES),
        "top_domains": top_domains(conn, where, params, False, client_ip=ip),
        "top_blocked": top_domains(conn, where, params, True, client_ip=ip),
        "recent": [{
            "time": local_time(r["ts"]), "domain": r["domain"],
            "type": QUERY_TYPE_NAMES.get(r["type"], f"#{r['type']}"),
            "status": STATUS_NAMES.get(r["status"], "?"),
            "blocked": r["status"] in BLOCKED_STATUSES,
            "reply": REPLY_TYPE_NAMES.get(r["reply"], "-"),
            "category": classify(r["domain"]), "ms": r["ms"],
        } for r in recent],
    }


def resolve_window(query: dict) -> int:
    key = (query.get("window", [DEFAULT_WINDOW])[0]).lower()
    return WINDOWS.get(key, WINDOWS[DEFAULT_WINDOW])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlparse(self.path)
        query = parse_qs(route.query)
        try:
            if route.path in ("/", "/index.html"):
                self._send(200, PAGE_HTML.encode(), "text/html; charset=utf-8")
            elif route.path == "/api/overview":
                self._json(self._with_conn(overview, resolve_window(query)))
            elif route.path == "/api/devices":
                self._json(self._with_conn(device_list, resolve_window(query)))
            elif route.path == "/api/device":
                ip = query.get("ip", [""])[0]
                self._json(self._with_conn(
                    device_detail, ip, resolve_window(query)))
            else:
                self._send(404, b"not found", "text/plain")
        except Exception as err:
            self._send(500, json.dumps({"error": str(err)}).encode(),
                       "application/json")

    def _with_conn(self, fn, *args):
        conn = open_readonly()
        try:
            return fn(conn, *args)
        finally:
            conn.close()

    def _json(self, payload):
        self._send(200, json.dumps(payload).encode(), "application/json")


PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pi-hole Lens &mdash; per-device DNS analytics</title>
<style>
:root{color-scheme:dark;--bg:#0b0f17;--panel:#121826;--panel2:#0f1420;--line:#1f2838;
--txt:#e6edf3;--mut:#8b98ad;--accent:#3b82f6;--ok:#3fb950;--bad:#f85149;--warn:#d29922;}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:14px 22px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:9;
background:#0b0f17f2;backdrop-filter:blur(8px)}
.top{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:700;letter-spacing:.2px}
.tag{color:var(--mut);font-size:11px}
.tabs{display:flex;gap:6px;margin-left:8px}
.tab{background:var(--panel);border:1px solid var(--line);color:var(--mut);padding:6px 14px;
border-radius:7px;cursor:pointer;font-size:13px}
.tab.active{background:var(--accent);border-color:var(--accent);color:#fff}
.wins{display:flex;gap:4px;margin-left:auto}
.win{background:var(--panel);border:1px solid var(--line);color:var(--mut);padding:6px 11px;
border-radius:7px;cursor:pointer;font-size:12px}
.win.active{background:#1f2a40;border-color:var(--accent);color:#fff}
.health{display:flex;gap:14px;font-size:11px;color:var(--mut);margin-left:14px;flex-wrap:wrap}
.health b{color:var(--txt)}
main{padding:18px 22px}
.tiles{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile .v{font-size:24px;font-weight:700}
.tile .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.tile .v.bad{color:var(--bad)}.tile .v.ok{color:var(--ok)}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.panel h3{margin:0 0 12px;font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.row{display:grid;grid-template-columns:120px 1fr auto;align-items:center;gap:10px;padding:3px 0;font-size:13px}
.row .k{color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .k.mono{font-family:ui-monospace,monospace;font-size:12px}
.bar{height:7px;border-radius:4px;background:#1c2537;overflow:hidden}
.bar>i{display:block;height:100%}
.bar.ok>i{background:var(--ok)}.bar.bad>i{background:var(--bad)}.bar.ac>i{background:var(--accent)}
.cnt{color:var(--mut);font-variant-numeric:tabular-nums;min-width:46px;text-align:right}
.dom{font-family:ui-monospace,monospace;font-size:12px}
.dom.blk{color:var(--bad)}
.catpill{display:inline-block;font-size:10px;padding:1px 7px;border-radius:9px;background:#1c2537;color:var(--mut);margin-left:6px}
/* devices master-detail */
.split{display:grid;grid-template-columns:330px 1fr;gap:14px}
.list{background:var(--panel);border:1px solid var(--line);border-radius:12px;max-height:78vh;overflow:auto}
.dev{padding:11px 13px;border-bottom:1px solid var(--line);cursor:pointer}
.dev:hover{background:var(--panel2)}.dev.sel{background:#16203250;border-left:3px solid var(--accent)}
.dev .n{font-size:13px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dev .s{font-size:11px;color:var(--mut);display:flex;justify-content:space-between;margin-top:3px}
.dev .s .b{color:var(--bad)}
.spark{display:flex;align-items:flex-end;gap:1px;height:20px;margin-top:6px}
.spark i{flex:1;background:var(--accent);min-height:1px;border-radius:1px;opacity:.7}
.detail{min-height:300px}
.idrow{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin-bottom:14px}
.idrow b{color:var(--txt);font-weight:600}
.feed{max-height:320px;overflow:auto;font-size:12px}
.feed table{width:100%;border-collapse:collapse}
.feed td{padding:4px 6px;border-bottom:1px solid var(--line);white-space:nowrap}
.feed td.d{font-family:ui-monospace,monospace;max-width:260px;overflow:hidden;text-overflow:ellipsis}
.feed .st{font-size:10px;padding:1px 6px;border-radius:6px;background:#17351f;color:var(--ok)}
.feed .st.b{background:#3a1416;color:var(--bad)}
svg{display:block;width:100%;height:110px}
.muted{color:var(--mut);font-size:12px}
.sectitle{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 8px}
.note{font-size:11px;color:var(--mut);margin-top:6px}
footer{color:#48526a;font-size:11px;padding:16px 22px}
</style></head>
<body>
<header><div class="top">
  <h1>Pi-hole Lens</h1>
  <span class="tag">DNS activity &middot; domains only, not URLs or content</span>
  <div class="tabs">
    <div class="tab active" data-v="overview">Overview</div>
    <div class="tab" data-v="devices">Devices</div>
  </div>
  <div class="health" id="health"></div>
  <div class="wins">
    <div class="win" data-w="1h">1h</div>
    <div class="win active" data-w="24h">24h</div>
    <div class="win" data-w="7d">7d</div>
    <div class="win" data-w="all">all</div>
  </div>
</div></header>
<main id="view"><div class="muted">Loading&hellip;</div></main>
<footer id="foot"></footer>
<script>
let win="24h", view="overview", selIp=null, devicesCache=[];
const fmt=n=>(n==null?0:n).toLocaleString();
const esc=s=>{const e=document.createElement("div");e.textContent=s==null?"":s;return e.innerHTML;};
const api=p=>fetch(p+(p.includes("?")?"&":"?")+"window="+win).then(r=>r.json());

const CAT_COLORS={"Ads & Tracking":"#f85149","Adult":"#db2777","Security & Antivirus":"#d29922",
"Social & Messaging":"#a371f7","Streaming & Media":"#3fb950","Gaming":"#1f6feb","AI Assistants":"#2dd4bf",
"Shopping":"#f0883e","Finance & Crypto":"#eab308","Education & Work":"#58a6ff","Software Updates":"#6e7681",
"Apple Services":"#c9d1d9","Google Services":"#4285f4","Microsoft Services":"#00a4ef",
"DNS & Network":"#8b98ad","Cloud & CDN":"#39c5cf","Other":"#484f58"};
const catColor=c=>CAT_COLORS[c]||"#484f58";

function barRow(k,v,max,cls,mono,cat){
  const pct=max?Math.round(100*v/max):0;
  return `<div class="row"><div class="k ${mono?'mono':''}">${esc(k)}${cat?`<span class="catpill" style="color:${catColor(cat)}">${cat}</span>`:""}</div>`+
    `<div class="bar ${cls}"><i style="width:${pct}%"></i></div><div class="cnt">${fmt(v)}</div></div>`;
}
function listPanel(title,items,key,cls){
  const max=items.length?items[0][key.v]:1;
  const rows=items.map(it=>barRow(it[key.k],it[key.v],max,
    it.blocked&&it.blocked===it[key.v]?"bad":cls,key.mono,it.category)).join("")||'<div class="muted">No data.</div>';
  return `<div class="panel"><h3>${title}</h3>${rows}</div>`;
}
function catPanel(title,cats){
  const max=cats.length?cats[0].count:1;
  const rows=cats.map(c=>{
    const pct=max?Math.round(100*c.count/max):0;
    const bpct=c.count?Math.round(100*c.blocked/c.count):0;
    return `<div class="row"><div class="k">${esc(c.category)}</div>`+
     `<div class="bar"><i style="width:${pct}%;background:${catColor(c.category)}"></i></div>`+
     `<div class="cnt">${fmt(c.count)}${c.blocked?` <span style="color:var(--bad)">(${bpct}%&#10007;)</span>`:""}</div></div>`;
  }).join("")||'<div class="muted">No data.</div>';
  return `<div class="panel"><h3>${title}</h3>${rows}</div>`;
}
function areaChart(tl){
  if(!tl.length) return '<div class="muted">No activity in this window.</div>';
  const W=600,H=110,n=tl.length,max=Math.max(1,...tl.map(d=>d.allowed+d.blocked));
  const bw=W/n;
  const bars=tl.map((d,i)=>{
    const x=i*bw, ta=d.allowed/max*H, tb=d.blocked/max*H;
    return `<rect x="${x+0.5}" y="${H-ta-tb}" width="${bw-1}" height="${tb}" fill="var(--bad)"/>`+
      `<rect x="${x+0.5}" y="${H-ta}" width="${bw-1}" height="${ta}" fill="var(--accent)"/>`;
  }).join("");
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${bars}</svg>`+
    `<div class="row" style="grid-template-columns:1fr 1fr;margin-top:6px"><span class="muted">${esc(tl[0].t||"")}</span>`+
    `<span class="muted" style="text-align:right">${esc(tl[tl.length-1].t||"")}</span></div>`;
}

async function renderOverview(){
  const d=await api("/api/overview");
  if(d.error){document.getElementById("view").innerHTML='<div class="muted">Error: '+d.error+'</div>';return;}
  renderHealth(d.health);
  const tiles=[["queries",fmt(d.total),""],["blocked",fmt(d.blocked),"bad"],
    ["block rate",d.block_pct+"%","bad"],["devices",fmt(d.devices),""],
    ["unique domains",fmt(d.unique_domains),""],["cache hits",d.cache_hit_pct+"%","ok"],
    ["avg lookup",d.avg_ms+" ms",""],["blocklist",fmt(d.gravity_domains),""]]
    .map(([l,v,c])=>`<div class="tile"><div class="v ${c}">${v}</div><div class="l">${l}</div></div>`).join("");
  const qt=d.query_types.map(x=>barRow(x.name,x.count,d.query_types[0].count,"ac")).join("");
  const rt=d.reply_types.map(x=>barRow(x.name,x.count,d.reply_types[0].count,"ac")).join("");
  const up=d.upstreams.map(x=>barRow(x.name,x.count,(d.upstreams[0]||{count:1}).count,"ac",true)).join("")||'<div class="muted">cache only</div>';
  document.getElementById("view").innerHTML=
    `<div class="tiles">${tiles}</div>`+
    `<div class="panel" style="margin-bottom:14px"><h3>Queries over time (blue allowed &middot; red blocked)</h3>${areaChart(d.timeline)}</div>`+
    `<div class="grid">`+
      catPanel("Traffic by category",d.categories)+
      listPanel("Top domains",d.top_domains,{k:"domain",v:"count",mono:true},"ac")+
      listPanel("Top blocked",d.top_blocked,{k:"domain",v:"count",mono:true},"bad")+
      `<div class="panel"><h3>Query types</h3>${qt}</div>`+
      `<div class="panel"><h3>Reply types</h3>${rt}</div>`+
      `<div class="panel"><h3>Upstream resolvers</h3>${up}<div class="note">DNSSEC validation: off</div></div>`+
    `</div>`;
}
function renderHealth(h){
  if(!h){document.getElementById("health").innerHTML="";return;}
  document.getElementById("health").innerHTML=
    `<span>CPU <b>${h.load1}</b>/${h.cpus}</span><span>RAM <b>${h.mem_used_pct}%</b> of ${h.mem_total_gb}G</span>`+
    (h.temp_c!=null?`<span>temp <b>${h.temp_c}&deg;C</b></span>`:"")+`<span>up <b>${h.uptime_h}h</b></span>`;
}

async function renderDevices(){
  const devs=await api("/api/devices");
  if(devs.error){document.getElementById("view").innerHTML='<div class="muted">Error: '+devs.error+'</div>';return;}
  devicesCache=devs;
  if(!selIp&&devs.length)selIp=devs[0].ip;
  const maxSpark=Math.max(1,...devs.flatMap(x=>x.spark.length?x.spark:[0]));
  const items=devs.map(x=>{
    const sp=x.spark.map(v=>`<i style="height:${Math.round(100*v/maxSpark)}%"></i>`).join("");
    return `<div class="dev ${x.ip===selIp?'sel':''}" data-ip="${x.ip}">
      <div class="n">${esc(x.label)}</div>
      <div class="s"><span>${x.ip} &middot; ${esc((x.vendor||"").slice(0,18))}</span><span class="b">${x.block_pct}%&#10007;</span></div>
      <div class="s"><span>${fmt(x.total)} queries</span><span>${esc(x.top_category)}</span></div>
      <div class="spark">${sp}</div></div>`;
  }).join("");
  document.getElementById("view").innerHTML=
    `<div class="split"><div class="list">${items}</div><div class="detail" id="detail"><div class="muted">Select a device&hellip;</div></div></div>`;
  document.querySelectorAll(".dev").forEach(el=>el.onclick=()=>{selIp=el.dataset.ip;renderDevices();});
  if(selIp)renderDetail(selIp);
}
async function renderDetail(ip){
  const d=await api("/api/device?ip="+encodeURIComponent(ip));
  const host=document.getElementById("detail");if(!host)return;
  if(d.error){host.innerHTML='<div class="muted">Error: '+d.error+'</div>';return;}
  const id=d.identity||{};
  const tiles=[["queries",fmt(d.total),""],["blocked",fmt(d.blocked),"bad"],["block rate",d.block_pct+"%","bad"],
    ["unique domains",fmt(d.unique_domains),""],["cache hits",d.cache_hit_pct+"%","ok"],["avg lookup",d.avg_ms+" ms",""]]
    .map(([l,v,c])=>`<div class="tile"><div class="v ${c}">${v}</div><div class="l">${l}</div></div>`).join("");
  const qt=d.query_types.map(x=>barRow(x.name,x.count,d.query_types[0].count,"ac")).join("");
  const rt=d.reply_types.map(x=>barRow(x.name,x.count,d.reply_types[0].count,"ac")).join("");
  const feed=d.recent.map(r=>`<tr><td>${esc((r.time||"").slice(11))}</td>`+
    `<td class="d ${r.blocked?'dom blk':'dom'}">${esc(r.domain)}</td><td><span class="catpill" style="color:${catColor(r.category)}">${r.category}</span></td>`+
    `<td>${r.type}</td><td><span class="st ${r.blocked?'b':''}">${esc(r.status)}</span></td><td>${r.ms??""}</td></tr>`).join("");
  host.innerHTML=
    `<div class="panel"><h3>${esc(id.label||ip)}</h3>
      <div class="idrow"><span>IP <b>${ip}</b></span><span>MAC <b>${esc(id.mac||"?")}</b></span>
      <span>vendor <b>${esc(id.vendor||"?")}</b></span><span>iface <b>${esc(id.iface||"?")}</b></span>
      <span>first seen <b>${esc(id.first_seen||"?")}</b></span><span>last seen <b>${esc(d.last_seen||"?")}</b></span>
      <span>lifetime <b>${fmt(id.lifetime)}</b> queries</span></div>
      <div class="tiles">${tiles}</div>
      <div class="sectitle">Activity over time</div>${areaChart(d.timeline)}</div>
    <div class="grid" style="margin-top:14px">`+
      catPanel("What it's doing (by category)",d.categories)+
      listPanel("Top domains",d.top_domains,{k:"domain",v:"count",mono:true},"ac")+
      listPanel("Top blocked",d.top_blocked,{k:"domain",v:"count",mono:true},"bad")+
      `<div class="panel"><h3>Query types</h3>${qt}</div>`+
      `<div class="panel"><h3>Reply types</h3>${rt}</div>`+
    `</div>`+
    `<div class="panel" style="margin-top:14px"><h3>Recent lookups (latest ${d.recent.length})</h3>`+
      `<div class="feed"><table>${feed||'<tr><td class="muted">none</td></tr>'}</table></div></div>`;
}

function render(){ view==="overview"?renderOverview():renderDevices(); }
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
  t.classList.add("active");view=t.dataset.v;render();});
document.querySelectorAll(".win").forEach(b=>b.onclick=()=>{
  document.querySelectorAll(".win").forEach(x=>x.classList.remove("active"));
  b.classList.add("active");win=b.dataset.w;render();});
render();
setInterval(()=>{ if(view==="overview")renderOverview(); else if(selIp)renderDetail(selIp); },30000);
document.getElementById("foot").textContent="Pi-hole Lens · read-only DNS analytics · auto-refresh 30s";
</script>
</body></html>
"""


def main() -> None:
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"serving on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
