#!/usr/bin/env python3
"""Build a static, keyless threat-intel snapshot for the Bulwark free tools.

Fetches the same community feeds the engine uses (no API keys), parses them
with the same rules as Sentinel.ThreatIntel, and writes data/blocklist.json so
/check works even when the engine/server is offline. The live API, when
reachable, still augments this snapshot.
"""
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "SentinelThreatIntel/2.0 (+https://bulwark.co.ke)"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data", "blocklist.json")

FEEDS = [
    ("firehol_level1",
     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
     "netset"),
    ("dshield_recommended", "https://www.dshield.org/block.txt", "dshield"),
    ("feodo_c2_recommended",
     "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "plain_ips"),
    ("urlhaus_recent", "https://urlhaus.abuse.ch/downloads/text_recent/", "url_hosts"),
]


def fetch(url):
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as ex:  # transient TLS/EOF resets are common on shared hosts
            last = ex
            time.sleep(2 * (attempt + 1))
    raise last


def netmask_to_prefix(mask):
    try:
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except Exception:
        return None


def parse_netset(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "/" not in line:
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            out.append(line)
        except ValueError:
            pass
    return out


def parse_dshield(text):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        try:
            start = ipaddress.IPv4Address(cols[0])
        except ValueError:
            continue
        third = cols[2].strip()
        prefix = netmask_to_prefix(third) if "." in third else (
            int(third) if third.isdigit() and 0 <= int(third) <= 32 else None)
        if prefix is None:
            continue
        out.append(f"{start}/{prefix}")
    return out


def parse_plain_ips(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            continue
        out.append(f"{ip}/32")
    return out


def parse_url_hosts(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or not re.match(r"^https?://", line, re.I):
            continue
        try:
            host = urllib.parse.urlsplit(line).hostname
        except Exception:
            continue
        if not host:
            continue
        host = host.lower()
        if host == "localhost":
            continue
        try:
            ipaddress.ip_address(host)
            continue  # bare IPs are handled by the net lists
        except ValueError:
            pass
        out.add(host)
    return sorted(out)


PARSERS = {"netset": parse_netset, "dshield": parse_dshield,
           "plain_ips": parse_plain_ips, "url_hosts": parse_url_hosts}


def main():
    nets = {}
    domains = {}
    sources = []
    for name, url, kind in FEEDS:
        try:
            entries = PARSERS[kind](fetch(url))
            error = None
        except Exception as ex:
            entries, error = [], str(ex)
        if kind == "url_hosts":
            if entries:
                domains[name] = entries
        else:
            if entries:
                nets[name] = entries
        sources.append({"name": name, "count": len(entries), "error": error})
        print(f"  {name:22} {len(entries):>7} {error or ''}", file=sys.stderr)

    payload = {
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": sources,
        "nets": nets,
        "domains": domains,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)

    # Also emit a JS file that works on file:// (no fetch needed)
    js_out = OUT.replace(".json", ".js")
    with open(js_out, "w", encoding="utf-8") as fh:
        fh.write("window.BULWARK_BLOCKLIST = ")
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)
        fh.write(";")

    size = os.path.getsize(OUT)
    print(f"wrote {os.path.relpath(OUT)} ({size/1024:.0f} KiB) + {os.path.basename(js_out)}")


if __name__ == "__main__":
    main()
