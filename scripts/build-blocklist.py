#!/usr/bin/env python3
"""Build a static, keyless threat-intel snapshot for the Bulwark free tools."""
import csv
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "BulwarkThreatIntel/2.1 (+https://bulwark.co.ke)"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data", "blocklist.json")

FEEDS = [
    ("firehol_level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "netset", {"category": "abusive-networks", "license": "CC BY-SA 4.0"}),
    ("firehol_level2", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", "netset", {"category": "abusive-networks", "license": "CC BY-SA 4.0"}),
    ("dshield_recommended", "https://www.dshield.org/block.txt", "dshield", {"category": "attackers", "license": "DShield terms"}),
    ("feodo_c2_recommended", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "plain_ips", {"category": "botnet-c2", "license": "CC0"}),
    ("et_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "plain_ips", {"category": "compromised-hosts", "license": "ET Open ruleset"}),
    ("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", "drop", {"category": "hijacked-networks", "license": "Spamhaus DROP terms"}),
    ("tor_exit_nodes", "https://check.torproject.org/torbulkexitlist", "plain_ips", {"category": "anonymisation", "license": "Tor Project public list"}),
    ("urlhaus_recent", "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv", "urlhaus_csv", {"category": "malware-urls", "license": "abuse.ch terms", "env": "ABUSECH_AUTH_KEY"}),
    ("otx_indicators", "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", "otx", {"category": "community-iocs", "license": "OTX terms", "env": "OTX_API_KEY"}),
]


def fetch(url, headers=None):
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers or {"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as ex:
            last = ex
            time.sleep(2 * (attempt + 1))
    raise last


def netmask_to_prefix(mask):
    try:
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except Exception:
        return None


def clean_network(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def clean_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def host_from_url(value):
    if not re.match(r"^https?://", value, re.I):
        return None
    try:
        host = urllib.parse.urlsplit(value).hostname
    except Exception:
        return None
    if not host or host.lower() == "localhost":
        return None
    if clean_ip(host):
        return None
    return host.lower()


def parse_netset(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "/" not in line:
            continue
        net = clean_network(line)
        if net:
            out.append(net)
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
        start = clean_ip(cols[0])
        if not start:
            continue
        third = cols[2].strip()
        prefix = netmask_to_prefix(third) if "." in third else (
            int(third) if third.isdigit() and 0 <= int(third) <= 32 else None)
        if prefix is None:
            continue
        net = clean_network(f"{start}/{prefix}")
        if net:
            out.append(net)
    return out


def parse_plain_ips(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = clean_ip(line.split()[0])
        if ip:
            out.append(f"{ip}/32")
    return out


def parse_drop(text):
    out = []
    for line in text.splitlines():
        value = line.split(";", 1)[0].strip()
        if not value or value.startswith("#"):
            continue
        net = clean_network(value)
        if net:
            out.append(net)
    return out


def parse_url_hosts(text):
    out = set()
    for line in text.splitlines():
        host = host_from_url(line.strip())
        if host:
            out.add(host)
    return sorted(out)


def parse_urlhaus_csv(text):
    out = set()
    rows = csv.reader(text.splitlines())
    headers = next(rows, [])
    try:
        url_col = headers.index("url")
    except ValueError:
        url_col = 2
    for row in rows:
        if len(row) <= url_col:
            continue
        host = host_from_url(row[url_col].strip())
        if host:
            out.add(host)
    return sorted(out)


def parse_otx(text):
    data = json.loads(text)
    nets = set()
    domains = set()
    for pulse in data.get("results", []):
        for item in pulse.get("indicators", []):
            value = str(item.get("indicator", "")).strip()
            kind = str(item.get("type", "")).lower()
            if not value:
                continue
            if kind in ("ipv4", "ipv6", "cidr"):
                net = clean_network(value if "/" in value else f"{clean_ip(value)}/32")
                if net:
                    nets.add(net)
            elif kind in ("domain", "hostname"):
                domains.add(value.lower().rstrip("."))
            elif kind in ("url", "uri"):
                host = host_from_url(value)
                if host:
                    domains.add(host)
    return {"nets": sorted(nets), "domains": sorted(domains)}


PARSERS = {
    "netset": parse_netset,
    "dshield": parse_dshield,
    "plain_ips": parse_plain_ips,
    "drop": parse_drop,
    "url_hosts": parse_url_hosts,
    "urlhaus_csv": parse_urlhaus_csv,
    "otx": parse_otx,
}


def load_previous():
    try:
        with open(OUT, encoding="utf-8") as fh:
            previous = json.load(fh)
        return previous if isinstance(previous, dict) else {}
    except (OSError, ValueError):
        return {}


def previous_entries(previous, key, name):
    bucket = previous.get(key, {})
    if isinstance(bucket, dict):
        return bucket.get(name, [])
    return []


def main():
    previous = load_previous()
    nets = {}
    domains = {}
    sources = []

    for name, url, kind, opts in FEEDS:
        error = None
        parsed = None
        key = os.environ.get(opts.get("env", ""), "").strip() if opts.get("env") else ""
        if opts.get("env") and not key:
            error = opts["env"] + " not configured"
        else:
            try:
                target = url.format(key=key) if "{key}" in url else url
                headers = {"User-Agent": UA}
                if name == "otx_indicators":
                    headers["X-OTX-API-KEY"] = key
                parsed = PARSERS[kind](fetch(target, headers))
            except Exception as ex:
                error = str(ex)

        if parsed is None:
            fallback_nets = previous_entries(previous, "nets", name)
            fallback_domains = previous_entries(previous, "domains", name)
            parsed = {"nets": fallback_nets, "domains": fallback_domains} if kind == "otx" else (
                fallback_domains if kind in ("url_hosts", "urlhaus_csv") else fallback_nets)
            has_fallback = bool(fallback_nets or fallback_domains)
            if has_fallback:
                error = (error + "; using previous snapshot") if error else "using previous snapshot"
            elif kind != "otx":
                parsed = []

        if kind == "otx":
            net_values = parsed.get("nets", [])
            domain_values = parsed.get("domains", [])
        elif kind in ("url_hosts", "urlhaus_csv"):
            net_values = []
            domain_values = parsed
        else:
            net_values = parsed
            domain_values = []

        if net_values:
            nets[name] = sorted(set(net_values))
        if domain_values:
            domains[name] = sorted(set(domain_values))
        count = len(net_values) + len(domain_values)
        source = {"name": name, "count": count, "error": error}
        source.update({k: v for k, v in opts.items() if k != "env"})
        sources.append(source)
        print(f"  {name:22} {count:>7} {error or ''}", file=sys.stderr)

    payload = {
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": sources,
        "nets": nets,
        "domains": domains,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)

    js_out = OUT.replace(".json", ".js")
    with open(js_out, "w", encoding="utf-8") as fh:
        fh.write("window.BULWARK_BLOCKLIST = ")
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)
        fh.write(";")

    size = os.path.getsize(OUT)
    print(f"wrote {os.path.relpath(OUT)} ({size/1024:.0f} KiB) + {os.path.basename(js_out)}")


if __name__ == "__main__":
    main()
