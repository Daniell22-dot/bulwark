#!/usr/bin/env python3
"""Build a source-attributed public OSINT snapshot for Bulwark."""
import json
import os
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
OUT_JSON = os.path.join(ROOT, "data", "osint_sources.json")
OUT_JS = os.path.join(ROOT, "data", "osint_sources.js")
BLOCKLIST_JSON = os.path.join(ROOT, "data", "blocklist.json")
UA = "BulwarkOSINT/1.0 (+https://bulwark.co.ke)"

SOURCES = [
    {"name": "cisa_kev", "label": "CISA KEV", "category": "exploited-vulnerabilities", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "license": "CC0 / US Government work", "kind": "cisa_kev"},
    {"name": "nvd", "label": "NVD", "category": "vulnerabilities", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20", "license": "NIST public data", "kind": "nvd"},
    {"name": "mitre_attack", "label": "MITRE ATT&CK", "category": "tactics-techniques", "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "license": "MITRE ATT&CK terms", "kind": "mitre_attack"},
    {"name": "threatfox", "label": "abuse.ch ThreatFox", "category": "malware-iocs", "url": "https://threatfox-api.abuse.ch/api/v1/", "license": "abuse.ch terms", "kind": "threatfox", "env": "ABUSECH_AUTH_KEY"},
    {"name": "otx", "label": "AlienVault OTX", "category": "community-iocs", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", "license": "OTX terms", "kind": "otx", "env": "OTX_API_KEY"},
]


def fetch(url, headers=None, payload=None):
    last = None
    for attempt in range(3):
        try:
            data = None
            all_headers = {"User-Agent": UA, "Accept": "application/json"}
            if headers:
                all_headers.update(headers)
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
                all_headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, headers=all_headers)
            with urllib.request.urlopen(req, timeout=90) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as ex:
            last = ex
            time.sleep(2 * (attempt + 1))
    raise last


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def parse_cisa_kev(text):
    data = json.loads(text)
    items = data.get("vulnerabilities", [])
    items.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return len(items), [{
        "id": x.get("cveID"),
        "name": x.get("vulnerabilityName"),
        "dateAdded": x.get("dateAdded"),
        "ransomware": x.get("knownRansomwareCampaignUse") == "Known"
    } for x in items[:50]]


def cvss_score(item):
    metrics = item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {}).get("baseScore")
    return None


def parse_nvd(text):
    data = json.loads(text)
    items = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        items.append({
            "id": cve.get("id"),
            "published": (cve.get("published") or "")[:10],
            "score": cvss_score(entry)
        })
    return data.get("totalResults", len(items)), items[:50]


def parse_mitre_attack(text):
    data = json.loads(text)
    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        external_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_id = ref["external_id"]
                break
        if not external_id.startswith("T"):
            continue
        tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
        techniques.append({"id": external_id, "name": obj.get("name"), "tactics": tactics})
    techniques.sort(key=lambda x: x["id"])
    return len(techniques), techniques[:50]


def parse_threatfox(text):
    data = json.loads(text)
    items = data.get("data") or []
    families = Counter(str(x.get("malware", "unknown")) for x in items)
    return len(items), [{"family": k, "count": v} for k, v in families.most_common(20)]


def parse_otx(text):
    data = json.loads(text)
    items = data.get("results") or []
    return len(items), [{
        "name": x.get("name"),
        "indicators": len(x.get("indicators") or []),
        "modified": (x.get("modified") or "")[:10]
    } for x in items[:30]]


PARSERS = {
    "cisa_kev": parse_cisa_kev,
    "nvd": parse_nvd,
    "mitre_attack": parse_mitre_attack,
    "threatfox": parse_threatfox,
    "otx": parse_otx,
}


def previous_source(previous, name):
    for source in previous.get("sources", []):
        if isinstance(source, dict) and source.get("name") == name:
            return source
    return {}


def build_blocklist_summary():
    data = load_json(BLOCKLIST_JSON)
    sources = data.get("sources", [])
    nets = sum(len(v) for v in (data.get("nets") or {}).values() if isinstance(v, list))
    domains = sum(len(v) for v in (data.get("domains") or {}).values() if isinstance(v, list))
    return {
        "generatedUtc": data.get("generatedUtc"),
        "totalIndicators": nets + domains,
        "nets": nets,
        "domains": domains,
        "sources": sources,
    }


def main():
    previous = load_json(OUT_JSON)
    blocklist_summary = build_blocklist_summary()
    results = []
    for source in SOURCES:
        cfg = dict(source)
        kind = cfg.pop("kind")
        env = cfg.pop("env", None)
        key = os.environ.get(env, "").strip() if env else ""
        error = None
        count = 0
        items = []

        if env and not key:
            error = env + " not configured"
        else:
            try:
                headers = {}
                payload = None
                if kind == "threatfox":
                    headers["Auth-Key"] = key
                    payload = {"query": "get_iocs", "days": 7}
                elif kind == "otx":
                    headers["X-OTX-API-KEY"] = key
                count, items = PARSERS[kind](fetch(cfg["url"], headers, payload))
            except Exception as ex:
                error = str(ex)

        if error is not None:
            old = previous_source(previous, cfg["name"])
            count = old.get("count", 0)
            items = old.get("items", [])
            error = error + "; using previous snapshot" if old else error

        entry = dict(cfg)
        entry.update({"count": count, "error": error, "items": items})
        results.append(entry)
        print(f"  {cfg['name']:18} {count:>8} {error or ''}", file=sys.stderr)

    results.append({
        "name": "public_blocklists",
        "label": "Public Blocklists",
        "category": "network-iocs",
        "url": "data/blocklist.json",
        "license": "per-source terms",
        "count": blocklist_summary.get("totalIndicators", 0),
        "error": None,
        "items": []
    })

    summary = {
        "sources": len(results),
        "ok": sum(1 for x in results if not x.get("error")),
        "failed": sum(1 for x in results if x.get("error")),
        "totalPublicIndicators": sum(x.get("count", 0) for x in results),
    }
    payload = {
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "sources": results,
        "blocklist": blocklist_summary,
    }

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)

    with open(OUT_JS, "w", encoding="utf-8") as fh:
        fh.write("window.BULWARK_OSINT_SOURCES = ")
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)
        fh.write(";")

    print(f"wrote {os.path.relpath(OUT_JSON)} ({os.path.getsize(OUT_JSON)/1024:.0f} KiB)")


if __name__ == "__main__":
    main()
