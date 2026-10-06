import os
import json
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import httpx

# ─── Threat Feed Sources ───
FEEDS = {
    "firehol_level1": {
        "url": "https://iplists.firehol.org/files/firehol_level1.netset",
        "type": "ipset",
        "description": "FireHOL Level 1 - aggressive attackers",
        "severity": "high"
    },
    "firehol_level2": {
        "url": "https://iplists.firehol.org/files/firehol_level2.netset",
        "type": "ipset",
        "description": "FireHOL Level 2 - known abusive",
        "severity": "medium"
    },
    "firehol_level3": {
        "url": "https://iplists.firehol.org/files/firehol_level3.netset",
        "type": "ipset",
        "description": "FireHOL Level 3 - potential risk",
        "severity": "low"
    },
    "dshield_top10": {
        "url": "https://feeds.dshield.org/top10-2.txt",
        "type": "dshield",
        "description": "DShield Top 10 attacking IPs",
        "severity": "critical"
    },
    "dshield_block": {
        "url": "https://feeds.dshield.org/block.txt",
        "type": "dshield",
        "description": "DShield recommended block list",
        "severity": "high"
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "feodo",
        "description": "Feodo Tracker C2 IPs",
        "severity": "critical"
    },
    "sslbl_abuse": {
        "url": "https://sslbl.abuse.ch/blacklist/sslblblacklist.csv",
        "type": "sslbl",
        "description": "SSLBL malicious SSL certificates",
        "severity": "high"
    },
    "urlhaus_payloads": {
        "url": "https://urlhaus.abuse.ch/downloads/payloads/",
        "type": "urlhaus",
        "description": "URLhaus malware payload URLs",
        "severity": "critical"
    }
}

# ─── Parsers ───
def parse_ipset(content: str) -> List[str]:
    """Parse FireHOL .netset format (CIDR per line, # comments)."""
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips

def parse_dshield(content: str) -> List[str]:
    """Parse DShield format (IP\tcount\tdate...)."""
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "\t" in line:
            ip = line.split("\t")[0].strip()
            if ip and not ip.startswith("#"):
                ips.append(ip)
    return ips

def parse_feodo(content: str) -> List[str]:
    """Parse Feodo Tracker JSON."""
    ips = []
    try:
        data = json.loads(content)
        for entry in data:
            if "ip_address" in entry:
                ips.append(entry["ip_address"])
    except:
        pass
    return ips

def parse_sslbl(content: str) -> List[str]:
    """Parse SSLBL CSV (sha256,listingdate,ip,port,reason)."""
    ips = []
    for line in content.splitlines()[1:]:  # skip header
        parts = line.split(",")
        if len(parts) >= 3:
            ips.append(parts[2].strip())
    return ips

PARSERS = {
    "ipset": parse_ipset,
    "dshield": parse_dshield,
    "feodo": parse_feodo,
    "sslbl": parse_sslbl,
}

# ─── Core Logic ───
@dataclass
class ThreatIntel:
    feed_name: str
    ips: Set[str]
    severity: str
    fetched_at: str
    source_url: str

class ThreatFeedIngestor:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "threat_intel.db"
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_ips (
                    ip TEXT PRIMARY KEY,
                    feeds TEXT NOT NULL,           -- JSON array of feed names
                    severities TEXT NOT NULL,      -- JSON array of severities
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source_details TEXT            -- JSON with feed metadata
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON threat_ips(feeds)")
    
    async def fetch_all(self) -> Dict[str, ThreatIntel]:
        results = {}
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            for name, cfg in FEEDS.items():
                try:
                    resp = await client.get(cfg["url"])
                    resp.raise_for_status()
                    parser = PARSERS.get(cfg["type"])
                    if parser:
                        ips = set(parser(resp.text))
                        results[name] = ThreatIntel(
                            feed_name=name,
                            ips=ips,
                            severity=cfg["severity"],
                            fetched_at=datetime.now(timezone.utc).isoformat(),
                            source_url=cfg["url"]
                        )
                        print(f"✓ {name}: {len(ips)} IPs")
                    else:
                        print(f"✗ {name}: no parser for type {cfg['type']}")
                except Exception as e:
                    print(f"✗ {name}: {e}")
        return results
    
    def merge_and_store(self, results: Dict[str, ThreatIntel]) -> Dict:
        """Merge all feeds into unified threat DB with consensus scoring."""
        ip_meta: Dict[str, Dict] = {}
        
        for name, intel in results.items():
            for ip in intel.ips:
                if ip not in ip_meta:
                    ip_meta[ip] = {
                        "feeds": [],
                        "severities": [],
                        "first_seen": intel.fetched_at,
                        "last_seen": intel.fetched_at,
                        "sources": {}
                    }
                meta = ip_meta[ip]
                meta["feeds"].append(name)
                meta["severities"].append(intel.severity)
                meta["last_seen"] = intel.fetched_at
                meta["sources"][name] = {
                    "severity": intel.severity,
                    "url": intel.source_url
                }
        
        # Consensus scoring
        consensus = {}
        for ip, meta in ip_meta.items():
            feed_count = len(set(meta["feeds"]))
            severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_sev_weight = max(severity_weights.get(s, 0) for s in meta["severities"])
            
            # Fleet consensus bonus: appears in multiple independent feeds
            consensus_score = max_sev_weight + min(feed_count - 1, 3)
            
            consensus[ip] = {
                "feeds": list(set(meta["feeds"])),
                "feed_count": feed_count,
                "max_severity": max(meta["severities"], key=lambda s: severity_weights.get(s, 0)),
                "consensus_score": consensus_score,
                "first_seen": meta["first_seen"],
                "last_seen": meta["last_seen"],
                "sources": meta["sources"]
            }
        
        # Store in SQLite
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            for ip, data in consensus.items():
                conn.execute("""
                    INSERT INTO threat_ips (ip, feeds, severities, first_seen, last_seen, source_details)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        feeds=excluded.feeds,
                        severities=excluded.severities,
                        last_seen=excluded.last_seen,
                        source_details=excluded.source_details
                """, (
                    ip,
                    json.dumps(data["feeds"]),
                    json.dumps([data["max_severity"]]),
                    data["first_seen"],
                    data["last_seen"],
                    json.dumps(data["sources"])
                ))
        
        # Export JSON for frontend
        export = {
            "generated_at": now,
            "total_ips": len(consensus),
            "by_feed": {name: len(intel.ips) for name, intel in results.items()},
            "consensus": consensus
        }
        
        export_path = self.data_dir / "threat_intel.json"
        with open(export_path, "w") as f:
            json.dump(export, f, indent=2)
        
        return export

async def run_ingestion(data_dir: str = "./data") -> Dict:
    """Main entry point for GitHub Actions workflow."""
    ingestor = ThreatFeedIngestor(Path(data_dir))
    results = await ingestor.fetch_all()
    export = ingestor.merge_and_store(results)
    return export

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_ingestion())