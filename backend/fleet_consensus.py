import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Set
from collections import Counter

def load_threat_intel(db_path: Path) -> Dict[str, Dict]:
    """Load threat IPs from SQLite."""
    if not db_path.exists():
        return {}
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM threat_ips").fetchall()
        return {row["ip"]: dict(row) for row in rows}

def load_agent_telemetry(db_path: Path, hours: int = 24) -> List[Dict]:
    """Load recent agent telemetry from SQLite."""
    if not db_path.exists():
        return []
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM telemetry WHERE received_at > ? ORDER BY received_at DESC",
            (cutoff,)
        ).fetchall()
        return [dict(row) for row in rows]

def fleet_consensus(threat_ips: Dict, telemetry: List[Dict]) -> Dict:
    """
    Correlate threat intel with fleet telemetry.
    Returns enriched threat data with fleet sightings.
    """
    # Build agent -> seen IPs mapping
    agent_sightings = {}
    for t in telemetry:
        agent = t.get("agent_id", "unknown")
        try:
            events = json.loads(t.get("events_json", "[]"))
            for e in events:
                # Extract IPs from event metadata
                meta = e.get("metadata", {})
                for key in ["remote_ip", "src_ip", "dst_ip", "c2_ip", "target_ip"]:
                    if key in meta:
                        ip = meta[key]
                        if ip not in agent_sightings:
                            agent_sightings[ip] = set()
                        agent_sightings[ip].add(agent)
        except:
            pass
    
    # Enrich threat intel with fleet data
    enriched = {}
    for ip, threat in threat_ips.items():
        agents = agent_sightings.get(ip, set())
        threat["fleet_sightings"] = len(agents)
        threat["fleet_agents"] = list(agents)
        threat["fleet_consensus"] = len(agents) > 1  # seen by multiple agents
        enriched[ip] = threat
    
    # Also find IPs seen by fleet but NOT in threat feeds (emerging threats)
    fleet_only = {}
    for ip, agents in agent_sightings.items():
        if ip not in threat_ips and len(agents) >= 2:
            fleet_only[ip] = {
                "ip": ip,
                "fleet_sightings": len(agents),
                "fleet_agents": list(agents),
                "fleet_consensus": True,
                "source": "fleet_only",
                "first_seen": datetime.now(timezone.utc).isoformat()
            }
    
    return {
        "enriched_threats": enriched,
        "fleet_only_threats": fleet_only,
        "stats": {
            "total_threat_feeds": len(threat_ips),
            "fleet_correlated": sum(1 for t in enriched.values() if t.get("fleet_consensus")),
            "fleet_only_emerging": len(fleet_only),
            "agents_reporting": len(set().union(*agent_sightings.values())) if agent_sightings else 0
        }
    }

def run_consensus(data_dir: str = "./data") -> Dict:
    threat_db = Path(data_dir) / "threat_intel.db"
    telemetry_db = Path(data_dir) / "telemetry.db"
    
    threat_ips = load_threat_intel(threat_db)
    telemetry = load_agent_telemetry(telemetry_db)
    result = fleet_consensus(threat_ips, telemetry)
    
    # Export
    export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result
    }
    
    out_path = Path(data_dir) / "fleet_consensus.json"
    with open(out_path, "w") as f:
        json.dump(export, f, indent=2)
    
    return export

if __name__ == "__main__":
    result = run_consensus()
    print(f"Enriched: {result['stats']['fleet_correlated']} threats")
    print(f"Fleet-only emerging: {result['stats']['fleet_only_emerging']}")
    print(f"Agents reporting: {result['stats']['agents_reporting']}")