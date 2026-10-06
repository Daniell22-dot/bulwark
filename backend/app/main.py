import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import httpx

# ─── Config ───
DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
DB_PATH = DATA_DIR / "telemetry.db"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO", "your-org/bulwark")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─── Database ───
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                host TEXT,
                ip TEXT,
                os TEXT,
                events_json TEXT NOT NULL,
                raw_json TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_time ON telemetry(agent_id, received_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                status TEXT DEFAULT 'completed'
            )
        """)

def store_telemetry(agent_id: str, host: str, ip: str, os: str, events: list, raw: dict) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO telemetry (received_at, agent_id, host, ip, os, events_json, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), agent_id, host, ip, os, json.dumps(events), json.dumps(raw))
        )
        return cur.lastrowid

def store_scan_result(target: str, scan_type: str, findings: list) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO scan_results (started_at, target, scan_type, findings_json) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), target, scan_type, json.dumps(findings))
        )
        return cur.lastrowid

def get_recent_telemetry(limit: int = 100) -> List[Dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM telemetry ORDER BY received_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_scan_results(limit: int = 50) -> List[Dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_results ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

# ─── GitHub Sync ───
async def push_to_github(path: str, content: str, message: str) -> bool:
    """Commit a file to the GitHub repo via API."""
    if not GITHUB_TOKEN:
        return False
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    async with httpx.AsyncClient(timeout=30) as client:
        # Get current SHA if file exists
        sha = None
        resp = await client.get(url, headers=headers, params={"ref": GITHUB_BRANCH})
        if resp.status_code == 200:
            sha = resp.json().get("sha")
        
        import base64
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": GITHUB_BRANCH
        }
        if sha:
            payload["sha"] = sha
        
        resp = await client.put(url, headers=headers, json=payload)
        return resp.status_code in (200, 201)

async def sync_telemetry_to_github():
    """Export recent telemetry as JSON and commit to repo for Actions to consume."""
    data = get_recent_telemetry(500)
    content = json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(), "telemetry": data}, indent=2)
    await push_to_github("data/telemetry.json", content, "chore: sync telemetry export")

async def sync_scans_to_github():
    data = get_scan_results(200)
    content = json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(), "scans": data}, indent=2)
    await push_to_github("data/scans.json", content, "chore: sync scan results")

# ─── Models ───
class TelemetryEvent(BaseModel):
    type: str
    severity: str = "info"
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = {}

class TelemetryPayload(BaseModel):
    agent_id: str
    host: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    events: List[TelemetryEvent]

class ScanTrigger(BaseModel):
    target: str
    scan_type: str = "web"  # web, repo, usb, network
    options: Dict[str, Any] = {}

# ─── App ───
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Bulwark Backend", version="1.0.0", lifespan=lifespan)

# ─── Routes ───
@app.post("/telemetry")
async def receive_telemetry(payload: TelemetryPayload, background: BackgroundTasks):
    """C# agents POST here with their event batches."""
    try:
        store_telemetry(
            payload.agent_id,
            payload.host or "unknown",
            payload.ip or "unknown",
            payload.os or "unknown",
            [e.model_dump() for e in payload.events],
            payload.model_dump()
        )
        background.add_task(sync_telemetry_to_github)
        return {"status": "ok", "stored": len(payload.events)}
    except Exception as e:
        raise HTTPException(500, f"Failed to store telemetry: {e}")

@app.post("/scan")
async def trigger_scan(payload: ScanTrigger, background: BackgroundTasks):
    """GitHub Actions or manual trigger calls this to run a scan."""
    # In a real setup, this would queue a scan job. For now, just record.
    findings = []  # populated by actual scanner
    scan_id = store_scan_result(payload.target, payload.scan_type, findings)
    background.add_task(sync_scans_to_github)
    return {"status": "queued", "scan_id": scan_id}

@app.get("/api/dashboard")
async def dashboard_data():
    """Frontend fetches this for the live dashboard."""
    return {
        "telemetry": get_recent_telemetry(50),
        "scans": get_scan_results(20),
        "generated_at": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "time": datetime.now(timezone.utc).isoformat()}

# ─── Run ───
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)