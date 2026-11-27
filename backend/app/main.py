import os
import json
import sqlite3
import secrets
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager, closing
from typing import Optional, List, Dict, Any, Literal

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Depends, Header, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AwareDatetime, BaseModel, Field
import httpx

# ─── Config ───
DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
DB_PATH = DATA_DIR / "telemetry.db"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO", "your-org/bulwark")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
DECEPTION_API_KEY = os.getenv("DECEPTION_API_KEY")

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─── Database ───
def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deception_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                decoy_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                host_id TEXT,
                process_name TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_deception_received "
            "ON deception_events(received_at DESC)"
        )

def store_telemetry(agent_id: str, host: str, ip: str, os: str, events: list, raw: dict) -> int:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO telemetry (received_at, agent_id, host, ip, os, events_json, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), agent_id, host, ip, os, json.dumps(events), json.dumps(raw))
        )
        return cur.lastrowid

def store_scan_result(target: str, scan_type: str, findings: list) -> int:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scan_results (started_at, target, scan_type, findings_json) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), target, scan_type, json.dumps(findings))
        )
        return cur.lastrowid

def get_recent_telemetry(limit: int = 100) -> List[Dict]:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM telemetry ORDER BY received_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_scan_results(limit: int = 50) -> List[Dict]:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_results ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def store_deception_event(event: "DeceptionEvent") -> int:
    received_at = datetime.now(timezone.utc).isoformat()
    occurred_at = (event.occurred_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        cur = conn.execute(
            """
            INSERT INTO deception_events
                (received_at, decoy_id, event_type, occurred_at, host_id, process_name)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                received_at,
                event.decoy_id,
                event.event_type,
                occurred_at,
                event.host_id,
                event.process_name,
            ),
        )
        return cur.lastrowid

def get_deception_events(limit: int = 100) -> List[Dict]:
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, received_at, decoy_id, event_type, occurred_at, host_id, process_name
            FROM deception_events ORDER BY received_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

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

class DeceptionEvent(BaseModel):
    model_config = {"extra": "forbid"}

    decoy_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    event_type: Literal["file_opened", "callback"]
    occurred_at: Optional[AwareDatetime] = None
    host_id: Optional[str] = Field(default=None, max_length=128)
    process_name: Optional[str] = Field(default=None, max_length=128)

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

def require_deception_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    if not DECEPTION_API_KEY:
        raise HTTPException(503, "Deception event intake is disabled")
    if not x_api_key or not secrets.compare_digest(x_api_key, DECEPTION_API_KEY):
        raise HTTPException(401, "Invalid or missing API key")

@app.post("/api/deception/events", status_code=201, dependencies=[Depends(require_deception_api_key)])
async def receive_deception_event(payload: DeceptionEvent):
    """Accept an authenticated report from a trusted deception sensor."""
    event_id = store_deception_event(payload)
    return {"status": "accepted", "event_id": event_id}

@app.get("/api/deception/events", dependencies=[Depends(require_deception_api_key)])
async def deception_events(limit: int = Query(default=100, ge=1, le=500)):
    """Return recent deception events to an authenticated operator."""
    return {
        "events": get_deception_events(limit),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

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