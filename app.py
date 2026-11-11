#!/usr/bin/env python3
"""FastAPI web application for Lab 03 network vulnerability scanner."""
import ipaddress
import os
import sqlite3
import threading
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import scanner_core as sc

REPORT_DIR = os.getenv("REPORT_DIR", "/app/data/reports")
CACHE_FILE = os.getenv("CACHE_FILE", "/app/data/cve_cache.json")
# No allowlist: any valid IP/CIDR may be scanned (lab use). Format is still validated.
NVD_API_KEY = os.getenv("NVD_API_KEY") or None
DB_PATH = os.getenv("DB_PATH", "/app/data/jobs.db")

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(CACHE_FILE) or ".", exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

app = FastAPI(title="Network Vulnerability Scanner  --  NetVulnScan", version="1.0")

# static + templates
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_db_lock = threading.Lock()


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            progress TEXT,
            message TEXT,
            csv_path TEXT,
            html_path TEXT,
            created_at TEXT,
            finished_at TEXT,
            error TEXT
        )""")
        conn.commit()


_init_db()


def _allowed_target(target: str) -> bool:
    try:
        # support comma-separated list of IPs/CIDRs from UI
        parts = [p.strip() for p in target.replace(";", ",").split(",") if p.strip()]
        if not parts:
            return False
        for p in parts:
            ipaddress.ip_network(p, strict=False)  # raises ValueError if invalid
        return True
    except ValueError:
        return False


class ScanRequest(BaseModel):
    target: str
    no_cve: bool = False
    nvd_api_key: Optional[str] = None


def _run_job(job_id: str, target: str, no_cve: bool, api_key: Optional[str]):
    def set_status(status, progress=None, message=None, csv_path=None, html_path=None, error=None):
        with _db_lock, _db() as conn:
            conn.execute(
                """UPDATE jobs SET status=?, progress=?, message=?, csv_path=?, html_path=?,
                   finished_at=?, error=? WHERE id=?""",
                (status, progress, message, csv_path, html_path,
                 datetime.now().isoformat() if status in ("done", "error") else None,
                 error, job_id))
            conn.commit()

    set_status("running", "10%", "Starting scan...")
    try:
        targets = [t.strip() for t in target.replace(";", ",").split(",") if t.strip()]
        # normalize single IP to /32 not needed; nmap accepts IP
        log_lines = []

        def log(msg):
            log_lines.append(msg)
            set_status("running", None, msg)

        set_status("running", "20%", "Host discovery...")
        result = sc.run_scan(
            targets=targets,
            api_key=api_key or NVD_API_KEY,
            skip_cve=no_cve,
            output_dir=REPORT_DIR,
            cache_file=CACHE_FILE,
            log=log,
        )
        set_status("done", "100%", "Scan complete.",
                   csv_path=result["csv_path"], html_path=result["html_path"])
    except Exception as e:
        set_status("error", "0%", "Scan failed.", error=str(e))


@app.get("/", response_class=HTMLResponse)
def index():
    path = os.path.join(TEMPLATE_DIR, "index.html")
    if not os.path.exists(path):
        return HTMLResponse("<h1>Template missing</h1>", status_code=500)
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.post("/api/scan")
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    if not _allowed_target(req.target):
        raise HTTPException(status_code=400, detail="Target not allowed by ALLOWED_CIDRS policy.")
    job_id = str(uuid.uuid4())
    with _db_lock, _db() as conn:
        conn.execute(
            "INSERT INTO jobs (id, target, status, progress, message, created_at) VALUES (?,?,?,?,?,?)",
            (job_id, req.target, "queued", "0%", "Queued", datetime.now().isoformat()))
        conn.commit()
    bg.add_task(_run_job, job_id, req.target, req.no_cve, req.nvd_api_key)
    return {"job_id": job_id}


@app.get("/api/scan/{job_id}")
def get_scan(job_id: str):
    with _db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return dict(row)


@app.get("/api/scan/{job_id}/report", response_class=HTMLResponse)
def get_report(job_id: str):
    with _db() as conn:
        row = conn.execute("SELECT html_path FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row or not row["html_path"] or not os.path.exists(row["html_path"]):
        raise HTTPException(status_code=404, detail="Report not ready")
    with open(row["html_path"], encoding="utf-8") as f:
        return f.read()


@app.get("/api/scan/{job_id}/csv")
def get_csv(job_id: str):
    with _db() as conn:
        row = conn.execute("SELECT csv_path FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row or not row["csv_path"] or not os.path.exists(row["csv_path"]):
        raise HTTPException(status_code=404, detail="CSV not ready")
    return FileResponse(row["csv_path"], filename=os.path.basename(row["csv_path"]),
                        media_type="text/csv")


@app.get("/api/jobs")
def list_jobs():
    with _db() as conn:
        rows = conn.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}
