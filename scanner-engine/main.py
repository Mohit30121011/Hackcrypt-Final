import sys
import asyncio

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import uuid
import os

from spider import Spider
from scanner import VulnerabilityScanner
from report_generator import PDFReport
from authenticator import Authenticator
import aiohttp

app = FastAPI(title="Defensive Vulnerability Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for hackathon/testing purposes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results
scan_results: Dict[str, Dict] = {}

# --- Models ---
class ScanRequest(BaseModel):
    url: str
    max_pages: int = 10
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

class Finding(BaseModel):
    type: str
    severity: str
    url: str
    evidence: str
    cwe: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    participant: Optional[str] = None
    payload: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: Optional[str] = None
    crawled_urls: List[str] = []
    findings: List[Finding] = []
    error: Optional[str] = None

# --- Background Task ---
async def run_scan(scan_id: str, url: str, max_pages: int, login_url: str = None, username: str = None, password: str = None):
    # Initialize Session
    session = None
    if login_url and username and password:
        try:
            auth = Authenticator()
            session = await auth.login(login_url, username, password)
        except Exception as e:
            print(f"[!] Auth Failed: {e}")
            session = aiohttp.ClientSession() # Fallback to unauthenticated
    else:
        session = aiohttp.ClientSession()

    scan_results[scan_id]["status"] = "Crawling"
    
    try:
        # 1. Crawl
        try:
            spider = Spider(url, max_pages)
            attack_surface = await spider.crawl(session)
            scan_results[scan_id]["crawled_urls"] = attack_surface
        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            print(f"[!] Scan Error: {error_msg}")
            scan_results[scan_id]["status"] = "Error"
            scan_results[scan_id]["error"] = str(e)
            return

        # 2. Scan
        scan_results[scan_id]["status"] = "Scanning"
        scanner = VulnerabilityScanner()
        # Link findings list immediately for real-time updates
        scan_results[scan_id]["findings"] = scanner.findings
        
        for link in attack_surface:
            await scanner.scan_url(link, session)
            
        scan_results[scan_id]["status"] = "Completed"

    finally:
        if session:
            await session.close()

# --- Routes ---

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "status": "Pending",
        "target": request.url,
        "crawled_urls": [],
        "findings": []
    }
    
    background_tasks.add_task(run_scan, scan_id, request.url, request.max_pages, request.login_url, request.username, request.password)
    
    return {"scan_id": scan_id, "status": "Pending"}

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    # Generate PDF name
    filename = f"report_{scan_id}.pdf"
    filepath = os.path.join(os.getcwd(), filename)
    
    # Generate and serve
    pdf = PDFReport()
    pdf.generate(scan_data, filepath)
    
    return FileResponse(filepath, media_type='application/pdf', filename=filename)
