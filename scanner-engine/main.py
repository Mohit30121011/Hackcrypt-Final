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
    auth_mode: str = "auto" # 'auto' (headless) or 'interactive' (headful)
    stealth_mode: bool = False # Enable WAF evasion (delays + jitter)

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
async def run_scan(scan_id: str, url: str, max_pages: int, login_url: str = None, username: str = None, password: str = None, auth_mode: str = "auto", stealth_mode: bool = False):
    # Initialize Session
    session = None
    if login_url:
        try:
            auth = Authenticator()
            if auth_mode == "interactive":
                session = await auth.interactive_login(login_url)
            elif username and password:
                session = await auth.login(login_url, username, password)
            else:
                 print("[!] Auto-login requires username & password, but they were missing. Proceeding unauthenticated.")
                 session = aiohttp.ClientSession()
        except Exception as e:
            print(f"[!] Auth Failed: {e}")
            session = aiohttp.ClientSession() # Fallback to unauthenticated
    else:
        session = aiohttp.ClientSession()

    try:
        # Crawling (Spider)
        spider = Spider(url, max_pages)
        crawled_urls = await spider.crawl(session_ignored=session)
        
        # Scanning (VulnerabilityScanner)
        scanner = VulnerabilityScanner(stealth_mode=stealth_mode)
        
        # Update status to Scanning
        scan_results[scan_id]["status"] = "Scanning"
        scan_results[scan_id]["crawled_urls"] = crawled_urls
        
        # Link findings list immediately for real-time updates
        scan_results[scan_id]["findings"] = scanner.findings
        
        for link in crawled_urls:
            await scanner.scan_url(link, session)
            
        scan_results[scan_id]["status"] = "Completed"

    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"[!] Scan Error: {error_msg}")
        scan_results[scan_id]["status"] = "Error"
        scan_results[scan_id]["error"] = error_msg

    finally:
        if session:
            await session.close()

# --- Routes ---

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    print(f"[DEBUG] Received Scan Request: {request}")
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "status": "Pending",
        "target": request.url,
        "crawled_urls": [],
        "findings": [],
        "error": None
    }
    
    background_tasks.add_task(run_scan, scan_id, request.url, request.max_pages, request.login_url, request.username, request.password, request.auth_mode, request.stealth_mode)
    
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
    
    # Check if report exists
    report_path = f"report_{scan_id}.pdf"
    if not os.path.exists(report_path):
         raise HTTPException(status_code=404, detail="Report not generating or failed.")
         
    return FileResponse(report_path, media_type="application/pdf", filename=f"security_report_{scan_id}.pdf")

@app.get("/debug/scans")
async def get_all_scans():
    return scan_results

    
    # Generate and serve
    pdf = PDFReport()
    pdf.generate(scan_data, filepath)
    
    return FileResponse(filepath, media_type='application/pdf', filename=filename)

if __name__ == "__main__":
    import uvicorn
    # Enforce Proactor for Windows + Playwright
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
