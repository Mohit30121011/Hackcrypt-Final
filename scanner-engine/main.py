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
from supabase import create_client, Client

from spider import Spider
from scanner import VulnerabilityScanner
from report_generator import PDFReport
from authenticator import Authenticator
import aiohttp

# Supabase Config
SUPABASE_URL = "https://hkjtntapeumanmhpydqb.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhranRudGFwZXVtYW5taHB5ZHFiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg1ODg5MzEsImV4cCI6MjA4NDE2NDkzMX0.Ssmante-lCIY90CkYjeg2LLMH0v-6nuse3CV_9cJDhI"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="Defensive Vulnerability Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class ScanRequest(BaseModel):
    url: str
    max_pages: int = 10
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_mode: str = "auto"
    stealth_mode: bool = False

class Finding(BaseModel):
    type: str
    severity: str
    url: str
    evidence: str
    cwe: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    remediation_code: Optional[str] = None
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
    print(f"[*] Starting Scan {scan_id}...")
    
    # Init Session
    session = None
    if login_url:
        try:
            auth = Authenticator()
            if auth_mode == "interactive":
                session = await auth.interactive_login(login_url)
            elif username and password:
                session = await auth.login(login_url, username, password)
            else:
                 session = aiohttp.ClientSession()
        except Exception as e:
            print(f"[!] Auth Failed: {e}")
            session = aiohttp.ClientSession()
    else:
        session = aiohttp.ClientSession()

    try:
        # Update Status -> Scanning
        supabase.table("scans").update({"status": "Scanning"}).eq("id", scan_id).execute()

        # Crawling
        spider = Spider(url, max_pages)
        crawled_urls = await spider.crawl(session_ignored=session)
        
        # Update Crawled Count
        supabase.table("scans").update({"crawled_count": len(crawled_urls)}).eq("id", scan_id).execute()

        # Scanning
        scanner = VulnerabilityScanner(scan_id=scan_id, supabase_client=supabase, stealth_mode=stealth_mode)
        
        for link in crawled_urls:
            await scanner.scan_url(link, session)
            
        # Update Status -> Completed
        supabase.table("scans").update({
            "status": "Completed", 
            "vulnerability_count": len(scanner.findings)
        }).eq("id", scan_id).execute()

    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"[!] Scan Error: {error_msg}")
        supabase.table("scans").update({"status": "Error"}).eq("id", scan_id).execute()

    finally:
        if session:
            await session.close()

# --- Routes ---

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    print(f"[DEBUG] Received Scan Request: {request}")
    
    # Create Scan Record
    res = supabase.table("scans").insert({
        "target_url": request.url,
        "status": "Pending"
    }).execute()
    
    scan_id = res.data[0]['id']
    
    background_tasks.add_task(run_scan, scan_id, request.url, request.max_pages, request.login_url, request.username, request.password, request.auth_mode, request.stealth_mode)
    
    return {"scan_id": scan_id, "status": "Pending", "target": request.url}

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    # Fetch Scan Info
    scan_res = supabase.table("scans").select("*").eq("id", scan_id).execute()
    if not scan_res.data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan_data = scan_res.data[0]
    
    # Fetch Findings
    findings_res = supabase.table("findings").select("*").eq("scan_id", scan_id).execute()
    
    return {
        "scan_id": scan_id,
        "status": scan_data.get("status"),
        "target": scan_data.get("target_url"),
        "crawled_count": scan_data.get("crawled_count", 0),
        "vulnerability_count": len(findings_res.data),
        "findings": findings_res.data
    }

@app.get("/history")
async def get_history():
    # Fetch last 50 scans
    res = supabase.table("scans").select("*").order("created_at", desc=True).limit(50).execute()
    return res.data

@app.get("/debug/scans")
async def debug_scans():
    res = supabase.table("scans").select("*").order("created_at", desc=True).limit(10).execute()
    return res.data

if __name__ == "__main__":
    import uvicorn
    # Enforce Proactor for Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
