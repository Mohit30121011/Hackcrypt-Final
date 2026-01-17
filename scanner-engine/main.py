import os
import asyncio
import sys
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from supabase import create_client, Client
import aiohttp

# Import Engine Modules
from spider import Spider
from scanner import VulnerabilityScanner

# --- Config ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[!] Warning: Supabase Credentials missing. DB operations will fail.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

app = FastAPI()

# CORS
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
    auth_mode: str = "none"
    stealth_mode: bool = False

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str

# --- Core Logic ---

async def run_scan(scan_id: str, target_url: str, max_pages: int, login_url: str, username: str, password: str, auth_mode: str, stealth_mode: bool):
    print(f"[INIT] Starting scan for {target_url}...")
    
    session = None
    try:
        # 1. Update Status -> Running
        supabase.table("scans").update({"status": "Running"}).eq("id", scan_id).execute()

        # 2. Create HTTP Session
        session = aiohttp.ClientSession()

        # 3. Crawl
        print("[*] Starting Crawler...")
        spider = Spider(target_url, max_pages)
        urls = await spider.crawl()
        
        crawled_count = len(urls)
        print(f"[*] Crawl Complete. Found {crawled_count} URLs.")
        
        supabase.table("scans").update({
            "crawled_count": crawled_count
        }).eq("id", scan_id).execute()

        # 4. Scan - Using correct constructor
        print(f"[*] Starting Vulnerability Scan on {crawled_count} URLs...")
        scanner = VulnerabilityScanner(
            scan_id=scan_id, 
            supabase_client=supabase, 
            stealth_mode=stealth_mode
        )
        
        # Scan each URL
        for url in urls:
             if not url.startswith("http"): continue
             print(f"[*] Scanning: {url}")
             await scanner.scan_url(url, session)

        vulnerability_count = len(scanner.findings)
        print(f"[SUCCESS] Scan completed. Found {vulnerability_count} vulnerabilities.")

        # 5. Save Results
        supabase.table("scans").update({
            "status": "Completed",
            "vulnerability_count": vulnerability_count,
            "completed_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()

    except Exception as e:
        print(f"[ERROR] Scan Failed: {e}")
        import traceback
        traceback.print_exc()
        supabase.table("scans").update({"status": "Error"}).eq("id", scan_id).execute()
    finally:
        if session:
            await session.close()

@app.post("/scan")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        # Insert initial record
        res = supabase.table("scans").insert({
            "target_url": request.url,
            "status": "Pending"
        }).execute()
        
        scan_id = res.data[0]['id']
        
        # Start Background Task
        background_tasks.add_task(
            run_scan, 
            scan_id, 
            request.url, 
            request.max_pages, 
            request.login_url, 
            request.username, 
            request.password, 
            request.auth_mode, 
            request.stealth_mode
        )
        
        return {"scan_id": scan_id, "status": "Pending", "target": request.url}
    
    except Exception as e:
        import traceback
        return {"error": str(e), "trace": traceback.format_exc()}

@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    res = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    
    # Get vulns
    vulns_res = supabase.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
    
    data = res.data
    data['findings'] = vulns_res.data
    
    return data

@app.get("/history")
async def get_history():
    res = supabase.table("scans").select("*").order("created_at", desc=True).limit(50).execute()
    return res.data

@app.get("/debug/scans")
async def debug_scans():
    res = supabase.table("scans").select("*").order("created_at", desc=True).limit(10).execute()
    return res.data

@app.get("/")
def health_check():
    return {"status": "online", "version": "2.0", "supabase_connected": supabase is not None}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
