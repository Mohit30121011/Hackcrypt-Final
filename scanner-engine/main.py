import os
import asyncio
import sys
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from supabase import create_client, Client

# Import Engine Modules
from spider import Spider
from scanner import VulnerabilityScanner
import aiohttp

# --- Config ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    # Fallback for local testing if env vars missing
    print("[!] Warning: Supabase Credentials missing. DB operations will fail.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI()

# --- Models ---
class ScanRequest(BaseModel):
    url: str
    max_pages: int = 10
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_mode: str = "none" # none, basic, form
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

        # 2. Authentication (Optional)
        if auth_mode != "none" and login_url:
            # Placeholder for Auth Logic (to be implemented in spider/scanner)
            # For now, we assume public scan or creating session
            pass

        # 3. Crawl
        print("[*] Starting Crawler...")
        spider = Spider(target_url, max_pages)
        urls = await spider.crawl()
        
        crawled_count = len(urls)
        print(f"[*] Crawl Complete. Found {crawled_count} URLs.")
        
        supabase.table("scans").update({
            "crawled_count": crawled_count
        }).eq("id", scan_id).execute()

        # 4. Scan
        print(f"[*] Starting Vulnerability Scan on {crawled_count} URLs...")
        scanner = VulnerabilityScanner(target_url) 
        
        all_findings = []
        
        # Iterating over ALL crawled URLs to find vulnerabilities
        for url in urls:
             # Basic check: Skip if it's just a fragment or unrelated
             if not url.startswith("http"): continue
             
             print(f"[*] Scanning Page: {url}")
             findings = await scanner.scan_page(url)
             all_findings.extend(findings)

        vulnerability_count = len(all_findings)
        print(f"[SUCCESS] Scan completed. Found {vulnerability_count} vulnerabilities.")

        # 5. Save Results
        supabase.table("scans").update({
            "status": "Completed",
            "vulnerability_count": vulnerability_count,
            "completed_at": datetime.utcnow().isoformat()
        }).eq("id", scan_id).execute()

        # Insert Vulnerabilities into DB
        if all_findings:
            vuln_records = []
            for vuln in all_findings:
                vuln_records.append({
                    "scan_id": scan_id,
                    "type": vuln.get("type"),
                    "severity": vuln.get("severity"),
                    "url": vuln.get("url"),
                    "description": vuln.get("description"),
                    "remediation": vuln.get("remediation")
                })
            
            supabase.table("vulnerabilities").insert(vuln_records).execute()

    except Exception as e:
        print(f"[ERROR] Scan Failed: {e}")
        import traceback
        traceback.print_exc()
        supabase.table("scans").update({"status": "Error"}).eq("id", scan_id).execute()

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
        return {"error": str(e)}

@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    res = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    
    # Get vulns
    vulns_res = supabase.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
    
    data = res.data
    data['findings'] = vulns_res.data
    
    return data

@app.get("/")
def health_check():
    return {"status": "online", "version": "2.0"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
