import aiohttp
import asyncio
import re
import random
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

class VulnerabilityScanner:
    def __init__(self, stealth_mode: bool = False):
        self.stealth_mode = stealth_mode
        self.findings: List[Dict[str, Any]] = []
        
        # WAF Evasion: User-Agent Rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]

        # Knowledge Base for Detection Logic
        self.sql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Unclosed quotation mark after the character string",
            "Unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "Syntax error near", # Common generic error
        ]
        self.xss_test_string = "<sc_test>"
        self.sensitive_patterns = {
            "API Key": r"(?i)(api_key|apikey)[\s:=]+[\w\-]+",
            "Password": r"(?i)(password|passwd)[\s:=]+[\w\-]+",
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        }
        self.fuzz_files = [".env", "config.php.bak", "backup.sql", ".git/HEAD", ".vscode/settings.json"]
        self.required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]
        
        # Smart 404 Detection
        self.scanned_hosts = set()
        self.smart_404_fingerprint = None
        
        # Knowledge Base for Reporting
        self.kb = {
            "sql_injection": {"name": "SQL Injection", "severity": "High", "cwe": "CWE-89", "description": "Untrusted input interferes with a database query.", "remediation": "Use parameterized queries."},
            "xss_reflected": {"name": "Reflected XSS", "severity": "Medium", "cwe": "CWE-79", "description": "Reflects untrusted data without escaping.", "remediation": "Use output encoding."},
            "sensitive_data": {"name": "Sensitive Data Exposure", "severity": "Low", "cwe": "CWE-200", "description": "Exposes sensitive information.", "remediation": "Remove from responses."},
            "security_header": {"name": "Missing Security Header", "severity": "Low", "cwe": "CWE-693", "description": "Missing HTTP security headers.", "remediation": "Configure strict headers."},
            "hidden_file": {"name": "Hidden File Exposure", "severity": "High", "cwe": "CWE-538", "description": "Sensitive file accessible.", "remediation": "Remove from web root."},
            "blind_sqli": {"name": "Blind SQL Injection", "severity": "Critical", "cwe": "CWE-89", "description": "Time-based SQL injection.", "remediation": "Use parameterized queries."},
            "union_sqli": {"name": "UNION SQLi", "severity": "Critical", "cwe": "CWE-89", "description": "UNION-based SQL injection.", "remediation": "Use parameterized queries."},
            "dom_xss": {"name": "DOM XSS", "severity": "Medium", "cwe": "CWE-79", "description": "Dangerous JS sinks found.", "remediation": "Avoid innerHTML, eval()."},
            "tech_stack": {"name": "Tech Stack Disclosure", "severity": "Info", "cwe": "CWE-200", "description": "Discloses tech versions.", "remediation": "Suppress Server headers."},
            "lfi": {"name": "Local File Inclusion", "severity": "Critical", "cwe": "CWE-22", "description": "Reads arbitrary files.", "remediation": "Validate against whitelist."},
            "ssti": {"name": "Server-Side Template Injection", "severity": "Critical", "cwe": "CWE-1336", "description": "Template engine RCE.", "remediation": "Sandbox templates."},
            "cors_misconfig": {"name": "CORS Misconfiguration", "severity": "High", "cwe": "CWE-346", "description": "Accepts arbitrary origins.", "remediation": "Whitelist trusted origins."},
            "open_port": {"name": "Open Port", "severity": "Info", "cwe": "CWE-200", "description": "Non-standard port open.", "remediation": "Close via firewall."},
            "csti": {"name": "Client-Side Template Injection", "severity": "High", "cwe": "CWE-79", "description": "Reflected in client templates.", "remediation": "Escape user input."},
            "blind_rce": {"name": "Blind RCE", "severity": "Critical", "cwe": "CWE-78", "description": "Executes commands (time delay).", "remediation": "Avoid system calls."},
            "rce": {"name": "Remote Code Execution", "severity": "Critical", "cwe": "CWE-78", "description": "Executes arbitrary commands.", "remediation": "Never pass user input to system."},
            "bola": {"name": "BOLA/IDOR", "severity": "High", "cwe": "CWE-639", "description": "Access to other users' objects.", "remediation": "Implement authorization checks."},
            "bac": {"name": "Broken Access Control", "severity": "High", "cwe": "CWE-285", "description": "Unprivileged access to admin pages.", "remediation": "Enforce RBAC."},
            "jwt_none": {"name": "Insecure JWT (alg:none)", "severity": "Critical", "cwe": "CWE-327", "description": "JWT signature bypass.", "remediation": "Reject 'none' algorithm."},
            "cookie_insecure": {"name": "Insecure Cookie Flags", "severity": "Low", "cwe": "CWE-1275", "description": "Missing Secure/HttpOnly flags.", "remediation": "Set cookie flags properly."},
            "weak_crypto": {"name": "Weak Cryptography", "severity": "Medium", "cwe": "CWE-327", "description": "Weak crypto algorithms.", "remediation": "Use AES-256, SHA-256."}
        }
        
    async def perform_request(self, session, method, url, **kwargs):
        """
        Wrapper for HTTP requests with WAF Evasion (Jitter + User-Agent Rotation).
        """
        if self.stealth_mode:
            # 1. Random Delay (Jitter)
            delay = random.uniform(0.5, 1.5)
            await asyncio.sleep(delay)
            
            # 2. Rotate User-Agent
            headers = kwargs.get("headers", {})
            if "User-Agent" not in headers:
                headers["User-Agent"] = random.choice(self.user_agents)
            kwargs["headers"] = headers
        
        # 3. Perform Request
        try:
            if method.upper() == "GET":
                return session.get(url, **kwargs)
            elif method.upper() == "POST":
                return session.post(url, **kwargs)
            elif method.upper() == "HEAD":
                return session.head(url, **kwargs)
        except Exception:
            # Return a dummy context manager that yields None or raises
            pass
        return session.get(url, **kwargs) # Fallback

    async def detect_smart_404(self, session, url):
        """
        Fingerprints the 'Not Found' page of the server to avoid FPs.
        """
        try:
            parsed = urlparse(url)
            # Use a specialized bogus path
            bogus_url = f"{parsed.scheme}://{parsed.netloc}/sc_404_{int(time.time())}"
            ctx = await self.perform_request(session, 'GET', bogus_url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                # Store status and length (with sloppy tolerance)
                self.smart_404_fingerprint = (resp.status, len(text))
                print(f"[*] Smart 404 Fingerprint: Status={resp.status}, Len={len(text)}")
        except:
            pass

    def is_custom_404(self, status, text):
        """
        Checks if a response matches the Smart 404 fingerprint.
        """
        if not self.smart_404_fingerprint:
            return False
            
        fp_status, fp_len = self.smart_404_fingerprint
        
        # If status matches exactly
        if status == fp_status:
            # If length is within 5% tolerance
            if abs(len(text) - fp_len) < (fp_len * 0.05):
                return True
        return False

    def _add_finding(self, key: str, url: str, evidence: str, param: str = None, payload: str = None):
        info = self.kb.get(key, {})
        self.findings.append({
            "type": info.get("name", "Unknown Issue"),
            "severity": info.get("severity", "Low"),
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "type": info.get("name", "Unknown Issue"),
            "severity": info.get("severity", "Low"),
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "remediation_code": info.get("remediation_code", ""), # New Field
            "cwe": info.get("cwe", "")
        })
        print(f"[!] {info.get('name')} found at {url}")

    async def scan_url(self, url: str, session: aiohttp.ClientSession):
        print(f"[*] Scanning {url}...")
        
        # 0. Smart 404 Baseline (Once per host)
        parsed = urlparse(url)
        if not self.smart_404_fingerprint:
             await self.detect_smart_404(session, url)
        
        # Network Level Checks (Once per host)
        await self.check_open_ports(url)
        
        await self.check_tech_stack(session, url)
        
        if url.endswith(".js"):
            await self.check_js_analysis(session, url)
            return

        # Injection Checks
        await self.check_sqli(session, url)
        await self.check_union_sqli(session, url) 
        await self.check_lfi(session, url)
        await self.check_rce(session, url)
        await self.check_blind_rce(session, url) # New
        await self.check_ssti(session, url)
        await self.check_csti(session, url) # New
        await self.check_bola(session, url) # New
        await self.check_bac(session, url) # New
        await self.check_jwt(session, url) # New
        await self.check_xss(session, url)
        
        # Configuration Checks
        await self.check_cors(session, url)
        await self.check_sensitive_info(session, url)
        await self.check_sensitive_info(session, url)
        await self.check_security_headers(session, url)
        await self.check_cookie_security(session, url) # New
        
        if urlparse(url).path in ["", "/"]:
            await self.check_sensitive_files(session, url)
        
        await self.check_time_based_sqli(session, url)
        await self.check_boolean_sqli(session, url)

    async def check_open_ports(self, url):
        hostname = urlparse(url).hostname
        if not hostname or hostname in self.scanned_hosts: return
        self.scanned_hosts.add(hostname)
        
        # Top 10 ports to scan
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080, 8443]
        
        for port in ports:
            try:
                # Simple async connect with timeout
                fut = asyncio.open_connection(hostname, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                await writer.wait_closed()
                self._add_finding("open_port", f"{hostname}:{port}", f"Port {port} is OPEN", str(port), None)
            except:
                pass


    async def check_cors(self, session, url):
        try:
            headers = {"Origin": "http://evil-scanner.com"}
            ctx = await self.perform_request(session, 'GET', url, headers=headers, timeout=5)
            async with ctx as resp:
                allow_origin = resp.headers.get("Access-Control-Allow-Origin")
                if allow_origin == "http://evil-scanner.com":
                    self._add_finding("cors_misconfig", url, "Server trustworthy reflected malicious Origin", None, "Origin: http://evil-scanner.com")
                elif allow_origin == "*":
                     self._add_finding("cors_misconfig", url, "Server allows wildcard (*) origin with credentials", None, "Access-Control-Allow-Origin: *")
        except: pass

    async def check_ssti(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # ${{7*7}} -> 49
        ssti_payloads = [
            "${{7*7}}", 
            "{{7*7}}", 
            "<%= 7*7 %>"
        ]

        for param in params:
            for payload in ssti_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        if "49" in text: # If 7*7 is evaluated to 49
                             self._add_finding("ssti", url, "Template Expression Evaluated (7*7 -> 49)", param, payload)
                             break
                except: pass

    async def check_csti(self, session, url):
        """
        Client-Side Template Injection (Angular/Vue)
        We look for the raw payload reflected in the response without escaping.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Vue/Angular/React payloads
        csti_payloads = [
            "{{7*7}}", 
            "{{1+1}}",
            "[[7*7]]"
        ]

        for param in params:
            for payload in csti_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        # If the payload is reflected EXACTLY as is, it *might* be CSTI.
                        # Stronger check: Look for context (ng-app, etc.) but for now reflection is good.
                        if payload in text:
                             # Exclude strict textareas or safe contexts if possible, but for now report reflection.
                             self._add_finding("csti", url, f"CSTI Payload reflected: {payload}", param, payload)
                             break
                except: pass

    async def check_bola(self, session, url):
        """
        Broken Object Level Authorization (BOLA / IDOR).
        Detects numeric IDs in params and tries to access other objects.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # 1. Check Query Params for IDs
        if params:
            for param, values in params.items():
                for value in values:
                    if value.isdigit():
                        original_id = int(value)
                        # Try ID+1 and ID-1
                        test_ids = [original_id + 1, original_id - 1]
                        
                        for tid in test_ids:
                            test_params = params.copy()
                            test_params[param] = [str(tid)]
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                            
                            try:
                                ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                                async with ctx as resp:
                                    if resp.status == 200:
                                        # Heuristic: If we get 200 for a different ID, it MIGHT be BOLA.
                                        # Use text diff or regex for PII (SSN, Email) to be sure.
                                        text = await resp.text()
                                        if "SSN" in text or "admin" in text.lower() or "private" in text.lower():
                                            self._add_finding("bola", url, f"Access to object ID {tid} successful", param, str(tid))
                                            break
                            except: pass

        # 2. Check URL Path for IDs (e.g., /api/user/100)
        # Regex to find integer segments in path
        path_segments = parsed.path.split('/')
        for i, segment in enumerate(path_segments):
            if segment.isdigit():
                original_id = int(segment)
                # Try ID+1
                new_path = list(path_segments)
                new_path[i] = str(original_id + 1)
                test_url = urlunparse(parsed._replace(path='/'.join(new_path)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        if resp.status == 200:
                             text = await resp.text()
                             if "SSN" in text or "admin" in text.lower() or "private" in text.lower():
                                self._add_finding("bola", url, f"Path-based ID access successful: {original_id+1}", "path", str(original_id+1))
                except: pass

    async def check_bac(self, session, url):
        """
        Broken Access Control (BAC).
        Tries to access common privileged endpoints.
        This is a 'force browsing' check run once per host.
        """
        parsed = urlparse(url)
        host = parsed.netloc
        base_url = f"{parsed.scheme}://{host}"
        
        # Only scan BAC once per host
        # We use a specific set for BAC to avoid conflicts with port scanning
        if not hasattr(self, 'bac_scanned_hosts'):
            self.bac_scanned_hosts = set()
            
        if host in self.bac_scanned_hosts:
            return 
        self.bac_scanned_hosts.add(host)
        
        admin_paths = [
            "/admin",
            "/dashboard",
            "/config",
            "/api/admin",
            "/users",
            "/admin/dashboard", # Specific for our test
            "/settings"
        ]
        
        for path in admin_paths:
            target = base_url + path
            try:
                ctx = await self.perform_request(session, 'GET', target, timeout=5)
                async with ctx as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Validate it's not a generic login page or error
                        if "login" not in text.lower() and "error" not in text.lower():
                             # Check for specific success indicators
                             if "dashboard" in text.lower() or "admin" in text.lower() or "settings" in text.lower():
                                  self._add_finding("bac", target, "Privileged area accessible without auth check", "path", path)
            except: pass

    async def check_blind_rce(self, session, url):
        """
        Time-Based Blind RCE.
        Injects sleep commands and measures delay.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        blind_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]

        for param in params:
            for payload in blind_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                start = time.time()
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=10)
                    async with ctx as resp:
                        await resp.text()
                        # If response took > 5 seconds, it worked
                        if time.time() - start > 5:
                             self._add_finding("blind_rce", url, "Server slept for 5+ seconds", param, payload)
                             break
                except: pass

    async def check_lfi(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        # Indicators of success
        lfi_indicators = [
            "root:x:0:0:",
            "[extensions]",
            "for 16-bit app support"
        ]

        for param in params:
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        for indicator in lfi_indicators:
                            if indicator in text:
                                self._add_finding("lfi", url, f"LFI Payload executed successfully. Found: {indicator}", param, payload)
                                break
                except: pass

    async def check_rce(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Simple echo tests for RCE
        rce_payloads = [
            "; echo 'sc_rce_test'",
            "| echo 'sc_rce_test'",
            "|| echo 'sc_rce_test'",
            "& echo 'sc_rce_test'"
        ]

        for param in params:
            for payload in rce_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    # Debug print to verify traffic
                    # print(f"[DEBUG] RCE Test: {test_url}") 
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        # print(f"[DEBUG] RCE Resp: {text[:30]}")
                        if "sc_rce_test" in text:
                             self._add_finding("rce", url, "Command Execution confirmed via echo test", param, payload)
                             break
                except: pass


    async def check_jwt(self, session, url):
        """
        Extracts and analyzes JWTs from Headers or Cookies.
        """
        try:
            # 1. Inspect Headers (Authorization)
            # This is hard because we are the client. We assume we might see JWTs in response headers or body (uncommon)
            # OR we check if the APP sets a cookie that looks like a JWT.
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                cookies = session.cookie_jar.filter_cookies(url)
                for key, cookie in cookies.items():
                    if cookie.value.count('.') == 2 and (cookie.value.startswith('eyJ') or "bearer" in key.lower()):
                         self._add_finding("weak_crypto", url, f"JWT found in cookie '{key}'", key, "JWT Deteced")
                         # Basic 'None' alg check (heuristic)
                         if "eyJhbGciOiJub25lIn0" in cookie.value: # {"alg":"none"} base64
                              self._add_finding("jwt_none", url, f"JWT with 'none' algorithm found in cookie '{key}'", key, cookie.value)

            # Note: A real scan would Fuzz the JWT. Here we just passive detect.
        except: pass

    async def check_cookie_security(self, session, url):
        """
        Checks Set-Cookie headers for missing security flags.
        """
        try:
             # We need access to raw cookies from the response history or cookie jar
             # aiohttp cookie jar abstracts this, so we check the jar for the domain
             cookies = session.cookie_jar.filter_cookies(url)
             for key, cookie in cookies.items():
                  issues = []
                  if not cookie["secure"]:
                       issues.append("Missing 'Secure' flag")
                  if not cookie["httponly"]:
                       issues.append("Missing 'HttpOnly' flag")
                  
                  if issues:
                       self._add_finding("cookie_insecure", url, f"Cookie '{key}' issues: {', '.join(issues)}", key, None)
        except: pass

    async def check_tech_stack(self, session, url):
        try:
            ctx = await self.perform_request(session, 'HEAD', url, timeout=5)
            async with ctx as resp:
                headers = resp.headers
                techs = []
                if "Server" in headers: techs.append(f"Server: {headers['Server']}")
                if "X-Powered-By" in headers: techs.append(f"Powered-By: {headers['X-Powered-By']}")
                if "X-AspNet-Version" in headers: techs.append(f"ASP.NET: {headers['X-AspNet-Version']}")
                
                if techs:
                    self._add_finding("tech_stack", url, "\n".join(techs))
        except: pass

    async def check_js_analysis(self, session, url):
        dangerous_sinks = {
            "eval(": "Executes arbitrary code string",
            "document.write(": "Writes raw HTML/JS to DOM",
            "innerHTML": "Sets HTML content (potential XSS)",
            "dangerouslySetInnerHTML": "React direct HTML injection"
        }
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                for sink, desc in dangerous_sinks.items():
                    if sink in text:
                        # Extract snippet
                        idx = text.find(sink)
                        snippet = text[max(0, idx-20):min(len(text), idx+50)]
                        self._add_finding("dom_xss", url, f"Found sink '{sink}' ({desc})\nContext: ...{snippet}...")
        except: pass

    async def check_union_sqli(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Simplified UNION check: detect if column count changes allow injection
        # We try ' UNION SELECT 1,2,3 -- - (up to 5 columns)
        for param in params:
            for cols in range(1, 6):
                payload_cols = ",".join([str(i) for i in range(1, cols + 1)])
                payload = f"' UNION SELECT {payload_cols} -- "
                
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        # If the page renders generic content + our numbers, it might be a hit.
                        # This is a heuristic: if we see the payload numbers reflected in body
                        text = await resp.text()
                        # Check strictly if our injected numbers appear sequentially or in a way that suggests reflection
                        # Simpler trigger: check if error DISAPPEARS compared to a bad query
                        if "You have an error" not in text and str(cols) in text:
                             # This is a weak check, but okay for a demo scanner
                             pass 
                except: pass
    
    async def check_sqli(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        for param in params:
            test_params = params.copy()
            test_params[param] = ["'"]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            try:
                ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                async with ctx as resp:
                    text = await resp.text()
                    for error in self.sql_errors:
                        if error in text:
                            # Double Verification:
                            # 1. Trigger Payload: ' (Causes Syntax Error)
                            # 2. Safe Payload: Original Value (Should be valid)
                            # Logic: If Trigger causes error AND Safe does NOT, it's SQLi.
                            
                            safe_params = params.copy()
                            safe_params[param] = params[param] # Use original value (e.g., "1")
                            safe_url = urlunparse(parsed._replace(query=urlencode(safe_params, doseq=True)))
                            
                            is_fp = False
                            try:
                                ctx = await self.perform_request(session, 'GET', safe_url, timeout=5)
                                async with ctx as safe_resp:
                                    safe_text = await safe_resp.text()
                                    # If the error persists even with valid syntax, the server is just broken/verbose
                                    if error in safe_text:
                                        print(f"[-] Discarding SQLi FP at {url}. Error present in benign request.")
                                        is_fp = True
                            except: pass

                            if not is_fp:
                                self._add_finding("sql_injection", url, f"Database error: {error}", param, "'")
                            break
            except: pass

    async def check_boolean_sqli(self, session, url):
        """
        Detects Boolean-based Blind SQLi by comparing True vs False conditions.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Simple arithmetic boolean tests
        payload_true = "' AND 1=1 -- "
        payload_false = "' AND 1=2 -- "

        for param in params:
            try:
                # 1. Baseline Request
                ctx = await self.perform_request(session, 'GET', url, timeout=5)
                async with ctx as r1:
                    base_len = len(await r1.text())

                # 2. True Condition
                test_params = params.copy()
                test_params[param] = [payload_true] # Simplified injection
                t_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                ctx = await self.perform_request(session, 'GET', t_url, timeout=5)
                async with ctx as r2:
                    true_len = len(await r2.text())

                # 3. False Condition
                test_params = params.copy()
                test_params[param] = [payload_false]
                f_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                ctx = await self.perform_request(session, 'GET', f_url, timeout=5)
                async with ctx as r3:
                    false_len = len(await r3.text())

                # Logic: If True is close to Base, but False is significantly different (missing content)
                # Tolerance of 5% difference for dynamic content
                if abs(base_len - true_len) < (base_len * 0.05) and abs(base_len - false_len) > (base_len * 0.1):
                    self._add_finding("sql_injection", url, 
                        f"Boolean behavior detected. True len: {true_len}, False len: {false_len}", 
                        param, payload_true)

            except: pass

    async def check_xss(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            test_params = params.copy()
            test_params[param] = [self.xss_test_string]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            try:
                ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                async with ctx as resp:
                    if self.xss_test_string in await resp.text():
                        self._add_finding("xss_reflected", url, "Payload reflected in response", param, self.xss_test_string)
            except: pass

    async def check_sensitive_info(self, session, url):
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                for name, pattern in self.sensitive_patterns.items():
                    if re.search(pattern, text):
                        self._add_finding("sensitive_data", url, f"Found pattern match for {name}")
        except: pass

    async def check_security_headers(self, session, url):
        try:
            ctx = await self.perform_request(session, 'HEAD', url, timeout=5)
            async with ctx as resp:
                headers = resp.headers
                for h in self.required_headers:
                    if h not in headers:
                        self._add_finding("security_header", url, f"Missing Header: {h}")
        except: pass

    async def check_sensitive_files(self, session, url):
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for f in self.fuzz_files:
            target = urljoin(base + "/", f)
            try:
                ctx = await self.perform_request(session, 'GET', target, timeout=5)
                async with ctx as resp:
                 if resp.status == 200 and len(await resp.text()) > 0:
                     text = await resp.text()
                     # Validated against Smart 404
                     if not self.is_custom_404(resp.status, text):
                          self._add_finding("hidden_file", target, f"Accessible file found: {f}")
                     else:
                          pass # Ignored as 404
            except: pass

    async def check_time_based_sqli(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        sleep_payloads = ["SLEEP(5)", "WAITFOR DELAY '0:0:5'"]
        
        for param in params:
            for payload in sleep_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                start = time.time()
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=10)
                    async with ctx as resp:
                        await resp.text()
                        if time.time() - start > 5:
                            self._add_finding("blind_sqli", url, f"Response delay > 5s", param, payload)
                            break
                except: pass
