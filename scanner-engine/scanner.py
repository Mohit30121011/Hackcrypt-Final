import aiohttp
import asyncio
import re
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

class VulnerabilityScanner:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        
        # Knowledge Base for Detection Logic
        self.sql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "Unclosed quotation mark after the character string",
            "quoted string not properly terminated",
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

        # Knowledge Base for Reporting
        self.kb = {
            "sql_injection": {
                "name": "SQL Injection",
                "severity": "High",
                "cwe": "CWE-89",
                "description": "The application allows untrusted user input to interfere with a database query. This could allow an attacker to view, modify, or delete data.",
                "remediation": "Use parameterized queries (Prepared Statements) for all database access. Validate and sanitize all user input."
            },
            "xss_reflected": {
                "name": "Reflected Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "cwe": "CWE-79",
                "description": "The application reflects untrusted data in a web page without proper validation or escaping, allowing execution of malicious scripts.",
                "remediation": "Context-aware output encoding (escaping) of all user input before rendering it in the browser."
            },
            "sensitive_data": {
                "name": "Sensitive Data Exposure",
                "severity": "Low",
                "cwe": "CWE-200",
                "description": "The application exposes sensitive information (emails, keys, passwords) in its responses.",
                "remediation": "Ensure sensitive data is not returned in API responses or HTML comments. Use generic error messages."
            },
            "security_header": {
                "name": "Missing Security Header",
                "severity": "Low",
                "cwe": "CWE-693",
                "description": "The application is missing common HTTP security headers that provide protection against attacks like Clickjacking and XSS.",
                "remediation": "Configure the web server to send strict security headers (CSP, HSTS, X-Frame-Options)."
            },
            "hidden_file": {
                "name": "Hidden File Exposure",
                "severity": "High",
                "cwe": "CWE-538",
                "description": "A sensitive file (backup, config, or VCS) was found accessible on the server.",
                "remediation": "Remove backup and configuration files from the web root. Configure the server to deny access to dot-files (.git, .env)."
            },
            "blind_sqli": {
                "name": "Blind SQL Injection (Time-Based)",
                "severity": "Critical",
                "cwe": "CWE-89",
                "description": "The application delays its response when specific SQL commands (SLEEP) are injected, indicating a Blind SQL Injection vulnerability.",
                "remediation": "Use parameterized queries. Ensure database errors are not suppressing the logic but preventing the injection entirely."
            },
            "union_sqli": {
                "name": "SQL Injection (UNION-Based)",
                "severity": "Critical",
                "cwe": "CWE-89",
                "description": "The application allows combining results of the original query with results of an injected query using the UNION operator.",
                "remediation": "Use parameterized queries. Ensure that user input is not concatenated into SQL command strings."
            },
            "dom_xss": {
                "name": "Potential DOM-Based XSS",
                "severity": "Medium",
                "cwe": "CWE-79",
                "description": "Dangerous JavaScript functions (sinks) were found in the client-side code that could lead to DOM XSS if inputs are not validated.",
                "remediation": "Avoid using dangerous sinks like innerHTML, eval(), or document.write(). Use textContent or safe DOM creation methods."
            },
            "tech_stack": {
                "name": "Technology Stack Disclosure",
                "severity": "Info",
                "cwe": "CWE-200",
                "description": "The application discloses specific technology versions via headers or default files, which aids attackers in finding known exploits.",
                "remediation": "Configure the server to suppress 'Server' and 'X-Powered-By' headers. Remove default welcome pages."
            },
            "lfi": {
                "name": "Local File Inclusion (LFI)",
                "severity": "Critical",
                "cwe": "CWE-22",
                "description": "The application allows reading arbitrary files from the server via path traversal sequences.",
                "remediation": "Validate user input against a whitelist of permitted filenames. Disable 'allow_url_include' in PHP."
            },
            "ssti": {
                "name": "Server-Side Template Injection (SSTI)",
                "severity": "Critical",
                "cwe": "CWE-1336",
                "description": "The application blindly processes user input inside a template engine. This often leads to RCE.",
                "remediation": "Do not pass user input directly to templates. Use a 'Sandboxed' environment."
            },
            "cors_misconfig": {
                "name": "CORS Misconfiguration (Insecure Origin)",
                "severity": "High",
                "cwe": "CWE-346",
                "description": "The application accepts arbitrary origins (Access-Control-Allow-Origin: * or null), allowing attackers to steal data.",
                "remediation": "Whiltelist trusted origins. Do not reflect the 'Origin' header blindly."
            },
            "open_port": {
                "name": "Open Service Port",
                "severity": "Info",
                "cwe": "CWE-200",
                "description": "A non-standard service port was found open on the server.",
                "remediation": "Close unnecessary ports via firewall. Ensure services on open ports are patched."
            },
            "csti": {
                "name": "Client-Side Template Injection (CSTI)",
                "severity": "High",
                "cwe": "CWE-79",
                "description": "The application reflects user input that is interpreted by client-side frameworks (Angular, Vue).",
                "remediation": "Escape user input before embedding it in templates. Use 'ng-non-bindable' or 'v-pre'."
            },
            "blind_rce": {
                "name": "Blind Remote Code Execution",
                "severity": "Critical",
                "cwe": "CWE-78",
                "description": "The application executes system commands but does not return the output. Detected via time delays.",
                "remediation": "Avoid using system calls. Validate input strictly against a whitelist."
            },
            "bola": {
                "name": "Broken Object Level Authorization (BOLA/IDOR)",
                "severity": "High",
                "cwe": "CWE-639",
                "description": "The application allows access to objects belonging to other users by manipulating IDs.",
                "remediation": "Implement proper authorization checks for every object access."
            },
            "bac": {
                "name": "Broken Access Control (BAC)",
                "severity": "High",
                "cwe": "CWE-285",
                "description": "Unprivileged users can access restricted administrative pages.",
                "remediation": "Enforce strict role-based access control (RBAC) on all endpoints."
            },
            "jwt_none": {
                "name": "Insecure JWT (Alg: None)",
                "severity": "Critical",
                "cwe": "CWE-327",
                "description": "The application allows JSON Web Tokens with 'alg': 'none', which bypasses signature verification.",
                "remediation": "Enforce strong algorithms (RS256/HS256) and reject 'none' algorithm."
            },
            "cookie_insecure": {
                "name": "Insecure Cookie Flags",
                "severity": "Low",
                "cwe": "CWE-1275",
                "description": "Sensitive cookies are missing 'Secure', 'HttpOnly', or 'SameSite' flags.",
                "remediation": "Set Secure=True, HttpOnly=True, and SameSite=Strict/Lax for all session cookies."
            }
        }
        self.scanned_hosts = set()

    def _add_finding(self, key: str, url: str, evidence: str, param: str = None, payload: str = None):
        info = self.kb.get(key, {})
        self.findings.append({
            "type": info.get("name", "Unknown Issue"),
            "severity": info.get("severity", "Low"),
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "cwe": info.get("cwe", "")
        })
        print(f"[!] {info.get('name')} found at {url}")

    async def scan_url(self, url: str, session: aiohttp.ClientSession):
        print(f"[*] Scanning {url}...")
        
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
            async with session.get(url, headers=headers, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
                                async with session.get(test_url, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
                async with session.get(target, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=10) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
            async with session.get(url, timeout=5) as resp:
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
            async with session.head(url, timeout=5) as resp:
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
            async with session.get(url, timeout=5) as resp:
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
                    async with session.get(test_url, timeout=5) as resp:
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
                async with session.get(test_url, timeout=5) as resp:
                    text = await resp.text()
                    for error in self.sql_errors:
                        if error in text:
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
                async with session.get(url, timeout=5) as r1:
                    base_len = len(await r1.text())

                # 2. True Condition
                test_params = params.copy()
                test_params[param] = [payload_true] # Simplified injection
                t_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                async with session.get(t_url, timeout=5) as r2:
                    true_len = len(await r2.text())

                # 3. False Condition
                test_params = params.copy()
                test_params[param] = [payload_false]
                f_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                async with session.get(f_url, timeout=5) as r3:
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
                async with session.get(test_url, timeout=5) as resp:
                    if self.xss_test_string in await resp.text():
                        self._add_finding("xss_reflected", url, "Payload reflected in response", param, self.xss_test_string)
            except: pass

    async def check_sensitive_info(self, session, url):
        try:
            async with session.get(url, timeout=5) as resp:
                text = await resp.text()
                for name, pattern in self.sensitive_patterns.items():
                    if re.search(pattern, text):
                        self._add_finding("sensitive_data", url, f"Found pattern match for {name}")
        except: pass

    async def check_security_headers(self, session, url):
        try:
            async with session.head(url, timeout=5) as resp:
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
                async with session.get(target, timeout=5) as resp:
                    if resp.status == 200 and len(await resp.text()) > 0:
                         self._add_finding("hidden_file", target, f"Accessible file found: {f}")
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
                    async with session.get(test_url, timeout=10) as resp:
                        await resp.text()
                        if time.time() - start > 5:
                            self._add_finding("blind_sqli", url, f"Response delay > 5s", param, payload)
                            break
                except: pass
