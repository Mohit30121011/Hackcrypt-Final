from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import HTMLResponse, JSONResponse
import subprocess
import os

app = FastAPI(title="Vulnerable Target App")

@app.get("/")
def home():
    return HTMLResponse("""
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
        <h1>Vulnerable Test Target</h1>
        <ul>
            <li><a href="/rce?cmd=echo 'hello'">Remote Code Execution (RCE)</a></li>
            <li><a href="/blind_rce?cmd=echo 'test'">Blind RCE (Time-Based)</a></li>
            <li><a href="/lfi?file=test.txt">Local File Inclusion (LFI)</a></li>
            <li><a href="/ssti?name=Guest">SSTI</a></li>
            <li><a href="/csti?search=vue">CSTI (Angular/Vue)</a></li>
            <li><a href="/sqli?id=1">SQL Injection</a></li>
            <li><a href="/sqli?id=1">SQL Injection</a></li>
            <li><a href="/cors">CORS</a></li>
            <li><a href="/auth/secret?id=1">Protected Area (Needs Login)</a></li>
        </ul>
        <!-- hidden credentials -->
        <!-- API_KEY: sk_live_1234567890 -->
    </body>
    </html>
    """)

@app.get("/rce")
def endpoint_rce(cmd: str = ""):
    # VULNERABLE: Executes arbitrary system commands
    # For safety in this demo, we restrict to 'echo' but the scanner will detect it
    if not cmd:
        return "Provide ?cmd=..."
    
    # Simulate RCE vulnerability detection
    # The scanner sends: ; echo 'sc_rce_test'
    if "sc_rce_test" in cmd:
        return f"Output: sc_rce_test"
    
@app.get("/blind_rce")
def endpoint_blind_rce(cmd: str = ""):
    # VULNERABLE: Blind RCE (Time Based)
    # The scanner sends: ; sleep 5
    if "sleep" in cmd:
        import time
        time.sleep(5)
        return "Executed (Delayed)"
    return "Executed (Immediate)"

@app.get("/lfi")
def endpoint_lfi(file: str = ""):
    # VULNERABLE: Path Traversal
    # The scanner sends: ../../../../etc/passwd
    if not file:
        return "Provide ?file=..."
    
    # Simulate finding root:x:0:0 (Linux) or [extensions] (Windows)
    if "etc/passwd" in file:
        return "root:x:0:0:root:/root:/bin/bash"
    if "win.ini" in file:
        return "[extensions]\nfont=..."
        
    return "File not found."

@app.get("/ssti")
def endpoint_ssti(name: str = ""):
    # VULNERABLE: Server Side Template Injection
    # The scanner sends: {{7*7}}
    if "{{7*7}}" in name or "${{7*7}}" in name or "<%= 7*7 %>" in name:
        return "Hello 49"
    
    return f"Hello {name}"

@app.get("/csti")
def endpoint_csti(search: str = ""):
    # VULNERABLE: Client-Side Template Injection
    # Reflects input without escaping, allowing Angular/Vue to execute it
    # The scanner sends: {{7*7}}
    return HTMLResponse(f"""
    <html>
    <body>
        <div ng-app>
            <p>You searched for: {search}</p>
        </div>
    </body>
    </html>
    """)


@app.get("/sqli")
def endpoint_sqli(id: str = ""):
    # VULNERABLE: SQL Injection
    if "'" in id:
        return JSONResponse(status_code=500, content={"error": "You have an error in your SQL syntax"})
    if "UNION" in id.upper():
        # Simulate UNION reflection
        return f"User: {id} - Reflecting injected data"
        
    return f"User ID: {id}"

@app.get("/cors")
def endpoint_cors(response: Response, request: Request):
    # VULNERABLE: CORS Misconfiguration
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
        
    return {"data": "sensitive_info_here"}

@app.get("/headers")
def endpoint_headers():
    # VULNERABLE: Missing headers
    # We purposefully do NOT set X-Frame-Options, CSP, etc.
    return "Insecure Headers"

@app.get("/login")
def login_page():
    return HTMLResponse("""
    <html>
    <body>
        <form action="/login" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """)

@app.post("/login")
def login_post(response: Response, username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "password":
        response.set_cookie(key="session_id", value="secret_admin_token")
        return "Logged in successfully"
    return Response("Invalid credentials", status_code=401)

@app.get("/auth/secret")
def protected_page(request: Request, id: str = ""):
    token = request.cookies.get("session_id")
    if token == "secret_admin_token":
        # VULNERABLE: Also check for SSTI here to verify authenticated scanning
        if id and ("{{" in id or "<%=" in id):
             return "Authenticated SSTI: 49" if "7*7" in id else f"Hello {id}"
        return "SECRET_DATA_ACCESS_GRANTED"
    return Response("Unauthorized", status_code=403)

if __name__ == "__main__":
    import uvicorn
    # Run on Port 8081 to avoid conflict with Scanner (8000) and Dashboard (3000)
    uvicorn.run(app, host="127.0.0.1", port=8081)
