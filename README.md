# Scancrypt 🕸️ 🚀
Advanced DAST Scanner with Stealth Mode & Interactive Authentication.

## 🚀 One-Click Startup
If you are using an AI Agent, just tell it:
> "Run the /start workflow"

### Windows Startup
Run the following script in PowerShell from the root directory:
```powershell
.\start_all.ps1
```

### Manual Individual Startup
1. **Scanner Backend**: 
   ```powershell
   cd scanner-engine; python main.py
   ```
2. **Dashboard Frontend**: 
   ```powershell
   cd dashboard; npm run dev
   ```
3. **Vulnerable App (Target)**: 
   ```powershell
   python vulnerable_app.py
   ```

## 🛠️ Features
- **Phase 1-5**: Core Crawl/Scan, SMART 404, Double Verification.
- **Phase 6**: Interactive Login Mode (Manual Browser Hook).
- **Phase 7**: Stealth Mode (Jitter + User-Agent Rotation).
- **Reporting**: Professional PDF reports with remediation snippets.

---
*Created for Hackcrypt Hackathon Final Round.*
