"use client";

import { useState } from "react";
import { ScanResults } from "@/components/ScanResults";
import { Shield, Search, Activity, Terminal } from "lucide-react";

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState("auto"); // 'auto' or 'interactive'
  const [isStealth, setIsStealth] = useState(false); // New Stealth Mode State
  const [showAuth, setShowAuth] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;

    setIsLoading(true);
    try {
      const payload: any = { url: targetUrl, stealth_mode: isStealth };
      if (showAuth && loginUrl) {
        payload.login_url = loginUrl;
        payload.auth_mode = authMode;
        if (authMode === "auto" && username && password) {
          payload.username = username;
          payload.password = password;
        }
      }

      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      setScanId(data.scan_id);
    } catch (err) {
      console.error("Failed to start scan:", err);
      alert("Failed to start scan. Is the backend running?");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 font-sans selection:bg-cyan-500/30">
      <div className="absolute inset-0 -z-10 h-full w-full bg-neutral-950 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:14px_24px]"></div>

      <div className="max-w-5xl mx-auto px-6 py-12">
        {/* Header */}
        <header className="mb-12 text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/30 border border-cyan-800/50 text-cyan-400 text-sm font-medium">
            <Shield className="w-4 h-4" />
            <span>Defensive Security Scanner</span>
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight bg-gradient-to-r from-white via-neutral-200 to-neutral-400 bg-clip-text text-transparent">
            Vulnerability Scanner
          </h1>
          <p className="text-neutral-400 max-w-lg mx-auto text-lg">
            Automated DAST engine to detect SQL Injection, XSS, and Sensitive Data Exposure in real-time.
          </p>
        </header>

        {/* Input Section */}
        <div className="max-w-2xl mx-auto mb-16">
          <form onSubmit={startScan} className="relative group space-y-4">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-xl opacity-20 group-hover:opacity-40 transition duration-500 blur"></div>
            <div className="relative flex flex-col bg-neutral-900 rounded-xl border border-neutral-800 p-2 shadow-2xl">
              <div className="flex items-center">
                <div className="pl-4 text-neutral-500">
                  <Search className="w-5 h-5" />
                </div>
                <input
                  type="url"
                  placeholder="Enter target URL (e.g., http://localhost:8000)"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-transparent border-none focus:ring-0 text-white placeholder-neutral-500 text-lg px-4 py-2"
                  required
                />
                <button
                  type="submit"
                  disabled={isLoading}
                  className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-6 py-3 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 min-w-[140px] justify-center"
                >
                  {isLoading ? (
                    <>
                      <Activity className="w-5 h-5 animate-spin" />
                      <span>Initing...</span>
                    </>
                  ) : (
                    <>
                      <Terminal className="w-5 h-5" />
                      <span>Start Scan</span>
                    </>
                  )}
                </button>
              </div>

              {/* Advanced Settings Toggles (Auth + Stealth) */}
              <div className="px-4 py-3 border-t border-neutral-800 flex items-center justify-between">
                <div className="flex items-center gap-6">
                  {/* Auth Toggle */}
                  <button
                    type="button"
                    onClick={() => setShowAuth(!showAuth)}
                    className={`text-sm font-medium transition-colors flex items-center gap-2 ${showAuth ? "text-cyan-400" : "text-neutral-500 hover:text-neutral-300"
                      }`}
                  >
                    {showAuth ? "[-] Configure Authentication" : "[+] Configure Authentication"}
                  </button>

                  {/* Stealth Toggle */}
                  <button
                    type="button"
                    onClick={() => setIsStealth(!isStealth)}
                    className={`text-sm font-medium transition-colors flex items-center gap-2 ${isStealth ? "text-emerald-400" : "text-neutral-500 hover:text-neutral-300"
                      }`}
                  >
                    <div className={`w-3 h-3 rounded-full ${isStealth ? "bg-emerald-500 animate-pulse" : "bg-neutral-600"}`}></div>
                    {isStealth ? "Stealth Mode: ON 🥷" : "Stealth Mode: OFF"}
                  </button>
                </div>
              </div>

              {/* Auth Config Panel */}
              {showAuth && (
                <div className="px-6 py-6 border-t border-neutral-800 bg-neutral-900/50 space-y-4 animate-in fade-in slide-in-from-top-2">
                  <input
                    type="url"
                    placeholder="Login Page URL (e.g. http://site.com/login)"
                    className="bg-neutral-950 border border-neutral-800 rounded px-3 py-2 text-sm text-neutral-300 focus:border-cyan-500 outline-none w-full"
                    value={loginUrl}
                    onChange={(e) => setLoginUrl(e.target.value)}
                  />
                  <div className="grid grid-cols-2 gap-3">
                    <input
                      type="text"
                      placeholder="Username"
                      className="bg-neutral-950 border border-neutral-800 rounded px-3 py-2 text-sm text-neutral-300 focus:border-cyan-500 outline-none"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                    />
                    <input
                      type="password"
                      placeholder="Password"
                      className="bg-neutral-950 border border-neutral-800 rounded px-3 py-2 text-sm text-neutral-300 focus:border-cyan-500 outline-none"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>

                  {/* Auth Mode Selection */}
                  <div className="flex gap-4 mt-2 p-1 bg-neutral-900 border border-neutral-800 rounded-lg">
                    <button
                      type="button"
                      onClick={() => setAuthMode("auto")}
                      className={`flex-1 py-1.5 text-xs font-medium rounded transition-all ${authMode === "auto"
                          ? "bg-cyan-900/50 text-cyan-200 shadow-sm"
                          : "text-neutral-500 hover:text-neutral-300"
                        }`}
                    >
                      Auto Login (Headless)
                    </button>
                    <button
                      type="button"
                      onClick={() => setAuthMode("interactive")}
                      className={`flex-1 py-1.5 text-xs font-medium rounded transition-all ${authMode === "interactive"
                          ? "bg-purple-900/50 text-purple-200 shadow-sm"
                          : "text-neutral-500 hover:text-neutral-300"
                        }`}
                    >
                      Interactive (Browser Hook)
                    </button>
                  </div>

                  {authMode === "interactive" && (
                    <p className="text-[10px] text-purple-400/80 px-1">
                      * A real browser window will open. You must log in manually within 60s.
                    </p>
                  )}
                </div>
              )}
            </div>

            <p className="mt-3 text-center text-neutral-500 text-xs">
              * Ensure you have permission to scan the target.
            </p>
          </form>
        </div>

        {/* Results Section */}
        {scanId && <ScanResults scanId={scanId} />}
      </div>
    </main>
  );
}
