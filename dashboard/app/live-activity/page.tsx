"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Activity, Clock, Target, CheckCircle2 } from "lucide-react";
import { MacTerminal } from "@/components/MacTerminal";
import { LiveFindingCard } from "@/components/LiveFindingCard";
import { Sidebar } from "@/components/Sidebar";

interface Finding {
    name: string;
    severity: string;
    url: string;
    evidence: string;
    param?: string;
    payload?: string;
    cwe?: string;
    description?: string;
    remediation?: string;
}

interface ScanStatus {
    status: string;
    crawled_urls: string[];
    findings: Finding[];
    logs?: string[];
    duration?: number;
}

import { Suspense } from "react";

function LiveActivityContent() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const scanId = searchParams.get("scanId");

    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [isComplete, setIsComplete] = useState(false);
    const [startTime] = useState(Date.now());
    const [elapsedTime, setElapsedTime] = useState(0);
    const [severityFilter, setSeverityFilter] = useState<string>("all");

    const [scanIdState, setScanIdState] = useState<string | null>(null);
    const processedRef = useRef<Set<string>>(new Set());

    // Elapsed time counter
    useEffect(() => {
        if (isComplete) return;
        const timer = setInterval(() => {
            setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
        }, 1000);
        return () => clearInterval(timer);
    }, [startTime, isComplete]);

    // Format elapsed time
    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, "0")}`;
    };

    // Poll for scan status
    const fetchStatus = useCallback(async () => {
        const currentId = scanId || scanIdState;
        if (!currentId) return;

        try {
            const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
            const res = await fetch(`${apiUrl}/scan/${currentId}`);
            const data: ScanStatus = await res.json();
            setScanStatus(data);

            const newLogs: string[] = [];
            const seen = processedRef.current;

            // Update logs with new crawled URLs
            data.crawled_urls?.forEach((url) => {
                const logEntry = `[CRAWL] Discovered: ${url}`;
                if (!seen.has(logEntry)) {
                    seen.add(logEntry);
                    newLogs.push(logEntry);
                }
            });

            // Add finding logs
            data.findings?.forEach((finding) => {
                const logEntry = `[${finding.severity.toUpperCase()}] Found: ${finding.name} at ${finding.url}`;
                if (!seen.has(logEntry)) {
                    seen.add(logEntry);
                    newLogs.push(logEntry);
                }
            });

            if (newLogs.length > 0) {
                setLogs((prev) => [...prev, ...newLogs]);
            }

            // Update findings
            setFindings(data.findings || []);

            // Check if complete
            if (data.status === "Completed" || data.status === "Error") {
                setIsComplete(true);
                const finalMsg = data.status === "Completed"
                    ? `[SUCCESS] Scan completed. Found ${data.findings?.length || 0} vulnerabilities.`
                    : `[ERROR] Scan failed.`;

                if (!seen.has(finalMsg)) {
                    seen.add(finalMsg);
                    setLogs((prev) => [...prev, finalMsg]);
                }
            }
        } catch (error) {
            console.error("Failed to fetch status:", error);
        }
    }, [scanId, scanIdState]); // Removed 'logs' dependency

    useEffect(() => {
        // If scanId provided in URL, use it
        if (scanId) {
            if (!processedRef.current.has(`INIT-${scanId}`)) {
                setLogs([`[INIT] Starting scan for target...`, `[INFO] Scan ID: ${scanId}`]);
                processedRef.current.add(`INIT-${scanId}`);
            }

            const interval = setInterval(fetchStatus, 1500);
            fetchStatus();
            return () => clearInterval(interval);
        }

        // If no scanId, try to get the latest one from localStorage
        try {
            const savedScans = localStorage.getItem('scancrypt_scan_history');
            if (savedScans) {
                const parsed = JSON.parse(savedScans);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    const latest = parsed.sort((a: { timestamp: number }, b: { timestamp: number }) => b.timestamp - a.timestamp)[0];
                    if (latest && latest.id) {
                        setScanIdState(latest.id); // Triggers re-render to start polling
                        // Update URL without full reload if possible, or just let state handle it
                        window.history.replaceState(null, "", `/live-activity?scanId=${latest.id}`);
                    }
                }
            }
        } catch (e) {
            console.error("Failed to recover last scan", e);
        }
    }, [scanId, fetchStatus]);

    // Effect to start polling if scanIdState is set (when recovered from storage)
    useEffect(() => {
        if (!scanIdState) return;

        const interval = setInterval(fetchStatus, 1500);
        fetchStatus();
        return () => clearInterval(interval);
    }, [scanIdState, fetchStatus]);

    // Stats
    const criticalCount = findings.filter((f) => f.severity.toLowerCase() === "critical").length;
    const highCount = findings.filter((f) => f.severity.toLowerCase() === "high").length;
    const mediumCount = findings.filter((f) => f.severity.toLowerCase() === "medium").length;
    const lowCount = findings.filter((f) => f.severity.toLowerCase() === "low").length;

    // Filtered findings based on severity filter
    const filteredFindings = severityFilter === "all"
        ? findings
        : findings.filter((f) => f.severity.toLowerCase() === severityFilter.toLowerCase());

    return (
        <main className="h-screen w-full flex items-center justify-center p-4 lg:p-6 relative overflow-hidden bg-black selection:bg-purple-500/30">
            {/* Aurora Background */}
            <div className="fixed inset-0 pointer-events-none">
                <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px]" />
                <div className="absolute top-[20%] right-[-10%] w-[40%] h-[40%] bg-purple-600/10 rounded-full blur-[120px]" />
                <div className="absolute bottom-[-10%] left-[20%] w-[40%] h-[40%] bg-emerald-600/5 rounded-full blur-[120px]" />
            </div>

            {/* Main Container */}
            <motion.div
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, ease: "easeOut" }}
                className="w-full h-full glass-panel rounded-[16px] md:rounded-[24px] lg:rounded-[32px] p-1.5 md:p-2 flex gap-2 md:gap-3 relative z-10 overflow-hidden shadow-2xl ring-1 ring-white/10"
            >
                {/* Sidebar */}
                <Sidebar activeItem="Live Activity" />

                {/* Main Content */}
                <div className="flex-1 rounded-[12px] md:rounded-[20px] lg:rounded-[24px] bg-[#0A0A0A]/50 relative overflow-hidden p-3 md:p-6 lg:p-8 flex flex-col min-h-0">

                    {/* Header */}
                    <div className="flex items-start justify-between mb-10">
                        <div>
                            <div className="flex items-center gap-4 mb-2">
                                <div className="w-12 h-12 rounded-[18px] bg-white/10 backdrop-blur-md border border-white/20 flex items-center justify-center shadow-lg shadow-emerald-500/20">
                                    <Activity className="w-6 h-6 text-emerald-400" />
                                </div>
                                <div>
                                    <h1 className="text-3xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-white to-white/60">
                                        Active Operations
                                    </h1>
                                    <div className="flex items-center gap-3 text-sm text-white/40 mt-1">
                                        <span className="flex items-center gap-1.5">
                                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]"></span>
                                            Scanning Target
                                        </span>
                                        <span>•</span>
                                        <span className="font-mono flex items-center gap-2">
                                            <Clock className="w-3 h-3" />
                                            {formatTime(elapsedTime)}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => router.push("/")}
                                className={`px-5 py-2.5 rounded-2xl text-sm font-medium flex items-center gap-2 transition-all cursor-pointer ${isComplete
                                    ? "bg-emerald-500 hover:bg-emerald-400 text-black shadow-[0_0_20px_rgba(16,185,129,0.3)]"
                                    : "bg-white/5 text-white/40 cursor-not-allowed"
                                    }`}
                                disabled={!isComplete}
                            >
                                <CheckCircle2 className="w-4 h-4" />
                                {isComplete ? "Complete" : "Scanning..."}
                            </button>
                        </div>
                    </div>

                    {/* Stats Row */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <StatCard
                            icon={Target}
                            label="URLs Crawled"
                            value={scanStatus?.crawled_urls?.length || 0}
                            color="text-cyan-400"
                            bg="from-cyan-500/20 to-cyan-600/5"
                        />
                        <StatCard
                            icon={Shield}
                            label="Vulnerabilities"
                            value={findings.length}
                            color="text-purple-400"
                            bg="from-purple-500/20 to-purple-600/5"
                        />
                        <StatCard
                            label="Critical/High"
                            value={`${criticalCount}/${highCount}`}
                            color="text-red-400"
                            bg="from-red-500/20 to-red-600/5"
                            icon={Activity}
                        />
                        <StatCard
                            label="Medium"
                            value={mediumCount}
                            color="text-amber-400"
                            bg="from-amber-500/20 to-amber-600/5"
                            icon={Activity}
                        />
                    </div>

                    {/* Split View for Terminal and Findings */}
                    <div className="flex-1 grid lg:grid-cols-2 gap-6 min-h-0">
                        {/* Terminal Column */}
                        <div className="flex flex-col h-full bg-[#1C1C1E] rounded-[24px] border border-white/5 overflow-hidden shadow-2xl">
                            {/* MacTerminal handles its own header/content, wrapping it here for layout */}
                            <div className="flex-1 overflow-hidden">
                                <MacTerminal
                                    logs={logs}
                                    isRunning={!isComplete}
                                    title={`Scanner Output`}
                                />
                            </div>
                        </div>

                        {/* Live Findings Column */}
                        <div className="flex flex-col h-full overflow-hidden">
                            <div className="flex flex-col gap-3 mb-4 px-1">
                                <div className="flex items-center justify-between">
                                    <h3 className="text-lg font-semibold text-white/90">Live Findings</h3>
                                    <span className="text-xs px-2.5 py-1 rounded-full bg-white/5 text-white/40 border border-white/5">{filteredFindings.length} found</span>
                                </div>

                                {/* Severity Filters */}
                                <div className="flex flex-wrap gap-2">
                                    {[
                                        { key: "all", label: "All", color: "bg-white/10 text-white" },
                                        { key: "critical", label: `Critical (${criticalCount})`, color: "bg-purple-500/20 text-purple-400" },
                                        { key: "high", label: `High (${highCount})`, color: "bg-red-500/20 text-red-400" },
                                        { key: "medium", label: `Medium (${mediumCount})`, color: "bg-amber-500/20 text-amber-400" },
                                        { key: "low", label: `Low (${lowCount})`, color: "bg-blue-500/20 text-blue-400" },
                                    ].map((filter) => (
                                        <button
                                            key={filter.key}
                                            onClick={() => setSeverityFilter(filter.key)}
                                            className={`text-xs px-3 py-1.5 rounded-lg transition-all ${severityFilter === filter.key
                                                ? `${filter.color} border border-current`
                                                : "bg-white/5 text-white/40 hover:bg-white/10 border border-transparent"
                                                }`}
                                        >
                                            {filter.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="flex-1 overflow-y-auto glass-scrollbar pr-2 space-y-3 pb-4">
                                <AnimatePresence mode="popLayout">
                                    {filteredFindings.length === 0 ? (
                                        <motion.div
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            className="h-full flex flex-col items-center justify-center text-white/30 bg-white/5 rounded-[24px] border border-white/5 border-dashed min-h-[200px]"
                                        >
                                            <Shield className="w-12 h-12 mx-auto mb-4 opacity-20" />
                                            <p className="text-sm font-medium opacity-60">{findings.length > 0 ? "No matches for filter" : "Waiting for findings..."}</p>
                                        </motion.div>
                                    ) : (
                                        filteredFindings.map((finding, index) => (
                                            <LiveFindingCard
                                                key={`${finding.name}-${finding.url}-${index}`}
                                                finding={finding}
                                                index={index}
                                            />
                                        ))
                                    )}
                                </AnimatePresence>
                            </div>
                        </div>
                    </div>
                </div>
            </motion.div>
        </main>
    );
}

export default function LiveActivityPage() {
    return (
        <Suspense fallback={
            <div className="h-screen w-full flex items-center justify-center bg-black text-white">
                <div className="flex flex-col items-center gap-4">
                    <Activity className="w-10 h-10 text-cyan-500 animate-pulse" />
                    <p className="text-sm text-white/50 font-mono">Initializing Neural Protocol...</p>
                </div>
            </div>
        }>
            <LiveActivityContent />
        </Suspense>
    );
}

function StatCard({
    icon: Icon,
    label,
    value,
    color,
    bg
}: {
    icon?: any;
    label: string;
    value: number | string;
    color: string;
    bg: string;
}) {
    return (
        <div className="glass-card rounded-[24px] p-6 relative overflow-hidden group">
            <div className={`absolute inset-0 bg-gradient-to-br ${bg} opacity-50 group-hover:opacity-100 transition-opacity duration-500`}></div>
            <div className="relative z-10">
                <div className="flex items-start justify-between mb-4">
                    <span className="text-xs font-bold text-white/40 uppercase tracking-widest">{label}</span>
                    {Icon && <Icon className={`w-5 h-5 ${color}`} />}
                </div>
                <p className={`text-4xl lg:text-5xl font-bold ${color} text-glow mb-1 truncate`}>{value}</p>
                <div className="h-1 w-12 rounded-full bg-white/10 mt-2" />
            </div>
        </div>
    );
}
