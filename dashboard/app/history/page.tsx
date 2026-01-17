"use client";

import React, { useState, useEffect } from "react";
import { getAllScans, getScanById, StoredScan } from "../../lib/scanStorage";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { motion } from "framer-motion";
import { Activity, Shield, AlertTriangle, CheckCircle, ChevronDown, Download, RefreshCw } from "lucide-react";
import { Sidebar } from "@/components/Sidebar";

export default function AnalyticsDashboard() {
    const [allScans, setAllScans] = useState<any[]>([]);
    const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
    const [selectedScan, setSelectedScan] = useState<any | null>(null);
    const [currentTime, setCurrentTime] = useState("");
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        setCurrentTime(new Date().toLocaleTimeString());

        // Fetch scans from API
        const fetchScans = async () => {
            try {
                const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
                const response = await fetch(`${apiUrl}/history`);
                const scans = await response.json();
                setAllScans(scans);
                if (scans.length > 0 && !selectedScanId) {
                    setSelectedScanId(scans[0].id);
                }
            } catch (error) {
                console.error("Failed to fetch scan history:", error);
            } finally {
                setIsLoading(false);
            }
        };

        fetchScans();

        const timer = setInterval(() => {
            setCurrentTime(new Date().toLocaleTimeString());
        }, 1000);

        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        const fetchScanDetails = async () => {
            if (!selectedScanId) return;

            try {
                const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
                const response = await fetch(`${apiUrl}/scan/${selectedScanId}`);
                const scanData = await response.json();
                setSelectedScan(scanData);
            } catch (error) {
                console.error("Failed to fetch scan details:", error);
            }
        };

        fetchScanDetails();
    }, [selectedScanId]);

    interface Finding {
        severity: string;
        url: string;
        type: string;
        [key: string]: any;
    }

    const findings: Finding[] = selectedScan?.findings || [];
    const stats = {
        total: findings.length,
        critical: findings.filter((f: Finding) => f.severity === "Critical").length,
        high: findings.filter((f: Finding) => f.severity === "High").length,
        medium: findings.filter((f: Finding) => f.severity === "Medium").length,
        low: findings.filter((f: Finding) => f.severity === "Low").length,
        info: findings.filter((f: Finding) => f.severity === "Info").length,
    };

    const severityData = [
        { name: "Critical", value: stats.critical, color: "#A855F7" }, // Purple
        { name: "High", value: stats.high, color: "#EF4444" },     // Red
        { name: "Medium", value: stats.medium, color: "#F59E0B" },   // Amber
        { name: "Low", value: stats.low, color: "#3B82F6" },      // Blue
        { name: "Info", value: stats.info, color: "#94A3B8" },     // Slate
    ];

    const crawledCount = selectedScan?.crawled_count || 0;
    const vulnerableUrlCount = new Set(findings.map((f: Finding) => f.url)).size;
    const urlData = [
        { name: "Vulnerable", value: vulnerableUrlCount, color: "#EF4444" },
        { name: "Clean", value: Math.max(0, crawledCount - vulnerableUrlCount), color: "#10B981" },
    ];

    if (isLoading) {
        return (
            <div className="h-screen w-full flex items-center justify-center bg-black text-white">
                <div className="flex flex-col items-center gap-4">
                    <Activity className="w-10 h-10 text-emerald-500 animate-pulse" />
                    <p className="text-sm text-white/50 font-mono">Loading History...</p>
                </div>
            </div>
        );
    }

    return (
        <main className="h-screen w-full flex items-center justify-center p-2 md:p-4 lg:p-6 relative overflow-hidden bg-black selection:bg-purple-500/30">
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
                <Sidebar activeItem="History" />

                {/* Main Content */}
                <div className="flex-1 rounded-[12px] md:rounded-[20px] lg:rounded-[24px] bg-[#0A0A0A]/50 relative overflow-y-auto glass-scrollbar p-3 md:p-6 lg:p-8 flex flex-col min-h-0">
                    {/* Header */}
                    <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 mb-6 md:mb-10 shrink-0">
                        <div>
                            <div className="flex items-center gap-3 md:gap-4 mb-2">
                                <div className="w-10 h-10 md:w-12 md:h-12 rounded-xl md:rounded-[18px] bg-white/10 backdrop-blur-md border border-white/20 flex items-center justify-center shadow-lg shadow-emerald-500/20 shrink-0">
                                    <Activity className="w-5 h-5 md:w-6 md:h-6 text-emerald-400" />
                                </div>
                                <div>
                                    <h1 className="text-xl md:text-3xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-white to-white/60">
                                        Command Center
                                    </h1>
                                    <div className="flex items-center gap-3 text-xs md:text-sm text-white/40 mt-1">
                                        <span className="flex items-center gap-1.5">
                                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]"></span>
                                            History Analysis
                                        </span>
                                        <span>•</span>
                                        <span className="font-mono">{currentTime}</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="flex gap-2 md:gap-3 overflow-x-auto pb-1 no-scrollbar shrink-0">
                            <button className="glass-button px-3 md:px-5 py-2 md:py-2.5 rounded-xl md:rounded-2xl text-xs md:text-sm font-medium flex items-center gap-2 hover:bg-white/15 whitespace-nowrap">
                                <RefreshCw className="w-3.5 h-3.5 md:w-4 md:h-4" />
                                Refresh
                            </button>
                            <button className="bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-3 md:px-5 py-2 md:py-2.5 rounded-xl md:rounded-2xl text-xs md:text-sm flex items-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all whitespace-nowrap">
                                <Download className="w-3.5 h-3.5 md:w-4 md:h-4" />
                                Export Report
                            </button>
                        </div>
                    </div>

                    {!selectedScan ? (
                        <div className="flex-1 flex flex-col items-center justify-center text-white/30">
                            <p>No scan history available.</p>
                        </div>
                    ) : (
                        <>
                            {/* Metric Cards Grid */}
                            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 md:gap-6 mb-6 md:mb-8 shrink-0">
                                {[
                                    { label: "Critical", value: stats.critical, color: "text-purple-400", icon: AlertTriangle, bg: "from-purple-500/20 to-purple-600/5" },
                                    { label: "High Risk", value: stats.high, color: "text-red-400", icon: Shield, bg: "from-red-500/20 to-red-600/5" },
                                    { label: "Medium", value: stats.medium, color: "text-amber-400", icon: Activity, bg: "from-amber-500/20 to-amber-600/5" },
                                    { label: "Low Risk", value: stats.low, color: "text-blue-400", icon: CheckCircle, bg: "from-blue-500/20 to-blue-600/5" },
                                ].map((card, idx) => (
                                    <motion.div
                                        key={idx}
                                        initial={{ opacity: 0, scale: 0.9 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: idx * 0.1 }}
                                        className={`glass-card rounded-xl md:rounded-[24px] p-4 md:p-6 relative overflow-hidden group`}
                                    >
                                        <div className={`absolute inset-0 bg-gradient-to-br ${card.bg} opacity-50 group-hover:opacity-100 transition-opacity duration-500`}></div>
                                        <div className="relative z-10">
                                            <div className="flex items-start justify-between mb-2 md:mb-4">
                                                <span className="text-[10px] md:text-sm font-medium text-white/50 uppercase tracking-widest">{card.label}</span>
                                                <card.icon className={`w-4 h-4 md:w-5 md:h-5 ${card.color}`} />
                                            </div>
                                            <p className={`text-2xl md:text-5xl font-bold ${card.color} text-glow mb-1`}>{card.value}</p>
                                            <p className="text-[10px] md:text-xs text-white/30 font-medium">Active Findings</p>
                                        </div>
                                    </motion.div>
                                ))}
                            </div>

                            {/* Charts Section */}
                            <div className="flex flex-col lg:grid lg:grid-cols-3 gap-4 md:gap-6 mb-6 md:mb-8 shrink-0">
                                {/* Bar Chart */}
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className="lg:col-span-2 glass-panel rounded-2xl md:rounded-[32px] p-4 md:p-8"
                                >
                                    <div className="flex items-center justify-between mb-4 md:mb-8">
                                        <h3 className="text-lg md:text-xl font-semibold text-white/90">Severity Distribution</h3>
                                        <button className="glass-button p-1.5 md:p-2 rounded-xl">
                                            <ChevronDown className="w-4 h-4 md:w-5 md:h-5 text-white/60" />
                                        </button>
                                    </div>
                                    <div className="h-[200px] md:h-[300px] w-full">
                                        <ResponsiveContainer width="99%" height="100%">
                                            <BarChart data={severityData}>
                                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                                <XAxis dataKey="name" tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 10 }} axisLine={false} tickLine={false} />
                                                <YAxis tick={{ fill: "rgba(255,255,255,0.4)", fontSize: 10 }} axisLine={false} tickLine={false} />
                                                <Tooltip
                                                    cursor={{ fill: "rgba(255,255,255,0.05)" }}
                                                    contentStyle={{
                                                        backgroundColor: "rgba(0,0,0,0.8)",
                                                        border: "1px solid rgba(255,255,255,0.1)",
                                                        borderRadius: "16px",
                                                        boxShadow: "0 10px 40px rgba(0,0,0,0.5)",
                                                        backdropFilter: "blur(10px)"
                                                    }}
                                                    itemStyle={{ color: "#fff" }}
                                                />
                                                <Bar dataKey="value" radius={[4, 4, 4, 4]} barSize={30}>
                                                    {severityData.map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={entry.color} strokeWidth={0} />
                                                    ))}
                                                </Bar>
                                            </BarChart>
                                        </ResponsiveContainer>
                                    </div>
                                </motion.div>

                                {/* Donut Chart */}
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.1 }}
                                    className="glass-panel rounded-2xl md:rounded-[32px] p-4 md:p-8"
                                >
                                    <h3 className="text-lg md:text-xl font-semibold text-white/90 mb-4 md:mb-8">Target Health</h3>
                                    <div className="h-[180px] md:h-[200px] relative">
                                        <ResponsiveContainer width="99%" height="100%">
                                            <PieChart>
                                                <Pie
                                                    data={urlData}
                                                    cx="50%"
                                                    cy="50%"
                                                    innerRadius={50}
                                                    outerRadius={70}
                                                    paddingAngle={5}
                                                    dataKey="value"
                                                    stroke="none"
                                                >
                                                    {urlData.map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                                    ))}
                                                </Pie>
                                                <Tooltip />
                                            </PieChart>
                                        </ResponsiveContainer>
                                        {/* Center Text */}
                                        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                                            <span className="text-2xl md:text-3xl font-bold text-white">{selectedScan?.crawled_urls?.length || selectedScan?.crawled_count || 0}</span>
                                            <span className="text-[10px] md:text-xs text-white/40 uppercase tracking-widest">URLs</span>
                                        </div>
                                    </div>
                                    <div className="mt-4 md:mt-6 space-y-2 md:space-y-3">
                                        {urlData.map((item, idx) => (
                                            <div key={idx} className="flex items-center justify-between text-xs md:text-sm">
                                                <div className="flex items-center gap-2">
                                                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }}></div>
                                                    <span className="text-white/60">{item.name}</span>
                                                </div>
                                                <span className="font-mono font-medium">{item.value}</span>
                                            </div>
                                        ))}
                                    </div>
                                </motion.div>
                            </div>

                            {/* Vulnerabilities List */}
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.2 }}
                                className="glass-panel rounded-2xl md:rounded-[32px] p-4 md:p-8 shrink-0"
                            >
                                <div className="flex items-center justify-between mb-4 md:mb-6">
                                    <h3 className="text-lg md:text-xl font-semibold text-white/90">Recent Vulnerabilities</h3>
                                    <button className="text-xs md:text-sm text-emerald-400 hover:text-emerald-300 transition-colors">View All Analysis</button>
                                </div>
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 md:gap-4">
                                    {selectedScan?.findings && selectedScan.findings.length > 0 ? (
                                        selectedScan.findings.slice(0, 8).map((finding: Finding, idx: number) => (
                                            <div
                                                key={idx}
                                                className="flex items-center gap-3 md:gap-4 p-3 md:p-4 rounded-xl md:rounded-2xl bg-white/5 border border-white/5 hover:bg-white/10 hover:border-white/10 transition-all cursor-pointer group"
                                            >
                                                <div
                                                    className="w-1.5 h-1.5 md:w-2 md:h-2 rounded-full shadow-[0_0_10px_currentColor] flex-shrink-0"
                                                    style={{
                                                        color:
                                                            finding.severity === "Critical" ? "#A855F7" :
                                                                finding.severity === "High" ? "#EF4444" :
                                                                    finding.severity === "Medium" ? "#F59E0B" :
                                                                        finding.severity === "Low" ? "#3B82F6" : "#6B7280",
                                                        backgroundColor: "currentColor"
                                                    }}
                                                ></div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-xs md:text-sm font-medium text-white/90 group-hover:text-white truncate transition-colors">{finding.name}</p>
                                                    <p className="text-[10px] md:text-xs text-white/40 truncate">{finding.url}</p>
                                                </div>
                                                <div className="px-2 py-0.5 md:px-2.5 md:py-1 rounded-lg bg-white/5 text-[10px] md:text-xs font-mono text-white/60 border border-white/5">
                                                    #{idx + 1}
                                                </div>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="col-span-1 lg:col-span-2 py-8 md:py-12 text-center text-white/30 italic text-sm">
                                            No active threats detected in current view.
                                        </div>
                                    )}
                                </div>
                            </motion.div>
                        </>
                    )}
                </div>
            </motion.div>
        </main>
    );
}
