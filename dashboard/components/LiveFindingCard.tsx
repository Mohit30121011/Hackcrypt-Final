"use client";

import { motion } from "framer-motion";
import { AlertTriangle, ChevronDown, ExternalLink, Shield } from "lucide-react";
import { useState } from "react";

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

interface LiveFindingCardProps {
    finding: Finding;
    index: number;
}

export function LiveFindingCard({ finding, index }: LiveFindingCardProps) {
    const [isExpanded, setIsExpanded] = useState(false);

    const severityConfig = getSeverityConfig(finding.severity);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{
                duration: 0.4,
                delay: index * 0.1,
                ease: [0.23, 1, 0.32, 1]
            }}
            className="w-full"
        >
            <div
                className={`
          relative overflow-hidden rounded-[20px] bg-[#1C1C1E] border border-white/5
          hover:border-white/10 transition-all duration-300 cursor-pointer
          ${severityConfig.glow}
        `}
                onClick={() => setIsExpanded(!isExpanded)}
            >
                {/* Severity Accent Line */}
                <div className={`absolute left-0 top-0 bottom-0 w-1 ${severityConfig.accentBg}`} />

                <div className="p-4 pl-5">
                    {/* Header */}
                    <div className="flex items-start justify-between gap-4">
                        <div className="flex items-start gap-3 flex-1 min-w-0">
                            <div className={`w-10 h-10 rounded-xl ${severityConfig.iconBg} flex items-center justify-center flex-shrink-0`}>
                                <AlertTriangle className={`w-5 h-5 ${severityConfig.iconColor}`} />
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1">
                                    <span className={`
                    px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider
                    ${severityConfig.badgeBg} ${severityConfig.badgeText}
                    shadow-lg ${severityConfig.badgeShadow}
                  `}>
                                        {finding.severity}
                                    </span>
                                    {finding.cwe && (
                                        <span className="text-[10px] text-white/30 font-mono">{finding.cwe}</span>
                                    )}
                                </div>
                                <h3 className="text-white font-semibold text-sm truncate">{finding.name}</h3>
                                <p className="text-white/40 text-xs truncate mt-0.5">{finding.url}</p>
                            </div>
                        </div>

                        <motion.div
                            animate={{ rotate: isExpanded ? 180 : 0 }}
                            transition={{ duration: 0.2 }}
                        >
                            <ChevronDown className="w-5 h-5 text-white/20" />
                        </motion.div>
                    </div>

                    {/* Expanded Content */}
                    <motion.div
                        initial={false}
                        animate={{ height: isExpanded ? "auto" : 0, opacity: isExpanded ? 1 : 0 }}
                        transition={{ duration: 0.3 }}
                        className="overflow-hidden"
                    >
                        <div className="pt-4 space-y-3 border-t border-white/5 mt-4">
                            {/* Evidence */}
                            <div>
                                <p className="text-[10px] uppercase tracking-wider text-white/30 mb-1.5">Evidence</p>
                                <div className="bg-black/40 rounded-lg p-3 font-mono text-xs text-white/70 overflow-x-auto">
                                    {finding.evidence || "N/A"}
                                </div>
                            </div>

                            {/* Param & Payload */}
                            {(finding.param || finding.payload) && (
                                <div className="grid grid-cols-2 gap-3">
                                    {finding.param && (
                                        <div>
                                            <p className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Parameter</p>
                                            <code className="text-xs text-cyan-400 font-mono">{finding.param}</code>
                                        </div>
                                    )}
                                    {finding.payload && (
                                        <div>
                                            <p className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Payload</p>
                                            <code className="text-xs text-orange-400 font-mono truncate block">{finding.payload}</code>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Description */}
                            {finding.description && (
                                <div>
                                    <p className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Description</p>
                                    <p className="text-xs text-white/60">{finding.description}</p>
                                </div>
                            )}

                            {/* View Full Details Button */}
                            <a
                                href={finding.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-2 text-xs text-white/40 hover:text-white transition-colors mt-2"
                                onClick={(e) => e.stopPropagation()}
                            >
                                <ExternalLink className="w-3.5 h-3.5" />
                                Open URL
                            </a>
                        </div>
                    </motion.div>
                </div>
            </div>
        </motion.div>
    );
}

function getSeverityConfig(severity: string) {
    switch (severity.toLowerCase()) {
        case "critical":
            return {
                accentBg: "bg-red-500",
                iconBg: "bg-red-500/20",
                iconColor: "text-red-400",
                badgeBg: "bg-red-500/20",
                badgeText: "text-red-400",
                badgeShadow: "shadow-red-500/20",
                glow: "hover:shadow-[0_0_30px_rgba(239,68,68,0.1)]"
            };
        case "high":
            return {
                accentBg: "bg-orange-500",
                iconBg: "bg-orange-500/20",
                iconColor: "text-orange-400",
                badgeBg: "bg-orange-500/20",
                badgeText: "text-orange-400",
                badgeShadow: "shadow-orange-500/20",
                glow: "hover:shadow-[0_0_30px_rgba(249,115,22,0.1)]"
            };
        case "medium":
            return {
                accentBg: "bg-yellow-500",
                iconBg: "bg-yellow-500/20",
                iconColor: "text-yellow-400",
                badgeBg: "bg-yellow-500/20",
                badgeText: "text-yellow-400",
                badgeShadow: "shadow-yellow-500/20",
                glow: "hover:shadow-[0_0_30px_rgba(234,179,8,0.1)]"
            };
        case "low":
            return {
                accentBg: "bg-blue-500",
                iconBg: "bg-blue-500/20",
                iconColor: "text-blue-400",
                badgeBg: "bg-blue-500/20",
                badgeText: "text-blue-400",
                badgeShadow: "shadow-blue-500/20",
                glow: "hover:shadow-[0_0_30px_rgba(59,130,246,0.1)]"
            };
        default: // Info
            return {
                accentBg: "bg-gray-500",
                iconBg: "bg-gray-500/20",
                iconColor: "text-gray-400",
                badgeBg: "bg-gray-500/20",
                badgeText: "text-gray-400",
                badgeShadow: "shadow-gray-500/20",
                glow: ""
            };
    }
}
