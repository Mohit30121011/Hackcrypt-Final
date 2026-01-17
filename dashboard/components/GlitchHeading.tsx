"use client";

import { motion } from "framer-motion";

interface GlitchHeadingProps {
    text: string;
    className?: string; // Allow passing text sizes/alignments
}

export function GlitchHeading({ text, className = "" }: GlitchHeadingProps) {
    return (
        <div className={`relative inline-block ${className}`}>
            {/* Main Text */}
            <h2 className="relative z-20 font-light tracking-wide bg-clip-text text-transparent bg-gradient-to-r from-cyan-400/90 via-blue-500/90 to-purple-600/90 drop-shadow-lg">
                {text}
            </h2>

            {/* Glitch Layer 1 - Cyan */}
            <motion.h2
                className="absolute inset-0 font-light tracking-wide text-[#00f0ff] z-10 pointer-events-none"
                style={{ opacity: 0 }}
                animate={{
                    x: [0, -4, 2, -4, 0],
                    y: [0, 2, -1, 0],
                    opacity: [0, 0.8, 0, 0.5, 0],
                }}
                transition={{
                    duration: 0.2,
                    repeat: Infinity,
                    repeatDelay: 3,
                    times: [0, 0.2, 0.4, 0.6, 1]
                }}
            >
                {text}
            </motion.h2>

            {/* Glitch Layer 2 - Violet */}
            <motion.h2
                className="absolute inset-0 font-light tracking-wide text-[#8b5cf6] z-10 pointer-events-none"
                style={{ opacity: 0 }}
                animate={{
                    x: [0, 4, -2, 4, 0],
                    y: [0, -2, 1, 0],
                    opacity: [0, 0.7, 0, 0.4, 0],
                }}
                transition={{
                    duration: 0.2,
                    repeat: Infinity,
                    repeatDelay: 3.5,
                    times: [0, 0.2, 0.4, 0.6, 1]
                }}
            >
                {text}
            </motion.h2>
        </div >
    );
}
