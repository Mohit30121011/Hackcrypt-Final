"use client";

import { Shield, Command, Activity, Lock, Smartphone } from "lucide-react";
import Link from "next/link";

interface SidebarProps {
    activeItem: string;
}

export function Sidebar({ activeItem }: SidebarProps) {
    const navItems = [
        { name: "Dashboard", icon: Command, href: "/", gradient: "from-purple-500/20 to-blue-500/20" },
        { name: "Live Activity", icon: Activity, href: "/live-activity", gradient: "from-purple-500/20 to-blue-500/20" },
        { name: "History", icon: Activity, href: "/history", gradient: "from-purple-500/20 to-blue-500/20" },
        { name: "Secure Enclave", icon: Lock, href: "/enclave", gradient: "from-purple-500/20 to-blue-500/20" },
    ];

    return (
        <div className="w-[300px] glass-card rounded-[40px] p-8 flex flex-col justify-between hidden lg:flex">
            <div>
                {/* Logo Section */}
                <div className="flex items-center gap-4 mb-12">
                    <div className="w-12 h-12 rounded-2xl bg-gradient-to-b from-white/10 to-white/5 border border-white/10 flex items-center justify-center shadow-lg">
                        <Shield className="w-6 h-6 text-white/90" />
                    </div>
                    <div>
                        <h1 className="text-xl font-bold tracking-tight text-white">Scancrypt</h1>
                        <p className="text-[10px] font-bold text-white/40 tracking-[0.2em] uppercase mt-1">iOS 26 Beta</p>
                    </div>
                </div>

                {/* Navigation */}
                <nav className="space-y-2">
                    {navItems.map((item) => {
                        const isActive = activeItem === item.name;
                        return (
                            <Link
                                key={item.name}
                                href={item.href}
                                className={`w-full flex items-center gap-4 px-5 py-4 rounded-[24px] transition-all duration-300 group relative overflow-hidden ${isActive ? "text-white shadow-lg shadow-purple-900/20" : "text-white/40 hover:text-white hover:bg-white/5"
                                    }`}
                            >
                                {isActive && (
                                    <div className={`absolute inset-0 bg-gradient-to-r ${item.gradient} border border-white/10`} />
                                )}
                                <item.icon className="w-5 h-5 relative z-10" />
                                <span className="font-medium relative z-10 text-[15px]">{item.name}</span>
                                {isActive && (
                                    <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-blue-400 blur-[2px] shadow-[0_0_8px_currentColor]" />
                                )}
                            </Link>
                        );
                    })}
                </nav>
            </div>

            {/* Admin User Card */}
            <div className="p-5 rounded-[32px] bg-[#0A0A0A] border border-white/5 group hover:border-white/10 transition-colors cursor-pointer">
                <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-blue-500 to-cyan-400 p-[2px]">
                        <div className="w-full h-full rounded-full bg-black flex items-center justify-center text-xs font-bold text-white">AD</div>
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-white group-hover:text-white/90 truncate">Admin User</p>
                        <p className="text-xs text-white/30 truncate">Pro License</p>
                    </div>
                    <Smartphone className="w-4 h-4 text-white/20" />
                </div>
            </div>
        </div>
    );
}
