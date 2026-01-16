"use client";

import { useState, useEffect } from "react";
import { Activity, Command, Lock, LogOut } from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

interface SidebarProps {
    activeItem?: string; // Optional now, we derive it ourselves
}

export function Sidebar({ activeItem: propActiveItem }: SidebarProps) {
    const pathname = usePathname();
    const router = useRouter();

    // Derive active item from pathname (ignore prop if not provided)
    const activeItem = propActiveItem || (
        pathname === "/" ? "Dashboard" :
            pathname.includes("/live-activity") ? "Live Activity" :
                pathname.includes("/history") ? "History" :
                    pathname.includes("/enclave") ? "Secure Enclave" : ""
    );

    const [user, setUser] = useState<any>(null);

    useEffect(() => {
        const fetchUser = async () => {
            const supabase = createClient();
            const { data: { user } } = await supabase.auth.getUser();
            setUser(user);
        };
        fetchUser();
    }, []);

    const handleSignOut = async () => {
        const supabase = createClient();
        await supabase.auth.signOut();
        router.push("/login");
    };

    const navItems = [
        { name: "Dashboard", icon: Command, href: "/", gradient: "from-blue-500/20 to-cyan-500/20" },
        { name: "Live Activity", icon: Activity, href: "/live-activity", gradient: "from-purple-500/20 to-blue-500/20" },
        { name: "History", icon: Activity, href: "/history", gradient: "from-purple-500/20 to-blue-500/20" },
        { name: "Secure Enclave", icon: Lock, href: "/enclave", gradient: "from-purple-500/20 to-blue-500/20" },
    ];

    return (
        <div className="w-[300px] glass-card rounded-[40px] p-8 flex flex-col justify-between hidden lg:flex">
            <div>
                {/* Logo Section */}
                <div className="flex items-center justify-center mb-4 mt-2">
                    <Image
                        src="/logo.png"
                        alt="Scancrypt Logo"
                        width={700}
                        height={250}
                        className="w-auto h-40 object-contain drop-shadow-[0_0_25px_rgba(168,85,247,0.7)]"
                        priority
                    />
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
                                    <div className={`absolute inset-0 bg-gradient-to-r ${item.gradient} border border-white/10 rounded-[24px]`} />
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

            {/* User Profile Card - Real Google Data */}
            {user ? (
                <div className="relative group bg-white/5 rounded-[32px] p-4 transition-all hover:bg-white/10 border border-white/5 hover:border-white/10">
                    <div className="flex items-center gap-4">
                        <div className="relative">
                            <div className="absolute inset-0 bg-gradient-to-tr from-cyan-400 to-purple-500 rounded-full blur-[2px]" />
                            {user.user_metadata?.avatar_url ? (
                                <Image
                                    src={user.user_metadata.avatar_url}
                                    alt="User"
                                    width={48}
                                    height={48}
                                    className="rounded-full relative z-10 border-2 border-black object-cover w-12 h-12"
                                />
                            ) : (
                                <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-purple-500 rounded-full relative z-10 flex items-center justify-center text-white font-bold">
                                    {user.email?.charAt(0).toUpperCase() || "U"}
                                </div>
                            )}
                            {/* Online Dot */}
                            <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 border-2 border-[#09090b] rounded-full z-20"></div>
                        </div>
                        <div className="flex-1 min-w-0">
                            <h3 className="font-semibold text-white truncate text-sm">
                                {user.user_metadata?.full_name || user.email?.split('@')[0] || "Agent"}
                            </h3>
                            <p className="text-white/40 text-xs truncate">{user.email}</p>
                        </div>

                        <button
                            onClick={handleSignOut}
                            className="text-white/40 hover:text-red-400 transition-colors p-2 rounded-lg hover:bg-red-500/10"
                            title="Sign Out"
                        >
                            <LogOut size={18} />
                        </button>
                    </div>
                </div>
            ) : (
                <div className="animate-pulse h-16 bg-white/5 rounded-[32px]"></div>
            )}
        </div>
    );
}
