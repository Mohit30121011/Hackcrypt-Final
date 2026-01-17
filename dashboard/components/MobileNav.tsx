"use client";

import { useState, useEffect } from "react";
import { Menu, X, Activity, Command, Lock, LogOut, Home } from "lucide-react";
import Link from "next/link";
import Image from "next/image";
import { usePathname, useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";
import { motion, AnimatePresence } from "framer-motion";

export function MobileNav() {
    const [isOpen, setIsOpen] = useState(false);
    const pathname = usePathname();
    const router = useRouter();
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
        { name: "Dashboard", icon: Command, href: "/" },
        { name: "Live Activity", icon: Activity, href: "/live-activity" },
        { name: "History", icon: Activity, href: "/history" },
        { name: "Secure Enclave", icon: Lock, href: "/enclave" },
    ];

    const isActive = (href: string) => pathname === href;

    return (
        <>
            {/* Mobile Header */}
            <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-white/10">
                <div className="flex items-center justify-between p-4">
                    <Image
                        src="/logo.png"
                        alt="Scancrypt"
                        width={150}
                        height={50}
                        className="h-8 w-auto object-contain"
                    />
                    <button
                        onClick={() => setIsOpen(!isOpen)}
                        className="p-2 text-white/70 hover:text-white transition-colors"
                    >
                        {isOpen ? <X size={24} /> : <Menu size={24} />}
                    </button>
                </div>
            </div>

            {/* Mobile Menu Overlay */}
            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ opacity: 0, x: "100%" }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: "100%" }}
                        transition={{ duration: 0.3, ease: "easeInOut" }}
                        className="lg:hidden fixed inset-0 z-40 bg-black/95 backdrop-blur-xl pt-20"
                    >
                        <nav className="flex flex-col p-6 space-y-2">
                            {navItems.map((item) => (
                                <Link
                                    key={item.name}
                                    href={item.href}
                                    onClick={() => setIsOpen(false)}
                                    className={`flex items-center gap-4 px-5 py-4 rounded-2xl transition-all ${isActive(item.href)
                                            ? "bg-gradient-to-r from-purple-500/20 to-blue-500/20 text-white border border-white/10"
                                            : "text-white/50 hover:text-white hover:bg-white/5"
                                        }`}
                                >
                                    <item.icon className="w-5 h-5" />
                                    <span className="font-medium">{item.name}</span>
                                </Link>
                            ))}
                        </nav>

                        {/* User Section */}
                        {user && (
                            <div className="absolute bottom-0 left-0 right-0 p-6 border-t border-white/10">
                                <div className="flex items-center gap-4">
                                    <div className="relative">
                                        {user.user_metadata?.avatar_url ? (
                                            <Image
                                                src={user.user_metadata.avatar_url}
                                                alt="User"
                                                width={48}
                                                height={48}
                                                className="rounded-full border-2 border-cyan-500 object-cover w-12 h-12"
                                            />
                                        ) : (
                                            <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-purple-500 rounded-full flex items-center justify-center text-white font-bold">
                                                {user.email?.charAt(0).toUpperCase() || "U"}
                                            </div>
                                        )}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-white font-medium truncate">
                                            {user.user_metadata?.full_name || user.email?.split('@')[0]}
                                        </p>
                                        <p className="text-white/40 text-sm truncate">{user.email}</p>
                                    </div>
                                    <button
                                        onClick={handleSignOut}
                                        className="p-3 text-white/40 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-colors"
                                    >
                                        <LogOut size={20} />
                                    </button>
                                </div>
                            </div>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>
        </>
    );
}
