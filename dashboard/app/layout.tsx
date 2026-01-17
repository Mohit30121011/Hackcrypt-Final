import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import BootAnimation from "@/components/BootAnimation";
import CustomCursor from "@/components/CustomCursor";
import { MobileNav } from "@/components/MobileNav";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Scancrypt - Vulnerability Scanner",
  description: "Next-gen AI-Powered Vulnerability Scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} aurora-bg selection:bg-white/20`}>
        <BootAnimation />
        <CustomCursor />
        <MobileNav />
        <div className="fixed inset-0 bg-[url('/noise.png')] opacity-[0.03] pointer-events-none mix-blend-overlay z-[5]"></div>
        <main className="pt-16 lg:pt-0">
          {children}
        </main>
      </body>
    </html>
  );
}
