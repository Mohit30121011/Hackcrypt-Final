import { createMiddlewareClient } from "@supabase/auth-helpers-nextjs";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export async function middleware(req: NextRequest) {
    const res = NextResponse.next();
    const supabase = createMiddlewareClient({ req, res });

    const {
        data: { session },
    } = await supabase.auth.getSession();

    // If user is not signed in and trying to access protected routes
    if (!session && (req.nextUrl.pathname === "/" || req.nextUrl.pathname.startsWith("/history") || req.nextUrl.pathname.startsWith("/live-activity"))) {
        return NextResponse.redirect(new URL("/login", req.url));
    }

    // If user is signed in and trying to access login page
    if (session && req.nextUrl.pathname === "/login") {
        return NextResponse.redirect(new URL("/", req.url));
    }

    return res;
}

export const config = {
    matcher: ["/", "/history/:path*", "/live-activity/:path*", "/login"],
};
