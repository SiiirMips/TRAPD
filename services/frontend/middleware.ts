import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;

  // Check for session cookie (NextAuth v5 with JWT uses this)
  const sessionToken = request.cookies.get("__Secure-next-auth.session-token") 
    || request.cookies.get("next-auth.session-token");
  
  const isLoggedIn = !!sessionToken;

  const protectedPaths = ["/dashboard"]; // extend with more paths when ready
  const isProtected = protectedPaths.some((p) => pathname.startsWith(p));

  if (isProtected && !isLoggedIn) {
    const url = new URL(`/login`, request.url);
    url.searchParams.set("callbackUrl", `${pathname}${search || ""}`);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
