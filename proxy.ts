import { NextResponse, type NextRequest } from "next/server";
import { desktopAPIAuthorized, desktopServer } from "./src/server/desktop-access.ts";
import { webAccess } from "./src/server/web-access.ts";

/** Every request except Next's own build assets passes one gate:
 *  - DESKTOP (the Electron-spawned server): /api requires the per-launch
 *    private capability header; pages are the static shell.
 *  - WEB/DEV (security hardening, 2026-10-26): loopback Host only, a
 *    per-run session cookie on every request, same-origin API writes
 *    (src/server/web-access.ts).
 *  No public callback or worker bypass: internal jobs call server
 *  functions, and any legitimate self-HTTP request must carry the gate's
 *  credential. */
export function proxy(request: NextRequest) {
	const url = request.nextUrl;
	const isApi = url.pathname === "/api" || url.pathname.startsWith("/api/");
	if (desktopServer()) {
		if (!isApi || desktopAPIAuthorized(request.headers)) return NextResponse.next();
		return NextResponse.json(
			{ error: "Desktop API access requires the trusted LearnHarness window." },
			{ status: 403, headers: { "Cache-Control": "no-store" } },
		);
	}
	const verdict = webAccess({ method: request.method, url, headers: request.headers, token: process.env.LH_WEB_TOKEN });
	if (verdict.kind === "allow") return NextResponse.next();
	if (verdict.kind === "exchange") {
		const response = NextResponse.redirect(new URL(verdict.location, url), 303);
		response.headers.set("Cache-Control", "no-store");
		response.headers.append("Set-Cookie", verdict.cookie);
		return response;
	}
	const headers = { "Cache-Control": "no-store" };
	return isApi
		? NextResponse.json({ error: verdict.reason }, { status: verdict.status, headers })
		: new NextResponse(verdict.reason, { status: verdict.status, headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" } });
}

export const config = { matcher: "/((?!_next/).*)" };
