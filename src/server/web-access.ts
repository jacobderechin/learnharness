import { timingSafeEqual } from "node:crypto";

/**
 * Web/dev access gate (security hardening, 2026-10-26) — the browser build
 * (`npm run dev` / `npm start`, no Electron) used to serve every API route
 * to anyone who could reach it: the LAN (Next binds all interfaces by
 * default), any website via CSRF, and DNS-rebinding pages (no Host check).
 *
 * Now (scripts/web-launch.mjs binds 127.0.0.1 and mints the token):
 *  1. HOST: only loopback names (localhost / 127.0.0.1 / [::1]) — a
 *     rebinding hostname is refused before anything else.
 *  2. SESSION: a per-run token (LH_WEB_TOKEN) the launcher prints as
 *     `/?lh_token=…`; that URL is exchanged once for an HttpOnly,
 *     SameSite=Strict `lh_session` cookie, which every request must carry.
 *     This also keeps out other local users and processes.
 *  3. WRITES: non-GET/HEAD API requests must be same-origin (Origin header
 *     equal to the addressed origin; Sec-Fetch-Site same-origin or none).
 *
 * No token configured = fail closed (start through the launcher). Pure
 * over its inputs — proxy.ts adapts Next's request; tests drive it directly.
 */

export const WEB_SESSION_COOKIE = "lh_session";
export const WEB_TOKEN_PARAM = "lh_token";
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type WebAccessVerdict =
	| { kind: "allow" }
	/** Valid token in the URL: set the session cookie and redirect here. */
	| { kind: "exchange"; location: string; cookie: string }
	| { kind: "deny"; status: 401 | 403 | 503; reason: string };

function sameSecret(supplied: string | undefined, expected: string): boolean {
	if (!supplied) return false;
	const a = Buffer.from(supplied);
	const b = Buffer.from(expected);
	return a.length === b.length && timingSafeEqual(a, b);
}

function cookieValue(header: string | null, name: string): string | undefined {
	for (const part of (header ?? "").split(";")) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) return rest.join("=");
	}
	return undefined;
}

export function webAccess(input: {
	method: string;
	url: URL;
	headers: Headers;
	token: string | undefined;
}): WebAccessVerdict {
	const { method, url, headers, token } = input;
	if (!token || token.length < 32) {
		return { kind: "deny", status: 503, reason: "Start LearnHarness with `npm run dev` or `npm start` — the launcher issues the access token." };
	}
	const host = headers.get("host") ?? "";
	let addressed: URL;
	try {
		addressed = new URL(`http://${host}`);
	} catch {
		return { kind: "deny", status: 403, reason: "Invalid Host header." };
	}
	if (!LOOPBACK.has(addressed.hostname) || addressed.username || addressed.password) {
		return { kind: "deny", status: 403, reason: "LearnHarness only answers on localhost." };
	}

	const offered = url.searchParams.get(WEB_TOKEN_PARAM);
	if (offered !== null) {
		if (!sameSecret(offered, token) || (method !== "GET" && method !== "HEAD")) {
			return { kind: "deny", status: 401, reason: "Invalid access token." };
		}
		const clean = new URL(url.pathname + url.search, addressed.origin);
		clean.searchParams.delete(WEB_TOKEN_PARAM);
		return {
			kind: "exchange",
			location: clean.pathname + clean.search,
			cookie: `${WEB_SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict`,
		};
	}

	if (!sameSecret(cookieValue(headers.get("cookie"), WEB_SESSION_COOKIE), token)) {
		return { kind: "deny", status: 401, reason: "Open the URL printed in the terminal that started LearnHarness." };
	}

	const isApi = url.pathname === "/api" || url.pathname.startsWith("/api/");
	if (isApi && method !== "GET" && method !== "HEAD") {
		const site = headers.get("sec-fetch-site");
		if (headers.get("origin") !== addressed.origin || (site !== null && site !== "same-origin" && site !== "none")) {
			return { kind: "deny", status: 403, reason: "Cross-origin requests are refused." };
		}
	}
	return { kind: "allow" };
}
