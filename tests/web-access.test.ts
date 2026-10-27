/**
 * The web/dev access gate (security hardening, 2026-10-26):
 * src/server/web-access.ts — loopback Host, per-run session cookie, token
 * exchange, same-origin API writes, fail-closed without a token.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { webAccess, WEB_SESSION_COOKIE } from "../src/server/web-access.ts";
import { desktopServer } from "../src/server/desktop-access.ts";

const TOKEN = "a".repeat(64);
const call = (path: string, init: { method?: string; headers?: Record<string, string>; token?: string | undefined } = {}) =>
	webAccess({
		method: init.method ?? "GET",
		url: new URL(path, "http://127.0.0.1:3000"),
		headers: new Headers({ host: "127.0.0.1:3000", ...init.headers }),
		token: "token" in init ? init.token : TOKEN,
	});
const session = { cookie: `other=1; ${WEB_SESSION_COOKIE}=${TOKEN}` };

describe("webAccess", () => {
	it("fails closed without a launcher token", () => {
		assert.deepEqual(call("/", { token: undefined }).kind, "deny");
		assert.equal((call("/", { token: "short" }) as { status: number }).status, 503);
	});

	it("refuses non-loopback Host headers (DNS rebinding), even with a session", () => {
		const verdict = call("/api/keys", { headers: { ...session, host: "attacker.invalid:3000" } });
		assert.deepEqual(verdict, { kind: "deny", status: 403, reason: "LearnHarness only answers on localhost." });
		assert.equal(call("/api/keys", { headers: { ...session, host: "localhost:3000" } }).kind, "allow");
		assert.equal(call("/api/keys", { headers: { ...session, host: "[::1]:3000" } }).kind, "allow");
	});

	it("requires the session cookie on pages and API reads", () => {
		assert.equal((call("/") as { status: number }).status, 401);
		assert.equal((call("/api/keys") as { status: number }).status, 401);
		assert.equal((call("/api/keys", { headers: { cookie: `${WEB_SESSION_COOKIE}=${"b".repeat(64)}` } }) as { status: number }).status, 401);
		assert.equal(call("/api/keys", { headers: session }).kind, "allow");
	});

	it("exchanges a valid token once for an HttpOnly SameSite=Strict cookie, dropping it from the URL", () => {
		const verdict = call(`/chat/new?x=1&lh_token=${TOKEN}`);
		assert.equal(verdict.kind, "exchange");
		if (verdict.kind !== "exchange") return;
		assert.equal(verdict.location, "/chat/new?x=1");
		assert.match(verdict.cookie, /^lh_session=a{64}; Path=\/; HttpOnly; SameSite=Strict$/);
		assert.equal((call(`/?lh_token=${"c".repeat(64)}`) as { status: number }).status, 401, "a wrong token is refused");
		assert.equal((call(`/api/keys?lh_token=${TOKEN}`, { method: "POST" }) as { status: number }).status, 401, "exchange is GET-only");
	});

	it("API writes must be same-origin (CSRF)", () => {
		const write = (headers: Record<string, string>) => call("/api/chats", { method: "POST", headers: { ...session, ...headers } });
		assert.equal(write({ origin: "http://127.0.0.1:3000", "sec-fetch-site": "same-origin" }).kind, "allow");
		assert.equal(write({ origin: "http://127.0.0.1:3000" }).kind, "allow", "non-browser clients send no Sec-Fetch-Site");
		assert.equal((write({ origin: "https://evil.example", "sec-fetch-site": "cross-site" }) as { status: number }).status, 403);
		assert.equal((write({ "sec-fetch-site": "same-origin" }) as { status: number }).status, 403, "no Origin on a write");
		assert.equal((write({ origin: "http://127.0.0.1:3000", "sec-fetch-site": "cross-site" }) as { status: number }).status, 403);
	});

	it("desktopServer: either desktop marker takes the desktop gate", () => {
		assert.equal(desktopServer({}), false);
		assert.equal(desktopServer({ LH_DESKTOP_SERVER: "1" }), true);
		assert.equal(desktopServer({ LH_DESKTOP_API_SECRET: "x" }), true);
	});
});

describe("app Content-Security-Policy (next.config.ts headers)", () => {
	it("blocks remote images/scripts and foreign framing; allows the dictation socket", async () => {
		const { default: nextConfig } = await import("../next.config.ts");
		const rules = await nextConfig.headers!();
		const headers = Object.fromEntries(rules[0]!.headers.map((h) => [h.key, h.value]));
		const csp = headers["Content-Security-Policy"]!;
		assert.match(csp, /img-src 'self' data: blob:(;|$)/);
		assert.match(csp, /script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'/);
		assert.match(csp, /connect-src 'self' wss:\/\/api\.deepgram\.com/);
		assert.match(csp, /object-src 'none'/);
		assert.match(csp, /frame-ancestors 'none'/);
		assert.doesNotMatch(csp, /upgrade-insecure-requests/, "the app is served over http://127.0.0.1");
		assert.equal(headers["Referrer-Policy"], "no-referrer");
		assert.equal(nextConfig.poweredByHeader, false);
	});
});

describe("Next.js telemetry is off everywhere the repo starts Next", () => {
	it("launcher (dev/start/build), desktop server spawn, and the build script", async () => {
		const { readFileSync } = await import("node:fs");
		const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");
		assert.match(read("../scripts/web-launch.mjs"), /NEXT_TELEMETRY_DISABLED: "1"/);
		assert.match(read("../electron/main.cjs"), /NEXT_TELEMETRY_DISABLED: "1"/);
		const pkg = JSON.parse(read("../package.json")) as { scripts: Record<string, string> };
		for (const name of ["dev", "start", "build", "desktop:dev"]) assert.match(pkg.scripts[name]!, /scripts\/web-launch\.mjs/, name);
		assert.doesNotMatch(pkg.scripts["desktop:dist"]!, /&& next build/, "desktop:dist builds through npm run build");
	});
});
