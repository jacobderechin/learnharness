#!/usr/bin/env node
/**
 * The web/dev launcher (security hardening, 2026-10-26) — `npm run dev`,
 * `npm start`, `npm run desktop:dev`, and `npm run build`:
 *
 *   node scripts/web-launch.mjs dev|start [--electron]
 *   node scripts/web-launch.mjs build
 *
 * Every Next process it starts runs with NEXT_TELEMETRY_DISABLED=1 (no
 * usage telemetry to Vercel). `build` only builds — no host, token, or
 * Electron.
 *
 * Binds Next to 127.0.0.1 only (never the LAN) and mints the per-run
 * access token (LH_WEB_TOKEN, 32 random bytes; an existing value of at
 * least 32 chars is reused) that src/server/web-access.ts requires. Open
 * the printed URL once: its token is exchanged for an HttpOnly session
 * cookie. --electron also starts the desktop dev shell against this
 * server (it loads the tokenized URL itself); either process exiting
 * stops the other.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [mode, ...rest] = process.argv.slice(2);
if (mode !== "dev" && mode !== "start" && mode !== "build") {
	console.error("usage: node scripts/web-launch.mjs dev|start [--electron] | build");
	process.exit(2);
}
const withElectron = rest.includes("--electron");
const port = process.env.PORT && /^\d+$/.test(process.env.PORT) ? process.env.PORT : "3000";
const token = process.env.LH_WEB_TOKEN && process.env.LH_WEB_TOKEN.length >= 32 ? process.env.LH_WEB_TOKEN : randomBytes(32).toString("hex");
const origin = `http://127.0.0.1:${port}`;
const env = { ...process.env, PORT: port, LH_WEB_TOKEN: token, NEXT_TELEMETRY_DISABLED: "1" };
const bin = (name) => path.join(ROOT, "node_modules", ".bin", process.platform === "win32" ? `${name}.cmd` : name);

const children = [];
let stopping = false;
function stopAll(code) {
	if (stopping) return;
	stopping = true;
	for (const child of children) if (child.exitCode === null) child.kill("SIGTERM");
	process.exitCode = code ?? 0;
}
function run(command, args, extraEnv = {}) {
	const child = spawn(command, args, { cwd: ROOT, env: { ...env, ...extraEnv }, stdio: "inherit", shell: process.platform === "win32" });
	child.on("exit", (code) => stopAll(code ?? 0));
	children.push(child);
	return child;
}
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => stopAll(0));

if (mode === "build") {
	run(bin("next"), ["build"]);
} else {
	run(bin("next"), [mode, "-H", "127.0.0.1", "-p", port]);
	if (withElectron) run(bin("electron"), ["."], { LH_DEV_URL: origin });
	console.log(`\n  LearnHarness (${mode}) — open this URL once to sign in this browser:\n  ${origin}/?lh_token=${token}\n`);
}
