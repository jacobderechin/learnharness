/**
 * The AuthStore adapter — BYOK provider keys as a flat {VAR: value} map.
 * Two shapes behind one port (security hardening, 2026-10-26):
 *
 * DESKTOP (LH_DESKTOP_SERVER with its private IPC channel): the keys live
 * in Electron main's key vault, sealed with the OS keyring
 * (electron/key-vault.cjs). This process holds them in memory only — the
 * snapshot is loaded once at boot (instrumentation.ts, before the first
 * request) and refreshed by every write's reply. Nothing
 * is written to disk here and nothing enters process.env. (instrumentation.ts
 * is import-free for tracing reasons, so it leaves the boot snapshot in a
 * globalThis slot that vault() adopts.)
 *
 * WEB/DEV: the plaintext auth.json at config.AUTH_FILE (gitignored repo
 * root by default) — owner-only by construction: 0700 directory, random
 * `wx` temp at 0600, fsync, rename. A file that is group/world-accessible
 * or owned by someone else is refused on read (treated as "no keys").
 * Hand-edits keep working (re-read on every access).
 *
 * The server (src/server/keys.ts) is the only intended writer: shape
 * validation happens there; unknown vars ride along untouched.
 */

import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { AUTH_FILE } from "../../config.ts";
import type { AuthStorageState, AuthStore } from "../core/ports.ts";

// ─── desktop: the main-process vault over inherited IPC ─────────────────────

interface VaultSnapshot extends AuthStorageState {
	vars: Record<string, string>;
}
interface Pending {
	resolve(value: VaultSnapshot): void;
	reject(error: Error): void;
	timer: ReturnType<typeof setTimeout>;
}
interface VaultState {
	snapshot: VaultSnapshot | null;
	pending: Map<string, Pending>;
	counter: number;
}
const VAULT_KEY = Symbol.for("lh.keyVault");
/** Where instrumentation.ts leaves the boot snapshot (import-free hook). */
const BOOT_SNAPSHOT = Symbol.for("lh.keyVault.boot");

/** The desktop server's private channel to main (same gate as the
 *  subscription/ChatGPT bridges). */
export function desktopKeyVault(): boolean {
	return (
		process.env.LH_DESKTOP_SERVER === "1" &&
		(process.env.LH_DESKTOP_API_SECRET?.length ?? 0) >= 64 &&
		typeof process.send === "function" &&
		process.connected === true
	);
}

function vault(): VaultState {
	const g = globalThis as typeof globalThis & { [VAULT_KEY]?: VaultState };
	if (!g[VAULT_KEY]) {
		const boot = (g as Record<symbol, unknown>)[BOOT_SNAPSHOT] as VaultSnapshot | undefined;
		const state: VaultState = { snapshot: boot ?? null, pending: new Map(), counter: 0 };
		g[VAULT_KEY] = state;
		process.on("message", (raw: unknown) => {
			const message = raw as { channel?: string; id?: string; ok?: boolean; value?: VaultSnapshot; error?: string };
			if (message?.channel !== "lh:keys" || !message.id) return;
			const pending = state.pending.get(message.id);
			if (!pending) return;
			clearTimeout(pending.timer);
			state.pending.delete(message.id);
			if (message.ok && message.value) pending.resolve(message.value);
			else pending.reject(new Error(message.error ?? "The key vault refused the request."));
		});
	}
	return g[VAULT_KEY];
}

function vaultRequest(op: "snapshot" | "set" | "delete", fields: Record<string, string> = {}): Promise<VaultSnapshot> {
	const state = vault();
	if (!desktopKeyVault()) return Promise.reject(new Error("The desktop key vault is not connected."));
	return new Promise((resolve, reject) => {
		const id = `${process.pid}:keys:${++state.counter}`;
		const timer = setTimeout(() => {
			state.pending.delete(id);
			reject(new Error("The desktop key vault timed out."));
		}, 15_000);
		state.pending.set(id, {
			timer,
			reject,
			resolve: (snapshot) => {
				state.snapshot = snapshot;
				resolve(snapshot);
			},
		});
		process.send!({ ...fields, channel: "lh:keys", id, op }, (error: Error | null) => {
			if (!error) return;
			clearTimeout(timer);
			state.pending.delete(id);
			reject(new Error("The desktop key vault connection closed."));
		});
	});
}

const desktopStore: AuthStore = {
	authVars() {
		return { ...(vault().snapshot?.vars ?? {}) };
	},
	async setAuthVar(name, value) {
		await vaultRequest("set", { name, value });
	},
	async deleteAuthVar(name) {
		await vaultRequest("delete", { name });
	},
	storage() {
		const snapshot = vault().snapshot;
		return { encrypted: snapshot?.encrypted ?? false, writable: snapshot?.writable ?? false };
	},
};

// ─── web/dev: the owner-only plaintext file ─────────────────────────────────

/** The flat string→string map, or {} for absent/corrupt/non-object — and
 *  for a file anyone but its owner could read (never trust a widened file). */
function readMap(): Record<string, string> {
	try {
		const stat = fs.lstatSync(AUTH_FILE);
		if (!stat.isFile()) return {};
		if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stat.uid !== process.getuid()))) {
			console.error(`[keys] refusing ${AUTH_FILE}: it must be owner-only (chmod 600)`);
			return {};
		}
		const raw = JSON.parse(fs.readFileSync(AUTH_FILE, "utf-8"));
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
		return Object.fromEntries(
			Object.entries(raw).filter(([, v]) => typeof v === "string") as [string, string][],
		);
	} catch {
		return {}; // absent or corrupt — the documented state is "no keys yet"
	}
}

/** Write the map atomically, owner-only: a partial write must never leave
 *  a readable file (secrets) or a truncated JSON (looks like "no keys"). */
function writeMap(map: Record<string, string>): void {
	const dir = path.dirname(AUTH_FILE);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const tmp = path.join(dir, `.auth.json.${randomUUID()}.tmp`);
	const fd = fs.openSync(tmp, "wx", 0o600);
	try {
		fs.writeFileSync(fd, `${JSON.stringify(map, null, "\t")}\n`);
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
	try {
		fs.chmodSync(tmp, 0o600); // umask may have relaxed the create mode
		fs.renameSync(tmp, AUTH_FILE);
	} catch (err) {
		fs.rmSync(tmp, { force: true });
		throw err;
	}
}

const fileStore: AuthStore = {
	authVars() {
		return readMap();
	},
	async setAuthVar(name, value) {
		const map = readMap();
		map[name] = value;
		writeMap(map);
	},
	async deleteAuthVar(name) {
		const map = readMap();
		if (!(name in map)) return; // absent = silent success, idempotent
		delete map[name];
		writeMap(map);
	},
	storage() {
		return { encrypted: false, writable: true };
	},
};

/** The live adapter: the desktop vault when the private channel exists,
 *  else the web/dev file. Chosen per call (the channel is fixed for the
 *  process lifetime, but tests flip env between cases). */
export const authStore: AuthStore = {
	authVars: () => (desktopKeyVault() ? desktopStore : fileStore).authVars(),
	setAuthVar: (name, value) => (desktopKeyVault() ? desktopStore : fileStore).setAuthVar(name, value),
	deleteAuthVar: (name) => (desktopKeyVault() ? desktopStore : fileStore).deleteAuthVar(name),
	storage: () => (desktopKeyVault() ? desktopStore : fileStore).storage(),
};
