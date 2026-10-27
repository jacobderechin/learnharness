"use strict";
const { KEYRING_MESSAGE, secretJsonFile } = require("./sealed-file.cjs");

/**
 * The BYOK key vault (security hardening, 2026-10-26): provider API keys
 * live in userData/auth.enc, sealed with the OS keyring (sealed-file.cjs).
 * Main owns it; the server child reads and writes it ONLY over the
 * inherited Node IPC channel ("lh:keys") — keys never enter the server's
 * environment, the renderer, or a plaintext file. A legacy plaintext
 * auth.json is migrated on load (when a real keyring exists) and deleted.
 */

const NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const MAX_VALUE = 8192;

function createKeyVault({ file, codec }) {
	const secret = secretJsonFile(file, { codec });
	let vars = {};
	let loadFailed = false;
	const clean = (raw) =>
		raw && typeof raw === "object" && !Array.isArray(raw)
			? Object.fromEntries(Object.entries(raw).filter(([name, value]) => NAME.test(name) && typeof value === "string"))
			: {};
	async function snapshot() {
		const state = await secret.state().catch(() => ({ encrypted: false, writable: false }));
		return { vars: { ...vars }, encrypted: state.encrypted, writable: state.writable && !loadFailed };
	}
	async function commit(next) {
		await secret.write(next);
		vars = next;
		return snapshot();
	}
	return {
		async load() {
			try {
				vars = clean(await secret.read());
				loadFailed = false;
			} catch {
				// A corrupt or foreign-owned file: start empty and refuse writes,
				// so the unreadable file is never overwritten silently.
				vars = {};
				loadFailed = true;
			}
			return snapshot();
		},
		snapshot,
		async set(name, value) {
			if (!NAME.test(name) || typeof value !== "string" || value.length === 0 || value.length > MAX_VALUE) throw new Error("Invalid key.");
			if (loadFailed) throw new Error("The saved key file could not be read; it was left untouched.");
			return commit({ ...vars, [name]: value });
		},
		async delete(name) {
			if (!NAME.test(name)) throw new Error("Invalid key.");
			if (loadFailed) throw new Error("The saved key file could not be read; it was left untouched.");
			if (!(name in vars)) return snapshot();
			const next = { ...vars };
			delete next[name];
			return commit(next);
		},
	};
}

/** Public error text for a vault failure (never echoes key material). */
function vaultError(err) {
	if (err?.code === "keyring") return KEYRING_MESSAGE;
	if (err?.code === "storage") return "The key file could not be written safely. Check the app's data folder permissions.";
	return err instanceof Error && err.message.length < 200 ? err.message : "The key could not be saved.";
}

/** Inherited child IPC for the server: snapshot / set / delete. */
function attachKeyChild(child, vault) {
	const listener = async (message) => {
		if (!message || message.channel !== "lh:keys" || typeof message.id !== "string" || message.id.length > 100) return;
		let reply;
		try {
			let value;
			if (message.op === "snapshot") value = await vault.snapshot();
			else if (message.op === "set" && typeof message.name === "string" && typeof message.value === "string") value = await vault.set(message.name, message.value);
			else if (message.op === "delete" && typeof message.name === "string") value = await vault.delete(message.name);
			else throw new Error("Invalid private operation");
			reply = { channel: "lh:keys", id: message.id, op: message.op, ok: true, value };
		} catch (err) {
			reply = { channel: "lh:keys", id: message.id, op: message.op, ok: false, error: vaultError(err) };
		}
		if (child.connected) child.send(reply, () => {});
	};
	child.on("message", listener);
	return { dispose: () => child.removeListener("message", listener) };
}

module.exports = { createKeyVault, attachKeyChild, vaultError };
