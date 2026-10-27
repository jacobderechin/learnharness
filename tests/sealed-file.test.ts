/**
 * Sealed secret files (security hardening, 2026-10-26): electron/sealed-file.cjs
 * + the BYOK key vault (electron/key-vault.cjs). A reversible fake codec
 * stands in for the OS keyring; the real codec's keyring detection is
 * pinned against a fake safeStorage.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const require = createRequire(import.meta.url);
const { keyringCodec, secretJsonFile, MAGIC } = require("../electron/sealed-file.cjs");
const { createKeyVault, attachKeyChild } = require("../electron/key-vault.cjs");

function fakeCodec(available = true) {
	return {
		available: async () => available,
		encrypt: async (text: string) => Buffer.from(Buffer.from(text, "utf8").map((b) => b ^ 0x5a)),
		decrypt: async (buffer: Buffer) => Buffer.from(buffer.map((b) => b ^ 0x5a)).toString("utf8"),
	};
}
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), "lh-sealed-"));

describe("keyringCodec: no real keyring = unavailable", () => {
	const safeStorage = (backend: string, available = true) => ({
		getSelectedStorageBackend: () => backend,
		isAsyncEncryptionAvailable: async () => available,
	});
	it("linux basic_text / unknown backends are refused; real backends pass", async () => {
		assert.equal(await keyringCodec(safeStorage("basic_text"), "linux").available(), false);
		assert.equal(await keyringCodec(safeStorage("unknown"), "linux").available(), false);
		assert.equal(await keyringCodec(safeStorage("gnome_libsecret"), "linux").available(), true);
		assert.equal(await keyringCodec(safeStorage("kwallet6"), "linux").available(), true);
	});
	it("macOS/Windows defer to safeStorage availability", async () => {
		assert.equal(await keyringCodec(safeStorage("unknown"), "darwin").available(), true);
		assert.equal(await keyringCodec(safeStorage("unknown", false), "win32").available(), false);
	});
});

describe("secretJsonFile", () => {
	it("writes owner-only ciphertext with the magic header; reads it back", async () => {
		const dir = await tmp();
		const file = path.join(dir, "auth.json");
		const store = secretJsonFile(file, { codec: fakeCodec() });
		await store.write({ OPENAI_API_KEY: "sk-throwaway-secret" });
		const raw = await fs.readFile(path.join(dir, "auth.enc"));
		assert.ok(raw.subarray(0, MAGIC.length).equals(MAGIC));
		assert.doesNotMatch(raw.toString("latin1"), /sk-throwaway-secret/);
		if (process.platform !== "win32") assert.equal((await fs.stat(path.join(dir, "auth.enc"))).mode & 0o777, 0o600);
		assert.deepEqual(await store.read(), { OPENAI_API_KEY: "sk-throwaway-secret" });
		assert.deepEqual(await store.state(), { encrypted: true, writable: true });
	});

	it("legacy plaintext: readable without a keyring (writes refused), migrated with one", async () => {
		const dir = await tmp();
		const file = path.join(dir, "auth.json");
		await fs.writeFile(file, JSON.stringify({ A: "legacy" }), { mode: 0o600 });
		const locked = secretJsonFile(file, { codec: fakeCodec(false) });
		assert.deepEqual(await locked.read(), { A: "legacy" }, "a working setup is never lost");
		await fs.access(file);
		assert.deepEqual(await locked.state(), { encrypted: false, writable: false });
		await assert.rejects(locked.write({ A: "new" }), (err: { code?: string }) => err.code === "keyring");
		const open = secretJsonFile(file, { codec: fakeCodec(true) });
		assert.deepEqual(await open.read(), { A: "legacy" });
		await assert.rejects(fs.access(file), "plaintext deleted after the verified migration");
		assert.deepEqual(await open.read(), { A: "legacy" }, "served from the sealed file now");
	});

	it("refuses a group/world-readable or tampered sealed file", async () => {
		if (process.platform === "win32") return;
		const dir = await tmp();
		const file = path.join(dir, "auth.json");
		await fs.writeFile(path.join(dir, "auth.enc"), "LHSEALED1\ngarbage", { mode: 0o600 });
		await assert.rejects(secretJsonFile(file, { codec: fakeCodec() }).read(), (err: { code?: string }) => err.code === "storage");
		await fs.chmod(path.join(dir, "auth.enc"), 0o644);
		await assert.rejects(secretJsonFile(file, { codec: fakeCodec() }).read(), (err: { code?: string }) => err.code === "storage");
	});
});

describe("key vault + lh:keys IPC", () => {
	it("set / delete / snapshot over the child channel; values validated; no keyring = refusal text", async () => {
		const dir = await tmp();
		const vault = createKeyVault({ file: path.join(dir, "auth.json"), codec: fakeCodec() });
		await vault.load();
		const sent: Array<Record<string, unknown>> = [];
		const listeners: Array<(m: unknown) => void> = [];
		const child = {
			connected: true,
			send: (m: Record<string, unknown>) => sent.push(m),
			on: (_: string, l: (m: unknown) => void) => listeners.push(l),
			removeListener: () => {},
		};
		attachKeyChild(child, vault);
		const call = async (m: Record<string, unknown>) => {
			const before = sent.length;
			listeners[0]!({ channel: "lh:keys", ...m });
			for (let i = 0; i < 50 && sent.length === before; i++) await new Promise((r) => setTimeout(r, 5));
			return sent.at(-1)!;
		};
		const set = await call({ id: "1", op: "set", name: "OPENAI_API_KEY", value: "sk-throwaway" });
		assert.equal(set.ok, true);
		assert.deepEqual((set.value as { vars: object }).vars, { OPENAI_API_KEY: "sk-throwaway" });
		assert.equal((await call({ id: "2", op: "set", name: "bad name", value: "x" })).ok, false);
		const del = await call({ id: "3", op: "delete", name: "OPENAI_API_KEY" });
		assert.deepEqual((del.value as { vars: object }).vars, {});

		const locked = createKeyVault({ file: path.join(dir, "other.json"), codec: fakeCodec(false) });
		await locked.load();
		assert.equal((await locked.snapshot()).writable, false);
		await assert.rejects(locked.set("OPENAI_API_KEY", "sk-throwaway"), (err: { code?: string }) => err.code === "keyring");
	});
});
