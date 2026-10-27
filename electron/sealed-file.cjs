"use strict";
const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

/**
 * Sealed secret files (security hardening, 2026-10-26): every credential
 * the desktop app persists — BYOK keys and the subscription OAuth tokens —
 * is encrypted with the OS keyring through Electron safeStorage (Keychain /
 * DPAPI / libsecret / KWallet) and written owner-only, atomically.
 *
 * NO REAL KEYRING = NO STORAGE (owner ruling): on Linux, safeStorage falls
 * back to a hardcoded key ("basic_text") when no secret service runs —
 * that is obfuscation, not encryption, so writes are refused with the
 * "keyring" code. A legacy plaintext file stays READABLE in that state (no
 * one loses a working setup), and is migrated — sealed, verified, then
 * deleted — the first time a real keyring is available.
 *
 * The codec is injected (main passes keyringCodec(safeStorage)); a store
 * without a codec is the plaintext owner-only file, the web/dev shape.
 */

const MAGIC = Buffer.from("LHSEALED1\n");
const failure = (code) => Object.assign(new Error(code), { code });

/** The keyring codec over Electron safeStorage (async API — the sync
 *  family is deprecated in Electron 45). */
function keyringCodec(safeStorage, platform = process.platform) {
	return {
		async available() {
			if (platform === "linux") {
				const backend = safeStorage.getSelectedStorageBackend();
				if (backend === "basic_text" || backend === "unknown") return false;
			}
			return safeStorage.isAsyncEncryptionAvailable();
		},
		encrypt: (text) => safeStorage.encryptStringAsync(text),
		async decrypt(buffer) {
			return (await safeStorage.decryptStringAsync(buffer)).result;
		},
	};
}

/** Read an owner-only regular file; null when absent. Refuses symlinks,
 *  group/world-accessible modes, and other owners (POSIX). */
async function readOwnerOnly(file, io = fs) {
	let stat;
	try {
		stat = await io.lstat(file);
	} catch (error) {
		if (error.code === "ENOENT") return null;
		throw failure("storage");
	}
	if (!stat.isFile()) throw failure("storage");
	if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stat.uid !== process.getuid()))) {
		throw failure("storage");
	}
	return io.readFile(file);
}

/** Atomic owner-only write: 0700 dir, random `wx` temp at 0600, fsync,
 *  rename, directory fsync (POSIX). */
async function writeOwnerOnly(file, data, io = fs) {
	const temporary = `${file}.${randomUUID()}.tmp`;
	let handle;
	try {
		await io.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
		handle = await io.open(temporary, "wx", 0o600);
		await handle.writeFile(data);
		await handle.sync();
		await handle.close();
		handle = null;
		await io.rename(temporary, file);
		if (process.platform !== "win32") {
			const directory = await io.open(path.dirname(file), "r");
			try { await directory.sync(); } finally { await directory.close(); }
		}
	} catch {
		throw failure("storage");
	} finally {
		await handle?.close().catch(() => {});
		await io.unlink(temporary).catch(() => {});
	}
}

/** The sealed path for a legacy plaintext file: `x-credentials.json` →
 *  `x-credentials.enc`, `auth.json` → `auth.enc`. */
function sealedPath(file) {
	return file.replace(/\.json$/i, "") + ".enc";
}

/**
 * One JSON value in a secret file. With a codec: the sealed file is the
 * truth; a legacy plaintext file is read when no sealed file exists and
 * migrated when the keyring is available. Without a codec: the plaintext
 * owner-only file (web/dev). `read()` → value | null (absent).
 */
function secretJsonFile(file, { codec = null, io = fs } = {}) {
	const sealed = codec ? sealedPath(file) : null;

	async function writeSealed(value) {
		if (!(await codec.available())) throw failure("keyring");
		const cipher = await codec.encrypt(JSON.stringify(value));
		await writeOwnerOnly(sealed, Buffer.concat([MAGIC, cipher]), io);
	}

	async function readSealed() {
		const raw = await readOwnerOnly(sealed, io);
		if (raw === null) return undefined;
		if (raw.length < MAGIC.length || !raw.subarray(0, MAGIC.length).equals(MAGIC)) throw failure("storage");
		try {
			return JSON.parse(await codec.decrypt(raw.subarray(MAGIC.length)));
		} catch {
			throw failure("storage");
		}
	}

	async function readPlain() {
		const raw = await readOwnerOnly(file, io);
		if (raw === null) return null;
		try {
			return JSON.parse(raw.toString("utf8"));
		} catch {
			throw failure("storage");
		}
	}

	return {
		/** Where the secret lives now — status surfaces only. */
		async state() {
			if (!codec) return { encrypted: false, writable: true };
			const writable = await codec.available();
			const legacy = (await io.lstat(file).catch(() => null)) !== null;
			return { encrypted: !legacy, writable };
		},
		async read() {
			if (!codec) return readPlain();
			const value = await readSealed();
			if (value !== undefined) return value;
			const legacy = await readPlain();
			if (legacy === null) return null;
			// Migrate: seal, verify by reading back, then remove the plaintext.
			if (await codec.available()) {
				await writeSealed(legacy);
				const check = await readSealed();
				if (JSON.stringify(check) !== JSON.stringify(legacy)) throw failure("storage");
				await io.unlink(file).catch(() => {});
			}
			return legacy;
		},
		async write(value) {
			if (!codec) return writeOwnerOnly(file, `${JSON.stringify(value)}\n`, io);
			await writeSealed(value);
			await io.unlink(file).catch(() => {});
		},
	};
}

/** The user-facing text for the refusal (shared by every store). */
const KEYRING_MESSAGE =
	"No OS keyring is available to encrypt credentials. Install or unlock GNOME Keyring or KWallet (or use environment variables), then try again.";

module.exports = { MAGIC, KEYRING_MESSAGE, keyringCodec, secretJsonFile, sealedPath, readOwnerOnly, writeOwnerOnly };
