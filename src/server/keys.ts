/**
 * The auth/keys composition (auth-keys wave, 2026-09-19): the server-side
 * key manager behind GET/PUT/DELETE /api/keys.
 *
 * KEYS NEVER ENTER THE ENVIRONMENT (security hardening, 2026-10-26): the
 * store (src/store/auth.ts — the keyring-sealed desktop vault, or the
 * owner-only dev file) is read at call time through keyValue(), and the
 * model engines receive keys through pi-ai's AuthContext seam
 * (providerEnvValue → agent/models.ts providerEnvSource), not process.env.
 * Saving a key still takes effect on the next request with no restart.
 *
 * PRECEDENCE (owner decision): real environment variables (incl.
 * .env.local in dev) always win over the store. Boot-time real-env vars
 * are snapshotted once per process; a PUT to one of them persists to the
 * store (for when the env goes away) and the status honestly reports
 * shadowedByEnv — the page explains why the saved key is not the live one.
 *
 * Unknown vars in the store are preserved verbatim and surfaced as
 * generic status rows (no catalog form to edit through — only curated
 * keys have shapes and docs; core/auth-keys.ts).
 *
 * THE FRESH-USER SWITCH (owner, interlude 2026-09-22): LH_IGNORE_ENV_KEYS=1
 * makes every env key invisible APP-WIDE — the exact new-user simulation
 * (a fresh empty data dir + the switch = zero keys, zero federated
 * providers, setup stage 1). Under the switch real env vars are DELETED
 * from the process at boot (not merely ignored by this seam), so no
 * consumer can see them; only the store counts. Unset switch = env wins.
 */

import {
	AUTH_KEYS,
	AUTH_PROVIDER_KEYS,
	AUTH_PROVIDER_ENV_VARS,
	type AuthKeyInfo,
	type AuthKeyStatus,
	genericProviderKeyGuard,
	isKnownAuthKey,
	isProviderEnvVar,
	maskKey,
	validateKeyShape,
} from "../core/auth-keys.ts";
import { authStore } from "../store/auth.ts";
import type { AuthStorageState } from "../core/ports.ts";
import { isSubscriptionProvider, subscriptionConnected } from "../agent/subscription-connections.ts";
import { providerEnvSource } from "../agent/models.ts";

// The once-per-process boot record — globalThis anchor (HMR re-imports the
// module; the snapshot must run once). Same pattern as
// globalThis.__lhExtractionRuns.
interface AuthBoot {
	/** Vars that were in the REAL env at first init — env precedence's set. */
	realEnv: Set<string>;
	initialized: boolean;
}
const BOOT_KEY = Symbol.for("lh.authBoot");

function boot(): AuthBoot {
	const g = globalThis as Record<symbol, AuthBoot | undefined>;
	if (!g[BOOT_KEY]) g[BOOT_KEY] = { realEnv: new Set(), initialized: false };
	return g[BOOT_KEY];
}

/** Is `id` a WRITABLE key name — curated catalog or model-provider env
 *  var (provider-keys interlude: PUT/DELETE accept both). */
export function isWritableAuthKey(id: string): boolean {
	return isKnownAuthKey(id) || isProviderEnvVar(id);
}

/** The settings page's provider dropdown: every pi-ai provider that takes
 *  a plain key ({id, envVar, label} — no-drift-pinned, see the table's doc
 *  in core/auth-keys.ts and tests/auth-provider-keys.test.ts). Sorted by
 *  id for a stable payload. */
export function providerKeyList() {
	return [...AUTH_PROVIDER_KEYS].sort((a, b) => a.id.localeCompare(b.id));
}

/** The fresh-user switch (owner, interlude 2026-09-22): env keys are
 *  invisible app-wide — deleted from the process at boot, file keys only.
 *  Read live per call (the launcher exports it before boot). */
export function envKeysIgnored(): boolean {
	return process.env.LH_IGNORE_ENV_KEYS === "1";
}

/**
 * The boot snapshot — idempotent. First call records which managed names
 * are real env (env precedence); under the fresh-user switch every managed
 * env var is deleted instead (re-run on every call — a reintroduced var
 * never resurrects) and nothing counts as env.
 */
export function initAuthEnv(): void {
	const record = boot();
	const managed = new Set<string>([
		...Object.keys(authStore.authVars()),
		...AUTH_KEYS.map((k) => k.id),
		// Provider env vars are managed names too (provider-keys interlude):
		// an env-exported OPENAI_API_KEY with a stored copy gets honest
		// shadow semantics, exactly like the curated vars.
		...AUTH_PROVIDER_KEYS.map((p) => p.envVar),
	]);
	if (envKeysIgnored()) {
		for (const name of managed) delete process.env[name];
		record.realEnv.clear();
	} else if (!record.initialized) {
		for (const name of managed) {
			if (process.env[name] !== undefined) record.realEnv.add(name);
		}
	}
	record.initialized = true;
}

/** Is this env-var name one the keys system manages (curated, provider,
 *  or held in the file)? */
function isManagedName(name: string): boolean {
	return isWritableAuthKey(name) || name in authStore.authVars();
}

/**
 * The pure status projection — exported for tests. `env` is the live
 * process env view; `realEnv` the boot snapshot (env precedence).
 */
export function resolveKeyStatuses(
	fileVars: Record<string, string>,
	env: Record<string, string | undefined>,
	realEnv: ReadonlySet<string>,
	/** The model-provider env vars (provider-keys interlude): PRESENT ones
	 *  join the status rows — absent ones never spam (the dropdown is the
	 *  discovery surface). Curated keys always get rows, present or not. */
	providerEnvVars: ReadonlySet<string> = new Set(),
): AuthKeyStatus[] {
	const ids = new Set<string>([...AUTH_KEYS.map((k) => k.id), ...Object.keys(fileVars)]);
	for (const envVar of providerEnvVars) {
		if (env[envVar] !== undefined || fileVars[envVar] !== undefined) ids.add(envVar);
	}
	const rows: AuthKeyStatus[] = [];
	for (const id of ids) {
		const envValue = env[id];
		const fileValue = fileVars[id];
		const isRealEnv = realEnv.has(id);
		// Env wins: the live value is the env's when set, else the store's.
		const live = envValue !== undefined ? envValue : fileValue;
		rows.push({
			id,
			info: AUTH_KEYS.find((k) => k.id === id) ?? null,
			present: live !== undefined,
			masked: live !== undefined ? `${maskKey(live)} (${live.trim().length} chars)` : null,
			source: isRealEnv ? "env" : live !== undefined ? "file" : "none",
			shadowedByEnv: isRealEnv && fileValue !== undefined && envValue !== fileValue,
		});
	}
	return rows;
}

/** The GET view: every curated key (present or not) + unknown file vars. */
export function keyStatuses(): AuthKeyStatus[] {
	return resolveKeyStatuses(authStore.authVars(), process.env, boot().realEnv, AUTH_PROVIDER_ENV_VARS);
}

/** The live value for one var, env-first (the env-wins rule) — the canonical
 *  read for consumers that don't live behind the @/src/server barrel (the
 *  STT route was the one cold-boot hole: a first-ever request to it would
 *  otherwise read env before any fill-gap ran). */
export function keyValue(id: string): string | undefined {
	// The fresh-user switch: ONLY the file store counts (belt-and-
	// suspenders — the boot deletion already emptied the env; this guards
	// any env key reintroduced after boot).
	if (envKeysIgnored()) return authStore.authVars()[id];
	return process.env[id] ?? authStore.authVars()[id];
}

/** The key-presence truth for one model provider (provider-key interlude,
 * 2026-09-25): would this provider's key be present at request time?
 * Reads through keyValue — the SAME env-first lookup pi-ai performs
 * natively at every request — so an env-shadowed key counts as present
 * (gate by what would run). Providers absent from AUTH_PROVIDER_KEYS take
 * no key at all: nothing to gate, present by definition. */
export function providerKeyPresent(provider: string): boolean {
	if (isSubscriptionProvider(provider)) return subscriptionConnected(provider);
	const info = AUTH_PROVIDER_KEYS.find((p) => p.id === provider);
	return info ? keyValue(info.envVar) !== undefined : true;
}

/** The pi-ai AuthContext lookup (agent/models.ts providerEnvSource):
 *  managed key names resolve through keyValue (env-first, then the store —
 *  never a process.env copy of a stored key); every other name (regional
 *  config, endpoints) is plain process.env, as pi-ai would read it. */
export function providerEnvValue(name: string): string | undefined {
	const value = isManagedName(name) ? keyValue(name) : process.env[name];
	return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

/** The key store's at-rest posture for the keys page (encrypted with the
 *  OS keyring on desktop; writable = a real keyring exists). */
export function keyStorage(): AuthStorageState {
	return authStore.storage();
}

/**
 * Save one key (PUT). Shape gate first (owner decision: bad pastes are
 * 400s, never stored), then the store write. A var the REAL env owns is
 * stored but shadowed — the status row reports shadowedByEnv so the page
 * can explain it. A store refusal (no OS keyring) is a 503 with its text.
 */
export async function saveKey(
	id: string,
	value: string,
): Promise<{ ok: true; status: AuthKeyStatus } | { ok: false; error: string; status: 400 | 503 }> {
	const shape = isProviderEnvVar(id) ? genericProviderKeyGuard(id, value) : validateKeyShape(id, value);
	if (!shape.ok) return { ok: false, error: shape.error, status: 400 };
	try {
		await authStore.setAuthVar(id, value.trim());
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err), status: 503 };
	}
	// validateKeyShape guarantees catalog membership, so the row exists.
	return { ok: true, status: keyStatuses().find((s) => s.id === id)! };
}

/**
 * Remove one key (DELETE): gone from the store; a real env var stays (env
 * wins) and the status shows the key still present from env.
 */
export async function deleteKey(
	id: string,
): Promise<{ ok: true; status: AuthKeyStatus } | { ok: false; error: string; status: 503 }> {
	try {
		await authStore.deleteAuthVar(id);
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err), status: 503 };
	}
	return { ok: true, status: keyStatuses().find((s) => s.id === id)! };
}

// Snapshot the env at first import (idempotent; the module is imported by
// every route/handler path that touches keys), and hand pi-ai's auth
// lookup to the store-backed resolver.
initAuthEnv();
providerEnvSource.current = providerEnvValue;
