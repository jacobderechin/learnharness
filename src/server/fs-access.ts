import path from "node:path";
import { AUTH_FILE, PATHS } from "../../config.ts";
import { validateReadableFolder, type FsScope } from "../agent/tools/fs-scope.ts";
import { effectiveSettings } from "./stores.ts";

/**
 * The learner-filesystem scope the composition root injects into every fs
 * tool and the pdf job (security hardening, 2026-10-26): the granted
 * folders come from settings (agent.readableFolders, read live per call),
 * and the app's own stores — the data dir and the key-store directory
 * (Electron userData on desktop; the repo root in dev) — are always denied.
 */
export const learnerFsScope: FsScope = {
	roots: () => effectiveSettings().agent.readableFolders,
	denied: () => [PATHS.data, path.dirname(AUTH_FILE)],
};

/** Settings-write validation for agent.readableFolders: every folder must
 *  exist, be a directory, and not be protected; stored as its real path. */
export async function validateReadableFolders(
	folders: readonly string[],
): Promise<{ ok: true; folders: string[] } | { ok: false; error: string }> {
	const out: string[] = [];
	for (const folder of folders) {
		const verdict = await validateReadableFolder(folder, learnerFsScope);
		if (!verdict.ok) return verdict;
		if (!out.includes(verdict.path)) out.push(verdict.path);
	}
	return { ok: true, folders: out };
}
