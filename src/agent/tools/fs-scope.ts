import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

/**
 * The learner-filesystem SCOPE (security hardening, 2026-10-26): the
 * read-only fs tools (read / ls / find / grep / the pdf job) reach ONLY the
 * folders the learner granted in Settings → Agent → Readable folders.
 * Nothing is granted by default — an empty scope refuses every path.
 *
 * Containment is decided on REAL paths: the target is realpath'd (or, when
 * it does not exist yet, its nearest existing ancestor is), so a symlink
 * inside a granted folder cannot lead out of it. A DENYLIST applies even
 * inside granted folders: the app's own stores (injected by the
 * composition root), credential directories, browser profiles, keychains,
 * and secret-looking file names. Walks (find/grep) start from a real root
 * and never follow symlinks (fs-shared.ts walkFiles), so every visited path
 * is real by construction and the denylist check there is a string check.
 */

/** The scope seam the composition root injects (agent layer never reads
 *  settings itself). Both lists are read live per tool call, so a folder
 *  added in Settings applies to the very next call. */
export interface FsScope {
	/** Granted folders (absolute paths, as stored in settings). */
	roots(): readonly string[];
	/** App-owned paths that are always refused (data dir, key store dir). */
	denied(): readonly string[];
}

/** The secure default: nothing granted, every path refused. */
export const NO_FS_ACCESS: FsScope = { roots: () => [], denied: () => [] };

/** Home-relative locations that are never readable, granted or not:
 *  credentials, keychains, and browser profiles on macOS, Linux, Windows. */
const HOME_DENIED = [
	".ssh",
	".gnupg",
	".aws",
	".azure",
	".kube",
	".docker",
	".config/gcloud",
	".netrc",
	".npmrc",
	".pypirc",
	".git-credentials",
	".mozilla",
	".config/google-chrome",
	".config/chromium",
	".config/BraveSoftware",
	".config/microsoft-edge",
	"snap/firefox",
	".var/app/org.mozilla.firefox",
	"Library/Keychains",
	"Library/Cookies",
	"Library/Safari",
	"Library/Application Support/Google/Chrome",
	"Library/Application Support/Chromium",
	"Library/Application Support/BraveSoftware",
	"Library/Application Support/Microsoft Edge",
	"Library/Application Support/Firefox",
	"AppData/Local/Google/Chrome",
	"AppData/Local/BraveSoftware",
	"AppData/Local/Microsoft/Edge",
	"AppData/Roaming/Mozilla",
	"AppData/Local/Microsoft/Credentials",
	"AppData/Roaming/Microsoft/Credentials",
];

/** File names that look like secrets — refused wherever they live. */
const SECRET_BASENAMES: RegExp[] = [
	/^\.env(\..*)?$/i,
	/\.(pem|key|p12|pfx|kdbx|enc)$/i,
	/^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/i,
	/^auth\.json$/i,
	/-credentials\.json$/i,
];

const caseInsensitive = process.platform === "darwin" || process.platform === "win32";
const norm = (p: string) => (caseInsensitive ? p.toLowerCase() : p);

/** Is `child` the same path as `parent` or inside it? (Both absolute.) */
export function isWithin(child: string, parent: string): boolean {
	const c = norm(path.resolve(child));
	const p = norm(path.resolve(parent));
	if (c === p) return true;
	return c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
}

/** realpath, or — for a path that does not exist — the realpath of its
 *  nearest existing ancestor with the missing tail re-appended. */
async function realOrNearest(absolute: string): Promise<string> {
	let current = absolute;
	const tail: string[] = [];
	for (;;) {
		try {
			const real = await fs.realpath(current);
			return tail.length ? path.join(real, ...tail.reverse()) : real;
		} catch {
			const parent = path.dirname(current);
			if (parent === current) return absolute;
			tail.push(path.basename(current));
			current = parent;
		}
	}
}

/** The granted roots, realpath'd; roots that no longer exist drop out. */
export async function realRoots(scope: FsScope): Promise<string[]> {
	const out: string[] = [];
	for (const root of scope.roots()) {
		if (!path.isAbsolute(root)) continue;
		try {
			const real = await fs.realpath(root);
			if ((await fs.stat(real)).isDirectory() && !out.includes(real)) out.push(real);
		} catch {
			/* a removed folder simply stops granting */
		}
	}
	return out;
}

/** Every denied prefix, realpath'd where it exists (so a denied folder
 *  reached through a symlinked parent still matches). */
export async function deniedPrefixes(scope: FsScope): Promise<string[]> {
	const home = os.homedir();
	const raw = [...scope.denied(), ...HOME_DENIED.map((rel) => path.join(home, rel))];
	return Promise.all(raw.map((p) => realOrNearest(path.resolve(p))));
}

/** The denylist verdict for a REAL absolute path. */
export function isDeniedPath(real: string, denied: readonly string[]): boolean {
	if (denied.some((prefix) => isWithin(real, prefix))) return true;
	const base = path.basename(real);
	return SECRET_BASENAMES.some((re) => re.test(base));
}

/** The message every refusal carries — the agent relays it to the learner. */
function grantHint(roots: readonly string[]): string {
	return roots.length === 0
		? "No readable folders are granted. Ask the learner to add the folder in Settings → Agent → Readable folders."
		: `Readable folders: ${roots.join(", ")}. Ask the learner to add the folder in Settings → Agent → Readable folders if it is elsewhere.`;
}

/**
 * Resolve a tool path argument inside the scope, or throw an error the
 * model sees. `~/…` expands to home; a relative path resolves against the
 * granted folder only when exactly one is granted (otherwise it would be
 * ambiguous). Returns the REAL absolute path to operate on.
 */
export async function resolveScopedPath(scope: FsScope, rawPath: string): Promise<string> {
	const roots = await realRoots(scope);
	if (roots.length === 0) throw new Error(`Access denied: ${rawPath}. ${grantHint(roots)}`);
	let candidate = rawPath.trim();
	if (candidate === "~" || candidate.startsWith("~/")) candidate = path.join(os.homedir(), candidate.slice(1));
	if (!path.isAbsolute(candidate)) {
		if (roots.length !== 1) {
			throw new Error(`Relative path "${rawPath}" is ambiguous with several readable folders — use an absolute path. ${grantHint(roots)}`);
		}
		candidate = path.join(roots[0]!, candidate);
	}
	const real = await realOrNearest(path.resolve(candidate));
	if (!roots.some((root) => isWithin(real, root))) {
		throw new Error(`Access denied: ${rawPath} is outside the readable folders. ${grantHint(roots)}`);
	}
	if (isDeniedPath(real, await deniedPrefixes(scope))) {
		throw new Error(`Access denied: ${rawPath} is a protected location (credentials, app data, or browser profiles) and is never readable.`);
	}
	return real;
}

/** Validate one folder the learner wants to grant (the settings write
 *  path): absolute, an existing directory, not the filesystem root, not a
 *  protected location. Returns its real path, or an error message. */
export async function validateReadableFolder(
	folder: string,
	scope: Pick<FsScope, "denied">,
): Promise<{ ok: true; path: string } | { ok: false; error: string }> {
	if (typeof folder !== "string" || !path.isAbsolute(folder)) {
		return { ok: false, error: `readable folder must be an absolute path: ${String(folder)}` };
	}
	let real: string;
	try {
		real = await fs.realpath(folder);
		if (!(await fs.stat(real)).isDirectory()) return { ok: false, error: `not a directory: ${folder}` };
	} catch {
		return { ok: false, error: `folder not found: ${folder}` };
	}
	if (path.dirname(real) === real) return { ok: false, error: "the filesystem root cannot be granted" };
	const denied = await deniedPrefixes({ roots: () => [], denied: scope.denied });
	if (isDeniedPath(real, denied)) return { ok: false, error: `protected location cannot be granted: ${folder}` };
	return { ok: true, path: real };
}

/** The walk bases for find/grep: the one scoped path given, or — no path —
 *  every granted folder. `relative` says how to print results: relative to
 *  the single base (pi's format), absolute when several folders are walked. */
export async function searchBases(
	scope: FsScope,
	rawPath: string | undefined,
): Promise<{ bases: string[]; relative: boolean }> {
	if (rawPath) return { bases: [await resolveScopedPath(scope, rawPath)], relative: true };
	const roots = await realRoots(scope);
	if (roots.length === 0) throw new Error(grantHint(roots));
	return { bases: roots, relative: roots.length === 1 };
}
