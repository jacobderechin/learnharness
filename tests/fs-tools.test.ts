import assert from "node:assert";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, it } from "node:test";

import type { AgentTool } from "@earendil-works/pi-agent-core";
import { expandBraces, globToRegex, matchGlob, walkFiles } from "../src/agent/tools/fs-shared.ts";
import { findToolFor } from "../src/agent/tools/find.ts";
import { NO_FS_ACCESS, validateReadableFolder, type FsScope } from "../src/agent/tools/fs-scope.ts";
import { grepToolFor } from "../src/agent/tools/grep.ts";
import { lsToolFor } from "../src/agent/tools/ls.ts";
import { readToolFor } from "../src/agent/tools/read.ts";

/**
 * The learner-filesystem tools (sources v1, 2026-09-19): ls/find/grep as
 * pure-Node pi ports, read alongside. Since the security hardening
 * (2026-10-26) every tool is built over a scope; the pi-port suites grant
 * the whole tmpdir (every fixture lives there) and drive absolute paths.
 * The scope suite at the bottom pins containment and the denylist.
 *
 * Fixture tree (tmpdir):
 *   notes/calculus.md         "The derivative measures force…"
 *   notes/linear.txt          eigenvector content
 *   notes/sub/hidden.md
 *   code/main.ts
 *   node_modules/skipme.txt   (excluded from walks)
 *   Library/alsoskip.txt      (excluded from walks)
 *   binary.bin                NUL byte — grep skips
 */

let FIXTURE: string;

/** The pi-port suites' scope: every fixture is created under tmpdir. */
const TMP_SCOPE: FsScope = { roots: () => [os.tmpdir()], denied: () => [] };
const lsTool = lsToolFor(TMP_SCOPE);
const findTool = findToolFor(TMP_SCOPE);
const grepTool = grepToolFor(TMP_SCOPE);
const readTool = readToolFor(TMP_SCOPE);

/** Drive one tool's native execute and return the model-facing text
 *  (pi signature: execute(toolCallId, params, signal) → AgentToolResult). */
async function runText(tool: AgentTool<any>, params: unknown, signal?: AbortSignal): Promise<string> {
	const result = await tool.execute!("c", params, signal);
	const first = result.content[0];
	assert.ok(first !== undefined && first.type === "text", "first content part is text");
	return (first as { type: "text"; text: string }).text;
}

async function setup(): Promise<string> {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "lh-fs-"));
	await fs.mkdir(path.join(root, "notes", "sub"), { recursive: true });
	await fs.mkdir(path.join(root, "code"), { recursive: true });
	await fs.mkdir(path.join(root, "node_modules"), { recursive: true });
	await fs.mkdir(path.join(root, "Library"), { recursive: true });
	await fs.writeFile(path.join(root, "notes", "calculus.md"), "Calculus notes\nThe derivative measures force.\nChapter 1\n");
	await fs.writeFile(path.join(root, "notes", "linear.txt"), "Eigenvectors keep their direction\nonly scaling remains\n");
	await fs.writeFile(path.join(root, "notes", "sub", "hidden.md"), "deep file about MU\n");
	await fs.writeFile(path.join(root, "code", "main.ts"), "const x = 1;\nconst eigenvector = 'here';\n");
	await fs.writeFile(path.join(root, "node_modules", "skipme.txt"), "eigenvector in node_modules\n");
	await fs.writeFile(path.join(root, "Library", "alsoskip.txt"), "eigenvector in Library\n");
	await fs.writeFile(path.join(root, "binary.bin"), Buffer.from([0x00, 0x01, 0x02, 0x65, 0x69, 0x67, 0x03]));
	return root;
}

describe("glob helpers (fs-shared)", () => {
	it("basename mode: a pattern without a slash matches at any depth", () => {
		assert.equal(matchGlob("notes/sub/calculus.md", "*.md"), true);
		assert.equal(matchGlob("calculus.md", "*.md"), true);
		assert.equal(matchGlob("notes/calculus.md", "*.ts"), false);
	});

	it("star does not cross slashes; double-star does", () => {
		assert.equal(matchGlob("a/b/c.txt", "*.txt"), true); // basename mode
		assert.equal(matchGlob("src/x/a.spec.ts", "src/**/*.spec.ts"), true);
		assert.equal(matchGlob("other/x/a.spec.ts", "src/**/*.spec.ts"), false);
		assert.equal(matchGlob("src/a.spec.ts", "src/**/*.spec.ts"), true, "** covers zero dirs");
	});

	it("slash patterns get an implied deep prefix unless anchored", () => {
		assert.equal(matchGlob("deep/nested/x/main.ts", "**/nested/**/main.ts"), true);
		assert.equal(matchGlob("x/main.ts", "nested/main.ts"), false, "no implied prefix for anchored-looking patterns");
	});

	it("brace alternatives expand", () => {
		assert.deepEqual(expandBraces("*.{ts,tsx}"), ["*.ts", "*.tsx"]);
		assert.equal(matchGlob("code/main.ts", "*.{ts,tsx,js}"), true);
		assert.equal(matchGlob("code/main.ts", "*.{js,jsx}"), false);
	});

	it("question mark is one char, literals are escaped", () => {
		assert.equal(globToRegex("a?c").test("abc"), true);
		assert.equal(globToRegex("a?c").test("ac"), false);
		assert.equal(matchGlob("a.b.txt", "a.b*"), true, "the dot is literal, not any-char");
	});
});

describe("ls (pi port)", () => {
	it("lists sorted, dirs suffixed, dotfiles included", async () => {
		FIXTURE = await setup();
		const out = await runText(lsTool, { path: FIXTURE });
		assert.ok(out.includes("code/"));
		assert.ok(out.includes("notes/"));
		assert.ok(out.includes("binary.bin"));
		// sorted alphabetically, case-insensitive
		const lines = out.split("\n").filter((l) => !l.startsWith("["));
		const sorted = [...lines].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
		assert.deepEqual(lines, sorted);
	});

	it("honors the entry limit with pi's truncation notice", async () => {
		const out = await runText(lsTool, { path: FIXTURE, limit: 2 });
		assert.match(out, /\[Truncated: 2 entries limit\]/);
	});

	it("missing path and non-directory throw (the model sees the error)", async () => {
		await assert.rejects(async () => lsTool.execute!("c", { path: path.join(FIXTURE, "nonexistent") }), /Path not found/);
		await assert.rejects(
			async () => lsTool.execute!("c", { path: path.join(FIXTURE, "binary.bin") }),
			/Not a directory/,
		);
	});
});

describe("find (pi port)", () => {
	it("finds by glob, relativized to the search root", async () => {
		const out = await runText(findTool, { pattern: "*.md", path: FIXTURE });
		assert.ok(out.includes("notes/calculus.md"));
		assert.ok(out.includes("notes/sub/hidden.md"));
		assert.ok(!out.includes(FIXTURE), "paths are relative, not absolute");
	});

	it("never enters node_modules or Library", async () => {
		const out = await runText(findTool, { pattern: "*.txt", path: FIXTURE });
		assert.ok(!out.includes("node_modules"));
		assert.ok(!out.includes("Library"));
		assert.ok(out.includes("notes/linear.txt"));
	});

	it("result limit carries pi's notice", async () => {
		const out = await runText(findTool, { pattern: "*", path: FIXTURE, limit: 2 });
		assert.match(out, /\[2 results limit reached\]/);
	});

	it("no-match message matches pi", async () => {
		const out = await runText(findTool, { pattern: "*.nomatch", path: FIXTURE });
		assert.equal(out, "No files found matching pattern");
	});

	it("slash patterns match paths, not basenames", async () => {
		const out = await runText(findTool, { pattern: "notes/**/*.md", path: FIXTURE });
		assert.ok(out.includes("notes/sub/hidden.md"));
		assert.ok(!out.includes("code/"));
	});
});

describe("grep (pi port)", () => {
	it("formats matches pi-style: rel:line: text", async () => {
		// case-sensitive: the lowercase "eigenvector" hits main.ts but NOT
		// linear.txt's capital-E "Eigenvectors" (that case lives below).
		const out = await runText(grepTool, { pattern: "eigenvector", path: FIXTURE });
		assert.equal(out, "code/main.ts:2: const eigenvector = 'here';");
		assert.ok(!out.includes("node_modules"), "excluded dirs are not searched");
		assert.ok(!out.includes("Library"));
		assert.ok(!out.includes("binary.bin"), "binary files are skipped");
	});

	it("ignoreCase and literal flags", async () => {
		const icase = await runText(grepTool, { pattern: "EIGENVECTOR", path: FIXTURE, ignoreCase: true });
		assert.match(icase, /linear\.txt:1:/);
		const literal = await runText(grepTool, { pattern: "e.gen", literal: true, path: path.join(FIXTURE, "code") });
		assert.equal(literal, "No matches found", "dots are literal when literal=true");
	});

	it("context lines use the dash format", async () => {
		const out = await runText(grepTool, { pattern: "scaling", path: FIXTURE, context: 1 });
		assert.match(out, /notes\/linear\.txt:2: only scaling remains/, "the match line uses colons");
		assert.match(out, /notes\/linear\.txt-1- Eigenvectors keep their direction/, "context before uses dashes");
		assert.match(out, /notes\/linear\.txt-3- $/, "context after (empty line) uses dashes");
	});

	it("glob filter restricts files", async () => {
		const out = await runText(grepTool, { pattern: "eigenvector", path: FIXTURE, glob: "*.ts" });
		assert.match(out, /main\.ts:2:/);
		assert.ok(!out.includes("linear.txt"));
	});

	it("single-file search prints basename; match limit notices pi-style", async () => {
		const file = path.join(FIXTURE, "notes", "calculus.md");
		const out = await runText(grepTool, { pattern: "e", path: file });
		assert.match(out, /^calculus\.md:1: /, "basename for a single-file search");
		const limited = await runText(grepTool, { pattern: "e", path: file, limit: 1 });
		assert.match(limited, /\[1 matches limit reached\]/);
	});

	it("no-match message matches pi", async () => {
		const out = await runText(grepTool, { pattern: "zzzz", path: FIXTURE });
		assert.equal(out, "No matches found");
	});
});

describe("read (pi port)", () => {
	it("reads a fixture file verbatim through the shared slice machinery", async () => {
		const out = await runText(readTool, { path: path.join(FIXTURE, "notes", "linear.txt") });
		assert.match(out, /Eigenvectors keep their direction/);
	});
});

describe("abort plumbing (the 2026-09-19 cascade fix)", () => {
	it("walkFiles stops promptly when the signal aborts mid-walk", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "lh-fs-abort-"));
		for (let i = 0; i < 20; i++) await fs.writeFile(path.join(root, `f${i}.txt`), "needle\n");
		const ac = new AbortController();
		let visited = 0;
		const result = await walkFiles(
			root,
			() => {
				visited++;
				if (visited === 3) ac.abort(); // deterministic: abort from inside the walk
				return false;
			},
			ac.signal,
		);
		assert.equal(result.aborted, true);
		assert.equal(result.timedOut, false);
		assert.ok(visited < 20, "the walk stopped early");
	});

	it("find honors a pre-aborted signal without walking", async () => {
		FIXTURE = await setup();
		const ac = new AbortController();
		ac.abort();
		const out = await runText(findTool, { pattern: "*.md" }, ac.signal);
		assert.equal(out, "Operation aborted");
	});

	it("grep honors a pre-aborted signal without scanning", async () => {
		const ac = new AbortController();
		ac.abort();
		const out = await runText(grepTool, { pattern: "eigenvector" }, ac.signal);
		assert.equal(out, "Operation aborted");
	});

	it("grep aborts mid-run with partial results, not a hang", async () => {
		// The exact shape of the 2.7-minute lesson: a tree big enough that
		// the walk+scan outlast an abort mid-flight. Whichever phase the
		// abort lands in, the tool returns promptly with an abort notice —
		// never "No matches found", never a hang.
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "lh-fs-midabort-"));
		await fs.mkdir(path.join(root, "deep"), { recursive: true });
		for (let i = 0; i < 200; i++) {
			await fs.writeFile(path.join(root, i % 2 ? `f${i}.txt` : `deep/f${i}.txt`), "needle line\n");
		}
		const ac = new AbortController();
		setTimeout(() => ac.abort(), 1);
		const started = Date.now();
		const out = await runText(grepTool, { pattern: "needle", path: root }, ac.signal);
		assert.match(out, /aborted/);
		assert.ok(Date.now() - started < 5_000, "returned promptly");
	});
});

describe("scope (security hardening 2026-10-26)", () => {
	async function tree(): Promise<{ root: string; outside: string }> {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "lh-scope-"));
		const outside = await fs.mkdtemp(path.join(os.tmpdir(), "lh-outside-"));
		await fs.mkdir(path.join(root, "notes"), { recursive: true });
		await fs.mkdir(path.join(root, "appdata"), { recursive: true });
		await fs.writeFile(path.join(root, "notes", "a.md"), "needle in notes\n");
		await fs.writeFile(path.join(root, ".env"), "needle=SECRET\n");
		await fs.writeFile(path.join(root, "id_ed25519"), "needle private key\n");
		await fs.writeFile(path.join(root, "appdata", "auth-ish.txt"), "needle app data\n");
		await fs.writeFile(path.join(outside, "secret.txt"), "outside needle\n");
		await fs.symlink(outside, path.join(root, "escape"));
		return { root, outside };
	}
	const scopeOf = (roots: string[], denied: string[] = []): FsScope => ({ roots: () => roots, denied: () => denied });

	it("no grants = every path refused, with the Settings hint", async () => {
		const { root } = await tree();
		await assert.rejects(
			() => readToolFor(NO_FS_ACCESS).execute!("c", { path: path.join(root, "notes", "a.md") }),
			/No readable folders are granted.*Settings → Agent → Readable folders/,
		);
		assert.match(await runText(lsToolFor(NO_FS_ACCESS), {}), /No readable folders are granted/);
	});

	it("paths outside the granted folders are refused (absolute, .., and symlink escapes)", async () => {
		const { root, outside } = await tree();
		const read = readToolFor(scopeOf([root]));
		await assert.rejects(() => read.execute!("c", { path: path.join(outside, "secret.txt") }), /outside the readable folders/);
		await assert.rejects(() => read.execute!("c", { path: path.join(root, "..", path.basename(outside), "secret.txt") }), /outside the readable folders/);
		await assert.rejects(() => read.execute!("c", { path: path.join(root, "escape", "secret.txt") }), /outside the readable folders/);
		assert.match(await runText(read, { path: path.join(root, "notes", "a.md") }), /needle in notes/);
	});

	it("the denylist applies inside granted folders: secret names and app-denied paths", async () => {
		const { root } = await tree();
		const read = readToolFor(scopeOf([root], [path.join(root, "appdata")]));
		await assert.rejects(() => read.execute!("c", { path: path.join(root, ".env") }), /protected location/);
		await assert.rejects(() => read.execute!("c", { path: path.join(root, "id_ed25519") }), /protected location/);
		await assert.rejects(() => read.execute!("c", { path: path.join(root, "appdata", "auth-ish.txt") }), /protected location/);
	});

	it("walks prune denied files and never follow symlinks out", async () => {
		const { root } = await tree();
		const scope = scopeOf([root], [path.join(root, "appdata")]);
		const grep = await runText(grepToolFor(scope), { pattern: "needle" });
		assert.equal(grep, "notes/a.md:1: needle in notes");
		const find = await runText(findToolFor(scope), { pattern: "*" });
		assert.ok(!find.includes(".env") && !find.includes("id_ed25519") && !find.includes("appdata") && !find.includes("secret"));
		const ls = await runText(lsToolFor(scope), { path: root });
		assert.ok(!ls.includes(".env") && !ls.includes("appdata/"), ls);
	});

	it("relative paths resolve against the single granted folder; ambiguous with several", async () => {
		const { root, outside } = await tree();
		assert.match(await runText(readToolFor(scopeOf([root])), { path: "notes/a.md" }), /needle in notes/);
		await assert.rejects(() => readToolFor(scopeOf([root, outside])).execute!("c", { path: "notes/a.md" }), /ambiguous/);
	});

	it("no path: ls lists the folders; find walks every folder with absolute output", async () => {
		const { root, outside } = await tree();
		const scope = scopeOf([root, outside]);
		const ls = await runText(lsToolFor(scope), {});
		assert.ok(ls.includes(`${await fs.realpath(root)}/`) && ls.includes(`${await fs.realpath(outside)}/`));
		const find = await runText(findToolFor(scope), { pattern: "*.txt" });
		assert.ok(find.includes(path.join(await fs.realpath(outside), "secret.txt")), find);
	});

	it("validateReadableFolder: absolute existing directories only, never root or protected", async () => {
		const { root } = await tree();
		const denied = { denied: () => [path.join(root, "appdata")] };
		assert.deepEqual(await validateReadableFolder(root, denied), { ok: true, path: await fs.realpath(root) });
		assert.equal((await validateReadableFolder("notes", denied)).ok, false);
		assert.equal((await validateReadableFolder(path.join(root, "missing"), denied)).ok, false);
		assert.equal((await validateReadableFolder(path.join(root, "notes", "a.md"), denied)).ok, false);
		assert.equal((await validateReadableFolder("/", denied)).ok, false);
		assert.equal((await validateReadableFolder(path.join(root, "appdata"), denied)).ok, false);
		assert.equal((await validateReadableFolder(path.join(os.homedir(), ".ssh"), denied)).ok, false);
	});
});
