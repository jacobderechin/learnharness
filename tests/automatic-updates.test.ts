/** Notify-only update checks (security hardening, 2026-10-26): actual shell
 * functions with fake Electron, a fake GitHub release check, and a fake
 * filesystem. No app, profile, network, or timer runs — and there is no
 * download/install path left to run. */
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, runInContext } from "node:vm";
import { describe, it } from "node:test";

const mainFile = fileURLToPath(new URL("../electron/main.cjs", import.meta.url));
const mainSource = readFileSync(mainFile, "utf8");
const mainRequire = createRequire(mainFile);
const releaseCheck = mainRequire("./release-check.cjs");
const RELEASE_URL = "https://github.com/jacobderechin/learnharness/releases/tag/v9.9.9";
/** Let the check's promise chain (then/finally) run to completion. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

function fixture({ packaged = true } = {}) {
	let settings: string | Error = JSON.stringify({ version: 1, general: { autoUpdate: true } });
	const settingsReads: string[] = [];
	const order: string[] = [];
	const intervals: { callback: () => void; delay: number }[] = [];
	const handles = new Map<string, (event: unknown) => unknown>();
	const windows: FakeWindow[] = [];
	let enumerationFails = false;
	let userData = "/fixture/custom-user-data";
	let menu: { submenu?: { label?: string; click?: () => void }[] }[] = [];
	const release = {
		checks: 0,
		result: { status: "up-to-date" } as Record<string, unknown>,
		failure: null as Error | null,
		pending: null as Promise<unknown> | null,
	};
	const opened: string[] = [];
	class FakeWebContents extends EventEmitter {
		mainFrame = { url: "http://127.0.0.1:9000/" };
		messages: { channel: string; value: unknown }[] = [];
		loading = false;
		fails = false;
		send(channel: string, value: unknown) {
			if (this.fails) throw new Error("window destroyed");
			this.messages.push({ channel, value: JSON.parse(JSON.stringify(value)) });
		}
		isLoadingMainFrame() { return this.loading; }
		setWindowOpenHandler() {}
		getZoomFactor() { return 1; }
	}
	class FakeWindow extends EventEmitter {
		webContents = new FakeWebContents();
		minimized = false;
		focused = false;
		constructor() { super(); windows.push(this); }
		loadURL() { this.webContents.loading = true; }
		isMinimized() { return this.minimized; }
		restore() { this.minimized = false; }
		focus() { this.focused = true; }
		show() {}
		static getAllWindows() {
			if (enumerationFails) throw new Error("window enumeration failed");
			return windows;
		}
		static fromWebContents(contents: FakeWebContents) { return windows.find(win => win.webContents === contents); }
	}
	const app = Object.assign(new EventEmitter(), {
		isPackaged: packaged,
		name: "LearnHarness",
		setName() {},
		getPath: () => userData,
		getVersion: () => "0.3.8",
		setPath: (_: string, value: string) => { userData = value; },
		requestSingleInstanceLock: () => false,
		quit() {},
		whenReady: async () => {},
	});
	const electron = {
		app, BrowserWindow: FakeWindow,
		Menu: { buildFromTemplate: (value: typeof menu) => value, setApplicationMenu: (value: typeof menu) => { menu = value; } },
		ipcMain: { on() {}, handle: (channel: string, fn: (event: unknown) => unknown) => handles.set(channel, fn) },
		session: { defaultSession: { setPermissionRequestHandler() {}, setPermissionCheckHandler() {} } },
		shell: { openExternal: async (target: string) => { opened.push(target); } },
	};
	const context = createContext({
		require: (id: string) => {
			if (id === "electron") return electron;
			if (id === "./release-check.cjs") return {
				...releaseCheck,
				checkLatestRelease: async () => {
					release.checks++;
					if (release.failure) throw release.failure;
					return release.result;
				},
			};
			if (id === "node:fs") return {
				readFileSync: (file: string) => {
					settingsReads.push(file);
					if (settings instanceof Error) throw settings;
					return settings;
				}, mkdirSync() {}, appendFileSync() {},
			};
			return mainRequire(id);
		},
		process: { argv: [], env: { LH_DEV_URL: "http://127.0.0.1:9000" }, platform: "darwin", on() {} },
		__dirname: path.dirname(mainFile), URL,
		setInterval: (callback: () => void, delay: number) => intervals.push({ callback, delay }),
		setTimeout() {},
		fixtureChild: { kill: (signal: string) => order.push(signal) },
	});
	runInContext(mainSource, context, { filename: mainFile });
	const run = (code: string) => runInContext(code, context);
	return {
		run, release, opened, windows, intervals, handles, settingsReads, order, app,
		setSettings: (value: unknown) => { settings = JSON.stringify(value); },
		setSettingsFailure: (value: string | Error) => { settings = value; },
		setEnumerationFailure: (value: boolean) => { enumerationFails = value; },
		window: () => new FakeWindow(),
		state: () => JSON.parse(JSON.stringify(run("updateState"))),
		check: async (manual = false) => { run(`checkForUpdates({ manual: ${manual} })`); await settle(); },
		menuCheck: () => menu[0]!.submenu!.find(item => item.label === "Check for Updates…")!.click!(),
	};
}

describe("automatic-check preference gate", () => {
	it("explicit OFF skips automatic checks, but manual checks still run without reading the preference", async () => {
		const f = fixture();
		f.setSettings({ general: { autoUpdate: false } });
		await f.check();
		assert.equal(f.release.checks, 0);
		assert.deepEqual(f.settingsReads, ["/fixture/custom-user-data-dev/data/settings.json"]);
		await f.check(true);
		assert.equal(f.release.checks, 1);
		assert.equal(f.settingsReads.length, 1);
	});

	for (const [label, setting] of [
		["ON", { general: { autoUpdate: true } }], ["absent field", { general: {} }],
		["absent section", { version: 1 }], ["null", null], ["non-boolean", { general: { autoUpdate: "false" } }],
	] as const) {
		it(`${label} keeps automatic checks enabled`, async () => {
			const f = fixture(); f.setSettings(setting); await f.check();
			assert.equal(f.release.checks, 1);
		});
	}
	for (const [label, failure] of [["missing", new Error("ENOENT")], ["unreadable", new Error("EACCES")], ["corrupt", "{nope"]] as const) {
		it(`${label} settings keep automatic checks enabled`, async () => {
			const f = fixture(); f.setSettingsFailure(failure); await f.check();
			assert.equal(f.release.checks, 1);
		});
	}

	it("re-reads the setting on each check, without triggering a check merely when saved", async () => {
		const f = fixture();
		f.setSettings({ general: { autoUpdate: false } }); await f.check();
		f.setSettings({ general: { autoUpdate: true } });
		assert.equal(f.release.checks, 0);
		await f.check();
		f.setSettings({ general: { autoUpdate: false } }); await f.check();
		assert.equal(f.release.checks, 1);
		assert.equal(f.settingsReads.length, 3);
	});

	it("unpackaged (dev) never checks and reports disabled", async () => {
		const f = fixture({ packaged: false });
		await f.check(true); await f.check();
		assert.equal(f.release.checks, 0);
		assert.equal(f.settingsReads.length, 0);
		assert.equal(f.state().status, "disabled");
	});
});

describe("status observation (notify-only)", () => {
	it("a newer release is reported as available with its pinned release page; nothing installs", async () => {
		const f = fixture(); const win = f.window();
		f.release.result = { status: "available", version: "9.9.9", url: RELEASE_URL };
		await f.check(true);
		const state = f.state();
		assert.equal(state.status, "available");
		assert.equal(state.version, "9.9.9");
		assert.equal(state.url, RELEASE_URL);
		assert.equal(win.webContents.messages.at(-1)!.channel, "lh:update-status");
		assert.deepEqual(f.order, [], "no server kill / install path exists");
		assert.equal(f.run("typeof installUpdateNow"), "undefined");
		assert.equal(f.run("typeof setupAutoUpdater"), "undefined");
	});

	it("a foreign release URL is never stored", async () => {
		const f = fixture();
		f.run('reportUpdateStatus("available", "9.9.9", "https://evil.example/learnharness.dmg")');
		assert.equal(f.state().url, null);
	});

	it("one check at a time; a settled check never blocks the next", async () => {
		const f = fixture();
		f.run("checkForUpdates({ manual: true }); checkForUpdates({ manual: true })");
		await settle();
		assert.equal(f.release.checks, 1);
		await f.check(true);
		assert.equal(f.release.checks, 2);
	});

	it("check failures settle to a generic error and later checks still run", async () => {
		const f = fixture();
		f.release.failure = new Error("private endpoint/diagnostic detail"); await f.check();
		assert.equal(f.state().status, "error");
		assert.ok(!JSON.stringify(f.state()).includes("private"));
		f.release.failure = null; await f.check();
		assert.equal(f.release.checks, 2); assert.equal(f.state().status, "up-to-date");
	});

	it("window enumeration/send failures do not break checks or the next window's notification", async () => {
		const f = fixture(); const bad = f.window(); bad.webContents.fails = true; const good = f.window();
		await f.check();
		assert.equal(good.webContents.messages.at(-1)!.channel, "lh:update-status");
		f.setEnumerationFailure(true); await f.check();
		f.setEnumerationFailure(false); await f.check();
		assert.equal(f.release.checks, 3);
	});
});

describe("startup, timer, trusted IPC and menu wiring", () => {
	it("starts and retains the 24h timer without any Settings subscription, checking current preference each time", async () => {
		const f = fixture(); f.setSettings({ general: { autoUpdate: false } });
		await f.run("main()"); await settle();
		assert.equal(f.release.checks, 0);
		assert.equal(f.intervals.length, 1); assert.equal(f.intervals[0]!.delay, 24 * 60 * 60 * 1000);
		f.setSettings({ general: { autoUpdate: true } }); f.intervals[0]!.callback(); await settle();
		assert.equal(f.release.checks, 1);
		f.windows.length = 0; f.intervals[0]!.callback(); await settle();
		assert.equal(f.release.checks, 2, "checks also work with every window closed");
	});

	it("ON/default boot checks immediately", async () => {
		const f = fixture(); f.setSettings({ version: 1 }); await f.run("main()"); await settle();
		assert.equal(f.release.checks, 1);
	});

	it("snapshot/manual/open IPC accept only an owned main frame; open reaches only the pinned release page", async () => {
		const f = fixture(); f.setSettings({ general: { autoUpdate: false } }); await f.run("main()"); await settle();
		const sender = f.windows[0]!.webContents;
		const event = { sender, senderFrame: sender.mainFrame };
		const get = f.handles.get("lh:update:get")!; const check = f.handles.get("lh:update:check")!; const open = f.handles.get("lh:update:open")!;
		assert.equal((get(event) as { status: string }).status, "idle"); assert.equal(f.release.checks, 0);
		open(event); assert.deepEqual(f.opened, [], "nothing to open before a newer release is found");
		f.release.result = { status: "available", version: "9.9.9", url: RELEASE_URL };
		check(event); await settle(); assert.equal(f.release.checks, 1);
		open(event); await settle();
		assert.deepEqual(f.opened, [RELEASE_URL]);
		for (const bad of [
			{ sender: {}, senderFrame: sender.mainFrame },
			{ sender, senderFrame: { url: sender.mainFrame.url } },
		]) {
			assert.throws(() => get(bad), /Untrusted/); assert.throws(() => check(bad), /Untrusted/); assert.throws(() => open(bad), /Untrusted/);
		}
		sender.mainFrame.url = "https://untrusted.invalid/";
		assert.throws(() => check(event), /Untrusted/);
		assert.equal(f.release.checks, 1);
		assert.equal(f.handles.has("lh:update-install"), false);
	});

	it("menu restores/focuses a minimized window, opens General, and manually checks while OFF", async () => {
		const f = fixture(); f.setSettings({ general: { autoUpdate: false } }); await f.run("main()");
		const win = f.windows[0]!; win.webContents.loading = false; win.minimized = true;
		f.menuCheck(); await settle();
		assert.equal(win.minimized, false); assert.equal(win.focused, true);
		assert.ok(win.webContents.messages.some(message => message.channel === "lh:open-settings" && message.value === "general"));
		assert.equal(f.release.checks, 1);
	});

	it("menu reopens a window and delivers General after load; loading existing windows are covered too", async () => {
		const f = fixture(); f.setSettings({ general: { autoUpdate: false } }); await f.run("main()");
		f.windows.length = 0; f.menuCheck(); await settle();
		assert.equal(f.windows.length, 1); assert.equal(f.release.checks, 1);
		const win = f.windows[0]!;
		assert.ok(!win.webContents.messages.some(message => message.channel === "lh:open-settings"));
		win.webContents.emit("did-finish-load");
		assert.ok(win.webContents.messages.some(message => message.channel === "lh:open-settings"));
		f.menuCheck(); win.webContents.emit("did-finish-load");
		assert.equal(win.webContents.messages.filter(message => message.channel === "lh:open-settings").length, 2);
	});

	it("menu navigation failure does not prevent its manual check", async () => {
		const f = fixture(); f.setSettings({ general: { autoUpdate: false } }); await f.run("main()");
		f.windows[0]!.webContents.fails = true; f.windows[0]!.webContents.loading = false;
		f.menuCheck(); await settle(); assert.equal(f.release.checks, 1);
	});
});

describe("release-check.cjs", () => {
	const { compareVersions, releasePageAllowed, checkLatestRelease } = releaseCheck;
	const github = (body: unknown, status = 200) => async () => new Response(JSON.stringify(body), { status });

	it("compares versions numerically; prereleases rank below their release", () => {
		assert.equal(compareVersions("0.3.10", "0.3.9"), 1);
		assert.equal(compareVersions("v1.0.0", "1.0.0"), 0);
		assert.equal(compareVersions("1.0.0-beta.1", "1.0.0"), -1);
		assert.equal(compareVersions("0.3.8", "0.4.0"), -1);
	});

	it("only this repository's release pages are openable", () => {
		assert.equal(releasePageAllowed(RELEASE_URL), true);
		for (const bad of ["https://github.com/amosblomqvist/learnharness/releases/tag/v1", "https://evil.example/", "file:///tmp/x", "https://github.com/jacobderechin/learnharness/releases.evil.example/"]) {
			assert.equal(releasePageAllowed(bad), false, bad);
		}
	});

	it("reports newer published releases only; foreign html_url falls back to the pinned tag page", async () => {
		assert.deepEqual(await checkLatestRelease({ current: "0.3.8", fetch: github({ tag_name: "v0.4.0", html_url: "https://github.com/jacobderechin/learnharness/releases/tag/v0.4.0" }) }),
			{ status: "available", version: "0.4.0", url: "https://github.com/jacobderechin/learnharness/releases/tag/v0.4.0" });
		assert.deepEqual(await checkLatestRelease({ current: "0.3.8", fetch: github({ tag_name: "v0.4.0", html_url: "https://evil.example/x" }) }),
			{ status: "available", version: "0.4.0", url: "https://github.com/jacobderechin/learnharness/releases/tag/v0.4.0" });
		assert.deepEqual(await checkLatestRelease({ current: "0.4.0", fetch: github({ tag_name: "v0.4.0" }) }), { status: "up-to-date" });
		assert.deepEqual(await checkLatestRelease({ current: "0.3.8", fetch: github({ tag_name: "v0.4.0", draft: true }) }), { status: "up-to-date" });
		assert.deepEqual(await checkLatestRelease({ current: "0.3.8", fetch: github({ tag_name: "v0.4.0", prerelease: true }) }), { status: "up-to-date" });
		await assert.rejects(checkLatestRelease({ current: "0.3.8", fetch: github({ tag_name: "nightly" }) }), /no version tag/);
		await assert.rejects(checkLatestRelease({ current: "0.3.8", fetch: github({}, 403) }), /HTTP 403/);
	});
});

describe("safeOpenExternal (security hardening 2026-10-26)", () => {
	it("hands only http, https, and mailto links to the OS", async () => {
		const f = fixture();
		for (const target of ["file:///etc/passwd", "smb://attacker.example/share", "vscode://x/y", "javascript:alert(1)", "https://user:pw@example.com/", "not a url"]) {
			await f.run(`safeOpenExternal(${JSON.stringify(target)})`);
		}
		assert.deepEqual(f.opened, []);
		for (const target of ["https://example.com/a", "http://example.com/", "mailto:someone@example.com"]) await f.run(`safeOpenExternal(${JSON.stringify(target)})`);
		assert.deepEqual(f.opened, ["https://example.com/a", "http://example.com/", "mailto:someone@example.com"]);
	});
});
