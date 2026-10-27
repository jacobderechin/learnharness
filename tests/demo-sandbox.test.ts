/**
 * Generated-content sandbox (security hardening, 2026-10-26): the shared
 * no-network policy (src/core/demo-sandbox.ts), the iframe srcDoc it rides
 * in, the SVG reference stripping before resvg, the verifier prompt, and
 * parity of every copy of the policy (main.cjs helper, the smoke probe).
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { DEMO_CSP, DEMO_SANDBOX_URL, withDemoCsp } from "../src/core/demo-sandbox.ts";
import { buildDemoSrcDoc } from "../components/artifacts/demo-card.tsx";
import { stripExternalSvgRefs } from "../src/agent/subagents/headless.ts";

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

describe("DEMO_CSP", () => {
	it("allows inline code and inline media, and no network at all", () => {
		assert.match(DEMO_CSP, /default-src 'none'/);
		assert.match(DEMO_CSP, /connect-src 'none'/);
		assert.doesNotMatch(DEMO_CSP, /https?:|\*|'self'/, "no remote or self source anywhere");
	});
});

describe("withDemoCsp / buildDemoSrcDoc", () => {
	it("puts the meta right after the doctype (standards mode, governs every script)", () => {
		const out = withDemoCsp("<!DOCTYPE html><html><head><script>1</script></head></html>");
		assert.ok(out.startsWith('<!DOCTYPE html><meta http-equiv="Content-Security-Policy"'));
		assert.ok(out.indexOf("Content-Security-Policy") < out.indexOf("<script>"));
	});
	it("prepends when there is no doctype", () => {
		assert.ok(withDemoCsp("<script>1</script>").startsWith("<meta http-equiv=\"Content-Security-Policy\""));
	});
	it("the learner's iframe document carries the policy and the bridge", () => {
		const doc = buildDemoSrcDoc("<!doctype html><body><p>x</p></body>");
		assert.match(doc, /^<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'none'/);
		assert.match(doc, /demo-resize/);
	});
});

describe("stripExternalSvgRefs (before resvg / the browser fallback)", () => {
	it("drops file and remote references, keeps data: and #fragments", () => {
		const svg = `<svg><image href="/home/u/.ssh/id_rsa.png"/><image xlink:href='https://x.test/a.png'/><image href="data:image/png;base64,AA"/><use href="#dot"/></svg>`;
		const out = stripExternalSvgRefs(svg);
		assert.doesNotMatch(out, /\.ssh|x\.test/);
		assert.match(out, /href="data:image\/png;base64,AA"/);
		assert.match(out, /href="#dot"/);
	});
});

describe("policy parity and prompt", () => {
	it("the Electron helper allows exactly the core sandbox URL", () => {
		assert.match(read("../electron/main.cjs"), new RegExp(`const DEMO_SANDBOX_URL = "${DEMO_SANDBOX_URL.replace(/[./]/g, "\\$&")}";`));
	});
	it("the packaged smoke probe serves the same CSP", () => {
		assert.ok(read("../scripts/smoke-demo-runtime.mjs").includes(`const CSP = "${DEMO_CSP}";`));
	});
	it("the demo builder is told there is no network (no CDN allowance)", () => {
		const builder = read("../src/agent/subagents/demo-builder.ts");
		assert.match(builder, /NO network of any kind/);
		assert.doesNotMatch(builder, /CDN imports .* are allowed/);
	});
	it("the Chrome fallback never disables the OS sandbox", () => {
		assert.doesNotMatch(read("../src/agent/subagents/headless.ts"), /"--no-sandbox"/);
	});
});
