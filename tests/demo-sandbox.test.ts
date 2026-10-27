/**
 * Generated-content sandbox (security hardening, 2026-10-26): the shared
 * no-network policy (src/core/demo-sandbox.ts), the iframe srcDoc it rides
 * in, the verifier prompt, and
 * parity of every copy of the policy (main.cjs helper, the smoke probe).
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { DEMO_CSP, DEMO_SANDBOX_URL, withDemoCsp } from "../src/core/demo-sandbox.ts";
import { buildDemoSrcDoc, buildDemoViewer } from "../components/artifacts/demo-card.tsx";

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

describe("buildDemoViewer (the safe demo download)", () => {
	it("frames the demo in an allow-scripts-only sandbox under the demo CSP, with everything escaped", () => {
		const out = buildDemoViewer('A "quoted" <title>', '<!doctype html><p onclick="x()">&amp; "q"</p>');
		assert.match(out, /^<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'/);
		assert.match(out, /<iframe sandbox="allow-scripts" title="A &quot;quoted&quot; &lt;title&gt;" srcdoc="/);
		assert.doesNotMatch(out, /allow-same-origin|allow-top-navigation|allow-popups/);
		assert.match(out, /<title>A &quot;quoted&quot; &lt;title&gt;<\/title>/);
		const srcdoc = /srcdoc="([^"]*)"/.exec(out)![1]!;
		assert.ok(!srcdoc.includes('"') && !srcdoc.includes("<"), "the attribute cannot be broken out of");
		const decoded = srcdoc.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
		assert.equal(decoded, buildDemoSrcDoc('<!doctype html><p onclick="x()">&amp; "q"</p>'), "the framed document is exactly the in-app one");
		assert.equal((out.match(/<script/gi) ?? []).length, 0, "the outer page runs nothing itself");
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
