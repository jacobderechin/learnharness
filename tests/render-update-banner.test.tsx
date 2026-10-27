/**
 * Update-banner render tests (Wave C, 2026-10-10): the banner is a pure
 * function of the shell's observational status — hidden without a bridge
 * or snapshot/event, visible with the downloaded
 * status, Restart wired to the bridge. The subscribe effect only runs
 * client-side, so the SSR pass pins the hidden state; the pushed state is
 * exercised by mounting with the bridge stubbed (classic-JSX shim as in
 * render-sidebar.test.tsx).
 */
import React from "react";
(globalThis as Record<string, unknown>).React = React;

import assert from "node:assert/strict";
import { describe, it, afterEach } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import * as ReactDOMClient from "react-dom/client";
import { flushSync } from "react-dom";
import { parseHTML } from "linkedom";
import UpdateBanner from "../components/update-banner.tsx";
import type { UpdateState } from "../components/settings/update-settings.tsx";

// linkedom as the DOM for the interactive pass (first createRoot test in
// the repo — the banner's push→render→click flow needs real effects).
// The window.lh bridge type is declared globally by components/sidebar.tsx.
const dom = parseHTML("<html><body></body></html>");
(globalThis as Record<string, unknown>).window = dom.window;
(globalThis as Record<string, unknown>).document = dom.document;

describe("update banner (notify-only)", () => {
	afterEach(() => {
		delete (window as { lh?: unknown }).lh;
	});

	it("renders nothing with no bridge (browser / SSR)", () => {
		const html = renderToStaticMarkup(<UpdateBanner />);
		assert.equal(html, "");
	});

	it("renders nothing when the bridge exists but no status has arrived", () => {
		const listeners: Array<(s: UpdateState) => void> = [];
		(window as { lh?: unknown }).lh = {
			onUpdateStatus: (cb: (s: UpdateState) => void) => {
				listeners.push(cb);
				return () => {};
			},
			openReleasePage: async () => {},
		};
		const html = renderToStaticMarkup(<UpdateBanner />);
		assert.equal(html, "");
		void listeners;
	});

	it("shows the version + Download once an available push arrives, and Download opens the release page", async () => {
		let pushed: ((s: UpdateState) => void) | null = null;
		let opened = 0;
		(window as { lh?: unknown }).lh = {
			onUpdateStatus: (cb: (s: UpdateState) => void) => {
				pushed = cb;
				return () => {};
			},
			openReleasePage: async () => {
				opened += 1;
			},
		};
		const host = document.createElement("div");
		document.body.appendChild(host);
		const root = ReactDOMClient.createRoot(host);
		flushSync(() => root.render(<UpdateBanner />));
		assert.equal(host.innerHTML, "", "hidden before the push");

		await new Promise((r) => setTimeout(r, 0));
		flushSync(() => pushed?.({ status: "available", version: "0.3.1", revision: 1 }));
		assert.ok(host.innerHTML.includes("0.3.1"), "the version renders");
		assert.ok(host.innerHTML.includes("Download"), "the download affordance renders");

		const button = host.querySelector<HTMLButtonElement>("[data-testid='update-banner'] button");
		assert.ok(button, "download button exists");
		button!.click();
		assert.equal(opened, 1, "Download asks the shell to open the release page (nothing installs)");
		root.unmount();
		host.remove();
	});
});
