"use strict";

/**
 * Notify-only update checks (security hardening, 2026-10-26, owner: no
 * automatic updating). The app asks GitHub Releases for the latest
 * published version, compares it with its own, and — when newer — offers a
 * link to the release page. Nothing is downloaded, staged, or installed by
 * the app; the person installs the new version themselves.
 */

const RELEASES_API = "https://api.github.com/repos/amosblomqvist/learnharness/releases/latest";
const RELEASE_PAGE_PREFIX = "https://github.com/amosblomqvist/learnharness/releases/";

/** Numeric x.y.z compare; a prerelease ranks below its release. */
function compareVersions(a, b) {
	const parse = (v) => {
		const [core, pre] = String(v).replace(/^v/, "").split("-", 2);
		return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre: pre ?? null };
	};
	const x = parse(a);
	const y = parse(b);
	for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
		const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
		if (d !== 0) return d > 0 ? 1 : -1;
	}
	if (x.pre === y.pre) return 0;
	if (x.pre === null) return 1;
	if (y.pre === null) return -1;
	return x.pre > y.pre ? 1 : -1;
}

/** Only this repository's release pages may be opened from the app. */
function releasePageAllowed(url) {
	try {
		const parsed = new URL(url);
		return parsed.href.startsWith(RELEASE_PAGE_PREFIX) && !parsed.username && !parsed.password;
	} catch {
		return false;
	}
}

/** → { status: "available", version, url } | { status: "up-to-date" };
 *  throws on network/shape failures (the caller reports "error"). */
async function checkLatestRelease({ current, fetch: request = globalThis.fetch, timeoutMs = 15_000 }) {
	const response = await request(RELEASES_API, {
		headers: { Accept: "application/vnd.github+json", "User-Agent": "LearnHarness update check" },
		redirect: "error",
		signal: AbortSignal.timeout(timeoutMs),
	});
	if (!response.ok) throw new Error(`GitHub releases: HTTP ${response.status}`);
	const release = await response.json();
	const version = typeof release?.tag_name === "string" ? release.tag_name.replace(/^v/, "") : null;
	if (!version || !/^\d+\.\d+\.\d+/.test(version)) throw new Error("GitHub releases: no version tag");
	if (release.draft || release.prerelease || compareVersions(version, current) <= 0) return { status: "up-to-date" };
	const url = typeof release.html_url === "string" && releasePageAllowed(release.html_url) ? release.html_url : `${RELEASE_PAGE_PREFIX}tag/v${version}`;
	return { status: "available", version, url };
}

module.exports = { RELEASES_API, RELEASE_PAGE_PREFIX, compareVersions, releasePageAllowed, checkLatestRelease };
