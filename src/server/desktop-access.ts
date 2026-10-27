import { timingSafeEqual } from "node:crypto";

/** Is this the Electron-spawned desktop server? (Either marker counts —
 *  a half-configured desktop launch must still take the desktop gate and
 *  fail closed there, never fall through to the web gate.) */
export function desktopServer(env: Record<string, string | undefined> = process.env): boolean {
	return env.LH_DESKTOP_SERVER === "1" || !!env.LH_DESKTOP_API_SECRET;
}

/** Per-launch desktop HTTP capability. This is not an OS-user malware
 * boundary and is not an OAuth credential. Outside desktop mode this check
 * does not apply (true) — the web/dev gate is src/server/web-access.ts. */
export function desktopAPIAuthorized(
	headers: Headers,
	env: Record<string, string | undefined> = process.env,
): boolean {
	const expected = env.LH_DESKTOP_API_SECRET;
	if (env.LH_DESKTOP_SERVER !== "1" && !expected) return true;
	if (!expected || expected.length < 64) return false;
	const supplied = headers.get("x-learnharness-desktop");
	if (!supplied) return false;
	const actual = Buffer.from(supplied);
	const wanted = Buffer.from(expected);
	return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}
