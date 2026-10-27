/**
 * Server boot hook (Next instrumentation — register() completes before the
 * server handles its first request). Desktop only: fetch the BYOK key
 * snapshot from Electron main's keyring-sealed vault over the private IPC
 * channel, so every request sees the keys in memory without them ever
 * touching the environment or a plaintext file. src/store/auth.ts adopts
 * the snapshot from the globalThis slot below and owns the channel after.
 *
 * SELF-CONTAINED ON PURPOSE: importing project modules here makes the
 * standalone tracer copy the whole repo (data/, tests/) into the payload —
 * outputFileTracingExcludes is keyed by route and does not cover this
 * entry. Keep this file import-free.
 */
const BOOT_SNAPSHOT = Symbol.for("lh.keyVault.boot");

export async function register() {
	if (process.env.NEXT_RUNTIME !== "nodejs" || process.env.LH_DESKTOP_SERVER !== "1") return;
	if (typeof process.send !== "function" || !process.connected) return;
	const id = `${process.pid}:keys:boot`;
	const snapshot = await new Promise<unknown>((resolve) => {
		const timer = setTimeout(() => done(null), 15_000);
		const listener = (raw: unknown) => {
			const message = raw as { channel?: string; id?: string; ok?: boolean; value?: unknown };
			if (message?.channel === "lh:keys" && message.id === id) done(message.ok ? message.value : null);
		};
		function done(value: unknown) {
			clearTimeout(timer);
			process.off("message", listener);
			resolve(value);
		}
		process.on("message", listener);
		process.send!({ channel: "lh:keys", id, op: "snapshot" }, (error: Error | null) => {
			if (error) done(null);
		});
	});
	if (snapshot) (globalThis as Record<symbol, unknown>)[BOOT_SNAPSHOT] = snapshot;
	else console.error("[keys] desktop key vault unavailable at boot");
}
