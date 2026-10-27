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
 * entry. Keep this file (and instrumentation-node.ts, its Node-only half —
 * split out so the Edge compile never sees Node APIs) import-free beyond
 * that one local module.
 */
export async function register() {
	if (process.env.NEXT_RUNTIME !== "nodejs") return;
	const { loadDesktopKeySnapshot } = await import("./instrumentation-node.ts");
	await loadDesktopKeySnapshot();
}
