/**
 * Server boot hook (Next instrumentation — register() completes before the
 * server handles its first request). Desktop only: load the BYOK key
 * snapshot from Electron main's keyring-sealed vault over the private IPC
 * channel (src/store/auth.ts), so every request sees the keys in memory
 * without them ever touching the environment or a plaintext file.
 */
export async function register() {
	if (process.env.NEXT_RUNTIME !== "nodejs" || process.env.LH_DESKTOP_SERVER !== "1") return;
	const { loadDesktopKeys } = await import("./src/store/auth.ts");
	await loadDesktopKeys();
}
