/** Node-only half of instrumentation.ts (kept out of the Edge compile).
 *  Import-free on purpose — see instrumentation.ts. */
const BOOT_SNAPSHOT = Symbol.for("lh.keyVault.boot");

export async function loadDesktopKeySnapshot() {
	if (process.env.LH_DESKTOP_SERVER !== "1") return;
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
