/**
 * PUT /api/keys/:id — save one key; DELETE — remove it (auth-keys wave,
 * 2026-09-19). `id` is the env-var/file key name (OPENROUTER_API_KEY, …).
 *
 * PUT body {value}: shape-gated (owner decision — bad pastes are 400s
 * naming the expected format, never stored; validation is SHAPE-ONLY, no
 * live pings). Saves take effect on the next request (no restart). A var
 * owned by the REAL env is stored for later but shadowed — the response's
 * status row carries shadowedByEnv so the page can explain why the saved
 * key is not the live one. A store refusal (desktop with no OS keyring) is
 * a 503 carrying the store's explanation.
 *
 * DELETE: gone from the store (a real env var stays — env wins).
 * Idempotent (absent key = success). Writable ids are the CURATED CATALOG ∪ THE
 * MODEL-PROVIDER env vars (provider-keys interlude); anything else is 404
 * — unknown file vars are preserved, not editable.
 */
import { isWritableAuthKey } from "@/src/server";
import { deleteKey, saveKey } from "@/src/server";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ id: string }> };

export async function PUT(req: Request, { params }: Params) {
	const { id } = await params;
	if (!isWritableAuthKey(id)) {
		return Response.json({ error: `unknown key "${id}"` }, { status: 404 });
	}
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return Response.json({ error: "body must be JSON" }, { status: 400 });
	}
	if (!body || typeof body !== "object" || Array.isArray(body) || typeof (body as { value?: unknown }).value !== "string") {
		return Response.json({ error: "body must be {value: string}" }, { status: 400 });
	}
	const result = await saveKey(id, (body as { value: string }).value);
	if (!result.ok) return Response.json({ error: result.error }, { status: result.status });
	return Response.json({ status: result.status });
}

export async function DELETE(_req: Request, { params }: Params) {
	const { id } = await params;
	if (!isWritableAuthKey(id)) {
		return Response.json({ error: `unknown key "${id}"` }, { status: 404 });
	}
	const result = await deleteKey(id);
	if (!result.ok) return Response.json({ error: result.error }, { status: result.status });
	return Response.json({ status: result.status });
}
