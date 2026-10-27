"use client";

/**
 * The update-available banner (notify-only update checks — security
 * hardening, 2026-10-26; owner: no automatic updating). The shell pushes
 * "lh:update-status" when a check finds a newer GitHub release; snapshot
 * retrieval also covers a late load. Download opens the release page in
 * the browser — the app never downloads or installs anything itself.
 * Browser builds have no window.lh and never see a push: renders null.
 */

import { useUpdateState } from "@/components/settings/update-settings.tsx";

export default function UpdateBanner() {
	const { state } = useUpdateState();
	if (state?.status !== "available") return null;
	return (
		<div
			data-testid="update-banner"
			className="fixed right-4 bottom-4 z-50 flex items-center gap-3 rounded-lg border border-border bg-popover px-4 py-3 shadow-lg"
		>
			<div className="text-sm">
				<span className="font-medium">LearnHarness {state.version ?? "update"} is available</span>
				<span className="text-muted-foreground"> — download it from the release page.</span>
			</div>
			<button
				type="button"
				onClick={() => void window.lh?.openReleasePage?.()}
				className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium transition-colors hover:bg-accent/80"
			>
				Download
			</button>
		</div>
	);
}
