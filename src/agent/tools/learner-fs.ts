import type { AgentTool } from "@earendil-works/pi-agent-core";
import { findToolFor } from "./find.ts";
import { NO_FS_ACCESS, type FsScope } from "./fs-scope.ts";
import { grepToolFor } from "./grep.ts";
import { lsToolFor } from "./ls.ts";
import { readToolFor } from "./read.ts";

/** The learner-filesystem set (read / ls / find / grep) over one scope —
 *  shared by the prober, teacher, and practice registries. An absent scope
 *  (tests, bare agents) is NO_FS_ACCESS: the tools exist and refuse. */
export function learnerFsTools(scope: FsScope = NO_FS_ACCESS): Record<string, AgentTool<any>> {
	return {
		read: readToolFor(scope),
		ls: lsToolFor(scope),
		find: findToolFor(scope),
		grep: grepToolFor(scope),
	};
}
