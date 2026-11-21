/**
 * Which program revision this service signs for.
 *
 * Revision 9 changed the `record_task_moderation` wire: the record's rent is
 * paid by an appended `rent_payer` (the task's creator), so the buyer pays
 * the deposit itself and gets it back when the task is closed. The two wires
 * do not mix:
 *
 *  - the revision 9 transaction sent to a revision 8 program would make this
 *    service's signer pay the deposit (revision 8 ignores the appended
 *    account and charges the moderator);
 *  - the revision 8 transaction sent to a revision 9 program fails (one
 *    account short).
 *
 * The upgrade lands the new program first and the revision stamp after it,
 * while the protocol is paused. So the only safe rule is the stamp: this
 * service signs approvals, and sends heartbeats, only while
 * `ProtocolConfig.surface_revision` says 9. On any other stamp it signs
 * nothing and answers 503 (retryable). The revision 8 deployment keeps
 * serving until this one is switched in, after the stamp and before the
 * unpause.
 */

import type { createSolanaRpc } from "@solana/kit";
import {
  getDeployedSurface,
  SURFACE_REVISION_ACCOUNTABLE_REVIEW,
} from "@tetsuo-ai/marketplace-sdk";
import { ModerationRejectError } from "./errors.js";

/** The one program revision this build signs for. */
export const SIGNING_SURFACE_REVISION = SURFACE_REVISION_ACCOUNTABLE_REVIEW;

/** Machine-readable code of the refusal on any other stamp. */
export const UNSUPPORTED_REVISION_CODE = "UNSUPPORTED_PROGRAM_REVISION";

type Rpc = ReturnType<typeof createSolanaRpc>;

/**
 * The cluster's `ProtocolConfig.surface_revision`. A missing or old-layout
 * config reads 0 (the SDK never throws on those).
 */
export async function readSurfaceRevision(rpc: Rpc): Promise<number> {
  const surface = await getDeployedSurface(rpc);
  return surface.surfaceRevision;
}

/**
 * Refuse, before anything is signed, unless the program is stamped with the
 * revision this build signs for. Returns the stamp it read.
 */
export async function requireSigningRevision(rpc: Rpc): Promise<number> {
  const revision = await readSurfaceRevision(rpc);
  if (revision !== SIGNING_SURFACE_REVISION) {
    throw new ModerationRejectError(
      503,
      `The marketplace program on this cluster is stamped revision ${revision}. This service signs approvals for revision ${SIGNING_SURFACE_REVISION} only, so nothing was signed. Try again shortly.`,
      { code: UNSUPPORTED_REVISION_CODE, retryable: true },
    );
  }
  return revision;
}
