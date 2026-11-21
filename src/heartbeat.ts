/**
 * Weekly moderation liveness heartbeat (revision 9).
 *
 * The program's moderation gates relax to moderation-optional when nobody has
 * sent `moderation_heartbeat` within the liveness window (90 days by default).
 * The attest service that holds the moderation authority key is the sender of
 * record: this job sends a plain heartbeat once a week so the gate stays armed
 * while the service is alive.
 *
 * What it sends, and nothing else:
 *  - `moderation_heartbeat` with no window (`None`): this job never changes the
 *    liveness window (a window change needs 2 of the 3 protocol owners);
 *  - on the revision 9 wire: moderation_config, the signer, and the
 *    protocol_config slot, which the SDK facade fills with the ProtocolConfig
 *    PDA (it works for every allowed sender; a two-account revision 8 wire
 *    fails on revision 9 with AccountNotEnoughKeys);
 *  - signed and paid by this service's signer (one fee, about 5,000 lamports).
 *
 * It sends only when every check passes: the job is turned on
 * (HEARTBEAT_ENABLED), a signer is configured, the program is stamped
 * revision 9, the signer is an allowed sender (the moderation authority, the
 * config authority, or a protocol owner; a roster attestor is not), and the
 * last heartbeat on chain is about a week old. A heartbeat from anyone else
 * resets that clock, so the job never doubles up on an operator's.
 *
 * Two triggers share this one function: `GET /v1/cron/heartbeat` (Vercel
 * Cron, authorized by CRON_SECRET) and an hourly timer in the self-host server
 * (`startHeartbeatTimer`). Checking more often than weekly is safe: an early
 * check is answered "not due" without sending.
 */

import { createSolanaRpc, none, type Instruction, type TransactionSigner } from "@solana/kit";
import {
  facade,
  fetchMaybeModerationConfig,
  fetchMaybeProtocolConfig,
  findModerationConfigPda,
  findProtocolConfigPda,
} from "@tetsuo-ai/marketplace-sdk";
import { readSurfaceRevision, SIGNING_SURFACE_REVISION } from "./revision.js";
import { signAndSend, tryLoadModeratorSigner } from "./signer.js";
import { SERVICE_NAME } from "./version.js";

/** One heartbeat a week. */
export const HEARTBEAT_INTERVAL_SECONDS = 7 * 24 * 60 * 60;
/**
 * A check that runs at the same time every day still sends on the seventh
 * day, even when the last heartbeat landed a few minutes after that time.
 */
export const HEARTBEAT_SLACK_SECONDS = 60 * 60;
/** How often the self-host timer checks whether a heartbeat is due. */
export const HEARTBEAT_CHECK_INTERVAL_MS = 60 * 60 * 1000;

/**
 * The heartbeat instruction this job sends: the revision 9 wire with the
 * protocol_config slot, built by the SDK facade, and no window change.
 */
export async function buildModerationHeartbeatInstruction(
  authority: TransactionSigner,
): Promise<Instruction> {
  return (await facade.moderationHeartbeat({
    authority,
    newWindowSecs: none(),
  })) as Instruction;
}

export type HeartbeatOutcome =
  | "sent"
  | "disabled"
  | "no-signer"
  | "unsupported-revision"
  | "no-moderation-config"
  | "not-allowed"
  | "not-due";

export interface HeartbeatReport {
  /** True only when this run sent a heartbeat. */
  sent: boolean;
  outcome: HeartbeatOutcome;
  message: string;
  /** The signature of the heartbeat this run sent. */
  signature?: string;
  /** The wallet this deployment sends with. */
  sender?: string;
  /** The program's revision stamp, when it was read. */
  surfaceRevision?: number;
  /** The last heartbeat on chain (`ModerationConfig.updated_at`). */
  lastHeartbeatAt?: string;
  /** When this job sends next, if nothing else heartbeats first. */
  nextDueAt?: string;
}

export interface HeartbeatDeps {
  rpcUrl: string;
  /** HEARTBEAT_ENABLED. When false the job reads nothing and sends nothing. */
  enabled: boolean;
  /** Current unix time in seconds (test seam). */
  now?: () => number;
}

function iso(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString();
}

/** Run one heartbeat check, and send the heartbeat when it is due. */
export async function runModerationHeartbeat(deps: HeartbeatDeps): Promise<HeartbeatReport> {
  if (!deps.enabled) {
    return {
      sent: false,
      outcome: "disabled",
      message: "The heartbeat job is off. Set HEARTBEAT_ENABLED=true to turn it on.",
    };
  }
  const signer = await tryLoadModeratorSigner();
  if (signer === null) {
    return {
      sent: false,
      outcome: "no-signer",
      message: "No signer is configured, so there is nothing to send the heartbeat with.",
    };
  }
  const sender = signer.address;
  const rpc = createSolanaRpc(deps.rpcUrl);

  const surfaceRevision = await readSurfaceRevision(rpc);
  if (surfaceRevision !== SIGNING_SURFACE_REVISION) {
    return {
      sent: false,
      outcome: "unsupported-revision",
      message: `The program is stamped revision ${surfaceRevision}. This job sends the revision ${SIGNING_SURFACE_REVISION} heartbeat only, so nothing was sent.`,
      sender,
      surfaceRevision,
    };
  }

  const [configPda] = await findModerationConfigPda();
  const config = await fetchMaybeModerationConfig(rpc, configPda);
  if (!config.exists) {
    return {
      sent: false,
      outcome: "no-moderation-config",
      message: "ModerationConfig is not initialized on this cluster, so there is nothing to keep alive.",
      sender,
      surfaceRevision,
    };
  }

  // The program's sender rule (moderation_heartbeat.rs `validate_heartbeat`):
  // the config authority, the moderation authority, or a protocol owner.
  let allowed =
    sender === String(config.data.authority) ||
    sender === String(config.data.moderationAuthority);
  if (!allowed) {
    const [protocolPda] = await findProtocolConfigPda();
    const protocol = await fetchMaybeProtocolConfig(rpc, protocolPda);
    allowed =
      protocol.exists &&
      protocol.data.multisigOwners
        .slice(0, protocol.data.multisigOwnersLen)
        .some((owner) => String(owner) === sender);
  }
  const last = Number(config.data.updatedAt);
  if (!allowed) {
    return {
      sent: false,
      outcome: "not-allowed",
      message:
        "This service's signer may not send the heartbeat. Only the moderation authority, the config authority or a protocol owner may; a roster attestor may not. Nothing was sent.",
      sender,
      surfaceRevision,
      lastHeartbeatAt: iso(last),
    };
  }

  const now = deps.now?.() ?? Math.floor(Date.now() / 1000);
  const dueAt = last + HEARTBEAT_INTERVAL_SECONDS - HEARTBEAT_SLACK_SECONDS;
  if (now < dueAt) {
    return {
      sent: false,
      outcome: "not-due",
      message: "The last heartbeat is less than a week old. Nothing was sent.",
      sender,
      surfaceRevision,
      lastHeartbeatAt: iso(last),
      nextDueAt: iso(dueAt),
    };
  }

  const instruction = await buildModerationHeartbeatInstruction(signer);
  const signature = await signAndSend(deps.rpcUrl, instruction, signer, "Moderation heartbeat");
  return {
    sent: true,
    outcome: "sent",
    message: "Heartbeat sent.",
    signature,
    sender,
    surfaceRevision,
    lastHeartbeatAt: iso(last),
    nextDueAt: iso(now + HEARTBEAT_INTERVAL_SECONDS - HEARTBEAT_SLACK_SECONDS),
  };
}

/**
 * Self-host trigger: check once shortly after boot, then every hour. One check
 * runs at a time. Logs one line per send, refusal or failure, never a key.
 */
export function startHeartbeatTimer(
  config: { rpcUrl: string },
  log: Pick<Console, "log" | "error"> = console,
): { stop(): void } {
  let running = false;
  const tick = async (): Promise<void> => {
    if (running) return;
    running = true;
    try {
      const report = await runModerationHeartbeat({ rpcUrl: config.rpcUrl, enabled: true });
      if (report.outcome !== "not-due") {
        log.log(
          `[${SERVICE_NAME}] heartbeat: ${report.outcome}${report.signature ? ` ${report.signature}` : ""}. ${report.message}`,
        );
      }
    } catch (error) {
      log.error(
        `[${SERVICE_NAME}] heartbeat failed: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    } finally {
      running = false;
    }
  };
  const first = setTimeout(() => void tick(), 30_000);
  const timer = setInterval(() => void tick(), HEARTBEAT_CHECK_INTERVAL_MS);
  first.unref?.();
  timer.unref?.();
  return {
    stop() {
      clearTimeout(first);
      clearInterval(timer);
    },
  };
}
