/**
 * Typed attest-core errors. In their own module (not signer.ts) so that both
 * the signer and the retrievability gate can throw them without a circular
 * import; signer.ts re-exports them for the public API.
 */

/** Thrown when the moderation signer secret is unset/invalid (callers → 503). */
export class ModerationSignerUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModerationSignerUnavailableError";
  }
}

/** Thrown when the request is well-formed but the spec can't be honestly attested (callers → 4xx). */
export class ModerationRejectError extends Error {
  constructor(
    public readonly httpStatus: number,
    message: string,
  ) {
    super(message);
    this.name = "ModerationRejectError";
  }
}

/**
 * Thrown when no retrievability path succeeds before an attestation would be
 * recorded — the fail-closed "every attestation implies retrievable content"
 * boundary. Retryable by design: the caller can host the spec (registry or any
 * public https URL) and request attestation again.
 */
export class SpecNotRetrievableError extends ModerationRejectError {
  public readonly code = "SPEC_NOT_RETRIEVABLE";
  public readonly retryable = true;
  constructor(message: string) {
    super(409, message);
    this.name = "SpecNotRetrievableError";
  }
}
