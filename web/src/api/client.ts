/**
 * The HTTP client.
 *
 * Three rules, each of which exists because breaking it would defeat a
 * server-side control:
 *
 *  1. No caching, at any layer. Every record the analyst sees was released by a
 *     policy decision that produced an audit record. Replaying a cached response
 *     shows intelligence under a decision that was never made and a disclosure
 *     that was never logged. `cache: "no-store"` on every request, and no
 *     in-memory response map anywhere in this module.
 *
 *  2. Errors are classified, not stringified. A 403 and a 413 mean completely
 *     different things to the analyst — "you may not see this" versus "narrow
 *     your request" — and collapsing them into a toast that says "Error 4xx"
 *     produces analysts who retry blindly and generate audit noise that hides
 *     real denials.
 *
 *  3. The disclosure envelope is never discarded. Callers receive the whole
 *     Envelope, not `.records`. There is deliberately no `unwrap()` helper: the
 *     easiest thing to do must be the thing that keeps the redaction counts and
 *     audit sequence attached to the data they describe.
 */

import type {
  CommunityRecord, EntityRecord, Envelope, ExpandRequest, Purpose,
  ReidentifyRequest, RelationshipRecord, ReviewRequest,
} from "./types";

/* --- Errors ------------------------------------------------------------ */

export type FailureKind =
  /** 401 — the session is gone or the token expired. Re-authenticate. */
  | "unauthenticated"
  /** 403 — policy said no. Not retryable; the denial is already audited. */
  | "denied"
  /** 404 — no such record, or none visible in this case. Indistinguishable by
   *  design: the API returns the same 404 either way so the endpoint cannot be
   *  used to test whether a case or entity exists. */
  | "not_found"
  /** 413 — the request would exceed the server's element ceiling. Actionable. */
  | "too_large"
  /** 429 — RATE_LIMIT_STRICT is in force for this principal. */
  | "rate_limited"
  /** 503 — the policy required an obligation this build cannot enforce. */
  | "unenforceable"
  /** Transport, parse, or anything unclassified. */
  | "unavailable";

export class ApiFailure extends Error {
  readonly kind: FailureKind;
  readonly status: number;
  /** Server-supplied detail. Safe to show: the API deliberately keeps denial
   *  bodies generic, and the one place it is specific (413) is specific on
   *  purpose because it tells the analyst how to narrow the request. */
  readonly detail: string;
  readonly requestId: string | undefined;

  constructor(kind: FailureKind, status: number, detail: string,
              requestId?: string) {
    super(detail);
    this.name = "ApiFailure";
    this.kind = kind;
    this.status = status;
    this.detail = detail;
    this.requestId = requestId;
  }

  /** What to put on screen. Written in the interface's voice: says what happened
   *  and what to do, does not apologise, and does not speculate about why the
   *  policy denied — the client does not know, and guessing out loud would teach
   *  analysts wrong models of the policy. */
  get analystMessage(): string {
    switch (this.kind) {
      case "unauthenticated":
        return "Your session has ended. Sign in again to continue.";
      case "denied":
        return "Policy does not permit this view. The request has been recorded. " +
               "If you need this material, ask your supervisor to authorise it.";
      case "not_found":
        return "Nothing matching that reference in this case.";
      case "too_large":
        return this.detail;
      case "rate_limited":
        return "Too many requests in a short period. Wait a moment, then retry.";
      case "unenforceable":
        return "This view cannot be released safely by the current service " +
               "version. Report this to the platform team — it is a fault, " +
               "not a permissions problem.";
      case "unavailable":
        return "The service did not respond. Nothing was disclosed.";
    }
  }
}

function classify(status: number): FailureKind {
  switch (status) {
    case 401: return "unauthenticated";
    case 403: return "denied";
    case 404: return "not_found";
    case 413: return "too_large";
    case 429: return "rate_limited";
    case 503: return "unenforceable";
    default:  return "unavailable";
  }
}

/* --- Transport --------------------------------------------------------- */

/** Supplies the bearer token. A function rather than a value so the token is
 *  read at call time from wherever the session holds it, and never captured into
 *  a long-lived closure that outlives the session. */
export type TokenSource = () => string | null;

export interface ClientOptions {
  token: TokenSource;
  /** Called on every response so the UI can surface the audit sequence and the
   *  redaction counts without each caller remembering to. */
  onEnvelope?: (e: Envelope<unknown>) => void;
  /** Called on 401 so the shell can wipe in-memory intelligence immediately
   *  rather than leaving it on screen behind a login prompt. */
  onSessionLost?: () => void;
}

export class Client {
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    this.opts = opts;
  }

  private async send<T>(path: string, init: RequestInit): Promise<Envelope<T>> {
    const token = this.opts.token();
    if (token === null) {
      throw new ApiFailure("unauthenticated", 401, "no session");
    }

    // Correlation id generated per request and echoed into the audit record. The
    // server bounds it (ascii, <= 64 chars) rather than trusting this value.
    const requestId = `w-${crypto.randomUUID()}`;

    let res: Response;
    try {
      res = await fetch(path, {
        ...init,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        // Same-origin only. The app is served from the same origin as the API in
        // every environment (see vite.config.ts), so a cross-origin request here
        // would mean something has rewritten the base path.
        mode: "same-origin",
        referrerPolicy: "no-referrer",
        headers: {
          ...(init.headers ?? {}),
          "Authorization": `Bearer ${token}`,
          "X-Request-Id": requestId,
          "Accept": "application/json",
        },
      });
    } catch {
      // Deliberately not forwarding the underlying error text. A fetch failure
      // message can carry the resolved URL and proxy details, and this string
      // ends up on an analyst's screen.
      throw new ApiFailure("unavailable", 0, "network error", requestId);
    }

    if (!res.ok) {
      const kind = classify(res.status);
      let detail = res.statusText || "request failed";
      try {
        const body = await res.json() as { detail?: unknown };
        if (typeof body.detail === "string") detail = body.detail;
      } catch {
        /* Non-JSON error body. Keep the status text; do not surface raw HTML,
           which on a misrouted request could be a proxy error page. */
      }
      if (kind === "unauthenticated") this.opts.onSessionLost?.();
      throw new ApiFailure(kind, res.status, detail, requestId);
    }

    const envelope = await res.json() as Envelope<T>;
    if (!envelope || typeof envelope !== "object" || !("disclosure" in envelope)) {
      // A 200 without a disclosure block is not a response this client will
      // render. It means something is proxying or rewriting the API, and showing
      // intelligence without knowing what was withheld from it is the failure
      // this whole envelope design exists to prevent.
      throw new ApiFailure(
        "unavailable", res.status,
        "response did not carry a disclosure envelope", requestId,
      );
    }
    this.opts.onEnvelope?.(envelope as Envelope<unknown>);
    return envelope;
  }

  private json(body: unknown): RequestInit {
    return {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    };
  }

  /* --- Endpoints ------------------------------------------------------ */

  /**
   * Expand one entity's neighbourhood.
   *
   * Server-side bounded: the API refuses with 413 rather than truncating, so the
   * analyst is told the request was too broad instead of shown a silently
   * partial graph they would read as complete. The client does not retry with a
   * smaller radius on their behalf — that would substitute a machine's guess at
   * scope for the analyst's stated intent, and the narrowed query is the one
   * that gets audited.
   */
  expand(req: ExpandRequest): Promise<Envelope<EntityRecord & { edges?: RelationshipRecord[] }>> {
    return this.send("/v1/subgraph/expand", this.json(req));
  }

  entity(eid: string, caseId: string, purpose: Purpose,
         justification?: string): Promise<Envelope<EntityRecord>> {
    const q = new URLSearchParams({ case_id: caseId, purpose });
    if (justification) q.set("justification", justification);
    return this.send(`/v1/entity/${encodeURIComponent(eid)}?${q}`, { method: "GET" });
  }

  community(snapshotId: string, communityId: string, caseId: string,
            purpose: Purpose): Promise<Envelope<CommunityRecord>> {
    const q = new URLSearchParams({ case_id: caseId, purpose });
    return this.send(
      `/v1/communities/${encodeURIComponent(snapshotId)}/` +
      `${encodeURIComponent(communityId)}?${q}`,
      { method: "GET" },
    );
  }

  /** Resolve surrogates to entity ids. Separate call, separate decision,
   *  separate audit record — reading a community's shape and learning who is in
   *  it are different disclosures. Returns ids only; attributes come from
   *  `entity()` under a decision that considers that entity's category. */
  reidentify(req: ReidentifyRequest): Promise<Envelope<{ eid: string }> & {
    unresolved_count: number;
  }> {
    return this.send("/v1/communities/reidentify", this.json(req)) as Promise<
      Envelope<{ eid: string }> & { unresolved_count: number }
    >;
  }

  /** Record a named human's review of an algorithmic output. `concurs: false` is
   *  a valid outcome and the UI must offer it as prominently as agreement. */
  async review(req: ReviewRequest): Promise<{ audit_seq: number; concurs: boolean }> {
    const token = this.opts.token();
    if (token === null) throw new ApiFailure("unauthenticated", 401, "no session");
    const res = await fetch("/v1/communities/review", {
      ...this.json(req),
      cache: "no-store",
      credentials: "omit",
      mode: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
        "X-Request-Id": `w-${crypto.randomUUID()}`,
      },
    });
    if (!res.ok) {
      const kind = classify(res.status);
      if (kind === "unauthenticated") this.opts.onSessionLost?.();
      throw new ApiFailure(kind, res.status, res.statusText);
    }
    return await res.json() as { audit_seq: number; concurs: boolean };
  }
}
