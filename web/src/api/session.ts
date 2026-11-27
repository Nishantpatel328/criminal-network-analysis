/**
 * Session state. In memory, and only in memory.
 *
 * NOTHING IN THIS MODULE TOUCHES localStorage, sessionStorage, IndexedDB OR
 * document.cookie.
 *
 * That is worth stating as loudly as a comment can, because storing the token
 * "so refresh does not log you out" is the single most likely future edit to this
 * file, and it would be a real regression: browser storage on a shared
 * intelligence workstation survives the analyst walking away, and an XSS anywhere
 * on the origin can read all of it. The cost of the correct behaviour is that F5
 * ends the session. That is the right trade in this domain, and the reason is
 * recorded here so it does not get re-litigated as a usability bug.
 *
 * Intelligence records are held the same way: in React state, wiped on session
 * loss and on idle. There is no offline mode.
 */

import type { Disclosure, Envelope, Purpose } from "./types";

/** CJIS requires re-authentication for CJI access from a non-secure location.
 *  The server enforces it via the SESSION_REAUTH_15M obligation; this mirror
 *  exists so the analyst sees the countdown instead of losing a half-written
 *  justification to a surprise 401. Server value is `Settings.reauth_seconds`. */
export const REAUTH_SECONDS = 900;

/** Wipe the screen after this long without input, independent of the token's
 *  lifetime. A logged-in workstation left unattended in an open-plan office is
 *  the most common real-world disclosure in police systems, and it is not an
 *  authentication failure — the session is perfectly valid, the analyst is just
 *  at lunch. Shorter than the re-auth window on purpose. */
export const IDLE_WIPE_SECONDS = 300;

export interface SessionIdentity {
  /** Collar number or equivalent. Painted into the canvas watermark. */
  actor: string;
  agency: string;
  roles: readonly string[];
  /** True when the edge proxy attested a secure network location via mTLS client
   *  certificate attributes. Never asserted by this client — displayed only. */
  fromSecureLocation: boolean;
}

export interface CaseScope {
  caseId: string;
  /** Chosen by the analyst per session, and re-stated on escalation. There is no
   *  default: purpose limitation is only enforceable if the purpose is declared,
   *  and a pre-selected dropdown value is not a declaration. */
  purpose: Purpose | null;
}

/**
 * The disclosure state of whatever is currently on screen.
 *
 * Accumulated rather than replaced: a graph built from three expansions has
 * three redaction counts, and showing only the most recent one would tell the
 * analyst that nothing was withheld from a view that is two-thirds redacted.
 */
export class DisclosureLedger {
  private redacted = 0;
  private withheld = 0;
  private truncated = false;
  private readonly noteSet = new Set<string>();
  private readonly obligations = new Set<string>();
  private lastSeq = -1;

  record(e: Envelope<unknown>): void {
    this.redacted += e.disclosure.fields_redacted;
    this.withheld += e.disclosure.fields_withheld;
    this.truncated = this.truncated || e.disclosure.truncated;
    for (const n of e.disclosure.notes) this.noteSet.add(n);
    for (const o of e.disclosure.obligations_applied) this.obligations.add(o);
    if (e.audit_seq > this.lastSeq) this.lastSeq = e.audit_seq;
  }

  snapshot(): Readonly<Disclosure & { audit_seq: number; active: boolean }> {
    return {
      fields_redacted: this.redacted,
      fields_withheld: this.withheld,
      notes: [...this.noteSet],
      obligations_applied: [...this.obligations] as Disclosure["obligations_applied"],
      truncated: this.truncated,
      audit_seq: this.lastSeq,
      /** True when anything at all was held back from the current view. Drives
       *  the amber state on the disclosure strip. */
      active: this.redacted > 0 || this.withheld > 0 || this.truncated,
    };
  }

  clear(): void {
    this.redacted = 0;
    this.withheld = 0;
    this.truncated = false;
    this.noteSet.clear();
    this.obligations.clear();
    this.lastSeq = -1;
  }
}

/**
 * Idle detection.
 *
 * Listens on the capture phase so a component that stops propagation cannot
 * accidentally make the workstation look idle while someone is using it, and
 * uses `passive` so it costs nothing on a canvas being dragged.
 */
export function watchIdle(seconds: number, onIdle: () => void): () => void {
  let timer = window.setTimeout(onIdle, seconds * 1000);
  const bump = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(onIdle, seconds * 1000);
  };
  const events = ["pointerdown", "keydown", "wheel", "pointermove"] as const;
  for (const ev of events) {
    window.addEventListener(ev, bump, { capture: true, passive: true });
  }
  // Tab hidden counts as idle immediately rather than after the timer: a
  // backgrounded tab is a screen the analyst is not watching, and throttled
  // timers in background tabs mean the countdown itself becomes unreliable.
  const onVisibility = () => { if (document.hidden) onIdle(); };
  document.addEventListener("visibilitychange", onVisibility);

  return () => {
    window.clearTimeout(timer);
    for (const ev of events) {
      window.removeEventListener(ev, bump, { capture: true });
    }
    document.removeEventListener("visibilitychange", onVisibility);
  };
}

/** Seconds remaining until re-authentication, floored at zero. */
export function reauthRemaining(startedAtMs: number, now = Date.now()): number {
  return Math.max(0, REAUTH_SECONDS - Math.floor((now - startedAtMs) / 1000));
}

export function formatCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}
