// When to fetch a run's history from GET /api/runs/{id} (ADR 0033). The live feed can miss the start
// of a run: a visitor who joins mid-session, events lost across a reconnect, or a tab that was hidden
// long enough for the stream to be closed. The timeline drops events it already has, so a backfill
// never double-counts; this decides only when one is due:
//
//   * a run the feed shows without its start (no `queued`/`started`), or events that name a run the
//     feed has never shown, once per run;
//   * the active run again whenever the stream opens after an interruption — a drop, or a stop while
//     the tab was hidden (that reconnect starts as "connecting", not "reconnecting");
//   * after a failed fetch, not again on every render: a JSON 404 (a run the store no longer keeps)
//     is final; anything else (the network, a 5xx) waits 30 s, then twice as long each time, up to
//     10 minutes.

import type { Result } from "./api";
import type { StreamEvent } from "./contract";
import type { ConnectionState } from "./sse";
import type { TimelineView } from "./timeline";

const FIRST_RETRY_MS = 30_000;
const MAX_RETRY_MS = 10 * 60_000;

export class Backfill {
  private readonly state = new Map<string, { busy: boolean; done: boolean; next: number; delay: number }>();
  private interrupted = false;

  constructor(
    private readonly fetchRun: (runId: string) => Promise<Result<{ events: StreamEvent[]; truncated: boolean }>>,
    private readonly push: (ev: StreamEvent) => void,
    private readonly now: () => number = Date.now,
    /** The store kept only part of this run (its per-run cap): what the page shows may have gaps. */
    private readonly onTruncated: (runId: string) => void = () => {},
  ) {}

  /** Every new view of the feed: backfill what it shows without a start. */
  view(v: TimelineView): void {
    for (const r of v.runs) if (r.states.queued === undefined && r.states.started === undefined) this.request(r.runId);
    for (const ev of v.unmatched) {
      const id = "run_id" in ev.data ? ev.data.run_id : undefined;
      if (id && !v.runs.some((r) => r.runId === id)) this.request(id);
    }
  }

  /** The stream stopped on purpose (the tab is hidden): the next open must catch up. */
  stopped(): void {
    this.interrupted = true;
  }

  /** The stream's state: on opening after any interruption, the active run is fetched again. */
  stream(state: ConnectionState, activeRunId: string | undefined): void {
    if (state === "offline" || state === "reconnecting") this.interrupted = true;
    if (state !== "open") return;
    if (this.interrupted && activeRunId) this.request(activeRunId, true);
    this.interrupted = false;
  }

  private request(runId: string, again = false): void {
    const s = this.state.get(runId) ?? { busy: false, done: false, next: 0, delay: 0 };
    this.state.set(runId, s);
    if (s.busy || (s.done && !again) || (!again && this.now() < s.next)) return;
    s.busy = true;
    void this.fetchRun(runId).then((r) => {
      s.busy = false;
      if (r.ok) {
        s.done = true;
        s.delay = 0;
        for (const ev of r.value.events) this.push(ev);
        if (r.value.truncated) this.onTruncated(runId);
      } else if (r.status === 404 && r.json) {
        // The run store does not have it (it keeps the last 50 runs): asking again will not change
        // that. Only a reconnect asks once more.
        s.done = true;
      } else {
        s.delay = s.delay ? Math.min(MAX_RETRY_MS, s.delay * 2) : FIRST_RETRY_MS;
        s.next = this.now() + s.delay;
      }
    });
  }
}
