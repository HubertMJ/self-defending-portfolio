// mountTerminal driven by the real API's event sequences (internal/runner/terminal.go, runner.go,
// server.go on the API side): the run and command events in the order and shape the API publishes
// them, each with the hub's event id, fed through the same parser and timeline the page uses.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type FetchLike } from "../../src/lib/api";
import { type StreamEvent, toStreamEvent } from "../../src/lib/contract";
import { terminalDetails } from "../../src/lib/fixtures";
import { buildTimeline } from "../../src/lib/timeline";
import { mountTerminal } from "../../src/ui/terminal";

const RUN = "4f1c2a9e8b7d6c5a";
const POD = "terminal-4f1c2a9e8b";
const TOKEN = "0123456789abcdef0123456789abcdef";
const T0 = Date.parse("2026-10-02T12:00:00Z");

/** The API's feed for one terminal run: every published event gets the hub's next id. */
class Feed {
  events: StreamEvent[] = [];
  private id = 100;
  constructor(readonly runId = RUN, readonly pod = POD) {}
  private push(type: string, data: Record<string, unknown>): StreamEvent {
    const ev = toStreamEvent(type, data, ++this.id);
    if (!ev) throw new Error(`not a valid ${type} event: ${JSON.stringify(data)}`);
    this.events.push(ev);
    return ev;
  }
  at = (ms: number) => new Date(T0 + ms).toISOString();
  run(state: string, ms: number, detail = "", extra: Record<string, unknown> = {}) {
    // RunEvent.Detail is not omitempty: the API always sends it, "" when there is none.
    return this.push("run", { run_id: this.runId, scenario: "terminal", state, at: this.at(ms), detail, ...(state === "queued" ? {} : { pod: this.pod }), ...extra });
  }
  cmd(seq: number, id: string, state: string, ms: number, extra: Record<string, unknown> = {}) {
    return this.push("command", { run_id: this.runId, seq, id, state, at: this.at(ms), ...extra });
  }
  out(seq: number, id: string, ms: number, chunk: string, stream = "stdout") {
    return this.cmd(seq, id, "output", ms, { stream, chunk });
  }
  falco(ms: number, rule: string, seq?: number) {
    return this.push("falco", { at: this.at(ms), rule, priority: "Warning", namespace: "sandbox", pod: this.pod, output: `${rule} | k8s_pod_name=${this.pod}`, ...(seq ? { command_seq: seq } : {}) });
  }
  talon(ms: number, action: "terminate" | "label", seq?: number) {
    return this.push("talon", {
      at: this.at(ms), action: action === "terminate" ? "Terminate Pod" : "Quarantine Pod", actionner: `kubernetes:${action}`,
      namespace: "sandbox", pod: this.pod, status: "success", ...(seq ? { command_seq: seq } : {}),
    });
  }
  victim(ms: number, status: string) {
    return this.push("victim", { run_id: this.runId, pod: this.pod, at: this.at(ms), status, title: "", banner: "", probe_ms: 3, checksum: "" });
  }
  /** queued → started → pod_ready, as the runner publishes them, plus the first probe. */
  open() {
    this.run("queued", 0);
    this.run("started", 40, "pod created");
    this.run("pod_ready", 1900, "9b2e7c4d1a0f");
    this.push("victim", { run_id: this.runId, pod: this.pod, at: this.at(1950), status: "up", title: "SDP Shop", banner: "", probe_ms: 4, checksum: "5e0c1a77d3b2f190" });
    return this;
  }
  /** A command that runs and exits on its own: started, its output lines, exited with a code. */
  ran(seq: number, id: string, ms: number, lines: string[], code: number, objective: boolean, stream = "stdout") {
    this.cmd(seq, id, "started", ms);
    lines.forEach((l, i) => this.out(seq, id, ms + 10 + i, `${l}\n`, stream));
    // `achieved` is omitempty on the API: absent when false.
    this.cmd(seq, id, "exited", ms + 40, { exit_code: code, ...(objective && code === 0 ? { achieved: true } : {}) });
  }
}

interface Harness {
  root: HTMLElement;
  calls: { method: string; path: string; body?: string }[];
  show(feed: Feed | StreamEvent[], now?: number): void;
}

const flush = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
};

async function harness(opts: { start?: boolean; commandStatus?: (id: string) => [number, unknown, Record<string, string>?] } = {}): Promise<Harness> {
  const calls: Harness["calls"] = [];
  let seq = 0;
  const fetch: FetchLike = async (input, init) => {
    const path = new URL(input, "http://x").pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ method, path, body: typeof init?.body === "string" ? init.body : undefined });
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
    if (path === "/api/scenarios/terminal/details") return json(200, terminalDetails());
    if (path === "/api/posture") return json(404, { error: "not found" });
    if (method === "POST" && path === "/api/attack/terminal") return json(202, { run_id: RUN, scenario: "terminal", state: "queued", token: TOKEN });
    if (method === "POST" && path.endsWith("/commands")) {
      const id = (JSON.parse(String(init?.body)) as { id: string }).id;
      if (opts.commandStatus) {
        const [status, body, headers] = opts.commandStatus(id);
        return json(status, body, headers);
      }
      return json(202, { seq: ++seq });
    }
    if (method === "DELETE") return json(202, { state: "finishing" });
    return json(404, { error: "not found" });
  };
  const root = document.createElement("div");
  document.body.replaceChildren(root);
  const term = mountTerminal(root, new ApiClient({ fetch }));
  await flush();
  if (opts.start ?? true) {
    (root.querySelector(".term-start__btn") as HTMLButtonElement).click();
    await flush();
  }
  return {
    root,
    calls,
    show(feed, now) {
      const events = Array.isArray(feed) ? feed : feed.events;
      term.update(buildTimeline(events, now ?? T0 + 60_000));
    },
  };
}

const lines = (root: HTMLElement, seq: number) => [...root.querySelectorAll(`.term__cmd[data-seq="${seq}"] .term__cmdout .term__line`)].map((p) => p.textContent);

beforeEach(() => {
  Element.prototype.scrollIntoView = () => {};
});
afterEach(() => {
  document.body.replaceChildren();
  vi.useRealTimers();
});

describe("terminal output, as the API publishes it (review 2, item 3)", () => {
  it("puts a backfilled middle chunk in its place, once, instead of duplicating the tail", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "ps", "started", 3000);
    const a = f.out(1, "ps", 3010, "AAA\n");
    const b = f.out(1, "ps", 3011, "BBB\n");
    const c = f.out(1, "ps", 3012, "CCC\n");
    // The live feed lost B across a reconnect…
    t.show(f.events.filter((e) => e !== b));
    expect(lines(t.root, 1)).toEqual(["AAA", "CCC"]);
    // …and the backfill from /api/runs/{id} brings it back.
    t.show(f.events);
    expect(lines(t.root, 1)).toEqual(["AAA", "BBB", "CCC"]);
    expect(a.id).toBeLessThan(c.id as number);
  });

  it("keeps two identical lines: two events, two ids", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "ps", "started", 3000);
    f.out(1, "ps", 3010, "same\n");
    f.out(1, "ps", 3010, "same\n");
    t.show(f.events);
    expect(lines(t.root, 1)).toEqual(["same", "same"]);
  });

  it("orders a wholly missed command before the ones after it", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.ran(1, "whoami", 3000, ["uid=10001 gid=10001 groups=10001,42"], 0, true);
    const before = f.events.length;
    f.ran(2, "hostname", 4000, [POD], 0, true);
    const missed = f.events.slice(before);
    f.ran(3, "ps", 5000, ["PID USER TIME COMMAND"], 0, true);
    t.show(f.events.filter((e) => !missed.includes(e)));
    t.show(f.events);
    expect([...t.root.querySelectorAll(".term__cmd[data-seq]")].map((e) => e.getAttribute("data-seq"))).toEqual(["1", "2", "3"]);
  });
});
