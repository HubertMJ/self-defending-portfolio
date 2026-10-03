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
  constructor(readonly runId = RUN, readonly pod = POD, readonly scenario = "terminal") {}
  private push(type: string, data: Record<string, unknown>): StreamEvent {
    const ev = toStreamEvent(type, data, ++this.id);
    if (!ev) throw new Error(`not a valid ${type} event: ${JSON.stringify(data)}`);
    this.events.push(ev);
    return ev;
  }
  at = (ms: number) => new Date(T0 + ms).toISOString();
  run(state: string, ms: number, detail = "", extra: Record<string, unknown> = {}) {
    // RunEvent.Detail is not omitempty: the API always sends it, "" when there is none.
    return this.push("run", { run_id: this.runId, scenario: this.scenario, state, at: this.at(ms), detail, ...(state === "queued" ? {} : { pod: this.pod }), ...extra });
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

type Hooks = Parameters<typeof mountTerminal>[2];

async function harness(opts: { start?: boolean; hooks?: Hooks; hangAttack?: boolean; timeoutMs?: number; attackStatus?: () => [number, unknown, Record<string, string>?]; commandStatus?: (id: string) => [number, unknown, Record<string, string>?] } = {}): Promise<Harness> {
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
    if (method === "POST" && path === "/api/attack/terminal" && opts.hangAttack) {
      // The server takes the request and never answers in time: the client's own timeout aborts it.
      return new Promise<Response>((_, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    }
    if (method === "POST" && path === "/api/attack/terminal") {
      if (opts.attackStatus) {
        const [status, body, headers] = opts.attackStatus();
        return json(status, body, headers);
      }
      return json(202, { run_id: RUN, scenario: "terminal", state: "queued", token: TOKEN });
    }
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
  const term = mountTerminal(root, new ApiClient({ fetch, timeoutMs: opts.timeoutMs }), opts.hooks);
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

const text = (el: Element | null) => (el?.textContent ?? "").replace(/\s+/g, " ").trim();
const stat = (root: HTMLElement, label: string) => {
  const dt = [...root.querySelectorAll(".term__sumstats dt")].find((d) => d.textContent === label);
  return dt?.nextElementSibling?.textContent ?? undefined;
};
const ended = (root: HTMLElement) => [...root.querySelectorAll(".term__summary .deflayer__entry")].filter((e) => e.querySelector(".deflayer__ended")).map((e) => e.querySelector("code")?.textContent);
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

/** `wget` (exit 1) → Falco → detected → Talon label → responded quarantine, all on command_seq 1. */
function quarantined(f: Feed, seq: number, ms: number, withSeq = true) {
  f.ran(seq, "beacon", ms, ["wget: can't connect to remote host (127.0.0.1): Connection refused"], 1, true, "stderr");
  const s = withSeq ? seq : undefined;
  f.falco(ms + 60, "SDP network tool in sandbox", s);
  f.run("detected", ms + 75, "SDP network tool in sandbox", s ? { command_seq: s } : {});
  f.talon(ms + 210, "label", s);
  f.run("responded", ms + 220, withSeq ? "quarantine" : "", s ? { command_seq: s } : {});
  f.victim(ms + 900, "unreachable");
}

/** `cat /etc/shadow` exits 0 (the read lands first), then Falco, Talon's terminate, the kill. */
function killedBy(f: Feed, seq: number, ms: number, withSeq = true) {
  f.ran(seq, "read-shadow", ms, ["root:*:19000:0:::::"], 0, true);
  const s = withSeq ? seq : undefined;
  f.falco(ms + 30, "Read sensitive file untrusted", s);
  f.run("detected", ms + 50, "Read sensitive file untrusted", s ? { command_seq: s } : {});
  f.talon(ms + 140, "terminate", s);
  f.run("responded", ms + 150, withSeq ? "terminate" : "", s ? { command_seq: s } : {});
  f.victim(ms + 400, "gone");
  f.run("finished", ms + 600, "killed");
}

describe("the session summary (review 2, item 1)", () => {
  it("a single terminate: the command that did it, killed N ms after its Enter, Falco to response", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.ran(1, "whoami", 3000, ["uid=10001"], 0, true);
    killedBy(f, 2, 5000);
    t.show(f.events);
    expect(t.root.querySelector(".term__summary")?.hasAttribute("hidden")).toBe(false);
    expect(ended(t.root)).toEqual(["cat /etc/shadow"]);
    expect(stat(t.root, "Killed after your Enter")).toBe("150 ms");
    expect(stat(t.root, "Falco to response")).toBe("120 ms");
    expect(stat(t.root, "Quarantined after your Enter")).toBeUndefined();
    expect(text(t.root.querySelector(".term__sumlead"))).toContain("after cat /etc/shadow");
  });

  it("quarantine then terminate: the terminate ends the session, the quarantine is its own line", async () => {
    const t = await harness();
    const f = new Feed().open();
    quarantined(f, 1, 3000);
    f.ran(2, "whoami", 6000, ["uid=10001"], 0, true);
    killedBy(f, 3, 8000);
    t.show(f.events);
    // `wget` did not end the session; `cat /etc/shadow` did.
    expect(ended(t.root)).toEqual(["cat /etc/shadow"]);
    expect(stat(t.root, "Killed after your Enter")).toBe("150 ms");
    expect(stat(t.root, "Quarantined after your Enter")).toBe("220 ms");
    expect(stat(t.root, "Falco to response")).toBe("120 ms");
    const lead = text(t.root.querySelector(".term__sumlead"));
    expect(lead).toContain("Quarantined after wget");
    expect(lead).toContain("after cat /etc/shadow");
  });

  it("without command_seq, ties each response to the last command started before it", async () => {
    const t = await harness();
    const f = new Feed().open();
    quarantined(f, 1, 3000, false);
    killedBy(f, 2, 8000, false);
    t.show(f.events);
    expect(ended(t.root)).toEqual(["cat /etc/shadow"]);
    // A `responded` tied to no command carries no action either, so Talon's own terminate is the time.
    expect(stat(t.root, "Killed after your Enter")).toBe("140 ms");
    expect(stat(t.root, "Quarantined after your Enter")).toBe("210 ms");
  });

  it("never prints 0 ms: a response stamped before the command's start is left out", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.ran(1, "read-shadow", 5000, ["root:*:19000:0:::::"], 0, true);
    f.talon(4990, "terminate", 1);
    f.run("responded", 5000, "terminate", { command_seq: 1 });
    f.run("finished", 5600, "killed");
    t.show(f.events);
    expect(ended(t.root)).toEqual(["cat /etc/shadow"]);
    expect(stat(t.root, "Killed after your Enter")).toBeUndefined();
    expect(text(t.root.querySelector(".term__summary"))).not.toMatch(/\b0 ms/);
  });
});

const foot = (root: HTMLElement, seq: number) => text(root.querySelector(`.term__cmd[data-seq="${seq}"] .term__cmdfoot`));
const sideLayer = (root: HTMLElement, layer: string) => root.querySelector(`.term__map .deflayer[data-layer="${layer}"]`)?.getAttribute("data-state");

describe("a command that exited without an exit code (review 2, item 2)", () => {
  it("cut off by the 5 s limit: finished, explained, its layer lit, the input free again", async () => {
    const t = await harness();
    const f = new Feed().open();
    t.show(f);
    (t.root.querySelector(".term__chip") as HTMLButtonElement).click(); // `id`
    await flush();
    expect(t.calls.filter((c) => c.method === "POST" && c.path.endsWith("/commands"))).toHaveLength(1);
    expect((t.root.querySelector(".term__send") as HTMLButtonElement).disabled).toBe(true);
    f.cmd(1, "whoami", "started", 3000);
    f.cmd(1, "whoami", "exited", 8010); // no exit_code: the API's own timeout
    t.show(f);
    expect(foot(t.root, 1)).toContain("timed out");
    expect(sideLayer(t.root, "runtime")).toBe("allowed");
    expect((t.root.querySelector(".term__send") as HTMLButtonElement).disabled).toBe(false);
  });

  it("stopped by leaving: says so, and the summary says the visitor left", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "ps", "started", 3000);
    f.out(1, "ps", 3010, "PID USER TIME COMMAND\n");
    t.show(f);
    f.cmd(1, "ps", "exited", 3200);
    f.run("finished", 3300, "left");
    t.show(f);
    expect(foot(t.root, 1)).toContain("the session was left");
    expect(text(t.root.querySelector(".term__sumlead"))).toContain("You left");
  });

  it("idle and deadline end the session with their own reason", async () => {
    for (const [detail, want] of [["idle", "idle timeout"], ["deadline", "120-second deadline"]]) {
      const t = await harness();
      const f = new Feed().open();
      f.ran(1, "whoami", 3000, ["uid=10001"], 0, true);
      f.run("finished", detail === "idle" ? 33_100 : 120_000, detail);
      t.show(f, T0 + 200_000);
      expect(text(t.root.querySelector(".term__sumlead"))).toContain(want);
      expect(stat(t.root, "Killed after your Enter")).toBeUndefined();
      expect(ended(t.root)).toEqual([]);
    }
  });
});

describe("the start panel between sessions (review 2, item 5)", () => {
  it("is patched in place: the focused button and its note survive every event of the feed", async () => {
    let busy = false;
    const t = await harness({ start: false, hooks: { blocked: () => (busy ? "A run is in progress" : null) }, attackStatus: () => [409, { error: "another attack is running; watch it on the live feed" }] });
    const btn = t.root.querySelector(".term-start__btn") as HTMLButtonElement;
    btn.focus();
    btn.click();
    await flush();
    expect(text(t.root.querySelector(".term-start__blocked"))).toContain("Another run is in progress");
    // Another visitor's one-click run streams in: events arrive, the start stays blocked.
    busy = true;
    const other = new Feed("1111222233334444", "network-tool-1111222233", "network-tool").open();
    for (let i = 0; i < 5; i++) t.show(other);
    expect(t.root.querySelector(".term-start__btn")).toBe(btn);
    expect(document.activeElement).toBe(btn);
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    expect(text(btn)).toContain("A run is in progress");
    expect(text(t.root.querySelector(".term-start__blocked"))).toContain("Another run is in progress");
  });

  it("unlocks by itself when a cooldown ends on a quiet page, and a blocked press says why", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(T0);
    const until = T0 + 3000;
    const left = () => Math.max(0, Math.ceil((until - Date.now()) / 1000));
    const t = await harness({ start: false, hooks: { blocked: () => (left() > 0 ? "Rate limited" : null), cooldownSeconds: left } });
    const btn = t.root.querySelector(".term-start__btn") as HTMLButtonElement;
    expect(text(btn)).toContain("Rate limited");
    btn.click();
    await flush();
    expect(text(t.root.querySelector(".term-start__blocked"))).toContain("you can start again in 3 s");
    expect(t.calls.some((c) => c.path === "/api/attack/terminal")).toBe(false);
    vi.advanceTimersByTime(3100); // no event, no update() call
    expect(text(btn)).toContain("Open the terminal");
    expect(btn.getAttribute("aria-disabled")).toBe("false");
  });
});

const posts = (t: Harness) => t.calls.filter((c) => c.method === "POST" && c.path.endsWith("/commands"));
const deletes = (t: Harness) => t.calls.filter((c) => c.method === "DELETE");
const chips = (root: HTMLElement) => [...root.querySelectorAll<HTMLButtonElement>(".term__chip")];
const send = (root: HTMLElement) => root.querySelector(".term__send") as HTMLButtonElement;

describe("one command at a time (review 2, items 7 and 12)", () => {
  it("frees the input when the command's end arrives before its 202", async () => {
    const t = await harness();
    const f = new Feed().open();
    t.show(f);
    chips(t.root)[0].click(); // POST sent; its 202 is still on the way…
    f.ran(1, "whoami", 3000, ["uid=10001"], 0, true); // …when the whole command has already run
    t.show(f);
    await flush(); // now the 202 arrives, and nothing else will
    expect(posts(t)).toHaveLength(1);
    expect(send(t.root).disabled).toBe(false);
    expect(chips(t.root).every((b) => !b.disabled)).toBe(true);
  });

  it("a second tap before the 202 sends nothing", async () => {
    const t = await harness();
    t.show(new Feed().open());
    chips(t.root)[0].click();
    chips(t.root)[1].click();
    await flush();
    expect(posts(t)).toHaveLength(1);
  });

  it("offers nothing before pod_ready or after the end; Leave rests after the end", async () => {
    const t = await harness();
    const f = new Feed();
    f.run("queued", 0);
    f.run("started", 40, "pod created");
    t.show(f);
    expect(chips(t.root).every((b) => b.disabled)).toBe(true);
    expect((t.root.querySelector("#term-input") as HTMLInputElement).disabled).toBe(true);
    f.run("pod_ready", 1900, "9b2e7c4d1a0f");
    t.show(f);
    expect(chips(t.root).every((b) => !b.disabled)).toBe(true);
    killedBy(f, 1, 3000);
    t.show(f);
    expect(chips(t.root).every((b) => b.disabled)).toBe(true);
    expect((t.root.querySelector(".term__exit") as HTMLButtonElement).disabled).toBe(true);
  });

  it("pagehide leaves once while live, never after the end, never again after a back/forward restore", async () => {
    const t = await harness();
    const f = new Feed().open();
    t.show(f);
    dispatchEvent(new Event("pagehide"));
    dispatchEvent(new Event("pagehide")); // hidden again after a bfcache restore
    await flush();
    expect(deletes(t)).toHaveLength(1);

    const u = await harness();
    const g = new Feed().open();
    g.run("finished", 5000, "idle");
    u.show(g);
    dispatchEvent(new Event("pagehide"));
    await flush();
    expect(deletes(u)).toHaveLength(0);
  });

  it("`exit` ends the session, as in a shell", async () => {
    const t = await harness();
    t.show(new Feed().open());
    const input = t.root.querySelector("#term-input") as HTMLInputElement;
    input.value = "exit";
    input.form?.requestSubmit();
    await flush();
    expect(deletes(t)).toHaveLength(1);
    expect(posts(t)).toHaveLength(0);
    expect(text(t.root.querySelector(".term__out"))).not.toContain("not in this sandbox's catalogue");
  });
});

describe("what the terminal tells the visitor (review 2, item 12)", () => {
  it("a watcher reads about someone else: no 'You will be uid 10001', no 'your Enter'", async () => {
    const t = await harness({ start: false });
    const f = new Feed().open();
    t.show(f);
    expect(text(t.root.querySelector(".term__status"))).toContain("read-only");
    const banner = text(t.root.querySelector(".term__out .term__line--sys"));
    expect(banner).toContain("Another visitor's session");
    expect(banner).not.toMatch(/\bYou\b/);
    killedBy(f, 1, 3000);
    t.show(f);
    expect(text(t.root.querySelector(".term__sumlead"))).toContain("under them");
    expect(stat(t.root, "Killed after their Enter")).toBe("150 ms");
    expect(stat(t.root, "Killed after your Enter")).toBeUndefined();
  });

  it("a failed or timed-out run says why", async () => {
    const t = await harness();
    const f = new Feed();
    f.run("queued", 0);
    f.run("started", 40, "pod created");
    f.run("timeout", 120_000, "pod did not become ready in time");
    t.show(f, T0 + 130_000);
    expect(text(t.root.querySelector(".term__sumlead"))).toBe("The session could not run: pod did not become ready in time.");
  });

  it("'Survived' counts from pod_ready, when the pod could first take a command", async () => {
    const t = await harness();
    const f = new Feed().open(); // pod_ready at 1 900 ms
    killedBy(f, 1, 3000); // finished at 3 600 ms
    t.show(f);
    expect(stat(t.root, "Survived")).toBe("1.7 s");
  });

  it("tells the run's command budget from the request limiter by the 429's body", async () => {
    let body = "too many commands in this run";
    const t = await harness({ commandStatus: () => [429, { error: body }, { "Retry-After": "1" }] });
    const f = new Feed().open();
    t.show(f);
    chips(t.root)[0].click();
    await flush();
    expect(text(t.root.querySelector(".term__out"))).toContain("the most commands a session allows");
    body = "too many requests";
    chips(t.root)[1].click();
    await flush();
    expect(text(t.root.querySelector(".term__out"))).toContain("too many requests from your address");
  });

  it("a start that timed out explains the read-only run that may follow", async () => {
    const t = await harness({ start: false, hangAttack: true, timeoutMs: 20 });
    (t.root.querySelector(".term-start__btn") as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 60));
    expect(text(t.root.querySelector(".term-start__blocked"))).toContain("The start request timed out");
    t.show(new Feed().open());
    expect(text(t.root.querySelector(".term__status"))).toContain("the start timed out");
    expect(text(t.root.querySelector(".term__out .term__line--sys"))).toContain("may be the run you just started");
  });
});

describe("joining a terminal run mid-session (review 2, item 6)", () => {
  it("shows the watcher's view though the replay held none of the run's start", async () => {
    const t = await harness({ start: false });
    const f = new Feed().open();
    quarantined(f, 1, 3000);
    f.ran(2, "whoami", 6000, ["uid=10001"], 0, true);
    // Only what a 50-event replay still holds: everything from the quarantine's `responded` on.
    const cut = f.events.findIndex((e) => e.type === "run" && e.data.state === "responded");
    t.show(f.events.slice(cut), T0 + 7000);
    expect(text(t.root.querySelector(".term__status"))).toContain("read-only");
    expect(lines(t.root, 2)).toEqual(["uid=10001"]);
  });
});
