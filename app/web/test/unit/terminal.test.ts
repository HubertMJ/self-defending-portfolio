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
  term: ReturnType<typeof mountTerminal>;
  calls: { method: string; path: string; body?: string }[];
  show(feed: Feed | StreamEvent[], now?: number): void;
}

const flush = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
};

type Hooks = Parameters<typeof mountTerminal>[2];

async function harness(opts: { start?: boolean; hooks?: Hooks; details?: () => Promise<[number, unknown, string?]>; hangAttack?: boolean; timeoutMs?: number; attackStatus?: () => [number, unknown, Record<string, string>?]; commandStatus?: (id: string) => [number, unknown, Record<string, string>?] } = {}): Promise<Harness> {
  const calls: Harness["calls"] = [];
  let seq = 0;
  const fetch: FetchLike = async (input, init) => {
    const path = new URL(input, "http://x").pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ method, path, body: typeof init?.body === "string" ? init.body : undefined });
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
    if (path === "/api/scenarios/terminal/details") {
      if (opts.details) {
        const [status, body, type] = await opts.details();
        return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": type ?? "application/json" } });
      }
      return json(200, terminalDetails());
    }
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
    term,
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
    expect(foot(t.root, 1)).toContain("timed out: a command gets 5 seconds");
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

  it("a TTY shell is cut at its own 10 s bound, and says so (final review, item 3)", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "shell", "started", 3000);
    f.cmd(1, "shell", "exited", 13_010);
    t.show(f, T0 + 14_000);
    expect(foot(t.root, 1)).toContain("timed out: a command with a terminal gets 10 seconds");
  });

  it("left: told by the run's own reason, though `finished` follows the pod's deletion seconds later (item 7)", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "ps", "started", 3000);
    f.cmd(1, "ps", "exited", 3200);
    f.run("finished", 7300, "left"); // after the cleanup's delete and its wait
    t.show(f);
    expect(foot(t.root, 1)).toContain("the session was left");
  });

  it("idle and deadline end the session with their own reason", async () => {
    for (const [detail, want] of [["idle", "idle timeout"], ["deadline", "300-second deadline"]]) {
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

describe("untrusted output in .term__out (review 2, item 11)", () => {
  it("markup and control characters arrive as text, never as elements or escapes", async () => {
    const t = await harness();
    const f = new Feed().open();
    f.cmd(1, "ls-shop", "started", 3000);
    f.out(1, "ls-shop", 3010, '<img src=x onerror="alert(1)"><script>alert(2)</script>&amp;\n');
    f.out(1, "ls-shop", 3011, "\u001b[31mred\u001b[0m\r‮evil‬​zero\u0007bell\ttab\n", "stderr");
    t.show(f);
    const out = t.root.querySelector(".term__out") as HTMLElement;
    expect(out.querySelector("img, script")).toBeNull();
    const [markup, controls] = lines(t.root, 1);
    expect(markup).toBe('<img src=x onerror="alert(1)"><script>alert(2)</script>&amp;');
    expect(controls).toBe("[31mred[0mevilzerobell\ttab");
    expect(controls).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f​‪-‮]/);
  });
});

describe("what 'reached' means in the summary (cross-side point)", () => {
  it("an objective reached by a command that exited 0 before the kill says how long the pod lasted after", async () => {
    const t = await harness();
    const f = new Feed().open();
    killedBy(f, 1, 3000); // `cat /etc/shadow` exits at 3 040 ms, the run ends at 3 600 ms
    t.show(f);
    const items = [...t.root.querySelectorAll(".term__sumreached li")].map((li) => text(li));
    expect(items).toEqual(["Steal credentials — cat /etc/shadow exited 0; the pod was deleted 560 ms after that exit."]);
    expect(stat(t.root, "Objectives reached")).toBe("1 of 5");
  });
});

describe("Tab and the completion hint (review 2, item 14)", () => {
  const tab = (input: HTMLInputElement) => {
    const e = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    input.dispatchEvent(e);
    return e.defaultPrevented; // true: Tab stayed in the input
  };

  it("never traps focus on a complete command that is also a prefix of another", async () => {
    const t = await harness();
    t.show(new Feed().open());
    const input = t.root.querySelector("#term-input") as HTMLInputElement;
    for (const typed of ["ps", "wget", "id"]) {
      input.value = typed;
      expect(tab(input), typed).toBe(false);
      expect(input.value).toBe(typed);
    }
    // A partial word is completed (Tab stays), then the next Tab moves on.
    input.value = "wg";
    expect(tab(input)).toBe(true);
    expect(input.value).toBe("wget");
    expect(tab(input)).toBe(false);
    // An ambiguous prefix lists its choices once, then lets Tab go.
    input.value = "c";
    expect(tab(input)).toBe(true);
    expect(tab(input)).toBe(false);
  });

  it("tells a screen reader through a region that is always live, not by toggling aria-live", async () => {
    const t = await harness();
    t.show(new Feed().open());
    const input = t.root.querySelector("#term-input") as HTMLInputElement;
    const live = [...t.root.querySelectorAll('[aria-live="polite"]')].find((e) => e.classList.contains("visually-hidden")) as HTMLElement;
    expect(live).toBeDefined();
    expect(t.root.querySelector(".term__hint")?.hasAttribute("aria-live")).toBe(false);
    input.value = "ch";
    input.dispatchEvent(new Event("input"));
    expect(live.textContent).toBe(""); // typing alone is not read out
    tab(input);
    expect(live.textContent).toContain("chown 0 /srv/shop/index.html");
  });
});

describe("the catalogue arriving after a watched run (final review, item 1)", () => {
  it("fills the read-only session in instead of replacing it with the start panel", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = await harness({ start: false, details: async () => (await gate, [200, terminalDetails()]) });
    const f = new Feed().open();
    f.ran(1, "whoami", 3000, ["uid=10001"], 0, true);
    t.show(f); // the stream's replay beats GET …/details
    const status = t.root.querySelector(".term__status");
    expect(text(status)).toContain("read-only");
    release();
    await flush();
    expect(t.root.querySelector(".term-start")).toBeNull();
    expect(status?.isConnected).toBe(true);
    expect(t.root.querySelectorAll(".term__obj")).toHaveLength(5);
    expect(text(t.root.querySelector(".term__objhead"))).toContain("1/5");
    // Later events still land in the page, not in detached nodes.
    f.ran(2, "hostname", 4000, [POD], 0, true);
    t.show(f);
    expect(lines(t.root, 2)).toEqual([POD]);
  });
});

describe("a catalogue that fails to load (final review, item 2)", () => {
  for (const [what, answer] of [
    ["a 5xx", [503, { error: "unavailable" }]],
    ["the request limiter's 429", [429, { error: "too many requests" }]],
    ["a non-JSON 404 (no API behind /api)", [404, "not found\n", "text/plain"]],
  ] as const) {
    it(`${what}: an offline state that retries, and the page is not degraded`, async () => {
      const available: boolean[] = [];
      let calls = 0;
      const t = await harness({ start: false, hooks: { onAvailable: (a) => available.push(a) }, details: async () => (calls++ === 0 ? [...answer] as [number, unknown, string?] : [200, terminalDetails()]) });
      expect(available).toEqual([]);
      expect(text(t.root)).toContain("cannot reach the API");
      (t.root.querySelector(".offline button") as HTMLButtonElement).click();
      await flush();
      expect(available).toEqual([true]);
      expect(t.root.querySelector(".term-start__btn")).not.toBeNull();
    });
  }

  it("a JSON 404 (an API without the terminal) degrades", async () => {
    const available: boolean[] = [];
    await harness({ start: false, hooks: { onAvailable: (a) => available.push(a) }, details: async () => [404, { error: "unknown scenario" }] });
    expect(available).toEqual([false]);
  });
});

describe("tests that must survive mutation (final review, item 5)", () => {
  it("orders same-millisecond output by event id when a backfill brings the middle chunk last", () => {
    const f = new Feed().open();
    f.cmd(1, "ps", "started", 3000);
    const a = f.out(1, "ps", 3010, "A\n");
    const b = f.out(1, "ps", 3010, "B\n");
    const c = f.out(1, "ps", 3010, "C\n");
    // The live feed delivered A and C; B arrives from /api/runs/{id} afterwards, same millisecond.
    const log = f.events.filter((e) => e !== b).concat(b);
    const run = buildTimeline(log, T0 + 60_000).runs[0];
    expect(run.commands[0].stdout).toBe("A\nB\nC\n");
    expect([a.id, b.id, c.id]).toEqual([...[a.id, b.id, c.id]].sort((x, y) => (x as number) - (y as number)));
  });

  it("names the first quarantine, the one that cut the pod off, when there were two", async () => {
    const t = await harness();
    const f = new Feed().open();
    quarantined(f, 1, 3000); // 220 ms after its Enter
    f.ran(2, "beacon", 6000, ["wget: can't connect"], 1, true, "stderr");
    f.talon(6300, "label", 2);
    f.run("responded", 6400, "quarantine", { command_seq: 2 }); // 400 ms after its Enter
    killedBy(f, 3, 9000);
    t.show(f);
    expect(stat(t.root, "Quarantined after your Enter")).toBe("220 ms");
  });
});

describe("a 404 for a command (final review, item 7)", () => {
  it("says the API does not know the command, not that the run has ended", async () => {
    let body = "unknown command";
    const t = await harness({ commandStatus: () => [404, { error: body }] });
    t.show(new Feed().open());
    chips(t.root)[0].click();
    await flush();
    expect(text(t.root.querySelector(".term__out"))).toContain("does not know that command");
    body = "unknown run";
    chips(t.root)[1].click();
    await flush();
    expect(text(t.root.querySelector(".term__out"))).toContain("the run has ended");
  });
});

describe("a run history the API had to cut short (final review, item 7)", () => {
  it("is said in the terminal of that run, once", async () => {
    const t = await harness({ start: false });
    t.show(new Feed().open());
    t.term.historyTruncated("ffffffffffffffff"); // another run: nothing
    t.term.historyTruncated(RUN);
    t.term.historyTruncated(RUN);
    const notes = [...t.root.querySelectorAll(".term__out .term__line--sys")].filter((p) => /only part of this run's history/.test(p.textContent ?? ""));
    expect(notes).toHaveLength(1);
  });
});

describe("long command lines (final review, item 7)", () => {
  it("offer a line break after each '/' and ';', with the text itself unchanged", async () => {
    const t = await harness();
    t.show(new Feed().open());
    const deface = chips(t.root).find((b) => b.textContent?.startsWith("echo pwned"))!;
    expect(deface.textContent).toBe(`echo pwned>/srv/shop/index.html;echo '{"status":"defaced"}'>/srv/shop/state.json`);
    const wbr = deface.querySelectorAll("wbr");
    expect(wbr.length).toBe(7); // 6 slashes, 1 semicolon
    for (const w of wbr) expect(w.previousSibling?.textContent).toMatch(/[/;]$/);
  });
});
