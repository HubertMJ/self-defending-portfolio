// The one door from the page to the in-page mock (ADR 0035, amending ADR 0033). main.ts imports this
// module and nothing else of the mock; the production build (scripts/build.mjs without --mock)
// resolves the import to mock-hook.prod.ts instead, so MockBackend, the fixtures and the terminal
// catalogue never reach the shipped bundle. A `define` flag with a dead branch would not do: esbuild
// keeps a module's top-level code (fixtures.ts has some) whenever the module is imported at all.
// The unit bundle test, the image smoke test and the live check grep the bundle for the mock's markers.

import type { FetchLike } from "./api";
import { byId, h } from "./dom";
import { MockBackend, mockOptionsFromUrl } from "./mock";
import type { EventSourceFactory } from "./sse";

/**
 * The two seams the mock plugs into (the client's fetch and the stream's EventSource factory), and
 * the words the page uses instead of "cluster" and "Live" while it shows the mock's data.
 */
export interface MockHook {
  fetch: FetchLike;
  eventSource: EventSourceFactory;
  /** In front of the connection word in the header: "cluster live" is never claimed for the mock. */
  headerWord: string;
  /** The hero counters' label. */
  statsLabel: string;
}

/** `?mock=1` (dev and test builds only): the mock backend, its banner shown; otherwise null. */
export function installMock(search: string): MockHook | null {
  const opts = mockOptionsFromUrl(search);
  if (!opts) return null;
  const mock = new MockBackend(opts);
  // The banner's styles ship only with the mock build (scripts/build.mjs copies src/mock.css).
  document.head.append(h("link", { rel: "stylesheet", href: "/assets/mock.css" }));
  const banner = byId("mock-banner");
  banner.hidden = false;
  // Into the sticky header: a page opened at #attack scrolls past where the banner sits.
  document.querySelector(".site-header")?.append(banner);
  document.documentElement.dataset.mock = "true";
  // The mock answers in-page, so the network never sees a request: its own call log is what the
  // end-to-end tests read to check what the page sent.
  (window as unknown as { sdpMock: MockBackend }).sdpMock = mock;
  return { fetch: mock.fetch, eventSource: mock.eventSource, headerWord: "mock ·", statsLabel: "Mock data — across every visitor" };
}
