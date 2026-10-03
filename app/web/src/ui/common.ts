import { isCommit, isRepoPath } from "../lib/contract";
import { h } from "../lib/dom";
import type { ConnectionState } from "../lib/sse";

/** The shared "this panel's data source is not reachable" state. The page around it keeps working. */
export function offlinePanel(opts: { title: string; body: string; detail?: string; onRetry?: () => void }): HTMLElement {
  return h(
    "div",
    { class: "offline", role: "status" },
    h("p", { class: "offline__title" }, h("span", { class: "offline__icon", "aria-hidden": "true" }, "⌁"), opts.title),
    h("p", { class: "offline__body" }, opts.body),
    opts.detail ? h("p", { class: "offline__detail" }, h("code", {}, opts.detail)) : null,
    opts.onRetry ? retryButton(opts.onRetry) : null,
  );
}

function retryButton(onRetry: () => void): HTMLButtonElement {
  const b = h("button", { type: "button", class: "btn btn--ghost" }, "Retry now");
  b.addEventListener("click", onRetry);
  return b;
}

/**
 * A command line with a line-break opportunity (<wbr>) after each "/" and ";": a long one wraps at a
 * path or statement boundary rather than mid-word. The text, and what is copied, is unchanged.
 */
export function breakable(line: string): (string | HTMLElement)[] {
  return line.split(/(?<=[/;])/).flatMap((part, i) => (i ? [h("wbr"), part] : [part]));
}

/** MITRE ATT&CK technique page for an id like T1059 or T1059.004; null if the id is malformed. */
export function attackUrl(technique: string): string | null {
  const m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(technique.trim());
  if (!m) return null;
  return `https://attack.mitre.org/techniques/T${m[1]}/${m[2] ? `${m[2]}/` : ""}`;
}

/** Where every source link points: the repository at the exact commit the API was built from. */
export const REPO_URL = "https://github.com/HubertMJ/self-defending-portfolio";

/** A link to a file (and line) of the repository at a commit; null if anything looks forged. */
export function sourceUrl(commit: string, file: string, line?: number): string | null {
  if (!isCommit(commit) || !isRepoPath(file)) return null;
  return `${REPO_URL}/blob/${commit}/${file}${line && line > 0 ? `#L${Math.floor(line)}` : ""}`;
}

/** An external link that says it opens a new tab, to screen readers too. */
export function extLink(href: string, ...text: (Node | string)[]): HTMLAnchorElement {
  return h("a", { href, rel: "noopener noreferrer", target: "_blank" }, ...text, h("span", { class: "visually-hidden" }, " (opens in a new tab)"));
}

/** A "Copy" button for a command; says "Copied" for a moment, or selects nothing and says why. */
export function copyButton(text: () => string, label = "Copy"): HTMLButtonElement {
  const b = h("button", { type: "button", class: "btn btn--ghost btn--small copy" }, label);
  b.addEventListener("click", () => {
    const done = (msg: string) => {
      b.textContent = msg;
      setTimeout(() => (b.textContent = label), 1600);
    };
    if (!navigator.clipboard) return done("Copy unavailable");
    navigator.clipboard.writeText(text()).then(
      () => done("Copied"),
      () => done("Copy blocked"),
    );
  });
  return b;
}

/**
 * Connection wording shared by the header pill and the timeline, so the two never disagree: the same
 * four words, the long form adding what it means for the visitor.
 */
export const CONNECTION_WORD: Record<ConnectionState, string> = {
  connecting: "connecting",
  open: "live",
  reconnecting: "reconnecting",
  offline: "offline",
};

export const CONNECTION_LONG: Record<ConnectionState, string> = {
  connecting: "Connecting to the cluster’s event stream…",
  open: "Live: events appear as the cluster reports them",
  reconnecting: "Reconnecting: the event stream dropped",
  offline: "Offline: the event stream is unreachable",
};
