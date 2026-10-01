import { h } from "../lib/dom";

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

/** MITRE ATT&CK technique page for an id like T1059 or T1059.004; null if the id is malformed. */
export function attackUrl(technique: string): string | null {
  const m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(technique.trim());
  if (!m) return null;
  return `https://attack.mitre.org/techniques/T${m[1]}/${m[2] ? `${m[2]}/` : ""}`;
}
