// The node panel (src/node-panel): a diagram's boxes are interactive in the normal look as they are in
// ASCII mode. Pointing at a box (a mouse or a pen), tapping it, or focusing it (Tab, then Enter or
// Space) shows its details in the panel under the diagram: the panel slides down and fades in the first
// time, and moving to another box crossfades the content in place. It stays with the last box when the
// pointer leaves; × or Escape closes it. A box that is a link still opens its page on a click; on touch
// the first tap shows the details, and the panel's "Open →" (or a second tap) goes there.
//
// The slot is laid out at build time (markup.ts) as tall as its tallest entry, so nothing here moves
// the page; focus moves with preventScroll. Motion is styles only (node-panel.css): gone with reduced
// motion. ASCII mode keeps its own popups and hides the panel.
//
// The same directory is copied into every repository that serves a page of the site (as src/ascii is).

/** Wires every panel slot under `scope` to the diagrams in its figure. */
export function mountNodePanels(scope: ParentNode = document): void {
  for (const slot of scope.querySelectorAll<HTMLElement>(".np-slot")) mount(slot);
}

function mount(slot: HTMLElement): void {
  if (slot.dataset.ready) return;
  slot.dataset.ready = "1";
  const figure = slot.closest("figure") ?? slot.parentElement;
  const panel = slot.querySelector<HTMLElement>(".np-panel");
  const close = slot.querySelector<HTMLButtonElement>(".np-close");
  const live = slot.querySelector<HTMLElement>(".np-live");
  if (!figure || !panel || !close || !live) return;
  const items = new Map([...panel.querySelectorAll<HTMLElement>(".np-item")].map((it) => [it.dataset.for ?? "", it]));
  const nodes = [...figure.querySelectorAll<SVGElement>("svg [data-node]")].filter((n) => items.has(n.getAttribute("data-node") ?? ""));
  let open: string | null = null;
  // The last pointer that pressed a box, so a tap's focus and click can tell themselves from a mouse's.
  let touch = false;
  // While the panel hands the focus back to a box on closing, that focus must not reopen it.
  let quiet = false;

  const set = (id: string | null): void => {
    if (id === open) return;
    open = id;
    panel.dataset.open = String(id !== null);
    close.tabIndex = id === null ? -1 : 0;
    for (const [k, it] of items) {
      const on = k === id;
      it.dataset.on = String(on);
      it.setAttribute("aria-hidden", String(!on));
      for (const a of it.querySelectorAll("a")) a.tabIndex = on ? 0 : -1;
    }
    for (const n of nodes) {
      const on = n.getAttribute("data-node") === id;
      n.classList.toggle("np-on", on);
      if (n.getAttribute("role") === "button") n.setAttribute("aria-expanded", String(on));
    }
    const it = id === null ? undefined : items.get(id);
    if (it) panel.dataset.role = it.dataset.role ?? "";
    // Said once, politely: the box's name and its sentence.
    live.textContent = it ? `${it.querySelector(".np-title")?.textContent ?? ""}: ${it.querySelector(".np-text")?.textContent ?? ""}` : "";
  };

  for (const n of nodes) {
    const id = n.getAttribute("data-node") ?? "";
    const link = n.tagName.toLowerCase() === "a";
    if (!link) {
      n.setAttribute("tabindex", "0");
      n.setAttribute("role", "button");
      n.setAttribute("aria-expanded", "false");
    }
    n.setAttribute("aria-controls", slot.id);
    n.addEventListener("pointerenter", (e) => {
      if (e.pointerType === "mouse" || e.pointerType === "pen") set(id);
    });
    n.addEventListener("pointerdown", (e) => {
      touch = e.pointerType === "touch";
    });
    n.addEventListener("focus", () => {
      // A tap focuses before it clicks: the click decides, so a link's first tap shows the details.
      if (!touch && !quiet) set(id);
    });
    n.addEventListener("click", (e) => {
      const tapped = touch;
      touch = false;
      if (link && tapped && open !== id) e.preventDefault();
      set(id);
    });
    n.addEventListener("keydown", (e) => {
      if (!link && (e.key === "Enter" || e.key === " ")) {
        e.preventDefault();
        set(id);
      }
    });
  }

  // On the page and drawn: not in a closed dialog, not hidden (ASCII mode hides the slot).
  const shown = (): boolean => slot.isConnected && !slot.closest("dialog:not([open]), [hidden]") && getComputedStyle(slot).display !== "none";
  const dismiss = (): void => {
    const was = open;
    const inside = slot.contains(document.activeElement);
    set(null);
    // Back to the box whose details were open, if the panel had the focus (no scroll).
    if (inside && was) {
      quiet = true;
      nodes.find((n) => n.getAttribute("data-node") === was && n.getClientRects().length)?.focus({ preventScroll: true });
      quiet = false;
    }
  };
  close.addEventListener("click", dismiss);
  // Escape closes an open panel wherever the focus is (a hover moves none), and only the panel: inside
  // a modal dialog it would close the dialog too, so it is taken first, in the capture phase.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Escape" || open === null || !shown()) return;
      e.preventDefault();
      e.stopPropagation();
      dismiss();
    },
    true,
  );
}
