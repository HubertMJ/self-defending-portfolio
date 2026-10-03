// The defence map (ADR 0033, part D). The static "How it works" list becomes a live diagram of the
// seven layers an attack has to pass. In the terminal it doubles as the result view: every finished
// command lights the layer that answered it, with the verdict and the one-line control.
//
// Layers a visitor in a pod can actually reach from inside it (network, pod security, runtime) light
// up from what they typed. The four they never get to try (edge, host, supply chain, admission) are
// shown as exactly that — with their standing evidence from GET /api/posture, so the map is honest
// about what the terminal does and does not exercise.

import type { CommandOutcome, DefenceLayer, Posture } from "../lib/contract";
import { DEFENCE_LAYERS } from "../lib/contract";
import { h, replace } from "../lib/dom";
import type { ApiClient, Result } from "../lib/api";

export interface LayerMeta {
  id: DefenceLayer;
  title: string;
  blurb: string;
  controls: string[];
  /** "pod": a command in the pod can reach it. "outside": it acts before the pod exists. */
  reach: "pod" | "outside";
  /** Standing evidence for an "outside" layer, drawn from the posture report. */
  evidence?: (p: Posture) => string | null;
}

const pct = (p: Posture): number => {
  const kb = p.kube_bench;
  const scored = kb.pass + kb.fail + kb.warn;
  return scored ? Math.round((kb.pass / scored) * 100) : 0;
};
const kyPass = (p: Posture): { pass: number; fail: number } =>
  p.kyverno.policies.reduce((a, x) => ({ pass: a.pass + x.pass, fail: a.fail + x.fail }), { pass: 0, fail: 0 });

export const LAYERS: LayerMeta[] = [
  {
    id: "edge",
    title: "Edge",
    blurb: "Cloudflare Tunnel: the cluster opens no inbound port. TLS, HSTS and a WAF terminate at the edge.",
    controls: ["Cloudflare Tunnel", "no inbound ports", "WAF · TLS · HSTS"],
    reach: "outside",
  },
  {
    id: "host",
    title: "Host",
    blurb: "A Debian VM hardened by Ansible: SSH lockdown, an nftables default-deny firewall, sysctl, auditd.",
    controls: ["nftables default-deny", "SSH lockdown", "auditd"],
    reach: "outside",
    evidence: (p) => `CIS benchmark ${pct(p)}% passing (kube-bench)`,
  },
  {
    id: "network",
    title: "Network",
    blurb: "Cilium is the CNI: default-deny between pods, and a quarantine policy can cut a pod off entirely, both ways.",
    controls: ["default-deny NetworkPolicies", "Cilium quarantine"],
    reach: "pod",
  },
  {
    id: "supply-chain",
    title: "Supply chain",
    blurb: "Images are built in CI, Trivy-gated, SBOM-attested and cosign keyless-signed. Anything unsigned is refused.",
    controls: ["Trivy gate", "cosign signatures", "SBOM"],
    reach: "outside",
    evidence: (p) => `${p.trivy.images} running images scanned${p.trivy.own ? `; this project's own: ${p.trivy.own.critical + p.trivy.own.high} critical+high` : ""}`,
  },
  {
    id: "admission",
    title: "Admission",
    blurb: "Kyverno at admission: Pod Security restricted, pinned digests, no :latest, mandatory resource limits, signed images only.",
    controls: ["Pod Security restricted", "verify-portfolio-images", "require-pod-resources"],
    reach: "outside",
    evidence: (p) => {
      const k = kyPass(p);
      return `${k.pass} admission checks passing, ${k.fail} failing`;
    },
  },
  {
    id: "pod-security",
    title: "Pod security",
    blurb: "What the pod is allowed to be: non-root, a read-only root filesystem, every Linux capability dropped, no service-account token, seccomp on.",
    controls: ["non-root", "read-only rootfs", "no capabilities", "no token"],
    reach: "pod",
  },
  {
    id: "runtime",
    title: "Runtime",
    blurb: "Falco watches syscalls over eBPF; Falcosidekick fans the alerts out; Falco Talon terminates or quarantines the pod.",
    controls: ["Falco (eBPF)", "Falco Talon"],
    reach: "pod",
  },
];

const byId = new Map(LAYERS.map((l) => [l.id, l]));

/** One command that reached a layer: its own verdict, and whether it ended the session. */
export interface LitEntry {
  input: string;
  outcome: CommandOutcome;
  control: string;
  ended: boolean;
}

/** What lit a layer in the terminal: every command that reached it, each with its own verdict. */
export interface LitLayer {
  /** The strongest verdict at this layer, for the card's colour. */
  outcome: CommandOutcome;
  entries: LitEntry[];
}

const OUTCOME_WORD: Record<CommandOutcome, string> = { allowed: "allowed", prevented: "prevented", detected: "detected" };

export function renderDefenceMap(opts: { posture?: Posture; lit?: Map<DefenceLayer, LitLayer>; heading?: string } = {}): HTMLElement {
  const lit = opts.lit;
  const live = lit !== undefined;
  const items = DEFENCE_LAYERS.map((id) => layerCard(byId.get(id) as LayerMeta, opts.posture, lit?.get(id), live));
  return h(
    "div",
    { class: "defmap", "data-mode": live ? "result" : "static" },
    opts.heading ? h("h4", { class: "defmap__heading" }, opts.heading) : null,
    h("ol", { class: "defmap__layers", role: "list" }, items),
  );
}

function layerCard(meta: LayerMeta, posture: Posture | undefined, lit: LitLayer | undefined, live: boolean): HTMLElement {
  const state = lit ? lit.outcome : meta.reach === "outside" && live ? "out-of-reach" : "idle";
  const ev = meta.evidence && posture ? meta.evidence(posture) : null;
  return h(
    "li",
    { class: `deflayer deflayer--${meta.reach}`, "data-layer": meta.id, "data-state": state },
    h(
      "div",
      { class: "deflayer__head" },
      h("span", { class: "deflayer__node", "aria-hidden": "true" }),
      h("h5", { class: "deflayer__title" }, meta.title),
      lit
        ? h("span", { class: `deflayer__verdict deflayer__verdict--${lit.outcome}` }, OUTCOME_WORD[lit.outcome])
        : meta.reach === "outside" && live
          ? h("span", { class: "deflayer__verdict deflayer__verdict--out" }, "never reached")
          : null,
    ),
    h("p", { class: "deflayer__blurb" }, meta.blurb),
    lit && lit.entries.length
      ? h(
          "ul",
          { class: "deflayer__entries", "aria-label": `${meta.title}: what each command met` },
          // Each command under its own layer with its own verdict; "ended the session" only for the
          // one that did (a quarantine does not end it).
          lit.entries.map((e) =>
            h(
              "li",
              { class: `deflayer__entry deflayer__entry--${e.outcome}` },
              h("code", {}, e.input),
              h("span", { class: `deflayer__verdict deflayer__verdict--${e.outcome}` }, OUTCOME_WORD[e.outcome]),
              e.ended ? h("span", { class: "deflayer__ended" }, "ended the session") : null,
            ),
          ),
        )
      : h(
          "ul",
          { class: "deflayer__controls", "aria-label": `${meta.title} controls` },
          meta.controls.map((c) => h("li", {}, c)),
        ),
    meta.reach === "outside" && ev ? h("p", { class: "deflayer__evidence" }, "Live posture: ", ev) : null,
  );
}

/** Builds the lit-layer map from a terminal run's finished commands and their catalogue entries. */
export function litFromCommands(entries: { layer: DefenceLayer; outcome: CommandOutcome; control: string; input: string; ended?: boolean }[]): Map<DefenceLayer, LitLayer> {
  const rank: Record<CommandOutcome, number> = { allowed: 0, prevented: 1, detected: 2 };
  const map = new Map<DefenceLayer, LitLayer>();
  for (const e of entries) {
    const entry: LitEntry = { input: e.input, outcome: e.outcome, control: e.control, ended: e.ended === true };
    const cur = map.get(e.layer);
    if (!cur) {
      map.set(e.layer, { outcome: e.outcome, entries: [entry] });
    } else {
      cur.entries.push(entry);
      if (rank[e.outcome] >= rank[cur.outcome]) cur.outcome = e.outcome;
    }
  }
  return map;
}

export function mountDefenceMap(root: HTMLElement, api: ApiClient): { refresh(): void } {
  const show = (res: Result<Posture> | null) => {
    const posture = res && res.ok ? res.value : undefined;
    replace(
      root,
      renderDefenceMap({ posture }),
      posture
        ? h("p", { class: "panel-foot" }, "Live posture numbers come from the dashboard above.", h("span", { class: "needs-terminal" }, " Launch the terminal to see which layer answers which move."))
        : h("p", { class: "panel-foot" }, "Posture numbers load with the dashboard above; the layers themselves are always here."),
    );
  };
  const refresh = () => {
    void api.posture().then(show);
  };
  // Render the static layers at once so the section is never blank, then fill the evidence.
  replace(root, renderDefenceMap({}));
  refresh();
  return { refresh };
}
