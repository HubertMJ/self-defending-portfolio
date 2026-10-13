// The architecture diagram's one source (site redesign 2026-10-12, ADR 0035 amendment). The hero's
// live diagram, its phone layout and docs/architecture/overview.svg are all drawn from this model by
// src/diagram/layout.ts; nothing here touches the DOM, so the same module runs in the browser, in
// vitest and in scripts/diagram.mjs (Node).
//
// Every node names the files it stands for, so the drawing can be checked against the repository the
// way docs/architecture/README.md's tables can. `detail: "hero"` nodes are the attack-and-answer story
// the page tells above the fold; "full" nodes appear only in the docs diagram (GitOps, the supply
// chain, posture scanning). The defence map's layer blurbs live here too, so the diagram's captions
// and "How it works" say the same words.

import type { DefenceLayer } from "../lib/contract";

export type Tone = "plain" | "control" | "attack" | "detect" | "respond";
/**
 * The fixed colour of a node at rest (owner, 2026-10-13): the request path, the attacked pod, what
 * detects, what responds, what records; the unguarded twin stays neutral. styles.css and the docs
 * file's own <style> colour `.dg-role--<role>`; the legend under the diagram names them.
 */
export type Role = "entry" | "attack" | "detect" | "respond" | "record" | "neutral";

/** The legend's words, in its order (the neutral twin has no swatch: its label says what it is). */
export const ROLE_LEGEND: { role: Exclude<Role, "neutral">; word: string }[] = [
  { role: "entry", word: "request path" },
  { role: "attack", word: "attacked pod" },
  { role: "detect", word: "detects" },
  { role: "respond", word: "responds" },
  { role: "record", word: "records" },
];
export type Detail = "hero" | "full";
export type View = "hero" | "narrow" | "full";

export interface DiagramNode {
  id: string;
  label: string;
  /** The small second line: namespace, port, image. Shown on the page only in Technical Mode. */
  sub: string;
  zone: string;
  detail: Detail;
  /** A control point of the defence (drawn stronger) or a plain component. */
  tone: "plain" | "control";
  /** The node's colour at rest. */
  role: Role;
  /** The defence layer this node is the main part of, if any (links the diagram to the defence map). */
  layer?: DefenceLayer;
  /** One or two sentences for the caption panel. */
  blurb: string;
  /** Repository paths (files or directories) the node is drawn from. */
  sources: string[];
  /** Grid cell per view, in columns and rows (rows may be fractional). Absent: not in that view. */
  at: Partial<Record<"hero" | "full", [number, number]>>;
}

export type Route = "auto" | "hv" | "vh" | "under" | "over";

export interface DiagramEdge {
  from: string;
  to: string;
  /** flow: the main path; side: a side relationship (dotted); response: an automatic answer. */
  kind: "flow" | "side" | "response";
  label?: string;
  detail: Detail;
  route?: Route;
  /** The views that draw it; absent: every view the two nodes share. */
  views?: ("hero" | "full")[];
  /** A second line drawn the other way (the tunnel: dialled out, requests ride back). */
  both?: boolean;
}

export interface DiagramZone {
  id: string;
  title: string;
  sub?: string;
  detail: Detail;
  /** Cell rectangle per view: [col, row, cols, rows]. */
  at: Partial<Record<"hero" | "full", [number, number, number, number]>>;
}

export interface DiagramModel {
  zones: DiagramZone[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  /** The phone's hero: a vertical path through these nodes, in this order. */
  narrow: string[];
}

/** The seven layers' one-line explanations: the defence map's cards and the diagram's captions. */
export const LAYER_BLURBS: Record<DefenceLayer, string> = {
  edge: "Cloudflare Tunnel: the cluster opens no inbound port. TLS, HSTS and a WAF terminate at the edge.",
  host: "A Debian VM hardened by Ansible: SSH lockdown, an nftables default-deny firewall, sysctl, auditd.",
  network: "Cilium is the CNI: default-deny between pods, and a quarantine policy can cut a pod off entirely, both ways.",
  "supply-chain": "Images are built in CI, Trivy-gated, SBOM-attested and cosign keyless-signed. Anything unsigned is refused.",
  admission: "Kyverno at admission: Pod Security restricted, pinned digests, no :latest, mandatory resource limits, signed images only.",
  "pod-security": "What the pod is allowed to be: non-root, a read-only root filesystem, every Linux capability dropped, no service-account token, seccomp on.",
  runtime: "Falco watches syscalls over eBPF; Falcosidekick fans the alerts out; Falco Talon terminates or quarantines the pod.",
};

export const MODEL: DiagramModel = {
  zones: [
    { id: "internet", title: "Internet", detail: "hero", at: { hero: [0, 0, 1, 2], full: [0, 0, 2, 1] } },
    { id: "k3s01", title: "k3s01", sub: "one VM · Ansible-hardened · nftables input drop · Cilium", detail: "hero", at: { hero: [1, 0, 4, 3.2], full: [2, 0, 4, 1] } },
    { id: "siem01", title: "siem01", sub: "own VM · append-only", detail: "hero", at: { hero: [5, 1.6, 1, 1.6], full: [5, 4, 1, 1] } },
    { id: "gitops", title: "GitOps: every cluster change is a commit", detail: "full", at: { full: [0, 1.4, 3, 2.2] } },
    { id: "supply", title: "Supply chain: only our own images, only if signed on main", detail: "full", at: { full: [3, 1.4, 3, 2.2] } },
    { id: "runtime", title: "Detection and response: no human in the loop, sandbox only", detail: "full", at: { full: [0, 4, 5, 2.2] } },
  ],
  nodes: [
    // ---- the path in ----
    { id: "visitor", label: "Visitor", sub: "browser", zone: "internet", detail: "hero", tone: "plain", role: "entry", blurb: "You. Every request to this page, and every attack you launch, comes in the same way: over HTTPS to Cloudflare.", sources: [], at: { hero: [0, 1], full: [0, 0] } },
    { id: "cloudflare", label: "Cloudflare edge", sub: "TLS · WAF · HSTS", zone: "internet", detail: "hero", tone: "control", role: "entry", layer: "edge", blurb: LAYER_BLURBS.edge, sources: ["docs/adr/0003-cloudflare-tunnel-exposure.md"], at: { hero: [0, 0], full: [1, 0] } },
    { id: "cloudflared", label: "cloudflared ×2", sub: "cloudflared · dials out", zone: "k3s01", detail: "hero", tone: "control", role: "entry", blurb: "The tunnel is dialled from inside the VM; nothing listens for the internet. Cloudflare's requests ride back along it. Two replicas, so a rolling update never takes the site down.", sources: ["cluster/infra/cloudflared/"], at: { hero: [1, 0], full: [2, 0] } },
    { id: "gateway", label: "Cilium Gateway", sub: "gateway · TLS from Let's Encrypt", zone: "k3s01", detail: "hero", tone: "control", role: "entry", layer: "network", blurb: "Cilium's Envoy terminates TLS again inside the cluster and adds the security headers. Default-deny network policies hold everywhere behind it.", sources: ["cluster/infra/gateway/", "cluster/infra/hello/httproute.yaml"], at: { hero: [2, 0], full: [3, 0] } },
    { id: "site", label: "This page + its API", sub: "hello · portfolio-api", zone: "k3s01", detail: "hero", tone: "plain", role: "entry", blurb: "A static page from a signed nginx image, and a small Go API that starts the attacks, watches the pods and streams every event back to your browser as it happens.", sources: ["app/web/", "app/api/"], at: { hero: [3, 0], full: [4, 0] } },
    { id: "kube-apiserver", label: "kube-apiserver", sub: "RBAC: sandbox pods only", zone: "k3s01", detail: "hero", tone: "control", role: "respond", layer: "admission", blurb: "The API creates the sandbox pod through it, and Talon's answer goes through it too. Kyverno admits only signed images in the restricted profile; the audit log of every call ships to the SIEM.", sources: ["cluster/infra/kyverno-policies/", "cluster/infra/portfolio-api/"], at: { hero: [4, 1], full: [4, 4] } },
    // ---- the attack and the answer ----
    { id: "pod", label: "Sandbox pod", sub: "sandbox · non-root · no token", zone: "k3s01", detail: "hero", tone: "plain", role: "attack", layer: "pod-security", blurb: LAYER_BLURBS["pod-security"], sources: ["cluster/infra/sandbox/", "cluster/infra/sandbox/scenarios/"], at: { hero: [1, 1], full: [0, 4] } },
    { id: "twin", label: "Unguarded twin", sub: "sandbox-unguarded", zone: "k3s01", detail: "hero", tone: "plain", role: "neutral", blurb: "The same pod, the same policies, the same attack, in a namespace Talon's rules do not match: Falco still sees it, nothing answers. The difference between the two is what the response is worth.", sources: ["cluster/infra/sandbox-unguarded/", "docs/adr/0031-unguarded-twin-namespace.md"], at: { hero: [1, 2.2], full: [0, 5.2] } },
    { id: "falco", label: "Falco", sub: "modern eBPF · falco", zone: "k3s01", detail: "hero", tone: "control", role: "detect", layer: "runtime", blurb: "Falco watches every syscall over eBPF. A shell with a terminal, a sensitive file read, a network tool, a binary run from the shop volume: each matches a rule within milliseconds.", sources: ["cluster/infra/falco/"], at: { hero: [2, 1], full: [1, 4] } },
    { id: "talon", label: "Falco Talon", sub: "falco-response", zone: "k3s01", detail: "hero", tone: "control", role: "respond", layer: "runtime", blurb: "Falcosidekick hands each alert to Talon, whose rules match only the sandbox namespace: terminate the pod, or label it so Cilium cuts it off both ways.", sources: ["cluster/infra/falco-response/"], at: { hero: [3, 1], full: [3, 4] } },
    { id: "siem", label: "OpenSearch SIEM", sub: "Sigma rules · correlation", zone: "siem01", detail: "hero", tone: "control", role: "record", blurb: "Fluent Bit ships every alert, action, flow, audit line and terminal command to a SIEM on its own VM that the cluster can append to but not rewrite. Sigma rules from this repository run there; the API joins their findings into incidents.", sources: ["siem/", "ansible/roles/fluent_bit/", "docs/adr/0034-siem-opensearch-security-analytics.md"], at: { hero: [5, 1.9], full: [5, 4] } },
  ],
  edges: [
    { from: "visitor", to: "cloudflare", kind: "flow", label: "HTTPS", detail: "hero" },
    { from: "cloudflare", to: "cloudflared", kind: "flow", label: "tunnel", detail: "hero", both: true },
    { from: "cloudflared", to: "gateway", kind: "flow", label: "HTTPS", detail: "hero" },
    { from: "gateway", to: "site", kind: "flow", label: "route", detail: "hero" },
    { from: "site", to: "kube-apiserver", kind: "flow", label: "starts the pod", detail: "hero", route: "hv", views: ["hero"] },
    { from: "pod", to: "falco", kind: "flow", label: "syscalls", detail: "hero" },
    { from: "twin", to: "falco", kind: "side", label: "syscalls", detail: "hero", route: "hv" },
    { from: "falco", to: "talon", kind: "flow", label: "alert", detail: "hero", views: ["hero"] },
    { from: "talon", to: "kube-apiserver", kind: "flow", label: "action", detail: "hero" },
    { from: "kube-apiserver", to: "pod", kind: "response", label: "delete or quarantine", detail: "hero", route: "under" },
    { from: "kube-apiserver", to: "siem", kind: "side", label: "logs", detail: "hero", route: "vh" },
  ],
  narrow: ["visitor", "cloudflare", "cloudflared", "gateway", "site", "pod", "falco", "talon", "kube-apiserver", "siem"],
};

/**
 * What the page ships: the hero's story, with sublabels that name namespaces and components but no
 * port, VLAN or address (ADR 0021: nothing that describes the infrastructure beyond what the page
 * shows). docs/architecture/overview.svg is drawn from FULL_MODEL in model-docs.ts, which adds the
 * GitOps, supply-chain and posture nodes and the docs-only detail.
 */
/** Nodes of a view: the hero's story, or everything. */
export function nodesOf(view: View, model: DiagramModel = MODEL): DiagramNode[] {
  if (view === "narrow") return model.narrow.map((id) => model.nodes.find((n) => n.id === id)).filter((n): n is DiagramNode => n !== undefined);
  return model.nodes.filter((n) => n.at[view] !== undefined);
}

/** Checks the model is consistent: unique ids, edges between known nodes, every hero node placed. Returns the problems. */
export function validateModel(model: DiagramModel = MODEL): string[] {
  const out: string[] = [];
  const ids = new Set<string>();
  for (const n of model.nodes) {
    if (ids.has(n.id)) out.push(`duplicate node ${n.id}`);
    ids.add(n.id);
    if (!model.zones.some((z) => z.id === n.zone)) out.push(`node ${n.id}: unknown zone ${n.zone}`);
    if (n.detail === "hero" && !n.at.hero) out.push(`node ${n.id}: hero node without a hero cell`);
    if (!n.at.full && n.detail === "full") out.push(`node ${n.id}: full node without a full cell`);
    if (!n.blurb) out.push(`node ${n.id}: no blurb`);
    if (!["entry", "attack", "detect", "respond", "record", "neutral"].includes(n.role)) out.push(`node ${n.id}: no role`);
  }
  for (const e of model.edges) {
    for (const end of [e.from, e.to]) if (!ids.has(end)) out.push(`edge ${e.from}->${e.to}: unknown node ${end}`);
    const a = model.nodes.find((n) => n.id === e.from);
    const b = model.nodes.find((n) => n.id === e.to);
    if (e.detail === "hero" && (!a?.at.hero || !b?.at.hero)) out.push(`edge ${e.from}->${e.to}: a hero edge between nodes not both in the hero`);
  }
  for (const id of model.narrow) if (!ids.has(id)) out.push(`narrow path: unknown node ${id}`);
  const zoneIds = new Set<string>();
  for (const z of model.zones) {
    if (zoneIds.has(z.id)) out.push(`duplicate zone ${z.id}`);
    zoneIds.add(z.id);
  }
  return out;
}
