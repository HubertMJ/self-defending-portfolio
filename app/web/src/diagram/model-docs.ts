// The full model for docs/architecture/overview.svg (scripts/diagram.mjs): the page's model plus the
// GitOps, supply-chain and posture nodes, and the detail (ports, a namespace, the SIEM's VLAN) the
// docs may carry but the page does not ship (ADR 0021). Not imported by anything under src/ui or
// src/main.ts, so none of it reaches the bundle.

import { type DiagramModel, type DiagramNode, LAYER_BLURBS, MODEL } from "./model";

const DOCS_NODES: DiagramNode[] = [
    { id: "falcosidekick", label: "Falcosidekick", sub: ":2801 · falco-response", zone: "k3s01", detail: "full", tone: "plain", blurb: "Fans each Falco alert out: to Talon, and to the portfolio API's internal webhook port.", sources: ["cluster/infra/falco-response/"], at: { full: [2, 4] } },
    { id: "operator", label: "Operator", sub: "git push main", zone: "gitops", detail: "full", tone: "plain", blurb: "Every change is a reviewed commit.", sources: [], at: { full: [0, 1.4] } },
    { id: "repo", label: "GitHub repository", sub: "main branch", zone: "gitops", detail: "full", tone: "plain", blurb: "The public repository is the only source of what runs.", sources: ["cluster/"], at: { full: [1, 1.4] } },
    { id: "ci", label: "CI lint.yml", sub: "validate · kyverno · gitleaks", zone: "gitops", detail: "full", tone: "plain", blurb: "Renders every kustomization, validates it against real schemas, tests the policies, scans for secrets.", sources: [".github/workflows/lint.yml"], at: { full: [1, 2.4] } },
    { id: "argocd", label: "Argo CD", sub: "ns argocd · KSOPS + age", zone: "gitops", detail: "full", tone: "control", blurb: "App-of-apps, pinned charts, self-heal: the cluster converges on the repository, secrets decrypted only inside Argo CD.", sources: ["cluster/apps/", "cluster/bootstrap/"], at: { full: [2, 1.4] } },
    { id: "apps", label: "Applications", sub: "cluster/infra/* + pinned Helm charts", zone: "gitops", detail: "full", tone: "plain", blurb: "One Application per component, in sync waves.", sources: ["cluster/apps/"], at: { full: [2, 2.4] } },
    { id: "build", label: "build-images.yml", sub: "web · api · scenario", zone: "supply", detail: "full", tone: "plain", blurb: "One matrix workflow builds every image of the project.", sources: [".github/workflows"], at: { full: [3, 1.4] } },
    { id: "trivy", label: "Trivy gate", sub: "fixable HIGH/CRIT fail", zone: "supply", detail: "full", tone: "control", layer: "supply-chain", blurb: LAYER_BLURBS["supply-chain"], sources: [".github/workflows"], at: { full: [4, 1.4] } },
    { id: "cosign", label: "cosign keyless", sub: "sign + SPDX attest", zone: "supply", detail: "full", tone: "control", layer: "supply-chain", blurb: "Every image is signed keylessly, bound to this workflow on main, with an SBOM attestation beside it.", sources: [".github/workflows", "scripts/verify-image.sh"], at: { full: [5, 1.4] } },
    { id: "ghcr", label: "GHCR", sub: "images + bundles", zone: "supply", detail: "full", tone: "plain", blurb: "The public registry holds the images with their signatures and attestations as OCI referrers.", sources: [], at: { full: [4, 2.4] } },
    { id: "kyverno", label: "Kyverno admission", sub: "failurePolicy Fail", zone: "supply", detail: "full", tone: "control", layer: "admission", blurb: LAYER_BLURBS.admission, sources: ["cluster/infra/kyverno-policies/"], at: { full: [3, 2.4] } },
    { id: "posture", label: "Posture scanning", sub: "Trivy Operator · kube-bench", zone: "supply", detail: "full", tone: "plain", blurb: "Trivy Operator scans running images and configuration; kube-bench runs the CIS benchmark daily; the page shows both.", sources: ["cluster/apps/trivy-operator.yaml", "cluster/infra/kube-bench/"], at: { full: [5, 2.4] } },
];

/** Sublabels the docs diagram shows instead of the page's. */
const DOCS_SUBS: Record<string, string> = {
  gateway: "ns gateway · :443 · LE cert (DNS-01)",
  cloudflared: "ns cloudflared · dials out :7844",
  falco: "modern eBPF · ns falco · no API token",
  talon: "ns falco-response · :2803",
  "kube-apiserver": "RBAC: sandbox pods only · audit log shipped",
};

const DOCS_ZONE_SUBS: Record<string, string> = {
  siem01: "VLAN 42 · 10.4.2.10 · append-only",
};

export const FULL_MODEL: DiagramModel = {
  zones: MODEL.zones.map((z) => (DOCS_ZONE_SUBS[z.id] ? { ...z, sub: DOCS_ZONE_SUBS[z.id] } : z)),
  nodes: [...MODEL.nodes.map((n) => (DOCS_SUBS[n.id] ? { ...n, sub: DOCS_SUBS[n.id] } : n)), ...DOCS_NODES],
  edges: [
    ...MODEL.edges,
    { from: "operator", to: "repo", kind: "flow", detail: "full" },
    { from: "repo", to: "ci", kind: "side", detail: "full" },
    { from: "repo", to: "argocd", kind: "flow", label: "poll", detail: "full" },
    { from: "argocd", to: "apps", kind: "flow", label: "sync waves", detail: "full" },
    { from: "build", to: "trivy", kind: "flow", detail: "full" },
    { from: "trivy", to: "cosign", kind: "flow", detail: "full" },
    { from: "cosign", to: "ghcr", kind: "flow", label: "push", detail: "full" },
    { from: "ghcr", to: "kyverno", kind: "flow", label: "verify", detail: "full" },
    { from: "ghcr", to: "posture", kind: "side", detail: "full" },
    { from: "falco", to: "falcosidekick", kind: "flow", label: "alert", detail: "full" },
    { from: "falcosidekick", to: "talon", kind: "flow", label: "POST", detail: "full" },
  ],
  narrow: MODEL.narrow,
};

export { LAYER_BLURBS };
