# Architecture

How the pieces of this repository fit together, drawn from the manifests rather than from intent.
Every box below names the namespace, port or file it comes from, so a diagram that drifts from the
code can be caught by reading the file it points at.

Status legend used in every diagram:

- solid line / solid box: in the repository today (phases 1-4);
- dashed line / box marked *planned*: phase 5/6 work in progress (the visitor-facing API, the attack
  scenarios and the new site). Those parts do not exist on `main` yet and may still change.

The overview below is a hand-drawn SVG (it follows the GitHub light/dark theme of your browser). The
four sections after it are Mermaid diagrams of one flow each.

![Architecture overview: network path, GitOps, supply chain, detection and response](overview.svg)

Contents:

1. [Network path: visitor to page](#1-network-path-visitor-to-page)
2. [GitOps flow: commit to running object](#2-gitops-flow-commit-to-running-object)
3. [Supply chain: source to admitted pod](#3-supply-chain-source-to-admitted-pod)
4. [Detection and response loop](#4-detection-and-response-loop)
5. [Posture reporting](#5-posture-reporting)
6. [Namespaces at a glance](#6-namespaces-at-a-glance)

---

## 1. Network path: visitor to page

```mermaid
flowchart LR
    V([visitor browser])
    subgraph CF["Cloudflare (trusted intermediary)"]
        EDGE["edge: TLS to visitor<br/>DNS CNAME to the tunnel"]
    end
    subgraph NODE["k3s01 (Proxmox VM, no inbound port from the internet)"]
        subgraph NS_CFD["ns cloudflared"]
            CFD["cloudflared x2<br/>credentials-file tunnel<br/>metrics :2000"]
        end
        subgraph NS_KS["ns kube-system"]
            ENVOY["cilium-envoy DaemonSet<br/>(host network ns)"]
        end
        subgraph NS_GW["ns gateway"]
            GW["Gateway portfolio<br/>listener http :80 (301 only)<br/>listener https :443<br/>cert portfolio-tls"]
            SVC["Service cilium-gateway-portfolio<br/>ClusterIP; LB IP 10.4.1.30 not announced"]
        end
        subgraph NS_HELLO["ns hello"]
            ROUTE["HTTPRoute hello<br/>security headers"]
            WEB["Deployment hello x2<br/>web image :8080, uid 101"]
        end
        subgraph NS_API["ns portfolio-api (planned)"]
            API["portfolio API :8080<br/>HTTPRoute /api"]
        end
    end
    V -- "HTTPS" --> EDGE
    CFD -- "outbound 7844 QUIC/HTTP2, 443" --> EDGE
    EDGE -. "requests ride the tunnel" .-> CFD
    CFD -- "HTTPS :443, SNI hubertjablon.ski,<br/>certificate verified" --> SVC
    SVC --- ENVOY
    ENVOY --- GW
    GW --> ROUTE --> WEB
    GW -.-> API
```

What the diagram claims, and where it is written down:

| Claim | Source |
|-------|--------|
| No port is opened on the router or on the host; the tunnel is dialled outbound | [ADR 0003](../adr/0003-cloudflare-tunnel-exposure.md), [`nftables.conf.j2`](../../ansible/roles/firewall/templates/nftables.conf.j2) (input policy drop) |
| Hostname routing lives in git, not in the Cloudflare dashboard (credentials-file mode); unknown hostnames get 404 | [`cluster/infra/cloudflared/config.yaml`](../../cluster/infra/cloudflared/config.yaml) |
| cloudflared may only talk to DNS, Cloudflare (`world` on 7844/443), the Gateway (443) and route backends on 8080 | [`cluster/infra/cloudflared/ciliumnetworkpolicy.yaml`](../../cluster/infra/cloudflared/ciliumnetworkpolicy.yaml) |
| The origin hop is HTTPS with verification (`originServerName`, `noTLSVerify: false`) | [`cluster/infra/cloudflared/config.yaml`](../../cluster/infra/cloudflared/config.yaml), [ADR 0010](../adr/0010-cilium-gateway-api.md) |
| Certificate: cert-manager, Let's Encrypt, DNS-01 against Cloudflare with a zone-scoped token | [`cluster/infra/cert-manager-issuers/`](../../cluster/infra/cert-manager-issuers/), [`cluster/apps/cert-manager.yaml`](../../cluster/apps/cert-manager.yaml) |
| Only namespaces labelled `portfolio.hubertjablon.ski/gateway-routes: "true"` may attach routes | [`cluster/infra/gateway/gateway.yaml`](../../cluster/infra/gateway/gateway.yaml) |
| HTTP is redirected to HTTPS twice: the `:80` listener, and `X-Forwarded-Proto: http` on `:443` | [`httproute-https-redirect.yaml`](../../cluster/infra/gateway/httproute-https-redirect.yaml), [`cluster/infra/hello/httproute.yaml`](../../cluster/infra/hello/httproute.yaml) |
| HSTS, CSP (`script-src 'none'` today), nosniff, Referrer-Policy, Permissions-Policy, COOP are set at the Gateway | [`cluster/infra/hello/httproute.yaml`](../../cluster/infra/hello/httproute.yaml) |
| Envoy trusts exactly one `X-Forwarded-For` hop (cloudflared) | [`cluster/apps/cilium.yaml`](../../cluster/apps/cilium.yaml) (`xffNumTrustedHops: 1`) |
| `hello` is default-deny, ingress only from Cilium's `ingress`/`host` identities on 8080, no egress at all | [`cluster/infra/hello/`](../../cluster/infra/hello/) |
| The Gateway's LoadBalancer address 10.4.1.30 exists only so the Gateway reports `Programmed`; nothing announces it | [`cluster/infra/gateway/lb-ip-pool.yaml`](../../cluster/infra/gateway/lb-ip-pool.yaml) |

Argo CD, Hubble and Policy Reporter are never routed through the Gateway or the tunnel; they are
reached with `kubectl port-forward` by someone who already holds cluster credentials.

**Planned (phase 5):** an HTTPRoute for `/api` to a Go service in namespace `portfolio-api`, with a
second, internal-only port 8081 for webhooks from `falco-response`. That namespace will need the
`gateway-routes` label, and cloudflared's existing "route backends on 8080" egress rule already covers
it. The CSP in the hello route is expected to loosen for the new frontend (scripts, SSE), as a
reviewed diff.

## 2. GitOps flow: commit to running object

```mermaid
flowchart TB
    DEV([operator]) -- "git push main" --> GH[("GitHub repo<br/>HubertMJ/self-defending-portfolio")]
    GH -- "every push / PR" --> CI["lint.yml<br/>yamllint, ansible-lint, shellcheck,<br/>validate, gitleaks, smoke"]
    subgraph NS_ARGO["ns argocd (installed once by cluster/bootstrap/bootstrap.sh)"]
        ROOT["Application root<br/>path cluster/apps"]
        RS["repo-server<br/>+ KSOPS init container"]
        AGE[("Secret sops-age<br/>age private key")]
        APPS["15 child Applications<br/>sync waves -2 .. 5"]
    end
    GH -- "poll (3 min) on main" --> RS
    AGE -. "mounted 0440" .-> RS
    RS --> ROOT --> APPS
    APPS -- "kustomize: cluster/infra/*" --> K8S[("cluster objects")]
    APPS -- "Helm charts, pinned versions" --> K8S
    ANS["Ansible (once)<br/>k3s + Cilium seed install"] --> K8S
    APPS -. "adopts Cilium release<br/>(server-side apply)" .-> K8S
```

- The **only** manual step after the host exists is [`cluster/bootstrap/bootstrap.sh`](../../cluster/bootstrap/bootstrap.sh):
  it creates the `argocd` namespace, the `sops-age` Secret from the operator's key file, and applies
  [`cluster/bootstrap/argocd/`](../../cluster/bootstrap/argocd/) (Argo CD v3.5.3 + KSOPS patch + the
  `root` Application). Its own README explains each choice: [`cluster/bootstrap/README.md`](../../cluster/bootstrap/README.md).
- `root` points at [`cluster/apps/`](../../cluster/apps/), one file per component. Wave order and the
  list of Applications are in [`cluster/apps/kustomization.yaml`](../../cluster/apps/kustomization.yaml):
  `gateway-api-crds` (-2), `cilium` (-1), `cert-manager` (0), `cert-manager-issuers` and `kyverno` (1),
  `kyverno-policies` and `cloudflared` (2), `gateway` (3), `hello` (4), and in wave 5 `policy-reporter`,
  `trivy-operator`, `kube-bench`, `falco`, `falco-response`, `sandbox`.
- Secrets are committed SOPS-encrypted (only `data`/`stringData`, see [`.sops.yaml`](../../.sops.yaml)) and decrypted
  inside the repo-server by KSOPS ([ADR 0006](../adr/0006-sops-age-for-secrets.md)). Two exist: the
  Cloudflare DNS-01 token and the tunnel credentials. CI refuses any plaintext `kind: Secret` under
  `cluster/` ([`scripts/check-secrets-encrypted.sh`](../../scripts/check-secrets-encrypted.sh)).
- Every Application uses `project: default` and auto-sync with self-heal. Prune is off for `cilium`,
  `kyverno` and `gateway-api-crds`, where an accidental prune would remove the CNI, the admission
  webhook's backend or every Gateway ([ADR 0005](../adr/0005-argocd-for-gitops.md)).
- Documented exception: `root-application.yaml` and `argocd-cm.yaml` belong to the bootstrap layer and
  reach the cluster only through a manual `kubectl apply -k` (ADR 0005, amendment 2026-10-01).
- What CI checks before Argo CD sees a commit: [`.github/workflows/lint.yml`](../../.github/workflows/lint.yml) runs
  [`scripts/validate-cluster.sh`](../../scripts/validate-cluster.sh) (kustomize build + kubeconform against
  Kubernetes 1.35 and CRD schemas, then `helm template` of every chart Application via
  [`scripts/render-charts.sh`](../../scripts/render-charts.sh) and `kyverno apply` of the repository's
  policies over all of it), plus gitleaks over the full history and an idempotency smoke test of the
  hardening playbook ([`tests/smoke.sh`](../../tests/smoke.sh)).

## 3. Supply chain: source to admitted pod

```mermaid
flowchart LR
    SRC["app/web/**<br/>push to main"] --> WF
    subgraph WF["build-web.yml (GitHub Actions, actions pinned by SHA)"]
        B["buildx push<br/>provenance/sbom off"] --> T["Trivy gate<br/>fixable CRITICAL/HIGH = fail"]
        T --> S["syft SBOM<br/>SPDX JSON"]
        S --> SIGN["cosign sign (keyless)"]
        SIGN --> ATT["cosign attest<br/>--type spdxjson"]
    end
    OIDC["GitHub OIDC token"] -.-> SIGN
    SIGN -.-> FUL["Sigstore Fulcio<br/>short-lived cert<br/>SAN = build-web.yml@refs/heads/main"]
    SIGN -.-> REK["Rekor<br/>transparency log"]
    B --> GHCR[("GHCR (public)<br/>ghcr.io/hubertmj/self-defending-portfolio/web<br/>bundles as OCI referrers")]
    ATT --> GHCR
    HUMAN([operator]) -- "commit digest to<br/>cluster/infra/hello/kustomization.yaml" --> ARGO["Argo CD sync"]
    ARGO --> ADM{"Kyverno admission<br/>ns hello, sandbox"}
    GHCR -. "referrers, bundles<br/>(anonymous pull)" .-> ADM
    ADM -- "signature + SBOM verified,<br/>registry allowed, no :latest" --> POD["Pod runs<br/>image pinned to verified digest"]
    ADM -- "anything else" --> DENY["rejected"]
    LAPTOP([anyone]) -- "scripts/verify-image.sh image@sha256:..." --> GHCR
```

| Step | File |
|------|------|
| Build, scan, SBOM, sign, attest | [`.github/workflows/build-web.yml`](../../.github/workflows/build-web.yml) |
| Why keyless, why a bundle, why fixable-only | [ADR 0011](../adr/0011-supply-chain.md) (and its 2026-10-01 amendment) |
| Admission: signature + SBOM by identity, `type: SigstoreBundle`, `mutateDigest`, `failurePolicy: Fail` | [`verify-portfolio-images.yaml`](../../cluster/infra/kyverno-policies/verify-portfolio-images.yaml) |
| Admission: only `ghcr.io/hubertmj/self-defending-portfolio/*` in `hello` and `sandbox` | [`restrict-image-registries.yaml`](../../cluster/infra/kyverno-policies/restrict-image-registries.yaml) |
| Admission: no image without a tag or with `:latest` (cluster-wide minus system namespaces) | [`disallow-latest-tag.yaml`](../../cluster/infra/kyverno-policies/disallow-latest-tag.yaml) |
| The same verdict without a cluster | [`scripts/verify-image.sh`](../../scripts/verify-image.sh) |
| The negative test (unsigned, foreign, `:latest` all rejected) | [`tests/admission/run.sh`](../../tests/admission/run.sh) |

The deployed digest is bumped by a human commit; nothing auto-promotes a build (ADR 0011, known gap).
Third-party images (Cilium, Kyverno, Falco, ...) are pinned by tag and digest
([ADR 0008](../adr/0008-pinned-versions.md)) but are not signature-verified at admission: only this
project's own registry path is.

**Planned (phase 5):** more images under the same registry path (the API and the attack-scenario
image), built by additional workflow files whose identity `verify-portfolio-images` will have to name,
still pinned to `refs/heads/main`.

## 4. Detection and response loop

```mermaid
flowchart TB
    subgraph NS_SB["ns sandbox (restricted, default-deny, DNS only)"]
        P["pod<br/>label quarantine=false"]
    end
    subgraph NS_FALCO["ns falco (PSA privileged, Kyverno restricted-falco)"]
        F["Falco 0.45 DaemonSet<br/>modern eBPF, 4 capabilities<br/>no API token, rules from image + git"]
    end
    subgraph NS_FR["ns falco-response (restricted)"]
        SK["Falcosidekick :2801<br/>forwards priority >= notice"]
        TA["Falco Talon 0.3.0 :2803<br/>leader Lease falco-talon"]
    end
    K8S[("kube-apiserver :6443")]
    Q["CiliumClusterwideNetworkPolicy<br/>quarantine: deny all in/out"]
    P -- "syscalls (exec, open, connect)" --> F
    F -- "http_output JSON" --> SK
    SK -- "HTTP POST" --> TA
    TA -- "Terminal shell in container<br/>-> kubernetes:terminate (grace 0)" --> K8S
    TA -- "SDP network tool in sandbox<br/>-> kubernetes:label quarantine=true" --> K8S
    TA -- "k8s Event on the pod" --> K8S
    K8S -. "label selects pod" .-> Q
    Q -. "isolates" .-> P
    SK -. "planned: webhook to API :8081" .-> API["portfolio API (planned)<br/>SSE /api/events to browser"]
    TA -. "planned: notifier to API :8081" .-> API
```

| Link | Enforced by |
|------|-------------|
| Falco: modern eBPF in least-privileged mode, `drop: [ALL]` + BPF, PERFMON, SYS_RESOURCE, SYS_PTRACE; no falcoctl, no k8smeta; custom rule "SDP network tool in sandbox" | [`cluster/apps/falco.yaml`](../../cluster/apps/falco.yaml), [ADR 0013](../adr/0013-runtime-detection-and-response.md) |
| Falco may only reach DNS and Falcosidekick:2801 | [`cluster/infra/falco/ciliumnetworkpolicy.yaml`](../../cluster/infra/falco/ciliumnetworkpolicy.yaml) |
| Falcosidekick accepts only Falco pods; Talon accepts only Falcosidekick; Talon egress only the API server | [`cluster/infra/falco-response/ciliumnetworkpolicy.yaml`](../../cluster/infra/falco-response/ciliumnetworkpolicy.yaml) |
| Response rules, both matching `k8s.ns.name=sandbox` | [`cluster/infra/falco-response/talon/rules.yaml`](../../cluster/infra/falco-response/talon/rules.yaml) |
| Talon may get/patch/delete pods and create events in `sandbox` only, plus `get` on Namespace `sandbox` and its own Lease | [`cluster/infra/sandbox/talon-rbac.yaml`](../../cluster/infra/sandbox/talon-rbac.yaml), [`cluster/infra/falco-response/talon-rbac.yaml`](../../cluster/infra/falco-response/talon-rbac.yaml) |
| Quarantine = a label plus a standing deny policy (deny beats allow) | [`cluster/infra/sandbox/quarantine-ccnp.yaml`](../../cluster/infra/sandbox/quarantine-ccnp.yaml) |
| End-to-end proof: shell -> alert -> kill, `wget` -> quarantine, RBAC can-i | [`tests/runtime/run.sh`](../../tests/runtime/run.sh) (`make runtime-test`) |

**Planned (phase 5):** a visitor presses a button, the API creates a pod from a fixed scenario
template in `sandbox`, optionally execs a command into it, correlates Falco and Talon events by pod name
and streams them to the browser over SSE. Falcosidekick and Talon get an extra webhook output to the
API's internal port, allowed by a network policy from `falco-response` only.

## 5. Posture reporting

```mermaid
flowchart LR
    KY["Kyverno<br/>5 ClusterPolicies,<br/>background scan"] --> PR[("PolicyReports<br/>wgpolicyk8s.io")]
    TO["Trivy Operator<br/>client/server, 1 scan Job at a time"] --> TR[("Vulnerability / ConfigAudit /<br/>ExposedSecret / RbacAssessment reports")]
    TR --> AD["trivy-operator-polr-adapter"] --> PR
    PR --> PRUI["Policy Reporter core + UI<br/>ClusterIP only, port-forward"]
    KB["kube-bench CronJob<br/>daily 03:17 UTC, k3s-cis-1.9"] --> LOG[("JSON in the Job log")]
    PR -. "planned" .-> POST["API: GET /api/posture (planned)"]
    LOG -. "planned" .-> POST
```

Sources: [ADR 0012](../adr/0012-pod-security-and-resource-policy.md),
[ADR 0014](../adr/0014-posture-scanning.md), [`cluster/apps/trivy-operator.yaml`](../../cluster/apps/trivy-operator.yaml),
[`cluster/apps/policy-reporter.yaml`](../../cluster/apps/policy-reporter.yaml),
[`cluster/infra/kube-bench/cronjob.yaml`](../../cluster/infra/kube-bench/cronjob.yaml).

## 6. Namespaces at a glance

| Namespace | PSA enforce | Network policy | Holds | Defined in |
|-----------|-------------|----------------|-------|------------|
| `kube-system` | none (cluster default) | none from this repo | Cilium agent/operator/envoy, Hubble relay, k3s add-ons | Ansible ([`ansible/roles/cilium/`](../../ansible/roles/cilium/)), [`cluster/apps/cilium.yaml`](../../cluster/apps/cilium.yaml) |
| `argocd` | restricted | none | Argo CD (no requests/limits: recorded debt) | [`cluster/bootstrap/argocd/`](../../cluster/bootstrap/argocd/) |
| `cert-manager` | restricted | none | cert-manager, issuers' DNS token | [`cluster/apps/cert-manager.yaml`](../../cluster/apps/cert-manager.yaml) |
| `kyverno` | restricted | none (egress open, see threat model) | admission, background, cleanup, reports controllers | [`cluster/apps/kyverno.yaml`](../../cluster/apps/kyverno.yaml) |
| `cloudflared` | restricted | CNP, explicit egress | tunnel x2 | [`cluster/infra/cloudflared/`](../../cluster/infra/cloudflared/) |
| `gateway` | restricted | n/a (no pods) | Gateway, redirect route, TLS Secret | [`cluster/infra/gateway/`](../../cluster/infra/gateway/) |
| `hello` | restricted | default-deny + CNP | the site | [`cluster/infra/hello/`](../../cluster/infra/hello/) |
| `policy-reporter` | restricted | default-deny + CNPs | reports UI | [`cluster/infra/policy-reporter/`](../../cluster/infra/policy-reporter/) |
| `trivy-system` | restricted | default-deny + CNPs (FQDN allow-list) | Trivy operator, server, scan Jobs, adapter | [`cluster/infra/trivy-operator/`](../../cluster/infra/trivy-operator/) |
| `kube-bench` | privileged (audit restricted) | default-deny, nothing opened | daily CIS CronJob | [`cluster/infra/kube-bench/`](../../cluster/infra/kube-bench/) |
| `falco` | privileged (audit restricted) | default-deny + CNP | Falco DaemonSet only | [`cluster/infra/falco/`](../../cluster/infra/falco/) |
| `falco-response` | restricted | default-deny + CNPs | Falcosidekick, Talon | [`cluster/infra/falco-response/`](../../cluster/infra/falco-response/) |
| `sandbox` | restricted | default-deny + DNS only + quarantine CCNP | short-lived victims / scenario pods | [`cluster/infra/sandbox/`](../../cluster/infra/sandbox/) |
| `portfolio-api` | *planned* | *planned* | phase 5 API | not in the repository yet |

Host level (outside Kubernetes): Debian 13 VM `k3s01` on Proxmox, hardened by the roles in
[`ansible/roles/`](../../ansible/roles/) (SSH key-only from two admin VLANs, nftables input
default-deny, sysctl, auditd, unattended upgrades) and running k3s with secrets encryption, an audit
policy and no flannel/kube-proxy ([`ansible/roles/k3s/templates/config.yaml.j2`](../../ansible/roles/k3s/templates/config.yaml.j2)).
