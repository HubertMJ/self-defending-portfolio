# ADR 0014: Posture scanning with Trivy Operator (client/server, offline scan jobs) and Policy Reporter

Date: 2026-10-01 · Status: accepted

## Context
Phase 4 adds runtime security, and the phase 6 posture page needs something to show besides
admission results: which running images carry known vulnerabilities or embedded secrets, which
workloads and RBAC objects are misconfigured, and how the node compares to the CIS benchmark. All of
it has to fit on one 8 GB node next to everything else, and none of it may become a new way out of
the cluster or a new holder of cluster-wide secrets.

The usual tools have defaults that conflict with that. The Trivy Operator chart runs every scan Job
in Standalone mode (each Job downloads the full vulnerability DB), runs scan Jobs and the Trivy
server with the image's default user (root), grants itself cluster-wide `secrets: create/get/update`
to copy pull secrets, and turns on node-collector (a root pod with host paths) for infrastructure
assessment and compliance. Trivy results are CRDs of Trivy's own (`aquasecurity.github.io`), which
Policy Reporter cannot read.

Options considered: Trivy Operator in Standalone vs. client/server mode; the Trivy Operator's
node-collector vs. kube-bench for the node benchmark (kube-bench: plan commit 5); Policy Reporter vs.
reading the CRDs directly from the phase 6 page; exposing the Policy Reporter UI through the Gateway
vs. port-forward only.

## Decision

**Trivy Operator, client/server, one scan at a time** (`cluster/apps/trivy-operator.yaml`, chart
0.36.0 / operator 0.34.0, Trivy 0.74.0). The built-in Trivy server (StatefulSet, 5 GiB local-path
volume, 200m/512Mi) is the only component that holds and downloads the vulnerability DB. Scan Jobs
run the Trivy client with `trivy.offlineScan: true`: they pull the scanned image from its registry,
analyse it locally and ask the server for the match; no Java DB download, no other lookup.
`scanJobsConcurrentLimit: 1`, `scanJobTimeout: 10m`, only current ReplicaSet revisions. Config and
RBAC audits run inside the operator with the checks embedded in its binary
(`useEmbeddedRegoPolicies`), so the trivy-checks bundle is never downloaded. Exposed-secret
scanning is on (it rides along in the vulnerability scan Job). Node-collector (infra assessment,
cluster compliance) and SBOM generation are off; the node benchmark is kube-bench's job.

**Explicit non-root everywhere.** The operator, the Trivy server and the scan Jobs all run as
65534 with `runAsNonRoot`, seccomp `RuntimeDefault`, no privilege escalation, every capability dropped
and a read-only root filesystem, set in the chart values rather than inherited (the `aquasec/trivy`
image defaults to root, and the chart sets no pod context for scan Jobs and no seccomp for the
server). The namespace `trivy-system` enforces PSS `restricted`. Scan Jobs are created at run time,
so the offline `kyverno apply` gate in `make validate` never sees them (ADR 0012); the values are the
only thing that keeps them admissible, and a Pod with exactly their shape was checked against the
policies by hand when this was written.

**No cluster-wide Secret access.** `operator.accessGlobalSecretsAndServiceAccount: false` removes
`secrets: create/get/update`, `serviceaccounts: get` and `nodes/proxy: get` from the operator's
ClusterRole. Every image in the cluster is public; a private registry later is a pull secret in
`trivy-system` named in `privateRegistryScanSecretsNames`, not a cluster-wide grant.

**Trivy results reach Policy Reporter through trivy-operator-polr-adapter** (chart and app 0.11.5, a
second chart source of the same Application). The plan assumed the Policy Reporter Trivy plugin
would do this; its source (`kyverno/policy-reporter-plugins`, trivy-plugin-v0.5.1) shows it only
serves CVE/GHSA details for results that already exist as PolicyReports, and its own documentation
names the adapter as the source of those PolicyReports. The adapter maps VulnerabilityReports,
ConfigAuditReports, ExposedSecretReports and RbacAssessmentReports into `wgpolicyk8s.io`
PolicyReports (CRDs from Kyverno, not installed a second time). Argo CD does not track Trivy's own
report kinds (ADR 0005 amendment, `resource.exclusions`); the PolicyReports are excluded upstream.

**Policy Reporter, cluster-internal** (`cluster/apps/policy-reporter.yaml`, chart 3.10.0). Core and
UI, ClusterIP only; the way in is `kubectl -n policy-reporter port-forward svc/policy-reporter-ui
8082:8080`, which needs cluster credentials and is spliced into the pod's network namespace by the
kubelet. No Gateway route: the UI has no authentication configured, and the posture page that is
meant for visitors is a separate, read-only phase 6 artefact. The Trivy plugin (user decision) runs
without a service account token (it only needs one for secretRefs, none are set) and with its
online lookups (`api.github.com`, `cveawg.mitre.org`) off, so it answers from the Trivy DB that its
init container downloads at start. The Kyverno plugin is off: the policies are in git and
PolicyExceptions are not used (ADR 0012).

**Egress is an allow-list per workload** (default-deny NetworkPolicy per namespace plus one
CiliumNetworkPolicy per workload, DNS through Cilium's DNS proxy so `toFQDNs` works):

| Workload | Egress |
|---|---|
| Trivy server | kube-dns; `mirror.gcr.io:443` (DB) |
| Scan Jobs | kube-dns; Trivy server 4954; the registries the cluster's images come from and their blob hosts: `index.docker.io`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`, `production.cloudfront.docker.com`, `ghcr.io`, `pkg-containers.githubusercontent.com`, `reg.kyverno.io`, `quay.io`, `*.quay.io`, `mirror.gcr.io`, `public.ecr.aws`, `d2glxqk2uabbnd.cloudfront.net` |
| Operator, adapter | kube-dns; kube-apiserver; (operator) Trivy server 4954 |
| Policy Reporter core / UI | kube-dns; kube-apiserver; (UI) core and plugin 8080 |
| Trivy plugin | kube-dns; core 8080; `mirror.gcr.io:443` (DB) |

The scan Job list is derived from the images actually rendered from git, not from a generic list:
`registry.k8s.io`, `*.pkg.dev` and `*.storage.googleapis.com` from the plan are left out because no
workload pulls from them. A new registry in git needs an entry here; until then the gap shows up as a
failed scan Job and a Hubble drop, not as silent success. Blob hosts were observed from the
development sandbox on 2026-10-01 where reachable (docker.io, ghcr.io, mirror.gcr.io, ECR Public);
quay.io's and reg.kyverno.io's are from their documentation and must be confirmed with Hubble.

**Sizing** (requests / limits): operator 50m/128Mi / 500m/384Mi; Trivy server 200m/512Mi / 1/1Gi;
scan Job 50m/64Mi / 500m/512Mi; adapter 10m/64Mi / 200m/192Mi; Policy Reporter core 10m/48Mi /
200m/128Mi, UI 10m/32Mi / 100m/96Mi, Trivy plugin 10m/64Mi / 200m/256Mi.

Rejected: Standalone mode (every scan Job downloads ~1 GiB of DB, and every scan Job needs the
internet); node-collector (root plus host paths in a namespace that otherwise enforces `restricted`);
the chart's own NetworkPolicies (plain NetworkPolicy cannot express FQDNs; one place for policy);
exposing the UI through the Gateway.

## Consequences
- Every running image gets a VulnerabilityReport (and an ExposedSecretReport) within one pass of the
  scan queue, every workload and Role a ConfigAuditReport / RbacAssessmentReport; Policy Reporter
  shows them next to the Kyverno results, which is what phase 6 reads.
- The cluster gains two outbound paths it did not have: the Trivy server and plugin to
  mirror.gcr.io, and the scan Jobs to the listed registries. Both are name-scoped and visible in
  Hubble; neither component has cluster-wide Secret access.
- `trivy-system` enforces `restricted`, so a regression in the scan Job security context is a
  rejected Job with the PSA reason in its events, not a root container.
- Scan coverage depends on the registry list: a workload from an unlisted registry has no report
  until the list is extended.
- `scripts/render-charts.sh` now writes one file per chart source (`chart_<app>-<n>.yaml`); with one
  file per Application, the adapter's render overwrote the operator's and the operator's Pods never
  reached the policy gate. It also drops comment-only YAML documents, which the trivy-operator CRDs
  produce and the kyverno CLI cannot load.
- Memory (this ADR's six workloads): about +0.85 GiB of requests and +2.0 GiB of limits steady
  state, plus one transient scan Job (512 MiB limit); plan section 3's per-commit gate
  (`kubectl top nodes` under 80 %) applies.
- The plugin's DB is as old as the plugin pod; restarting the Deployment refreshes it. The server's
  DB refreshes itself.
