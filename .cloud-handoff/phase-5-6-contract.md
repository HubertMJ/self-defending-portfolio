# Phase 5/6 shared contract (parallel cloud sessions) — removed before merge

Base: `phase-5-base` = phase-4-falco (Phase 4: Kyverno, Trivy Operator, kube-bench, Policy Reporter, Falco ->
Falcosidekick -> Talon, namespace `sandbox`, quarantine label `sdp.hubertjablon.ski/quarantine`, DoD test tests/runtime).
Phase 4 is not yet deployed/accepted; phase 5/6 branches merge only after it is.

## Product
A visitor of https://hubertjablon.ski sees the cluster's live security posture and can trigger one of 4 controlled
attacks in the `sandbox` namespace, then watches Falco detect it and Talon respond, live (SSE).

## Ownership (do not edit files owned by another session; if you need a change there, describe it in your report)
| Session | Branch | Owns |
|---|---|---|
| A api | `phase-5-api` | `app/api/**` (Go), `cluster/infra/portfolio-api/**`, `cluster/apps/portfolio-api.yaml`, `.github/workflows/build-*.yml` (generic image build), `cluster/infra/kyverno-policies/verify-portfolio-images.yaml` (identity for new images), Falcosidekick/Talon webhook outputs to the API (only the output/notifier lines in their values), HTTPRoute `/api` |
| B scenarios | `phase-5-scenarios` | `app/scenario/**` (Dockerfile + scripts for attack images), `cluster/infra/sandbox/scenarios/**` (scenario ConfigMap), Falco custom rules + Talon rulesOverride entries for the scenarios, `sandbox` ResourceQuota/LimitRange, `tests/scenarios/**` |
| C frontend | `phase-6-frontend` | `app/web/**` (replaces the placeholder site; keep nginx-unprivileged base + build-web.yml flow) |
| D docs | `phase-6-docs` | `README.md`, `docs/architecture/**`, `docs/threat-model.md`, `docs/adr/README.md` index only |
New ADRs: A uses 0015-0016, B uses 0017-0018, C 0019, D 0020 (renumber at merge if unused).

## API (served by A at https://hubertjablon.ski/api/*, JSON, no auth, CORS same-origin only)
- `GET /api/healthz` -> `{"status":"ok"}`
- `GET /api/scenarios` -> `[{"id","title","summary","technique" (MITRE ATT&CK id),"detection" (Falco rule name),"response" ("terminate"|"quarantine")}]`
- `POST /api/attack/{id}` -> `202 {"run_id","scenario","state":"queued"}`; `404` unknown id; `409` another run active
  (global concurrency 1); `429` rate limited (`Retry-After` header). Body empty.
- `GET /api/events` (SSE, `text/event-stream`, heartbeat comment every 15 s, replays last 50 events on connect):
  - `event: run` data `{"run_id","scenario","state":"queued|started|detected|responded|finished|failed|timeout","at","detail"}`
  - `event: falco` data `{"at","rule","priority","namespace","pod","output"}` (output truncated 300 chars; only ns sandbox)
  - `event: talon` data `{"at","action","namespace","pod","status"}`
- `GET /api/posture` -> `{"generated_at","kyverno":{"policies":[{"name","pass","fail","warn"}]},"trivy":{"images":N,"critical":N,"high":N,"medium":N,"low":N},"kube_bench":{"last_run","pass","fail","warn","info"},"falco":{"alerts_24h":N},"talon":{"actions_24h":N}}` (cached 60 s).
- Internal only (separate port 8081, not routed by Gateway, CNP allows only falco-response): `POST /internal/falco`
  (Falcosidekick webhook payload), `POST /internal/talon` (Talon webhook notifier payload).

## Scenarios (B defines, A executes)
ConfigMap `scenarios` in ns `portfolio-api` (key `scenarios.yaml`), list of:
`{id, title, summary, technique, detection, response, timeout_seconds, pod: <PodSpec template, image from ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:...>, exec: {command: [...], tty: bool} | null}`.
A creates the pod in `sandbox` (labels `sdp.hubertjablon.ski/run-id`, `sdp.hubertjablon.ski/quarantine: "false"`,
`activeDeadlineSeconds`), waits Ready, optionally execs `exec.command` (tty when needed, e.g. for "Terminal shell in
container"), correlates Falco/Talon events by pod name, deletes the pod at the end. IDs fixed:
`shell-in-container` (terminate), `network-tool` (quarantine), `sensitive-file-read` (terminate), `package-manager-drift`
or another drift/execution scenario of B's choice (B documents the final 4th id in the ConfigMap; A must not hardcode ids).

## Abuse limits (A enforces; B sizes sandbox quota)
Client IP from `CF-Connecting-IP` (trust only via cloudflared path); 3 attacks / 10 min / IP, 30 / hour global,
1 concurrent run; sandbox ResourceQuota (pods 3, cpu 500m, mem 512Mi); scenario pod timeout <= 120 s;
backend RBAC limited to sandbox pods create/get/list/watch/delete + pods/exec create + read of PolicyReports,
VulnerabilityReports, kube-bench Job logs (namespaced reads only where possible).

## Images
All images from `ghcr.io/hubertmj/self-defending-portfolio/<name>`, built, Trivy-gated, SBOM'd and cosign-keyless signed
on main by a workflow whose identity verify-portfolio-images accepts (A owns that change; identity stays pinned to
specific workflow files on refs/heads/main). Pin by digest in git; digests are filled after the first CI build on main
(use a clearly marked placeholder digest until then and list it in the report).
