# ADR 0031: The unguarded twin namespace: Falco detects, nothing responds, so the response's worth is visible

Date: 2026-10-02 · Status: accepted

## Context
The live demo's defender always wins at once, which makes the response look free and therefore unimpressive:
the visitor sees a pod detected and killed, but has nothing to compare it against. The owner asked to show
what the automatic response is *worth* by running the same attack twice at once - once where the cluster
responds, once where it only watches - so the contrast is the exhibit. The contract's part C is that
side-by-side "unguarded twin": the API's `compare` run creates two pods from one scenario, one in `sandbox`
and one in a namespace where Falco detects but nothing responds, and the page shows them next to each other.

The design question is what "unguarded" is allowed to mean. A namespace with the controls switched off would
teach the wrong lesson - that the pods were only safe because they were coddled. The point of this project is
that an ordinary hardened pod is detected and answered at runtime; the twin must keep being an ordinary
hardened pod. So "unguarded" has to mean exactly one thing missing, and everything else identical.

## Decision

**A second namespace, `sandbox-unguarded` (`cluster/infra/sandbox-unguarded`, Application
`cluster/apps/sandbox-unguarded.yaml`, wave 5 alongside `sandbox`), identical to `sandbox` in every preventive
layer and missing only the automatic response:**

- **Same preventive layers.** Pod Security `restricted` on the namespace; the same default-deny NetworkPolicy
  and DNS-only CiliumNetworkPolicy; the same victim ingress policy (`sandbox-unguarded-victim-from-api`,
  selecting the API's `managed-by` label, admitting the API on :8080); the same ResourceQuota (3 pods, 500m
  CPU, 512 MiB) and LimitRange. The Kyverno gate covers it: `sandbox-unguarded` is added to the namespace lists
  of `verify-portfolio-images` and `restrict-image-registries`, and `pod-security-restricted` already matches
  every namespace it does not explicitly exempt, so the twin's pods must be signed, from our registry, and
  `restricted` exactly as `sandbox`'s are. `make validate` renders every scenario pod in `sandbox-unguarded`
  too and runs the Kyverno gate over it.
- **The API has the same reach.** A `portfolio-api-runner` Role in `sandbox-unguarded`
  (`cluster/infra/portfolio-api/rbac.yaml`), identical verbs to the one in `sandbox`: the API creates, execs
  and deletes the twin pod exactly as the guarded one, and polls its shop on :8080 (the egress half of its CNP
  lists the twin).
- **The one thing missing: the automatic response.** Falco Talon gets **no Role** in `sandbox-unguarded` (there
  is no `talon-rbac.yaml` in the twin), and **no Talon rule matches it** - every rule in
  `cluster/infra/falco-response/talon/rules.yaml` pins `k8s.ns.name=sandbox`. Falco still *detects* in the twin:
  the stock rules fire everywhere, and the custom rules ("SDP network tool in sandbox", "SDP execution from
  shop volume") match `k8s.ns.name in (sdp_sandbox_namespaces)`, which includes the twin (ADR 0032). So the
  same attack raises the same alert in both namespaces; only in `sandbox` does an alert become an action.

**Why no quarantine policy copy.** The quarantine CiliumClusterwideNetworkPolicy is one cluster-wide object
(in `cluster/infra/sandbox`) that selects the quarantine label wherever it is set. Nothing sets that label in
the twin - no Talon rule runs there - so it never matches a twin pod, and there is no second copy to keep.

**Offline proof.** `tests/scenarios/offline.sh` asserts that every Talon response rule pins
`k8s.ns.name=sandbox` and none mentions `sandbox-unguarded`: a rule added without a namespace pin (which would
act cluster-wide, twin included) fails there. `make validate` renders the scenario pods in the twin and runs
the Kyverno gate, so a pod the twin would refuse fails in CI.

## Consequences
- A compromised twin pod keeps running and keeps serving the attacker's defacement - nothing kills or isolates
  it - which is exactly the contrast the side-by-side view shows: the guarded shop cut off or gone, the
  unguarded shop still compromised, with the time the attacker has held it. The API deletes the twin pod itself
  `compare_hold_seconds` after the guarded arm's response (ADR for the API), so "no automatic response" is not
  "runs forever".
- "Unguarded" is bounded, not open: the twin pod is still a `restricted`, signed, quota-capped,
  default-deny-networked pod. The lesson is "detection without response is not protection," not "these pods were
  only ever safe because something was switched off."
- The twin doubles the scenario pods `make validate` renders and the Kyverno gate judges; a scenario a policy
  would refuse now fails for both namespaces.
- The twin is only meaningful for the one-click catalogue scenarios (the API runs `compare` for those, not for
  the interactive terminal). The namespace and its policies exist regardless; nothing runs there unless the API
  places a pod.
- Live check integration must run: a `compare` run end to end, confirming Falco alerts in both namespaces and
  Talon acts only in `sandbox`.
