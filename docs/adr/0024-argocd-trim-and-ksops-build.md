# ADR 0024: Argo CD runs only the controllers this installation uses

Date: 2026-10-02 · Status: accepted

## Context
ADR 0023 removed Dex from Argo CD's `install.yaml` because nothing used it, and recorded that nothing
else was found unused. That search looked at images, i.e. at what moves the posture number. Two
more upstream components are unused, but they run the same `quay.io/argoproj/argocd:v3.5.3` image as
the rest of Argo CD, so removing them was not visible in a per-image count and was not looked at:

- **The ApplicationSet controller.** `cluster/apps` is an app-of-apps of plain `Application` objects,
  one file each, each reviewed on its own; there is no `ApplicationSet` in this repository
  (`git grep -i applicationset`) or in the cluster (`kubectl get applicationsets -A`: none). The
  controller still ran, with a ClusterRole of its own, a Service, a NetworkPolicy and about 40 MiB.
- **The notifications controller.** Argo CD notifications need triggers, templates and services in
  `argocd-notifications-cm` and `notifications.argoproj.io/subscribe*` annotations on Applications or
  AppProjects. This repository sets none (the live ConfigMap and Secret have no data; no
  Application or AppProject carries the annotation). Alerting here is Falco -> Falcosidekick
  (ADR 0013). The controller still ran, with its Role, a metrics Service and about 37 MiB.

Each unused controller is a process with API credentials that can be wrong, a deployment to keep
patched and memory on an 8 GB node; none of that buys anything.

## Decision
**1. Both controllers are removed from the bootstrap kustomization**, by kustomize `$patch: delete`
on every object install.yaml v3.5.3 creates for them, matched by kind and name - the pattern
`argocd-dex-server-delete.yaml` set (ADR 0023):
`cluster/bootstrap/argocd/argocd-applicationset-controller-delete.yaml` (Deployment, Service,
ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy) and
`cluster/bootstrap/argocd/argocd-notifications-controller-delete.yaml` (Deployment, metrics
Service, ServiceAccount, Role, RoleBinding, NetworkPolicy, ConfigMap `argocd-notifications-cm`).
The rendered bootstrap goes from 55 objects to 40.

**2. What stays, and why** (checked against the v3.5.3 sources, not assumed):
- The CRD `applicationsets.argoproj.io`. argocd-server v3.5.3 builds an ApplicationSet informer
  unconditionally (`server/server.go`, `NewServer`: `appFactory.Argoproj().V1alpha1()
  .ApplicationSets().Informer()`, started in `Run`) and serves the ApplicationSet API and UI from
  it. It is not in the server's cache-sync wait, so the server would start without the CRD - but the
  informer would then fail its list/watch for the life of the process, and the UI's ApplicationSet
  view would error. With the CRD and no controller it is an empty list. The CRD also keeps an
  accidental `ApplicationSet` visible as a known, inert kind instead of an unknown one.
- Secret `argocd-notifications-secret`, empty. argocd-server reads it (and the ConfigMap) for its
  notifications API through notifications-engine, which treats either object being absent as empty
  (`pkg/api/factory.go`, `getConfigMapAndSecretWithListers`), so deleting both would be safe. The
  ConfigMap is deleted. The Secret is not, because a `$patch: delete` for it is a plaintext
  `kind: Secret` document in git, which `scripts/check-secrets-encrypted.sh` refuses (ADR 0006). The
  guard is right and is not weakened to remove an empty object.
- argocd-server's own RBAC on applicationsets, the `applicationsetcontroller.*` keys of
  argocd-cmd-params-cm, and upstream's `argocd-repo-server-network-policy`, which still names both
  controllers' pod labels as allowed clients on 8081. All inert without the controllers; patching
  them would widen the diff against install.yaml for no change in behaviour. A pod claiming either
  label needs create rights in `argocd`, which is already full control of Argo CD.

**3. Live objects are deleted explicitly, once, by name.** `kubectl apply -k` never prunes, and the
bootstrap is not an Argo CD Application (ADR 0005, amendment), so nothing would ever remove the
running controllers. `cluster/bootstrap/prune-removed-argocd-components.sh` lists every object the
three delete patches remove (Dex included, a no-op where 8.1 already ran), by kind and name, no label
selectors. It re-checks the preconditions against the cluster (no ApplicationSets, an empty
notifications ConfigMap), refuses to run while the checked-out kustomization still declares any of
the components, and is a server-side dry run unless given `--delete`. Runbook: `docs/bootstrap.md`,
8.5.

## Consequences
- Two fewer Deployments, one fewer ClusterRole/ClusterRoleBinding pair, two fewer Roles, Services,
  ServiceAccounts and NetworkPolicies in `argocd`; about 77 MiB of memory back. No change to the
  posture number: the image they ran is still running as argocd-server, repo-server and the
  application controller.
- Using either feature later is deleting its patch entry from `kustomization.yaml` (and, for
  notifications, adding the configuration as a patch) and re-applying the bootstrap.
- An Argo CD bump must re-check the delete patches against the new install.yaml: a renamed or new
  object for either controller would otherwise come back silently. `kubectl kustomize
  cluster/bootstrap/argocd | grep -i 'applicationset-controller\|notifications-controller'` must
  stay empty.
