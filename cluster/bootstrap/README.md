# Bootstrap: the last manual step

Everything in `cluster/apps/` and `cluster/infra/` is deployed by Argo CD from git. Argo CD itself
cannot be, so it is installed once, from here, by `bootstrap.sh`. After that this directory is read
only in practice: it is applied again only to upgrade Argo CD.

The bootstrap is also the only moment anything in this project holds `cluster-admin`. `bootstrap.sh`
runs with an operator kubeconfig; from the next minute on, the cluster changes because a commit
landed, and the only credential in play is Argo CD's own service account.

## What is in here

| Path | What it is |
|------|------------|
| `bootstrap.sh` | idempotent installer: namespace, age key Secret, `kubectl apply -k argocd/`, wait, print next steps |
| `argocd/kustomization.yaml` | pinned upstream `install.yaml` + the three patches below |
| `argocd/namespace.yaml` | `argocd` namespace with Pod Security Standards `restricted` |
| `argocd/argocd-cm.yaml` | `kustomize.buildOptions` so the KSOPS exec plugin runs |
| `argocd/argocd-cmd-params-cm.yaml` | `server.insecure: "true"` — the UI is LAN-only, never published |
| `argocd/argocd-repo-server-ksops.yaml` | KSOPS init container + the age key mount |
| `argocd/root-application.yaml` | the app-of-apps root, pointing at `cluster/apps` |

## Before the first run

**1. The deployment-specific values are already filled in.** This repository deploys one cluster
(`hubertjablon.ski`, GitHub owner `HubertMJ`), and every value that names it is committed for real.
A fork has to replace each of them before its first sync:

| Value | Where | What it is |
|-------|-------|------------|
| `HubertMJ` / `hubertmj` | `cluster/apps/*.yaml`, `cluster/bootstrap/argocd/root-application.yaml`, the image path in `cluster/infra/hello/`, both image policies in `cluster/infra/kyverno-policies/`, `.github/workflows/build-web.yml`, `scripts/verify-image.sh`, `tests/admission/` | GitHub owner; the registry path is its lower-case form |
| `hubertjablon.ski` | `cluster/infra/gateway/`, `cluster/infra/hello/`, `cluster/infra/cloudflared/config.yaml`, `cluster/infra/cert-manager-issuers/` | the site's hostname and DNS zone |
| ACME contact email | `cluster/infra/cert-manager-issuers/clusterissuer-*.yaml` | Let's Encrypt account contact |
| tunnel UUID | `tunnel:` in `cluster/infra/cloudflared/config.yaml` | output of `cloudflared tunnel create portfolio` |
| age recipient | `.sops.yaml` | your age public key |
| `*.sops.yaml` | `cluster/infra/cert-manager-issuers/`, `cluster/infra/cloudflared/` | encrypted to this repository's key; a fork re-creates both from the `.example` templates |

```sh
grep -rIl -i 'hubertmj\|hubertjablon\.ski' --exclude-dir=.git .   # every file a fork has to look at
```

**2. Templates must not reach the cluster unfilled.** The `.example` templates carry
`REPLACE-ME` values. `bootstrap.sh` refuses to run while any file under `cluster/` other than a
`.example` template, or `.sops.yaml`, still contains `REPLACE-ME` or the age placeholder,
which catches a template copied into place and committed before it was filled in.

**3. Create the age key and the two encrypted secrets.** See `docs/bootstrap.md`, phase 2. The
cluster comes up without them; the two Applications that need them stay `Degraded` with the
decryption error visible in the UI until they exist. That is on purpose — see below.

## Running it

```sh
export KUBECONFIG=$PWD/kubeconfig                          # fetched by the Ansible k3s role
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
cluster/bootstrap/bootstrap.sh
```

Run it twice if you like; the second run changes nothing.

## Decisions recorded here

### The Argo CD version lives in a URL

`argocd/kustomization.yaml` pulls
`https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.3/manifests/install.yaml` as a kustomize
resource. The version is in the path, not in a `stable` alias, so "which Argo CD is this cluster
running" is answered by reading one line of a manifest, and upgrading is a one-line diff with a
changelog to point at (ADR 0008).

`kustomize build cluster/bootstrap/argocd` works with a stock kustomize — no KSOPS, no plugins. The
bootstrap layer deliberately does not depend on the plugin it installs.

### The UI is not exposed, so it does not terminate TLS

`server.insecure: "true"` reads alarming out of context. In context: there is no Ingress, no
HTTPRoute and no tunnel route for Argo CD (ADR 0003). The Service is a ClusterIP reached by
`kubectl port-forward` from the LAN. Terminating TLS in `argocd-server` would add a self-signed
certificate that no client validates, plus the redirect loop that comes with running it behind a
port-forward. Authentication is unchanged: login is still required.

### The age key is the one secret that cannot come from git

`bootstrap.sh` creates Secret `argocd/sops-age` from `$SOPS_AGE_KEY_FILE` by piping the file into
`kubectl create --dry-run=client -o yaml | kubectl apply -f -`. The key is never an argument, so it
never appears in the process table or the shell history, and it is never echoed.

Everything else — the Cloudflare DNS token, the tunnel credentials — is committed encrypted and
decrypted in-cluster by KSOPS with this key (ADR 0006).

### The KSOPS image has no shell

The usual KSOPS init container is `sh -c 'cp ... /custom-tools/'`. `viaductoss/ksops:v4.5.1` is
distroless: no `sh`, no `cp`. The copy is therefore done by the binary itself,
`ksops install /custom-tools`. Only the plugin is installed. Upstream's `--with-kustomize` form also
copies the image's kustomize (v5.3.0) over Argo CD's own (v5.8.1), and that older kustomize cannot
render Helm charts with the Helm 4 that Argo CD v3.5.3 bundles (ADR 0013, amendment). The
init container also needs `runAsUser: 65532` explicitly, because the image's `USER` is the *name*
`nonroot`, which the kubelet cannot resolve to a UID — `runAsNonRoot: true` alone fails it.

### A missing secret fails the sync instead of half-working

`cluster/infra/cert-manager-issuers/` and `cluster/infra/cloudflared/` each have a `ksops.yaml`
that names a `*.sops.yaml` file which is **not committed until you encrypt it**. Only the
`.example` template is in git.

That means `kustomize build` of those directories fails until the real file exists — loudly, in the
Argo CD UI, naming the missing file. The alternative designs were worse: an empty placeholder Secret
would let the ClusterIssuer sync and then fail DNS-01 with an authentication error three layers
away from the cause, and copying the example to the real name during bootstrap would put a secret
with the value `REPLACE-ME` into the cluster and into git history.

`scripts/validate-cluster.sh` knows about this. When the encrypted file and a readable
`$SOPS_AGE_KEY_FILE` are both there it renders for real, with the KSOPS plugin, from the same image
and digest the repo-server uses — so an operator who mis-encrypts finds out before pushing.
Otherwise (CI, or a fresh clone) it renders a throwaway copy with the generator removed and says so,
so the manifests next to the secret are still validated.
