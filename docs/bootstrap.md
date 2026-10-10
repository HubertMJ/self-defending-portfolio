# Bootstrap: from nothing to a hardened k3s node

Everything below is one-time and runs from an operator machine (any Linux/macOS with `curl`, `jq`,
`python3`, `ansible`). After bootstrap, no manual step touches the cluster: changes go through git.

## 0. Prerequisites (human, once)

| What | Where | Why |
|------|-------|-----|
| Proxmox API token | Proxmox UI → Datacenter → Permissions → API Tokens | `scripts/pve-create-vm.sh` creates the VM |
| SSH key pair | `ssh-keygen -t ed25519` | cloud-init injects the public key for user `ansible` |
| Cloudflare API token (zone: DNS edit + zone read) | Cloudflare dashboard | cert-manager DNS-01 (phase 2, step 4.2) |
| Cloudflare tunnel credentials | `cloudflared tunnel create` | inbound exposure without an open port (phase 2, step 4.2) |
| age key pair | `age-keygen -o ~/.config/sops/age/keys.txt` | SOPS secrets (phase 2, step 4.1) |

Proxmox token permissions (role on `/vms`, `/storage/<storage>` and `/nodes/<node>`; not root):
`VM.Allocate VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network VM.Config.Options
VM.Config.Cloudinit VM.PowerMgmt VM.Audit Datastore.AllocateSpace Datastore.AllocateTemplate Datastore.Audit Sys.Audit`.
Requires Proxmox VE 8.4 or newer (import of cloud images by URL).

The storage that receives the downloaded cloud image (`IMPORT_STORAGE`, `local` by default) must
advertise the `import` content type; Proxmox does not enable it out of the box. On the node, once:

```sh
pvesm set local --content iso,vztmpl,backup,import
```

`scripts/pve-create-vm.sh` checks this before downloading and stops with that command in the message
if it is missing.

Export the token for the current shell only (never write it to a file inside the repo):

```sh
export PVE_HOST=10.2.1.2 PVE_TOKEN_ID='ansible@pve!portfolio' PVE_TOKEN='...'
export PVE_INSECURE=1   # only if Proxmox still uses its self-signed certificate
```

Addresses reserved in the DMZ (VLAN 41, 10.4.1.0/24):

| Address | Use |
|---------|-----|
| 10.4.1.20 | k3s01 node (UniFi DHCP reservation on the VM's fixed MAC, static in cloud-init) |
| 10.4.1.30 | Cilium LB IPAM address of the Gateway Service; not announced, in-cluster only |

## 1. Create the VM

```sh
make vm            # or: scripts/pve-create-vm.sh  (VMID 120, k3s01, 10.4.1.20 in DMZ VLAN 41)
ssh ansible@10.4.1.20 true   # accept the host key after checking the fingerprint on the Proxmox console
```

The VM is created with `ciupgrade=0`, so cloud-init does not run a distribution upgrade on first
boot and does not hold the dpkg lock against the first Ansible run; patching is the
`unattended_upgrades` role's job. `hardening.yml` still waits for `cloud-init status --wait` before
it touches apt, so running it immediately after the VM starts is safe.

## 2. Harden the host (phase 1)

```sh
make hardening     # ansible-playbook playbooks/hardening.yml
make hardening     # second run must report changed=0 (Definition of Done)
```

What it does: base packages, journald cap, SSH drop-in (key-only, no root, no forwarding, modern crypto),
nftables default-deny input, sysctl hardening compatible with Cilium, auditd rules, unattended upgrades.

Escape hatch if SSH is lost: the VM runs the QEMU guest agent (`agent=1` on the VM, the
`qemu-guest-agent` package is part of the `base` role), so the Proxmox node can execute commands
inside the guest over the virtio serial port, with no network path and no password involved:

```sh
# on the Proxmox node
qm guest exec 120 -- /usr/sbin/nft flush ruleset          # drop the host firewall entirely
qm guest exec 120 -- /usr/bin/systemctl restart ssh       # after a bad sshd drop-in
qm guest exec 120 -- /usr/bin/journalctl -u ssh -n 50     # read why it is refusing connections
```

`nft flush ruleset` there is the blunt instrument: it also removes the tables Cilium and containerd
own, so re-run `make hardening` (and restart the Cilium agent) afterwards. The serial console
(`qm terminal 120`) shows boot output but cannot be logged into - cloud-init creates `ansible` with
an SSH key and no password by design. If the guest agent itself is not running, rebuilding the VM
(below) is the remaining option.

## 3. Cluster (phase 1 -> 2 handover)

```sh
make cluster       # k3s (no flannel, no kube-proxy) + Cilium
make verify        # read-only assertions
export KUBECONFIG=$PWD/kubeconfig   # fetched by the k3s role, gitignored
kubectl get nodes
```

## 4. GitOps (phase 2)

After step 3 the cluster is a working, empty, hardened k3s node. This section installs Argo CD once
and then never touches the cluster by hand again: `https://hubertjablon.ski` is served because a
commit landed, not because somebody ran a command.

Read `cluster/bootstrap/README.md` alongside this — it explains *why* each piece looks the way it
does. This section is the *order*.

### 4.0 Deployment-specific values

This repository deploys one cluster, and every value that names it is committed for real: GitHub
owner `HubertMJ` (registry path `ghcr.io/hubertmj/...`), hostname and zone `hubertjablon.ski`, the
ACME contact, the tunnel UUID, the age recipient in `.sops.yaml` and the two encrypted secrets. On this
repository there is nothing to replace; go to 4.4 if the key and the secrets already exist.

A fork replaces every one of them first. The full table of where each value lives is in
`cluster/bootstrap/README.md` ("Before the first run"); this finds every file to look at:

```sh
grep -rIl -i 'hubertmj\|hubertjablon\.ski' --exclude-dir=.git .
```

Only the `.example` templates carry `REPLACE-ME` values, and `bootstrap.sh` refuses to run if one is
found anywhere else under `cluster/` or in `.sops.yaml`.

### 4.1 age key and `.sops.yaml`

One key pair for this environment. The private half stays on the operator machine and, as a Secret,
in the cluster; nothing else ever sees it (ADR 0006).

```sh
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt        # prints the public key on stderr
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt

# put the public key (age1...) into .sops.yaml as the recipient (a fork replaces the committed one)
grep -o 'age1[0-9a-z]*' ~/.config/sops/age/keys.txt
$EDITOR .sops.yaml
```

Back up `keys.txt` somewhere that is not this repository and not this machine. Losing it means
re-creating both secrets below, which is cheap but not free.

### 4.2 Cloudflare: token and tunnel

Two credentials, two different scopes. Neither is the global API key.

**DNS-01 token**, for cert-manager. Cloudflare dashboard -> My Profile -> API Tokens -> Create
Token -> Custom token:

| Permission | Resource |
|------------|----------|
| Zone / DNS / Edit | Include -> Specific zone -> `hubertjablon.ski` |
| Zone / Zone / Read | Include -> Specific zone -> `hubertjablon.ski` |

That is the minimum needed to write and clean up `_acme-challenge` TXT records. It cannot touch the
tunnel, the WAF or any other zone.

**Tunnel**, for cloudflared. This uses *credentials-file* mode, not token mode, so the
hostname-to-service routing lives in git rather than in the Zero Trust dashboard (see the long
comment in `cluster/infra/cloudflared/config.yaml`):

```sh
cloudflared tunnel login                       # browser, once; authorises the zone
cloudflared tunnel create portfolio            # prints the UUID and writes ~/.cloudflared/<UUID>.json
cloudflared tunnel route dns portfolio hubertjablon.ski
cloudflared tunnel list
```

`tunnel route dns` creates the proxied CNAME `hubertjablon.ski -> <UUID>.cfargotunnel.com`. That is
the only DNS record the site needs, and it points at Cloudflare, never at the home IP (ADR 0003).

Copy the UUID into `tunnel:` in `cluster/infra/cloudflared/config.yaml`.

### 4.3 Encrypt the two secrets

Both directories ship a `.example` template next to the encrypted file (on this repository both
encrypted files are committed; a fork re-creates them with its own key). Without the encrypted file,
`kustomize build` — and therefore the Argo CD sync — fails. That is deliberate; see
`cluster/bootstrap/README.md`.

```sh
cd cluster/infra/cert-manager-issuers
cp cloudflare-api-token.sops.yaml.example cloudflare-api-token.sops.yaml
$EDITOR cloudflare-api-token.sops.yaml         # paste the DNS-01 token into stringData.api-token
sops -e -i cloudflare-api-token.sops.yaml
cd -

cd cluster/infra/cloudflared
cp cloudflared-credentials.sops.yaml.example cloudflared-credentials.sops.yaml
# paste the contents of ~/.cloudflared/<UUID>.json as the value of stringData."credentials.json"
$EDITOR cloudflared-credentials.sops.yaml
sops -e -i cloudflared-credentials.sops.yaml
cd -

# keys stay readable, values do not -- this is what makes a rotation reviewable
git diff --cached --stat
```

Check before committing: `stringData` must be an encrypted blob and there must be a `sops:` block at
the bottom of each file.

```sh
make validate     # now renders the KSOPS generators for real, using your key
git add -A && git commit -m 'phase 2: cluster secrets' && git push
```

### 4.4 Bootstrap Argo CD

```sh
export KUBECONFIG=$PWD/kubeconfig
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
cluster/bootstrap/bootstrap.sh
```

It creates the `argocd` namespace, the `sops-age` Secret from your key file (never printed), applies
`cluster/bootstrap/argocd`, waits for `argocd-server` and `argocd-repo-server`, and prints how to
read the initial admin password and how to reach the UI.

This is the only command in the whole project that holds `cluster-admin`.

```sh
kubectl -n argocd get applications -w
```

Expected order, by sync wave: `gateway-api-crds` (-2), `cilium` (-1), `cert-manager` (0),
`cert-manager-issuers` and `kyverno` (1), `kyverno-policies` and `cloudflared` (2), `gateway` (3),
`hello` (4).

`cilium` will show as adopting an existing release rather than creating one — Ansible installed it in
step 3 and Argo CD takes it over field by field via server-side apply. See the header comment in
`cluster/apps/cilium.yaml`. Do not run the Ansible `cilium` role against the cluster again unless
`scripts/check-cilium-values.sh` is green.

The Gateway API CRDs and Cilium's Gateway support both arrive in step 3, from the Ansible `cilium`
role, before Argo CD exists: `cilium-operator` only starts its Gateway controller if the CRDs are
already registered when it starts, and `gatewayAPI.enabled` is part of `cilium-config`, so switching
it on under running agents means restarting the Cilium DaemonSet and `cilium-envoy` by hand. Argo CD
re-applies the same CRDs (wave -2) and the same values (wave -1) and therefore changes nothing; no
restarts are part of this procedure.

### 4.5 Staging certificate first, then production

`cluster/infra/gateway/gateway.yaml` ships with `cert-manager.io/cluster-issuer: letsencrypt-prod`.
For a first bring-up, or any time the DNS-01 plumbing is unproven, switch it to staging first:
Let's Encrypt production has a hard per-domain rate limit and a broken solver burns it in minutes.

```sh
sed -i 's/letsencrypt-prod/letsencrypt-staging/' cluster/infra/gateway/gateway.yaml
git commit -am 'gateway: staging issuer' && git push

kubectl -n gateway get certificate portfolio-tls -w
kubectl -n gateway describe certificate portfolio-tls          # events show the DNS-01 challenge
kubectl -n cert-manager logs deploy/cert-manager -f
```

`Ready=True` with issuer `letsencrypt-staging` means the token, the zone permissions, the solver and
the Gateway annotation all work. The certificate is untrusted by browsers, which is the point.

Now switch to production and delete the staging Secret so cert-manager issues a fresh one:

```sh
sed -i 's/letsencrypt-staging/letsencrypt-prod/' cluster/infra/gateway/gateway.yaml
git commit -am 'gateway: production issuer' && git push
kubectl -n gateway delete secret portfolio-tls
kubectl -n gateway get certificate portfolio-tls -w
```

### 4.6 Verify

```sh
# the Gateway is programmed; its Service shows EXTERNAL-IP 10.4.1.30, an address nothing announces
# (ADR 0010, amendment 2026-10-01)
kubectl -n gateway get gateway portfolio
kubectl -n gateway get svc cilium-gateway-portfolio

# the tunnel has registered connections to the edge
kubectl -n cloudflared logs -l app.kubernetes.io/name=cloudflared --tail=20 | grep -i 'registered'

# the certificate the origin hop actually presents, read from the Secret Envoy serves
kubectl -n gateway get secret portfolio-tls -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -subject -issuer -dates

# from anywhere on the internet
curl -sI https://hubertjablon.ski
```

`curl -sI` must show `HTTP/2 200`, `strict-transport-security`, `content-security-policy`,
`x-content-type-options: nosniff` and a `cf-ray` header. Then:

```sh
curl -sI http://hubertjablon.ski        # 301 to https
```

### 4.7 The Definition of Done

Phase 2 is done when this changes the site and nothing else does:

```sh
$EDITOR app/web/src/index.html        # app/web/public/ until phase 6
git commit -am 'web: reword' && git push
# since phase 3 the page is an image: wait for the image workflow (build-images.yml since phase 5),
# then pin the digest it prints: scripts/bump-image-digest.sh web sha256:... (section 5.3), push again
# wait for Argo CD's poll (3 min by default), or nudge it:
kubectl -n argocd patch app hello --type merge -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"normal"}}}'
curl -s https://hubertjablon.ski | grep -i reword
```

### Troubleshooting

| Symptom | Cause |
|---------|-------|
| `hello` Application `Degraded`, "no such file or directory: *.sops.yaml" | step 4.3 not done, or the encrypted file was not committed |
| `cert-manager-issuers` sync error mentioning age | `sops-age` Secret missing or holds the wrong key; re-run `bootstrap.sh` |
| `Certificate` stuck `False`, challenge `pending` | DNS token lacks *Zone / Zone / Read*, or the zone in the solver's `dnsZones` is wrong |
| Cloudflare 502, tunnel healthy | Gateway has no certificate yet, or `cilium-gateway-portfolio` does not exist — check the GatewayClass is `Programmed` |
| Cloudflare 502, certificate ready | origin TLS verification failed; `originServerName` must equal the certificate's hostname |
| `gateway` Application stuck `Progressing` | Gateway API CRDs (wave -2) or the `cilium` GatewayClass (wave -1) missing |

## 5. Supply chain (phase 3)

Kyverno arrives with the rest of the cluster (`cluster/apps/kyverno.yaml`, wave 1; chart 3.9.1 /
Kyverno v1.19.1) and its three phase 3 ClusterPolicies in wave 2
(`cluster/apps/kyverno-policies.yaml` -> `cluster/infra/kyverno-policies/`; phase 4 adds two more,
section 6).

**State of this repository: all three image policies are Enforce.** The handover described in
5.1-5.4 - from "policies installed and watching" (Audit) to "policies gating" (Enforce), which cannot
happen before a signed image exists - was done in one commit ("phase 3: Kyverno admission ...; hello
runs the signed image"). The steps stay here as the procedure and its reasoning. A fork starts from the
Enforce state, so it must run 5.1 and 5.2 and commit its own signed digest (5.3) *before* the `hello`
Application syncs, or the site's pods are rejected; flipping the two image policies back to Audit
(5.4 in reverse, `mutateDigest` included) is the alternative for a first bring-up.

```sh
grep -n 'failureAction' cluster/infra/kyverno-policies/*.yaml
```

| Policy | Committed action | Scope |
|--------|------------------|-------|
| `verify-portfolio-images` | Enforce (was Audit until 5.4) | Pods in `hello`, `sandbox` |
| `restrict-image-registries` | Enforce (was Audit until 5.4) | Pods in `hello`, `sandbox` |
| `disallow-latest-tag` | Enforce from the start | Pods everywhere except kube-system, kyverno, argocd, cilium-secrets, cert-manager, gateway, cloudflared |

### 5.1 The first build must run

Verification is an assertion about a signature that does not exist yet. Push to `main` and let
the image workflow complete at least once (`.github/workflows/build-web.yml` in phase 3, replaced by
`.github/workflows/build-images.yml` for every image under `app/` in phase 5, ADR 0016); it builds the image, pushes it to
`ghcr.io/hubertmj/self-defending-portfolio/web`, signs the digest keylessly with cosign and attaches
an SPDX SBOM attestation.

### 5.2 The GHCR package must be public

Kyverno pulls the image manifest, the cosign signature and the attestation **anonymously**, from
inside the cluster. A package that GHCR created private makes every verification fail with
`UNAUTHORIZED`, which looks exactly like an unsigned image.

GitHub → your profile → Packages → `self-defending-portfolio/web` → Package settings → Change
visibility → Public. Also link it to the repository there, so the package inherits the repo's
Actions permissions.

Check it the way Kyverno will, with no credentials:

```sh
docker logout ghcr.io
crane digest ghcr.io/hubertmj/self-defending-portfolio/web:<tag>     # or: docker manifest inspect
cosign verify ghcr.io/hubertmj/self-defending-portfolio/web:<tag> \
  --certificate-identity-regexp '^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images|build-web)\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation ghcr.io/hubertmj/self-defending-portfolio/web:<tag> --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images|build-web)\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Both commands must succeed from a machine that is not logged in to GHCR. The identity regexp and
issuer above are character-for-character what `cluster/infra/kyverno-policies/verify-portfolio-images.yaml`
asserts, so if `cosign` is happy, Kyverno will be. That holds because the policy uses
`type: SigstoreBundle`: cosign v3 stores the signature and attestation as OCI 1.1 referrers (Sigstore
bundles), not as `.sig`/`.att` tags, and Kyverno's default `type: Cosign` would not find them
(ADR 0011, amendment 2026-10-01). `--type spdxjson` is a cosign CLI short name; the policy has to
spell out the predicate type `https://spdx.dev/Document`.

### 5.3 Point `hello` at the signed digest

Before phase 3, `hello` ran `nginxinc/nginx-unprivileged` plus a ConfigMap, which is not ours and
which nobody signed. It now runs our own image, pinned by digest through a kustomize `images:`
transformer in `cluster/infra/hello/kustomization.yaml` rather than in the Deployment: the image
reference has one home, a rebuild is a one-line diff, and nothing else in the Deployment moves. Every
new build is deployed the same way, by committing the digest that the image workflow (`build-web.yml`
in phase 3, `build-images.yml` since phase 5) prints in its job summary:

```yaml
# cluster/infra/hello/kustomization.yaml
images:
  - name: ghcr.io/hubertmj/self-defending-portfolio/web
    newTag: main                 # informational only
    digest: sha256:<digest>      # what is actually pulled and verified (ADR 0008)
```

The image must listen on 8080 as a non-root uid and run with a read-only root filesystem, because the
`hello` namespace enforces Pod Security Standards `restricted` and the Deployment's `securityContext`
already says so. Check `runAsUser` in the Deployment against the uid the new image actually uses.

### 5.4 Flip Audit → Enforce, in the same commit (done)

This was one commit with 5.3, not a follow-up, and that is still the rule for a fork. Enforce before the image is ours stops the site;
our image without Enforce means phase 3 is not done.

In `cluster/infra/kyverno-policies/verify-portfolio-images.yaml`:

- `verify-signature`: `failureAction: Audit` → `Enforce` **and** `mutateDigest: false` → `true`.
  Those two move together: Kyverno refuses to install a rule that rewrites the image reference while
  only auditing (`mutateDigest must be set to false for 'Audit' failure action`), and `mutateDigest`
  is what closes the gap between the digest that was verified and the one the kubelet pulls.
- `verify-sbom-attestation`: `failureAction: Audit` → `Enforce`. Its `mutateDigest` stays `false` —
  `verify-signature` already pinned the digest. Do not `sed` the file.

In `cluster/infra/kyverno-policies/restrict-image-registries.yaml`: `failureAction: Audit` →
`Enforce`.

```sh
make validate
git commit -am 'phase 3: hello runs the signed image, image policies enforce' && git push
kubectl -n argocd get app hello kyverno-policies -w
kubectl get clusterpolicy                       # all three Ready
kubectl get policyreport -A                     # should go quiet for hello
```

### 5.5 Prove it

```sh
export KUBECONFIG=$PWD/kubeconfig
tests/admission/run.sh
```

Three `kubectl apply --dry-run=server` calls that must all be **denied**, each by the policy named in
the Pod's `tests.hubertjablon.ski/expect-policy` annotation: an unsigned image from our own registry
path, a perfectly ordinary `docker.io/library/busybox:1.37`, and a `:latest` tag. The specs are
`restricted`-compliant on purpose, so the only thing left for the cluster to object to is the image —
a PSS rejection would make the test pass for the wrong reason. Nothing is scheduled and no image is
pulled.

Pass the signed digest to assert the other half, that the gate has a hole exactly where it should:

```sh
SIGNED_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/web@sha256:... tests/admission/run.sh
```

The same policies can be exercised without a cluster, which is what CI does:

```sh
docker run --rm -v "$PWD":/work -w /work \
  ghcr.io/kyverno/kyverno-cli:v1.19.1@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a \
  apply cluster/infra/kyverno-policies/ --resource tests/admission/latest-pod.yaml
```

### 5.6 Kyverno's egress is deliberately open for now

The `kyverno` namespace has **no NetworkPolicy**, and the chart's own `networkPolicy` options are
left off. Verification needs the API server, GHCR (image manifests, signatures, attestations), Fulcio
and Rekor; a default-deny namespace would turn every one of those into a verification failure, which
with `failurePolicy: Fail` means a cluster that cannot start Pods. Phase 4 adds a
`CiliumNetworkPolicy` that allows exactly those destinations and denies the rest.

One related trade-off, recorded where it will be read: `verify-portfolio-images` and
`restrict-image-registries` use `failurePolicy: Fail` (a Kyverno outage must not admit an unverified
Pod) but match only two namespaces, so an outage cannot wedge the cluster. `disallow-latest-tag`
matches almost every namespace and therefore uses `failurePolicy: Ignore`: with `Fail` it would
stop every Pod creation on this single node during a Kyverno outage, including the Kyverno and Argo CD
pods needed to end it. A floating tag slipping in during those minutes is caught by CI and reported
afterwards; an unrecoverable cluster is not.

### Troubleshooting

| Symptom | Cause |
|---------|-------|
| every verification fails with `UNAUTHORIZED` or `MANIFEST_UNKNOWN` | the GHCR package is still private (5.2), or the tag was never pushed |
| `failed to verify image ...: no matching signatures` | the workflow ran on a branch or as a `pull_request`, so the certificate SAN is not `@refs/heads/main` |
| `image attestations verification failed, verifiedCount: 0` | the build ran before `cosign attest` was added, or signed a different digest than it attested |
| `kyverno-policies` Application `Degraded`, `no matches for kind "ClusterPolicy"` | wave 1 has not finished; `SkipDryRunOnMissingResource=true` covers the dry-run but the CRD still has to exist before the apply |
| `mutateDigest must be set to false for 'Audit' failure action` | half a flip: `failureAction` was set back to `Audit` without putting `mutateDigest` back to `false` (5.4) |
| webhook timeouts on Pod creation, cluster-wide | Kyverno cannot reach Rekor/Fulcio/GHCR; check egress before suspecting the policy (5.6) |
| Pods cannot be created at all and Kyverno is down | `kubectl delete validatingwebhookconfiguration -l webhook.kyverno.io/managed-by=kyverno` breaks the deadlock; Kyverno recreates them on startup |

## 6. Runtime security and posture (phase 4)

Everything in this phase arrives through Argo CD like the rest; there is nothing to install by hand.
The new Applications, all wave 5 (`cluster/apps/kustomization.yaml`):

| Application | Namespace (PSA enforce) | What | ADR |
|-------------|-------------------------|------|-----|
| `policy-reporter` | `policy-reporter` (restricted) | reports UI, cluster-internal; Trivy CVE details plugin | 0014 |
| `trivy-operator` | `trivy-system` (restricted) | image / config / RBAC scans, Trivy server, PolicyReport adapter | 0014 |
| `kube-bench` | `kube-bench` (privileged) | daily CIS benchmark CronJob, JSON in the Job log | 0014 |
| `falco` | `falco` (privileged) | modern eBPF sensor, 4 capabilities, no API token | 0013 |
| `falco-response` | `falco-response` (restricted) | Falcosidekick -> Falco Talon | 0013 |
| `sandbox` | `sandbox` (restricted) | victims for the runtime test, quarantine policy, Talon's Role | 0013 |

The two privileged namespaces hold one workload each and are judged control by control by Kyverno's
`pod-security-restricted` policy (ADR 0012), which is **Enforce** since the flip in 6.4.

One bootstrap change comes with this phase. `argocd-cm` gains `--enable-helm` in
`kustomize.buildOptions`, so that `cluster/infra/falco` can render the Falco chart and patch its host
mounts read-only (ADR 0013, amendment). Apply it by hand, once, before the falco Application syncs:

```sh
kubectl diff -k cluster/bootstrap/argocd        # expect only ConfigMap argocd-cm to differ
kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts
```

One host change comes with this phase as well. `kernel.perf_event_paranoid` goes from Debian's 3
to the upstream default 2 (ADR 0013, amendment), without which the least-privileged Falco probe
cannot attach its tracepoints. It is part of the sysctl role:

```sh
cd ansible && ansible-playbook playbooks/hardening.yml --tags sysctl
ssh <node> sysctl kernel.perf_event_paranoid        # 2
```

After each Application syncs, check the node's memory (plan budget: under 80 %, about 6.2 GiB):

```sh
kubectl top nodes
```

### 6.1 Look at the reports

```sh
kubectl -n policy-reporter port-forward svc/policy-reporter-ui 8082:8080    # http://localhost:8082
kubectl get vulnerabilityreports -A                                         # first pass: ~30 min
kubectl -n kube-bench create job --from=cronjob/kube-bench kube-bench-manual
kubectl -n kube-bench logs job/kube-bench-manual | jq '.Totals'
```

kube-bench reads the k3s components' flags from the node's journal (`journalctl -m -u k3s`, the
`Running kube-apiserver ...` line k3s logs at start-up), with upstream's k3s-cis-1.9 plus this
repository's patch (ADR 0025 and its 2026-10-10 amendment; until ADR 0025 from
`/etc/rancher/k3s/config.yaml`, ADR 0014, which made every flag k3s sets itself fail). A flag check
that FAILs or WARNs with an empty actual value means the journal no longer holds the last start's
lines: `journalctl -u k3s | grep -c 'Running kube-apiserver'` on the node.

Expected since 8.11: 69 PASS / 0 FAIL / 2 WARN / 17 INFO in kube-bench's own totals. The 17 INFO
are the checks the benchmark marks not applicable (`type: skip`) - the posture page shows them as
"not applicable" with their reason, not as INFO. The 2 WARN are 3.1.1 and 3.1.2, documented
exceptions (ADR 0025, amendment).

```sh
kubectl -n kube-bench logs job/kube-bench-manual \
  | jq -r '.Controls[].tests[].results[] | select(.status!="PASS") | "\(.status) \(.type) \(.test_number)"'
```

### 6.2 Falco is running with the least-privileged probe

```sh
kubectl -n falco logs ds/falco | grep -m1 'Opening .syscall. source with modern BPF probe'
kubectl -n falco-response get lease falco-talon -o jsonpath='{.spec.holderIdentity}{"\n"}'
kubectl get polr -n falco -o wide        # pod-security-restricted: 0 fail for the Falco pod
```

If the probe does not open, check the AppArmor and BPF messages in the Falco log first; the
`restricted-falco` exclusions and the four capabilities are the contract, not a starting point to widen.

### 6.3 Prove it: the Definition of Done

```sh
export KUBECONFIG=$PWD/kubeconfig
make runtime-test          # = tests/runtime/run.sh; run it twice in a row
```

It creates short-lived victim pods in `sandbox` (our signed web image, `restricted`, labelled
`sdp.hubertjablon.ski/quarantine: "false"`) and deletes them on exit:

1. `kubectl exec -it` a shell into a victim (through `script`, so there is a real TTY) and asserts
   that the pod is deleted within 30 s, with a Falco "Terminal shell in container" alert, a
   Falcosidekick POST to Talon, and a successful Talon `kubernetes:terminate` log line.
2. Runs `wget` in a second victim and asserts that Talon labels it `quarantine=true`, that it keeps
   running, and that a DNS lookup that worked before now fails (the quarantine policy).
3. Asserts with `kubectl auth can-i` that Talon's ServiceAccount can delete and patch pods in
   `sandbox` and nothing in `hello` or `kube-system`, no Namespaces, no Events, no secrets, no exec.

Needs `script` (util-linux) on the operator machine.

### 6.4 Flip Audit → Enforce (plan commit 9)

`pod-security-restricted` and `require-pod-resources` move to Enforce only when both
`kubectl get polr,cpolr -A` (after the Trivy scan Jobs have run at least once) and `make validate`
show zero failures for both policies. Both held on 2026-10-01 (ADR 0012, amendment), and the commit
flips every rule of both policies to `failureAction: Enforce`; `failurePolicy` stays `Ignore`.

After Argo CD has synced it:

```sh
kubectl get clusterpolicy pod-security-restricted require-pod-resources   # both Ready
tests/admission/run.sh       # now also: privileged Pod and Pod without resources in `default` rejected
tests/runtime/run.sh         # victims still admitted
kubectl get applications -n argocd   # all Synced / Healthy
```

Rollback is the revert of that commit (back to Audit); the policies fail open either way.

### Troubleshooting

| Symptom | Cause |
|---------|-------|
| `falco` Application error, `must specify --enable-helm` | the argocd-cm change above was not applied |
| Falco CrashLoop, `perf_event_open() failed: Permission denied` | `kernel.perf_event_paranoid` is still Debian's 3; run the sysctl role (above) |
| Falco CrashLoop, other BPF / permission errors | AppArmor not `Unconfined`, or a capability missing from `containerSecurityContext` (all four must be listed next to `drop: [ALL]`) |
| Falco alerts but Talon does nothing | Talon holds no Lease (RBAC for `leases` in `falco-response`), or Falcosidekick's POSTs are dropped (`hubble observe --namespace falco-response`) |
| Talon logs a 403 | it acted on a pod outside `sandbox`, which is the RBAC working; or its `sandbox` Role is missing |
| victim not labelled, Talon logs a JSON Patch error | the victim lacks the pre-set `sdp.hubertjablon.ski/quarantine: "false"` label |
| Trivy scan Jobs fail pulling layers | a registry or blob host missing from `cluster/infra/trivy-operator/ciliumnetworkpolicy.yaml` |
| dropped flows anywhere | `kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --verdict DROPPED --namespace <ns> --last 50` |

## 7. The portfolio API, the attack scenarios and the new site (phases 5 and 6)

Phases 5 and 6 reach `main` in two merges, because Argo CD syncs `main` and the images the new
manifests pin do not exist until CI has built them from `main` (ADR 0016).

### 7.1 Stage 1: the images are built, nothing in the cluster changes

The first merge carries the sources (`app/api`, `app/scenario`, the rewritten `app/web`), the single
image workflow `.github/workflows/build-images.yml` and the widened signer identity in
`verify-portfolio-images` (`build-images.yml` *or* the phase 3 `build-web.yml`, so the digest hello
runs today stays admissible). No Application, digest or route changes, so the live site is untouched.

1. Merge and push to `main`. Because the workflow file itself changed, `build-images` builds all three
   images: `api`, `scenario` and `web`. Each job's summary prints `<image>@sha256:...`.
2. **Check that the two new packages are public.** Kyverno reads signatures anonymously, so a private
   package fails verification like an unsigned image does. GHCR usually gives a package pushed by a
   public repository's workflow the repository's visibility; if `self-defending-portfolio/api` or
   `self-defending-portfolio/scenario` is private, make it public as in 5.2 and link it to the
   repository. The check in step 3 (logged out) answers the question either way.
3. Check each digest from a machine that is not logged in to GHCR:

   ```sh
   docker logout ghcr.io
   for n in api scenario web; do scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/$n@sha256:<digest>; done
   ```

Stage 2 (the digest pins, the `portfolio-api` Application, hello's switch to the new site) is
section 7.2.

### 7.2 Stage 2: pin the digests, then let Argo CD roll it out

The second merge adds the `portfolio-api` Application (wave 6: the API and, as its second source, the
scenario catalogue `cluster/infra/sandbox/scenarios`), the sandbox ResourceQuota and LimitRange, the
two new Talon rules, the Falcosidekick and Talon webhooks to the API, and hello's switch to the new
site together with the route CSP that site needs (ADR 0019). It is committed with all-zero
placeholder digests, which `make validate` and CI refuse (`scripts/check-image-digests.sh`), so it
cannot reach `main` until they are filled.

1. Pin the three digests from the stage 1 run, verify each, and validate:

   ```sh
   scripts/bump-image-digest.sh web      sha256:<web digest>       # cluster/infra/hello
   scripts/bump-image-digest.sh api      sha256:<api digest>       # cluster/infra/portfolio-api
   scripts/bump-image-digest.sh scenario sha256:<scenario digest>  # the scenario catalogue
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/web@sha256:<web digest>
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/api@sha256:<api digest>
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:<scenario digest>
   make lint validate     # validate now runs Kyverno's signature check on all three digests
   ```

2. Commit the pins on the stage 2 branch, merge, push. `build-images` does not run again unless
   `app/` changed; Argo CD syncs `falco-response` (new webhook output, Talon config), `sandbox` (quota,
   LimitRange), `hello` (new digest and CSP; a rolling update, `maxUnavailable: 0`) and creates
   `portfolio-api`.
3. Accept it on the cluster, in this order:

   ```sh
   argocd app list                                  # every Application Synced/Healthy, portfolio-api included
   SIGNED_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/web@sha256:<web digest> tests/admission/run.sh
   make runtime-test                                # phase 4 DoD, now with hello's new image as the victim
   make scenario-test                               # the four scenarios: alert, action, end state
   make abuse-test                                  # against https://hubertjablon.ski (spends your own quota)
   curl -sI https://hubertjablon.ski/ | grep -i content-security-policy   # the ADR 0019 policy
   curl -s https://hubertjablon.ski/api/healthz     # {"status":"ok"}
   ```

   Then open the site: posture panel filled, scenario list shows four entries, launching one shows
   attack -> detection -> response in the timeline; the browser console shows no CSP or Trusted Types
   violation.

4. Once that has held for a while, drop the transitional `|build-web` alternative from the signer
   identity in `verify-portfolio-images`, `scripts/verify-image.sh` and the cosign commands in 5.2,
   in one commit of its own (ADR 0016). Until then a revert of stage 2 can bring back the phase 3
   digest without a rebuild.

Rollback: revert the stage 2 merge. hello goes back to the phase 3 digest (still admissible during the
transition), the `portfolio-api` Application and its namespace are pruned, and Talon and
Falcosidekick lose their webhook. Stage 1 can stay: it changes nothing Argo CD deploys apart from the
two image policies' identity and namespace list.

### 7.3 Cloudflare: cached assets follow the origin, errors are never cached

Manual, in the Cloudflare dashboard (this repository has no Cloudflare API access by design, ADR 0003).
The origin already marks every error `no-store` (ADR 0019, amendment); this rule makes the edge
independent of that, so one origin mistake cannot be served from cache for a year.

1. **Purge what is already wrong.** Caching -> Configuration -> Purge Cache -> **Purge Everything**.
   Purge by URL is not enough: the page loads its bundle as a module script, which sends an `Origin`
   header, and the cached 404 was a variant keyed on it that a URL purge did not reach (observed
   2026-10-01). Purging everything is harmless here: the assets are content-hashed and refill on
   their first request.

   With errors marked `no-store` at the origin and the rule below, a purge is no longer part of a
   normal rollout. When one is needed, it stays a manual dashboard step. The Cloudflare API token in
   `cluster/infra/cert-manager-issuers` exists for DNS-01 challenges inside the cluster; it should
   carry Zone:DNS:Edit for this zone and nothing else. A Cache Purge permission on it gives cert-manager
   (and anything that can read that Secret) the power to flush the site's cache for no benefit, so
   remove that permission again. Do not reuse the token in CI either: that would copy a zone-wide
   credential into GitHub secrets for a step that a cache-safe origin makes unnecessary.
2. **Cache Rule for the assets.** Caching -> Cache Rules -> Create rule:
   - When incoming requests match: URI Path starts with `/assets/`;
   - Cache eligibility: Eligible for cache;
   - Edge TTL: use the cache-control header if present, bypass the cache if not;
   - Status code TTL: range 400-599 -> No store;
   - Browser TTL: respect origin.
3. **Check from outside**, for a missing and an existing asset:

   ```sh
   curl -sI https://hubertjablon.ski/assets/main-NOTBUILT.js | grep -i -E '^HTTP|cache-control|cf-cache-status'
   # HTTP/2 404, cache-control: no-store, cf-cache-status: BYPASS or MISS - never HIT
   curl -sI "https://hubertjablon.ski$(curl -s https://hubertjablon.ski/ | grep -o '/assets/main-[A-Za-z0-9_-]*\.js' | head -1)" \
     | grep -i -E '^HTTP|cache-control'
   # HTTP/2 200, cache-control: public, max-age=31536000, immutable
   ```

## 8. Fewer third-party vulnerabilities (ADR 0023)

The posture page counts every CRITICAL and HIGH finding Trivy Operator reports in every running
image, and the count stays honest: nothing is ignored, filtered or suppressed (ADR 0023). It goes
down only when an image goes away or is replaced by a fixed one. Most of those changes arrive through
Argo CD like everything else; the ones below are the exceptions, because they touch what Argo CD does
not manage.

### 8.1 Argo CD: Dex removed, Redis one patch release on (bootstrap re-apply)

`cluster/bootstrap/argocd/` is applied by hand (ADR 0005, amendment). Check that the diff is what you
expect - the Dex objects gone from the rendered set, `argocd-redis` on `8.2.10-alpine@sha256:b516...`
and nothing else - then apply:

```sh
kubectl diff -k cluster/bootstrap/argocd          # argocd-redis image; Dex is absent, not "deleted"
kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts
kubectl -n argocd rollout status deploy/argocd-redis
```

#### Removing Dex

`kubectl apply` does not prune, so the Dex objects the old bootstrap created stay until they are
deleted once. Nothing refers to them (no `dex.config`, no `oidc.config` in `argocd-cm`):

```sh
kubectl -n argocd get cm argocd-cm -o jsonpath='{.data.dex\.config}{.data.oidc\.config}'   # empty
kubectl -n argocd delete deployment/argocd-dex-server service/argocd-dex-server \
  serviceaccount/argocd-dex-server role/argocd-dex-server rolebinding/argocd-dex-server \
  networkpolicy/argocd-dex-server-network-policy
argocd login localhost:8080 --username admin --plaintext   # through the usual port-forward: still works
```

Trivy Operator deletes the VulnerabilityReports of a workload that is gone, so the posture page
drops Dex's findings within a scan cycle.

### 8.2 k3s v1.35.9+k3s1: the bundled CoreDNS (Ansible, by hand)

CoreDNS and metrics-server are not Argo CD's: k3s deploys them from manifests compiled into its
binary, so their images move only with k3s. v1.35.9+k3s1 (2026-09-30) bundles CoreDNS 1.14.7
(v1.35.8: 1.14.6, 14 HIGH in the cluster; with today's Trivy DB 1.14.6 scans 26 HIGH, 1.14.7 16)
and the same metrics-server v0.9.0, which stays: nothing newer is published, and `kubectl top` (6)
uses it. (Since ADR 0025 metrics-server is this repository's build, deployed by Argo CD, and k3s no
longer deploys its own copy: 8.10.) The release also moves Kubernetes to v1.35.9 and containerd to
v2.2.7-k3s1; its Traefik warning does not apply (Traefik is disabled, `k3s_disable_components`).

`k3s_version` is pinned in `ansible/inventory/group_vars/k3s_nodes.yml` (and the role default). The
role downloads the binary from the release and checks it against the release's own
`sha256sum-amd64.txt`, so the bump is the version string only. Run the k3s role alone - never the
cilium role against the live cluster (`cluster/apps/cilium.yaml`):

```sh
cd ansible
ansible-playbook playbooks/cluster.yml --tags k3s --check --diff   # expect: the binary, "Restart k3s"
ansible-playbook playbooks/cluster.yml --tags k3s                   # restarts k3s once; pods keep running
cd .. && kubectl get nodes -o wide                                  # VERSION v1.35.9+k3s1, Ready
kubectl -n kube-system get deploy coredns -o jsonpath='{.spec.template.spec.containers[0].image}'
# rancher/mirrored-coredns-coredns:1.14.7
make verify
```

A restart of k3s on one node interrupts the API server for under a minute. Running containers keep
running (their containerd shims outlive the restart), and Argo CD and Kyverno reconnect on their own.

Since ADR 0026 the image the cluster runs is this repository's (8.7), not k3s's: the bump above still
matters for Kubernetes, containerd and metrics-server, and on every k3s bump compare the release's
`manifests/coredns.yaml` with `ansible/roles/k3s/templates/coredns-sdp.yaml.j2`.

### 8.3 Falco Talon from this repository (two stages, like section 7)

`app/talon` is built and signed by `build-images.yml` only from `main`, and the manifests that run it
pin its digest, so it reaches the cluster in two pushes - the same pattern as 7.1/7.2:

1. **Stage 1: the image.** Push everything up to and including the commit that adds `app/talon/`
   (and none of the commit "falco-response: run Talon from this repository's signed image"). The
   workflow builds `talon` (Trivy gate, SBOM, cosign) and prints `.../talon@sha256:...`. Nothing in
   the cluster changes. Make sure the new GHCR package `self-defending-portfolio/talon` is public
   (5.2), then from a machine that is not logged in to GHCR:

   ```sh
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/talon@sha256:<digest>
   docker run --rm -v "$PWD/cluster/infra/falco-response/talon":/t:ro \
     ghcr.io/hubertmj/self-defending-portfolio/talon@sha256:<digest> rules check -c /t/config.yaml -r /t/rules.yaml
   ```

2. **Stage 2: the switch.** On the switch commit, replace the placeholder and validate - `make
   validate` refuses the placeholder and runs Kyverno's signature check on the real digest, now
   that `falco-response` is in `verify-portfolio-images`:

   ```sh
   scripts/bump-image-digest.sh talon sha256:<digest>   # cluster/infra/falco-response/kustomization.yaml
   make lint validate scenario-offline                  # scenario-offline reads the same digest
   git commit --amend --no-edit && git push
   ```

   Argo CD rolls `falco-talon` (one replica: an alert that arrives in the seconds of the roll may go
   unanswered, the same window as any Talon update). Accept it:

   ```sh
   kubectl -n falco-response get deploy falco-talon -o jsonpath='{.spec.template.spec.containers[0].image}'
   kubectl -n falco-response logs deploy/falco-talon | head -5     # JSON lines, leader elected
   make runtime-test && make scenario-test
   ```

Rollback: revert the switch commit; the upstream 0.3.0 image comes back and the two policy additions
go with it.

### 8.4 Everything else arrives with the sync

Falcosidekick 2.35.0 (`falco-response`), Trivy 0.75.0 (`trivy-operator`, `policy-reporter`) and the
posture API/page changes (`build-images.yml`, then `scripts/bump-image-digest.sh api|web ...` as in
7.2) need nothing by hand. After a scan cycle, the number on the page is the live count again:

```sh
kubectl get vulnerabilityreports -A -o json | jq '[.items[] | {k: (.report.registry.server + "/"
  + .report.artifact.repository + "@" + .report.artifact.digest), n: (.report.summary.criticalCount
  + .report.summary.highCount)}] | unique_by(.k) | map(.n) | add'
curl -s https://hubertjablon.ski/api/posture | jq '.trivy | {critical, high, own, third_party}'
```

### 8.5 Argo CD: ApplicationSet and notifications controllers removed (bootstrap re-apply, ADR 0024)

Two more upstream components that nothing uses leave the bootstrap kustomization:
`argocd/argocd-applicationset-controller-delete.yaml` and
`argocd/argocd-notifications-controller-delete.yaml` (15 objects; the rendered bootstrap goes from 55
to 40). The CRD `applicationsets.argoproj.io` and the empty `argocd-notifications-secret` stay - the
patch files say why. This does not move the posture number: both controllers ran the same
`quay.io/argoproj/argocd:v3.5.3` image as the rest of Argo CD, which is still running. What goes is
two processes, a ClusterRole, and their memory on an 8 GB node.

First confirm the reasons still hold, then re-apply. The diff is empty: the removed objects are
*absent* from the rendered set, not marked for deletion, and every object that stays is unchanged:

```sh
kubectl get applicationsets -A                                         # No resources found
kubectl -n argocd get cm argocd-notifications-cm -o jsonpath='{.data}'   # empty
kubectl get applications,appprojects -A -o json \
  | jq -r '.items[].metadata.annotations // {} | keys[]' | grep -c notifications.argoproj.io   # 0
kubectl diff -k cluster/bootstrap/argocd --server-side --force-conflicts   # no output, exit 0
kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts
```

#### Removing the live objects

`kubectl apply` does not prune, so the two controllers keep running until they are deleted once.
Every object is listed by kind and name, with nothing selected by label, in
`cluster/bootstrap/prune-removed-argocd-components.sh`. It checks the same preconditions again,
refuses to run while the checked-out kustomization still declares any of the components, and
deletes nothing without `--delete`:

```sh
cluster/bootstrap/prune-removed-argocd-components.sh            # server-side dry run: lists what would go
cluster/bootstrap/prune-removed-argocd-components.sh --delete
kubectl -n argocd get deploy                 # argocd-redis, argocd-repo-server, argocd-server
kubectl -n argocd get sts                    # argocd-application-controller
kubectl get clusterrole argocd-applicationset-controller   # NotFound
argocd login localhost:8080 --username admin --plaintext   # through the usual port-forward: still works
argocd app list                              # every Application still Synced/Healthy
```

The Dex block in the script is a no-op on this cluster (8.1 already removed it, `--ignore-not-found`);
it is there so one file covers every component the bootstrap has dropped.

Rollback: remove the two patch entries from `cluster/bootstrap/argocd/kustomization.yaml` and
re-apply; `apply -k` recreates every object from install.yaml.

### 8.6 KSOPS from this repository (two stages, then a bootstrap re-apply, ADR 0024)

`app/ksops` is built and signed by `build-images.yml` only from `main`, and the repo-server's init
container pins its digest, so it arrives like Talon in 8.3 - with one difference: the pin lives in
the bootstrap kustomization, which Argo CD does not deploy, so the last step is a manual apply.

1. **Stage 1: the image.** Push everything up to and including the commit that adds `app/ksops/`
   (and none of the commit "argocd: run KSOPS from this repository's signed image"). The workflow
   builds `ksops` (upstream tests, Trivy gate, SBOM, cosign) and prints `.../ksops@sha256:...`.
   Nothing in the cluster changes. Make the new GHCR package `self-defending-portfolio/ksops`
   public (5.2) - a fresh bootstrap pulls it without credentials - then from a machine that is not
   logged in to GHCR:

   ```sh
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/ksops@sha256:<digest>
   mkdir -m 777 /tmp/ksops-check && docker run --rm --read-only --user 65532:65532 --cap-drop ALL \
     --network none -v /tmp/ksops-check:/custom-tools \
     ghcr.io/hubertmj/self-defending-portfolio/ksops@sha256:<digest> install /custom-tools
   file /tmp/ksops-check/ksops     # ELF 64-bit LSB executable, x86-64, statically linked
   ```

2. **Stage 2: the switch.** On the switch commit, replace the placeholder and validate - `make
   validate` refuses the placeholder, and with `SOPS_AGE_KEY_FILE` set it renders both KSOPS
   directories for real with the binary installed from that very digest:

   ```sh
   scripts/bump-image-digest.sh ksops sha256:<digest>   # cluster/bootstrap/argocd/kustomization.yaml
   SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt make lint validate   # "(KSOPS decrypted)" twice
   git commit --amend --no-edit && git push
   ```

3. **The bootstrap re-apply.** The diff must be the repo-server Deployment's init container image
   and nothing else:

   ```sh
   kubectl diff -k cluster/bootstrap/argocd --server-side --force-conflicts
   kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts
   kubectl -n argocd rollout status deploy/argocd-repo-server
   kubectl -n argocd get deploy argocd-repo-server \
     -o jsonpath='{.spec.template.spec.initContainers[0].image}'   # .../ksops:main@sha256:<digest>
   kubectl -n argocd logs deploy/argocd-repo-server -c install-ksops   # installed /custom-tools/ksops
   ```

   Accept it by making Argo CD decrypt again: a hard refresh of the two Applications with KSOPS
   generators must render their Secrets, i.e. stay Synced/Healthy with no ComparisonError:

   ```sh
   argocd app get cert-manager-issuers --hard-refresh | grep -E 'Sync Status|Health Status'
   argocd app get cloudflared --hard-refresh | grep -E 'Sync Status|Health Status'
   ```

   One repo-server replica: while it rolls (seconds), Argo CD cannot render manifests and retries;
   nothing already running is touched.

Rollback: revert the switch commit and re-apply the bootstrap; upstream's `viaductoss/ksops:v4.5.1`
comes back with the same `ksops install /custom-tools` command.

### 8.7 CoreDNS from this repository (two stages, then the k3s role, ADR 0026)

`app/coredns` is built and signed by `build-images.yml` only from `main`. It is not deployed by Argo
CD (Argo CD needs cluster DNS) but by the k3s role, as a k3s auto-deploy manifest that replaces k3s's
bundled `coredns.yaml`; the pin is `k3s_coredns_image` in `ansible/roles/k3s/defaults/main.yml`.

1. **Stage 1: the image.** Push everything up to and including the commit that adds `app/coredns/`
   (and none of the commit "k3s: run CoreDNS from this repository's signed image"). The workflow
   builds `coredns` (upstream tests, Trivy gate, SBOM, cosign) and prints `.../coredns@sha256:...`.
   Nothing in the cluster changes. Make the GHCR package `self-defending-portfolio/coredns` public
   (5.2): containerd pulls it without credentials, and a fresh node needs it before anything else.
   Then, from a machine not logged in to GHCR:

   ```sh
   IMG=ghcr.io/hubertmj/self-defending-portfolio/coredns@sha256:<digest>
   scripts/verify-image.sh "$IMG"
   docker run --rm "$IMG" -version          # CoreDNS-1.14.7 / linux/amd64, go1.26.8, 427fc80
   printf '.:53 {\n  hosts {\n    10.4.1.20 k3s01\n  }\n}\n' > /tmp/Corefile
   docker run -d --name cdns --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE \
     --security-opt no-new-privileges -v /tmp/Corefile:/Corefile:ro "$IMG" -conf /Corefile
   docker run --rm --network container:cdns alpine:3.22 sh -c \
     'apk add -q bind-tools && dig +short @127.0.0.1 k3s01'   # 10.4.1.20 (uid 65532 bound :53)
   docker rm -f cdns
   ```

2. **Stage 2: the switch.** On the switch commit, replace the placeholder and validate - `make
   validate` (scripts/check-image-digests.sh) refuses the placeholder in `ansible/` too:

   ```sh
   scripts/bump-image-digest.sh coredns sha256:<digest>   # ansible/roles/k3s/defaults/main.yml
   make lint validate
   git commit --amend --no-edit && git push
   ```

3. **The role run (the cutover).** Before, record the state; keep a second terminal running a DNS
   probe from inside the cluster for the whole run - it must not stop answering:

   ```sh
   kubectl -n kube-system get deploy coredns \
     -o jsonpath='{.metadata.annotations.objectset\.rio\.cattle\.io/owner-name} {.spec.template.spec.containers[0].image}{"\n"}'
   # coredns rancher/mirrored-coredns-coredns:1.14.7
   kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}{"\n"}'   # 10.43.0.10
   # terminal 2: a throwaway resolver loop in kube-system (exempt from the Kyverno pod rules, no
   # CiliumNetworkPolicy there), resolving through the kube-dns Service like every pod does:
   kubectl -n kube-system run dnsprobe --rm -it --restart=Never --image=docker.io/library/busybox:1.37 \
     -- sh -c 'while true; do printf "%s " "$(date +%T)"; nslookup -timeout=1 kubernetes.default.svc.cluster.local >/dev/null 2>&1 && echo ok || echo FAIL; sleep 0.5; done'
   ```

   ```sh
   cd ansible
   ansible-playbook playbooks/cluster.yml --tags k3s --check --diff
   # expect: coredns-sdp.yaml (new), config.yaml (+cluster-dns, +coredns under disable), "Restart k3s"
   ansible-playbook playbooks/cluster.yml --tags k3s
   ```

   The role writes the manifest first; k3s applies it within 15 s and takes five objects over in
   place; the Deployment rolls surge-first. k3s cannot take Service `kube-dns` over by itself (its
   fixed ClusterIP makes the create fail with "provided IP is already allocated" before the
   AlreadyExists that triggers a takeover), so the role hands it over (owner label and annotations)
   and waits until all six objects belong to `coredns-sdp` and the Addon has recorded the file's
   checksum (a clean apply), plus a finished rollout. Only then does it disable k3s's copy and restart
   k3s (API down under a minute, DNS unaffected - it is served by the running pod). Accept it:

   ```sh
   kubectl -n kube-system get deploy coredns \
     -o jsonpath='{.metadata.annotations.objectset\.rio\.cattle\.io/owner-name} {.spec.template.spec.containers[0].image}{"\n"}'
   # coredns-sdp ghcr.io/hubertmj/self-defending-portfolio/coredns:main@sha256:<digest>
   kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}{"\n"}'   # still 10.43.0.10
   kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide       # one pod, Running, 1/1
   kubectl -n kube-system get addon coredns                           # NotFound (k3s removed it)
   kubectl -n kube-system get addon coredns-sdp                       # present, CHECKSUM set
   kubectl -n kube-system get svc kube-dns \
     -o jsonpath='{.metadata.annotations.objectset\.rio\.cattle\.io/owner-name} {.metadata.creationTimestamp}{"\n"}'
   # coredns-sdp <the Service's original creation time: it was never re-created>
   kubectl -n kube-system logs deploy/coredns | head                  # CoreDNS-1.14.7, no errors
   ssh k3s01 sudo ls /var/lib/rancher/k3s/server/manifests/            # coredns-sdp.yaml, no coredns.yaml
   ```

   Then check what depends on the `k8s-app: kube-dns` labels: the probe never printed FAIL; Hubble
   still logs DNS lookups through the L7 rules (`hubble observe --protocol dns -n cloudflared`);
   the Applications stay Synced/Healthy (Argo CD resolves github.com); `make verify`. Trivy Operator
   rescans kube-system within its cycle and the posture page moves CoreDNS to the own column at 0.

**Rollback.** Two levels, both a role run:

- *Binary only, no gap* - keep the delivery, run upstream's image:
  `ansible-playbook playbooks/cluster.yml --tags k3s -e
  k3s_coredns_image=docker.io/rancher/mirrored-coredns-coredns:1.14.7@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286`
  (a surge-first roll, no k3s restart).
- *Delivery* - back to k3s's own CoreDNS: `-e k3s_coredns_own=false` (or revert the switch commit
  and set it in the role defaults). The role removes `coredns-sdp.yaml` (which deletes nothing),
  drops `coredns` from `disable` and restarts k3s; k3s re-stages its manifest and takes five
  objects back, the role hands Service `kube-dns` back to Addon `coredns` the same way and waits
  for all six objects, a clean apply and the rollout. Nothing is deleted, so the Service and its
  ClusterIP stay; but that roll uses k3s's `maxUnavailable: 1`, so expect a few seconds without a
  ready DNS pod (the old pod stops, the new one needs about 2-5 s to pass /ready); clients retry.
  Prefer the binary-only rollback when the delivery itself is not the problem. Afterwards
  `kubectl -n kube-system delete addon coredns-sdp` removes the stale bookkeeping object (its
  objects carry no owner references, so nothing else goes with it).

### 8.8 Cilium from this repository (stage 1, then three switch commits, agent last; ADR 0028)

`app/cilium`, `app/cilium-operator-generic`, `app/hubble-relay` and `app/cilium-envoy` are Cilium
1.19.8 with the Go binaries rebuilt against fixed dependencies (and Ubuntu's OpenSSL updated), on
upstream's own layers. They are deployed through chart image overrides in `cluster/apps/cilium.yaml`
(Argo CD) and, identically, in `cilium_values` of the cilium role (which only matters for a rebuild
from zero: the role leaves a release Argo CD owns alone). This is the one component where a bad
image takes the whole node off the network, Argo CD included, so the switch is three commits pushed
one at a time, each image pre-pulled, each step checked before the next, and the rollback rehearsed
in your head before you start.

1. **Stage 1: the images (done).** The commit that adds `app/cilium*` and `app/hubble-relay` is on
   `main` (with the smoke-test fix after it). The workflow builds four images
   (upstream tests, Trivy gate, image smoke test, SBOM, cosign) and prints a digest for each. Nothing
   in the cluster changes. Make the four GHCR packages public (5.2): containerd pulls them without
   credentials, and a rebuild from zero needs the agent image before anything else runs. Then, from a
   machine not logged in to GHCR:

   ```sh
   R=ghcr.io/hubertmj/self-defending-portfolio
   for n in cilium cilium-operator-generic hubble-relay cilium-envoy; do
     read -rp "$n digest: " d; scripts/verify-image.sh "$R/$n@$d" && app/$n/test/image-smoke.sh "$R/$n@$d"
   done
   ```

2. **Baseline, before every switch.** Record what "healthy" looks like, so "after" is a diff, not an
   impression. Keep the DNS probe from 8.7 running in a second terminal through every step.

   ```sh
   kubectl -n argocd get applications                                        # all Synced/Healthy
   kubectl -n kube-system get ds,deploy -l app.kubernetes.io/part-of=cilium -o wide
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --brief   # OK
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg version
   # Client: 1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.8 linux/amd64 (Daemon: the same)
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose \
     | grep -E 'KubeProxyReplacement|Envoy|Hubble|Controller Status|Proxy Status|Cluster health'
   RELAY=$(kubectl -n kube-system get svc hubble-relay -o jsonpath='{.spec.clusterIP}')
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble status --server "$RELAY:80"
   # Healthcheck (via ...): Ok, Connected Nodes: 1/1
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --last 5 --server "$RELAY:80"
   curl -s -o /dev/null -w '%{http_code}\n' https://hubertjablon.ski/              # 200
   curl -s https://hubertjablon.ski/api/healthz                                   # {"status":"ok"}
   kubectl -n kube-system logs ds/cilium -c cilium-agent --since=30m | grep -cE 'level=(error|fatal)'
   kubectl -n kube-system get vulnerabilityreports \
     -o custom-columns=NAME:.metadata.name,IMAGE:.report.artifact.repository,C:.report.summary.criticalCount,H:.report.summary.highCount \
     | grep -E 'cilium|hubble'                                                     # the "before"
   ```

   Pre-pull the step's image on the node, so no rollout waits on a registry after its old pod is
   gone (`cilium` and `cilium-envoy` are DaemonSets with `maxSurge: 0` on one node: the old pod is
   deleted before the new one starts). A failed pull here is also the cheapest way to find a package
   that is still private. Do not prune images on the node during the rollout: upstream's images
   staying in containerd's store is what makes the rollback instant.

   ```sh
   ssh k3s01 sudo k3s crictl pull ghcr.io/hubertmj/self-defending-portfolio/<name>@sha256:<digest>
   ```

   **Each switch commit carries its real digests and is pushed alone**, on top of `main`, with the
   checks of its step done before the next push. The digests pinned (built from `main` and signed
   by build-images.yml; `scripts/verify-image.sh` each before the first push):

   | image | digest |
   |---|---|
   | cilium | `sha256:5c5dcd9b1a13a333194166dfc94051cd7793ab7b65e9a653bd0d831e0d984e29` |
   | cilium-operator-generic | `sha256:04f4695b73b283f33b22b2d27b301df8214f35916f4d24129d71ee8f558c5db0` |
   | hubble-relay | `sha256:23fb1c3769503fd2a322e386d65df2fe0402c3ba4185f338d6de53ae4d5bbf3e` |
   | cilium-envoy | `sha256:6ad67d1d41da91b9b93b7b42cc16c1f899fefd2e4dfc425438c00017f95c91e0` |

   ```sh
   git push origin <switch commit>:main      # one switch at a time, oldest first
   ```

   A later rebuild (new digest) is `scripts/bump-image-digest.sh <name> sha256:<digest>`, which
   rewrites both `cluster/apps/cilium.yaml` and the role, then `make lint validate`, commit, push -
   again with the pre-pull and the step's checks.

3. **Switch 1: operator and Hubble Relay** (commit "cilium: run the operator and Hubble Relay from
   this repository's signed images"). Neither is
   on the packet path: the agent keeps forwarding without the operator, and Relay is only Hubble's
   cluster-wide view.

   Argo CD syncs within its poll (3 min), or nudge it:
   `kubectl -n argocd patch app cilium --type merge -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"normal"}}}'`. Then:

   ```sh
   kubectl -n kube-system rollout status deploy/cilium-operator --timeout=5m
   kubectl -n kube-system rollout status deploy/hubble-relay --timeout=5m
   kubectl -n kube-system get deploy cilium-operator hubble-relay \
     -o jsonpath='{range .items[*]}{.spec.template.spec.containers[0].image}{"\n"}{end}'   # ghcr.io/... both
   kubectl -n kube-system logs deploy/cilium-operator --since=10m | grep -E 'level=(error|fatal)'   # nothing new
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble status --server "$RELAY:80"      # Ok, 1/1
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --last 5 --server "$RELAY:80"
   ```

   The operator's own work shows within minutes: its log shows it acquiring the leader lease and
   starting its controllers (Gateway API among them), and `kubectl get gateway -A` stays Programmed.

4. **Switch 2: cilium-envoy** (commit "cilium: run cilium-envoy from this repository's signed
   image"). This restarts the Gateway's L7 data plane, so the site blips for the seconds the Envoy
   pod takes to come back; do it when a blip is acceptable. Pre-pull, push the commit, then:

   ```sh
   kubectl -n kube-system rollout status ds/cilium-envoy --timeout=5m
   kubectl -n kube-system logs ds/cilium-envoy --since=10m | grep -iE 'critical|error' | head
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose | grep -iA2 envoy
   curl -s -o /dev/null -w '%{http_code}\n' https://hubertjablon.ski/              # 200
   curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://hubertjablon.ski/   # the https redirect
   curl -s https://hubertjablon.ski/api/healthz
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --protocol dns -n cloudflared --last 5
   ```

   The site checks exercise the Gateway listeners (TLS from the certificate in `cilium-secrets`,
   the routes, the trusted XFF hop). The last line is a control: L7 DNS visibility is the agent's DNS
   proxy, not Envoy, and must be unaffected.

5. **Switch 3: the agent** (commit "cilium: run the Cilium agent from this repository's signed
   image"). Last, and alone. What happens on one node: the agent pod is deleted, its BPF programs and
   maps stay pinned in the kernel, so established connections and Services keep working; for the
   30-90 s until the new agent is Ready, *new* pods cannot get an address (CNI ADD fails and the
   kubelet retries). Pre-pull (the agent image is about 1 GB - pull it before, not during), push
   the commit, then:

   ```sh
   kubectl -n kube-system rollout status ds/cilium --timeout=5m
   kubectl -n kube-system get ds cilium -o jsonpath='{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{.spec.template.spec.containers[0].image}{"\n"}'
   # seven lines, all ghcr.io/hubertmj/self-defending-portfolio/cilium:main@sha256:<digest>
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --brief   # OK
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg version          # identical to the baseline
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose \
     | grep -E 'KubeProxyReplacement|Envoy|Hubble|Controller Status|Proxy Status|Cluster health'
   kubectl -n kube-system logs ds/cilium -c cilium-agent --since=10m | grep -E 'level=(error|fatal)'
   kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble status --server "$RELAY:80"
   curl -s -o /dev/null -w '%{http_code}\n' https://hubertjablon.ski/              # 200
   make runtime-test     # new pods (CNI ADD), Falco -> Talon, and the quarantine CiliumClusterwideNetworkPolicy
   make verify
   kubectl -n argocd get applications                                        # all Synced/Healthy
   ```

   `make runtime-test` is the end-to-end proof for the agent: it creates pods (the CNI path), and its
   second case only passes if the agent enforces a freshly applied CiliumClusterwideNetworkPolicy
   (DNS works, then the quarantine label cuts it off). A visitor-facing check: start one attack
   scenario from the site and watch it finish.

   **Stop condition, every step:** a rollout not complete in 5 minutes, `cilium-dbg status --brief`
   not `OK`, the site not 200, the DNS probe printing FAIL for more than a few seconds, or new
   `level=error` lines that were not in the baseline - roll back, then investigate.

6. **After.** Trivy Operator rescans kube-system within its cycle: the VulnerabilityReports for the
   cilium DaemonSet (agent and its six init containers), cilium-envoy, cilium-operator and
   hubble-relay show the ghcr.io images at 0, and the posture page moves Cilium to the own column.

**Rollback.** Three levels, from the normal one down:

- *Normal: revert the switch commit.* `git revert <commit> && git push`; Argo CD rolls back to the
  chart's upstream image within its poll (or the refresh nudge above). Upstream's images are still in
  the node's image store, so the pull is instant. Revert the switches in reverse order if more than
  one is in. Then repeat the checks of that step.
- *Argo CD cannot act* (for example the new agent is crash-looping and Argo CD's own pods have lost
  networking, or GitHub is unreachable). The API server is a k3s host process on 10.4.1.20:6443 and
  does not need Cilium, so kubectl works from the operator machine (or `ssh k3s01 sudo k3s kubectl`).
  First stop Argo CD from undoing the fix - the root Application would restore the cilium
  Application's sync policy, so both - then put the upstream image back directly:

  ```sh
  kubectl -n argocd patch application root   --type merge -p '{"spec":{"syncPolicy":{"automated":null}}}'
  kubectl -n argocd patch application cilium --type merge -p '{"spec":{"syncPolicy":{"automated":null}}}'
  U=quay.io/cilium/cilium:v1.19.8@sha256:e9f7ee1f2f3a41e44339612e3b6b88170bdde7679c9c9461f287bb27702a8ecf
  kubectl -n kube-system set image ds/cilium cilium-agent=$U config=$U mount-cgroup=$U \
    apply-sysctl-overwrites=$U mount-bpf-fs=$U clean-cilium-state=$U install-cni-binaries=$U
  kubectl -n kube-system set image ds/cilium-envoy \
    cilium-envoy=quay.io/cilium/cilium-envoy:v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82@sha256:af7382699576b9e65e9184efa52eeca0b58aea70ad6e511bf260c91d9f740463
  kubectl -n kube-system set image deploy/cilium-operator \
    cilium-operator=quay.io/cilium/operator-generic:v1.19.8@sha256:786ec9bb1a9344435e3e3f994bc4ed3a4a85afa6a314e98681af241f8be79833
  kubectl -n kube-system set image deploy/hubble-relay \
    hubble-relay=quay.io/cilium/hubble-relay:v1.19.8@sha256:f78768be216b5c00137c7d4da440724d0b49986805d361e7458cc8fe9ff976ff
  kubectl -n kube-system rollout status ds/cilium --timeout=5m
  ```

  (Only the lines for the components that were switched are needed.) Then revert the switch commits
  in git and push, and give Argo CD its sync policy back by re-applying the bootstrap, which restores
  the root Application, which restores the cilium Application:
  `kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts`. Argo CD then finds the
  live objects already equal to git.
- *Ansible is not a rollback tool here.* The cilium role deliberately skips `helm` once the Argo CD
  Application exists (a `helm upgrade` would trip over objects Argo CD created without Helm's
  ownership metadata). Its `cilium_values` carry the same overrides only so that a rebuild from zero
  installs what Argo CD will then adopt unchanged; after a revert they carry upstream's images again,
  and `make cluster` on a fresh VM installs those.
### 8.9 Argo CD from this repository (two stages, then a bootstrap re-apply, ADR 0027)

`app/argocd` is Argo CD v3.5.3 rebuilt from the release commit with fixed dependencies - the same
release `install.yaml` names, with the helm, kustomize and git-lfs it ships - and it arrives like
KSOPS in 8.6: the pin lives in the bootstrap kustomization, so the last step is a manual apply. This
one replaces the image of every Argo CD container, so it is the one bootstrap change where Argo CD
itself restarts.

1. **Stage 1: the image.** Push everything up to and including the commit that adds `app/argocd/`
   (and none of the commit "argocd: run Argo CD from this repository's signed image"). The workflow
   builds `argocd` (helm, kustomize, git-lfs and argocd upstream tests, the UI, Trivy gate, SBOM,
   cosign; the heaviest image here, expect 15-25 minutes) and prints `.../argocd@sha256:...`.
   Nothing in the cluster changes. Make the new GHCR package `self-defending-portfolio/argocd`
   public (5.2) - a fresh bootstrap cannot start Argo CD otherwise - then from a machine that is not
   logged in to GHCR:

   ```sh
   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/argocd@sha256:<digest>
   img=ghcr.io/hubertmj/self-defending-portfolio/argocd@sha256:<digest>
   docker run --rm "$img" argocd version --client     # argocd: v3.5.3+c9c369e.dirty, go1.26.8
   docker run --rm "$img" sh -c 'helm version --short; kustomize version; git-lfs version; id'
   # v4.2.1+gd591a19 / v5.8.1 / git-lfs/3.7.1 (GitHub; ...) / uid=999(argocd) gid=999(argocd)
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.75.0 image \
     --severity CRITICAL,HIGH --quiet "$img"      # 0 everywhere
   ```

2. **Stage 2: the switch.** On the switch commit, replace the placeholder and validate (`make
   validate` refuses the placeholder):

   ```sh
   scripts/bump-image-digest.sh argocd sha256:<digest>   # cluster/bootstrap/argocd/kustomization.yaml
   make lint validate
   git commit --amend --no-edit && git push
   ```

3. **The bootstrap re-apply.** The diff must be the image of five containers and nothing else -
   `argocd-server`, `argocd-repo-server` and its `copyutil` init container,
   `argocd-application-controller` and the Redis `secret-init` init container - each going from
   `quay.io/argoproj/argocd:v3.5.3` to `ghcr.io/hubertmj/self-defending-portfolio/argocd:main@sha256:<digest>`
   (plus the managed-fields noise a server-side diff shows). No ConfigMap, RBAC, Service or
   NetworkPolicy may appear in it:

   ```sh
   kubectl diff -k cluster/bootstrap/argocd --server-side --force-conflicts | grep -E '^[-+] .*image:'
   kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts
   kubectl -n argocd rollout status deploy/argocd-redis
   kubectl -n argocd rollout status deploy/argocd-repo-server
   kubectl -n argocd rollout status deploy/argocd-server
   kubectl -n argocd rollout status statefulset/argocd-application-controller
   kubectl -n argocd get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.initContainers[*]}{.image}{" "}{end}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}'
   # every argocd container on .../argocd:main@sha256:<digest>; redis on 8.2.10-alpine; ksops on .../ksops
   ```

   Accept it by making Argo CD do everything it does, with the new binaries:

   ```sh
   argocd version                               # server: v3.5.3+c9c369e.dirty, Kustomize v5.8.1, Helm v4.2.1
   argocd app get falco --hard-refresh | grep -E 'Sync Status|Health Status'                 # helmCharts render
   argocd app get cert-manager-issuers --hard-refresh | grep -E 'Sync Status|Health Status'  # KSOPS decrypt
   argocd app get cloudflared --hard-refresh | grep -E 'Sync Status|Health Status'
   argocd app list                              # every Application Synced/Healthy as before, no ComparisonError
   kubectl -n argocd logs deploy/argocd-repo-server | grep -iE 'level.:.(error|fatal)|kustomize version'
   ```

   and open the UI over the LAN as before (it is embedded in the binary, built from the same
   release). The rollout restarts all of Argo CD: for a minute or two nothing syncs and the UI may
   drop; workloads Argo CD manages keep running untouched. The application controller resumes from
   the cluster's state, nothing is lost with Redis (a cache).

Rollback: revert the switch commit and re-apply the bootstrap; upstream's
`quay.io/argoproj/argocd:v3.5.3` comes back with no other change, because the paths, user and
configuration are upstream's. If Argo CD cannot start at all (for example the GHCR package is
private), the same revert-and-apply is the fix - it needs only `kubectl`, not Argo CD.

### 8.10 Falcosidekick, metrics-server, Trivy Operator and kube-bench from this repository (ADR 0025)

Four more images built here (`app/falcosidekick`, `app/metrics-server`, `app/trivy-operator`,
`app/kube-bench`), staged like Talon in 8.3 - with one addition: metrics-server moves from k3s to
Argo CD, and k3s has to let go of it first.

1. **Stage 1: the images.** Push everything up to and including the four `app/...` commits (and none
   of the switch commits). The workflow builds all four (upstream tests, Trivy gate, SBOM, cosign) and
   prints a digest for each. Nothing in the cluster changes. Make the four new GHCR packages public
   (5.2), then from a machine that is not logged in to GHCR:

   ```sh
   for n in falcosidekick metrics-server trivy-operator kube-bench; do
     scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/$n@sha256:<digest of $n>
   done
   docker run --rm --read-only --user 1234 ghcr.io/hubertmj/self-defending-portfolio/falcosidekick@sha256:<d> --version   # 2.35.0
   docker run --rm --read-only ghcr.io/hubertmj/self-defending-portfolio/metrics-server@sha256:<d> --version            # v0.9.0
   docker run --rm --read-only ghcr.io/hubertmj/self-defending-portfolio/kube-bench@sha256:<d> version                  # v0.16.0
   ```

2. **Stage 2a: Falcosidekick, Trivy Operator, kube-bench.** Two switch commits ("falco-response,
   trivy-operator: ..." and "kube-bench: ..."; the second also drops the config override and mounts
   the node's journal). Pin the three digests into them (a fixup per commit, or one pin commit on
   top) and validate - `make validate` runs Kyverno's signature check for real on Falcosidekick,
   whose namespace is already in `verify-portfolio-images`:

   ```sh
   scripts/bump-image-digest.sh falcosidekick sha256:<d>    # cluster/apps/falco-response.yaml (tag line)
   scripts/bump-image-digest.sh trivy-operator sha256:<d>   # cluster/apps/trivy-operator.yaml (tag line)
   scripts/bump-image-digest.sh kube-bench sha256:<d>       # cluster/infra/kube-bench/kustomization.yaml
   make lint validate
   git commit -am "falcosidekick, trivy-operator, kube-bench: pin the build-images digests" && git push
   ```

   Accept it:

   ```sh
   kubectl -n falco-response get deploy falcosidekick -o jsonpath='{.spec.template.spec.containers[0].image}'
   kubectl -n falco-response logs deploy/falcosidekick | head -3   # version 2.35.0, outputs [Webhook Talon]
   make runtime-test && make scenario-test                         # alerts still reach Talon and the API
   kubectl -n trivy-system rollout status deploy/trivy-operator
   kubectl -n trivy-system logs deploy/trivy-operator | grep -ci error   # no new errors after start-up
   # a scan cycle later: reports are being written by the new operator
   kubectl get vulnerabilityreports -A --sort-by=.metadata.creationTimestamp | tail -3
   kubectl -n kube-bench create job --from=cronjob/kube-bench kube-bench-own-check
   kubectl -n kube-bench wait --for=condition=complete job/kube-bench-own-check --timeout=300s
   kubectl -n kube-bench logs job/kube-bench-own-check | jq '.Totals'
   # was 35 PASS / 27 FAIL with the config override; expect about 58 PASS / 4 FAIL now (ADR 0025) -
   # the flag checks read the journal. The FAILs left: 1.1.9, 1.1.10, 1.1.20, 1.2.26.
   kubectl -n kube-bench logs job/kube-bench-own-check \
     | jq -r '.Controls[].tests[].results[] | select(.status=="FAIL") | .test_number'
   kubectl -n kube-bench delete job kube-bench-own-check
   ```

3. **Stage 2b: metrics-server - Ansible first.** `k3s_disable_components` now lists `metrics-server`,
   and the role sets the k3s server certificates to 0600 (CIS 1.1.20, ADR 0025). Run only the k3s
   role (as in 8.2); k3s restarts once and, because the add-on is disabled, deletes its own
   metrics-server objects (Deployment, Service, APIService, RBAC). `kubectl top` stops working until
   the next step - nothing in this cluster scales on the metrics API.

   ```sh
   cd ansible
   ansible-playbook playbooks/cluster.yml --tags k3s --check --diff   # expect: config.yaml gains "metrics-server",
                                                                       # "Restart k3s", server/tls/*.crt -> 0600
   ansible-playbook playbooks/cluster.yml --tags k3s
   ssh k3s01 sudo stat -c '%a %n' /var/lib/rancher/k3s/server/tls/*.crt   # all 600
   cd .. && kubectl -n kube-system get deploy metrics-server             # NotFound
   kubectl get apiservice v1beta1.metrics.k8s.io                         # NotFound
   ```

   Then pin and push the metrics-server switch commit:

   ```sh
   scripts/bump-image-digest.sh metrics-server sha256:<d>   # cluster/infra/metrics-server/kustomization.yaml
   make lint validate
   git commit -am "metrics-server: pin the build-images digest" && git push   # with the k3s CIS commit
   kubectl -n argocd get application metrics-server                      # Synced, Healthy
   kubectl -n kube-system rollout status deploy/metrics-server
   kubectl get apiservice v1beta1.metrics.k8s.io                         # AVAILABLE True
   kubectl top nodes && kubectl top pods -A | head
   ```

   Do not push this commit before the Ansible run: Argo CD would adopt k3s's objects (they keep
   k3s's labels), and the later k3s restart would delete them again by owner - Argo CD recreates them
   with selfHeal, but that is a second gap and a confusing one.

4. **Stage 3: the policies.** Only after 2a and 2b are live (the PolicyReports of the background
   scan would otherwise flag the upstream pods still running): `restrict-image-registries` loses the
   Falcosidekick exception and covers `falco-response` and `kube-bench` whole;
   `verify-portfolio-images` adds `kube-bench` and `trivy-system`.

   ```sh
   make lint validate
   git push
   kubectl get clusterpolicy restrict-image-registries verify-portfolio-images   # READY True
   kubectl get policyreports -n falco-response -o json | jq '[.items[].summary.fail] | add'   # 0
   kubectl -n kube-bench create job --from=cronjob/kube-bench kube-bench-admission-check   # admitted (signed)
   kubectl -n kube-bench delete job kube-bench-admission-check
   kubectl -n trivy-system rollout restart deploy/trivy-operator && kubectl -n trivy-system rollout status deploy/trivy-operator
   ```

Rollback, per stage: revert the policy commit first (it would refuse upstream's Falcosidekick and
kube-bench images); then revert 2a, and upstream's images come back with the same values. For
metrics-server: revert the switch commit (Argo CD prunes its objects), then revert the Ansible change
and run the k3s role again - k3s re-extracts its bundled manifests on start and deploys its own copy.

### 8.11 The CIS benchmark: not applicable, and the manual checks' controls (ADR 0025, amendment 2026-10-10)

Three parts: the kube-bench image (its benchmark patch), the API and the page (the not-applicable
count and lists), and the k3s role (admission plugins, flags, audit policy). Each is safe alone in
either order; the page reaches its final numbers when all three are live and kube-bench has run.

1. **Images.** The push builds `kube-bench`, `api` and `web` (build-images.yml). Check and pin:

   ```sh
   docker run --rm --read-only ghcr.io/hubertmj/self-defending-portfolio/kube-bench@sha256:<d> version   # v0.16.0
   scripts/bump-image-digest.sh kube-bench sha256:<d>   # cluster/infra/kube-bench/kustomization.yaml
   scripts/bump-image-digest.sh api sha256:<d>
   scripts/bump-image-digest.sh web sha256:<d>
   make lint validate
   git commit -am "kube-bench, api, web: pin the build-images digests (CIS not applicable)" && git push
   kubectl -n argocd get application kube-bench portfolio-api hello   # Synced, Healthy
   ```

   From here the page lists not-applicable checks (upstream's 14 now; 17 after the next kube-bench
   run) and the WARN checks, and 1.1.9, 1.1.10 and 1.2.26 leave the FAIL count.

2. **The k3s role, in a maintenance window** (one k3s restart, as in 8.2). It writes
   `/etc/rancher/k3s/admission-config.yaml`, adds the admission plugins and flags to config.yaml,
   reorders the audit policy, keeps `server/db` at 0700 and restarts k3s once. Running pods keep
   running; from now on new pods get `imagePullPolicy: Always` (AlwaysPullImages, ADR 0025
   amendment: their registry must answer).

   ```sh
   make golden                                                         # the audit-policy golden passes
   cd ansible
   ansible-playbook playbooks/cluster.yml --tags k3s --check --diff   # expect: admission-config.yaml (new),
                                                                       # config.yaml (+ CIS args), audit-policy.yaml,
                                                                       # "Restart k3s"
   ansible-playbook playbooks/cluster.yml --tags k3s
   ssh k3s01 sudo journalctl -u k3s -n 2000 | grep -o 'Running kube-apiserver.*' | tail -n1 \
     | tr ' ' '\n' | grep -E 'admission|request-timeout|bootstrap-token'   # the four flags
   cd .. && kubectl get nodes && make runtime-test                     # Ready; Talon still quarantines
   ```

3. **Run kube-bench now** rather than at 03:17 UTC; the API picks the newest successful run up within
   its 60 s cache:

   ```sh
   kubectl -n kube-bench create job --from=cronjob/kube-bench kube-bench-cis-check
   kubectl -n kube-bench wait --for=condition=complete job/kube-bench-cis-check --timeout=300s
   kubectl -n kube-bench logs job/kube-bench-cis-check | jq '.Totals'   # 69 pass, 0 fail, 2 warn, 17 info
   curl -s https://hubertjablon.ski/api/posture | jq '.kube_bench | {pass, fail, warn, info, not_applicable}'
   ```

   Leave the Job; its TTL removes it after a day, like the CronJob's own.

Rollback: the role first - set `k3s_admission_plugins: [NodeRestriction]`, drop the other CIS
arguments (or revert the commit; `admission-config.yaml` may stay, nothing reads it once the flag is
gone) and run the k3s role again: one more restart. A bootstrap-token join needs only
`k3s_bootstrap_token_auth: true`. Then revert the digest pins if the images are the problem; the
previous web renders the new API's response as before (it ignores the new fields), and the previous
API reads the new kube-bench log with the 17 skips in INFO.

## 9. The SIEM host siem01 (ADR 0034)

OpenSearch 3.9.0 with Security Analytics, single node, on its own VM in its own VLAN and firewall zone.
k3s01 can append to it but not rewrite it (see ADR 0034 and its amendment of 2026-10-04 for what
"cannot rewrite" means exactly). Everything runs from Ansible in the tooling container: Ansible is
not installed on the operator machine, and `make siem` wraps the container invocation (`ARGS=` passes
playbook arguments through).

### 9.1 Create the VM

```sh
VMID=121 VM_NAME=siem01 VM_VLAN=42 VM_IP=10.4.2.10/24 VM_GW=10.4.2.1 VM_DISK_GB=80 VM_DATA_DISK_GB=20 \
  scripts/pve-create-vm.sh                   # 4 vCPU and 8 GB are the script defaults (VM_CORES, VM_MEMORY_MB)
ssh ansible@10.4.2.10 true                    # accept the host key after checking it on the Proxmox console
```

The data disk carries the serial `siem01-data`; the `siem_disk` role finds it by that serial and
never by device name, formats it only while it holds no filesystem and mounts it by label at
`/var/lib/opensearch-snapshots`. The UniFi zone `Siem` allows exactly k3s01 → 10.4.2.10:9200/tcp and
the admin networks → :22/tcp; the host firewall repeats that list.

### 9.2 Apply

```sh
make siem ARGS="--check --diff"   # look first
make siem                          # base, ssh, firewall, sysctl, auditd, patching, disk, OpenSearch, Dashboards, config
make siem                          # second run must report changed=0
make siem-verify                   # read-only: sshd, nft 22+9200 only, audit watches, NTP, listeners, green, PA off, certs
make siem-acceptance               # live acceptance (P1): refusals, write block, rewrites refused, audit log, TLS, restore, tunnel
```

What the playbook guarantees, and where:
- The OpenSearch and Dashboards debs come only from their repository whose key's primary fingerprint
  equals the pin (`opensearch_apt_key_fingerprint`), with the package SHA256 in the signed index equal
  to the pin before install, an apt preference at 1001 and a dpkg hold. The deb's demo security
  configuration is never installed (`DISABLE_INSTALL_DEMO_CONFIG=true`).
- `/tmp` must allow executables: the security plugin unpacks a JNI probe there and OpenSearch does
  not start otherwise. The role checks it before the first start.
- Every client authenticates with a certificate of the host's own CA; there is no password path and
  no internal user. Performance Analyzer is off. Health is green (0 replicas everywhere).
- The security plugin's refusals (failed logins, missing privileges, TLS errors) go to
  `/var/log/opensearch/sdp-security-audit.log`; 9200 from k3s01 is capped at 4 MB/s by nftables.
- Inside OpenSearch: the `sdp-final` pipeline (which refuses any write with a client-supplied id), the ISM policy `sdp-30d` (created before the streams,
  because it only attaches to indices created after it), one template and data stream per source from
  `siem/fields/`, the snapshot repository on the data disk with an hourly policy, and the ops monitors.
  Request bodies the role last wrote are hashed under `/var/lib/sdp-siem/state`; an unchanged object is
  not re-sent. The security configuration is re-applied whenever its files changed or the live role
  mapping differs from them.

Bursts of new SSH connections from the operator network to the Siem zone have been seen to be
dropped for several minutes (connection timeouts, nothing logged on siem01). Each `make siem` uses one
connection; `tests/siem/p1-acceptance.sh` multiplexes everything over one control master. For manual
work, use a control master as well (`-o ControlMaster=auto -o ControlPath=... -o ControlPersist=10m`).

### 9.3 Dashboards through the tunnel

```sh
ssh -N -L 5601:127.0.0.1:5601 ansible@10.4.2.10
# then http://127.0.0.1:5601 in a local browser
```

Dashboards listens on 127.0.0.1 only and runs without the security plugin; it talks to OpenSearch
with its own certificate (`dashboards-g<N>`), mapped to the read-only analyst role. sshd allows local
forwarding to exactly `127.0.0.1:5601` (`PermitOpen`) and nothing else.

### 9.4 Certificates

All keys are made on siem01 and stay there: the CA (`/etc/sdp-siem/pki/ca.key`, 10 years), the node
key (`/etc/opensearch/certs/node.key`) and the local client identities `admin`, `rules-sync`,
`shipper-siem01` (`/etc/sdp-siem/pki/`) and `dashboards` (`/etc/opensearch-dashboards/certs/`). Client
certificates are `CN=<name>-g<N>,OU=siem,O=sdp`. Client and node certificates are valid one year: the
role re-issues the node certificate and the local client certificates with fewer than 45 days left,
and `make siem-verify` fails at 30. Remote client certificates are renewed by signing a new CSR:
`shipper-k3s01` by `make ingest` itself (9.7, it re-requests at 45 days left), `portfolio-api` by
`scripts/siem-api-cert.sh` (9.8).

Generations (`opensearch_cert_generations` in `group_vars/siem_nodes.yml`):
- Rotation of a local identity: raise its generation and run `make siem`; the new certificate is
  issued and mapped in the same run. For `admin` the run also changes `plugins.security.authcz.admin_dn`
  and restarts OpenSearch.
- Rotation of a remote identity (`shipper-k3s01`, `portfolio-api`): keep the old generation mapped
  with `opensearch_config_extra_generations: {portfolio-api: [1]}`, raise the generation, sign and
  deploy the new certificate, then drop the extra generation and run `make siem` again.
- Revocation is removing the identity from the role mapping (`make siem` re-applies it).

### 9.5 Signing a CSR made elsewhere

`roles/opensearch/tasks/sign_client_csr.yml` is the only way a key made elsewhere gets a certificate.
The expected identity comes from the command line, never from the CSR, and only `shipper-k3s01`,
`portfolio-api` and `shipper-test` are signed. The CSR's subject must be exactly
`CN=<name>-g<N>,OU=siem,O=sdp`; a CSR asking for `CA:TRUE` or a SAN is refused; the certificate gets
CA:FALSE, keyUsage digitalSignature, EKU clientAuth, no SAN, 365 days, and no extension of the CSR.

```sh
# the CSR must be inside the checkout, given as the absolute path the container sees (/work is the
# checkout; .ansible/ is gitignored); a relative path is refused
make siem ARGS="--tags client-cert -e siem_client_csr=/work/.ansible/shipper-k3s01-g1.csr \
  -e siem_client_name=shipper-k3s01 -e siem_client_generation=1"
# -> .ansible/shipper-k3s01-g1.crt next to it
make siem ARGS="--tags api-cert -e siem_api_csr=/work/.ansible/portfolio-api-g1.csr -e siem_api_generation=1"
```

`make siem-csr-test` runs the same task file against generated CSRs in the container
(`tests/siem/csr-signer.sh`).

### 9.6 Recovery and rollback

```sh
# on the Proxmox node, when SSH is lost
qm guest exec 121 -- /usr/sbin/nft flush ruleset          # siem01 runs no other nftables tables
qm guest exec 121 -- /usr/bin/systemctl restart ssh
qm guest exec 121 -- /usr/bin/journalctl -u opensearch -n 50
```

Rollback of the shippers: `systemctl disable --now fluent-bit` on the host (k3s01 or siem01); nothing
in the cluster depends on them. Rollback of P1 is restoring the vzdump backup taken
before the first apply (`qmrestore <archive> 121 --force` on the Proxmox node). The OpenSearch
repository key's signing subkey expires on 2027-03-06: before then delete
`/var/lib/sdp-siem/opensearch-release.pgp` on siem01 and run `make siem`; the new key is trusted only
if its primary fingerprint still equals the pin.

### 9.7 Shipping: Fluent Bit on siem01 and k3s01

siem01's own logs (journald ssh/sudo/kernel drops, auditd, OpenSearch's security audit log) go into
`sdp-siem01` from Fluent Bit on siem01, part of `make siem` (role `fluent_bit`, its local
`shipper-siem01` identity). k3s01's six streams come from Fluent Bit on k3s01, its own playbook:

```sh
make ingest ARGS="--check --diff"     # on a host without the package: reports what the first run does
make ingest                           # key on k3s01, CSR signed on siem01 (delegated), unit started
make ingest                           # second run: changed=0
```

The unit runs as `fluent-bit` with only `CAP_DAC_READ_SEARCH`, inside a systemd sandbox that hides
the kubeconfig, k3s's TLS/credentials/token, kubelet, shadow, `/etc/ssh` and `/root`; its start check
refuses to run when it can read the kubeconfig (siem01: the admin key). Keys: `/etc/fluent-bit/keys/`
(root 0400, handed to the unit as systemd credentials); the HMAC key is rotated by deleting it and
running the playbook again (pseudonyms change from then on). Metrics, including throttle drops:
`curl -s 127.0.0.1:2020/api/v2/metrics/prometheus` on the host. Offline proof of the whole role:
`make siem-ingest-test`; the filter alone: `make siem-lua-test`.

### 9.8 The API's SIEM certificate

```sh
scripts/siem-api-cert.sh 1            # key here, CSR signed on siem01, Secret written sops-encrypted
git add cluster/infra/portfolio-api/siem-client.sops.yaml
```

The key exists in plaintext only in `.siem-tmp/` (git-ignored, shredded on exit). For a rotation see
9.4 (map the next generation first). The API reads the certificate once, at start (ADR 0036): after
Argo has synced the new Secret, restart it (`kubectl -n portfolio-api rollout restart
deploy/portfolio-api`) before the old generation is unmapped, or the Correlation section goes
unavailable.

## Rebuild from zero

```sh
# on the Proxmox node
qm stop 120 && qm destroy 120 --purge
# from the operator machine
make vm && make hardening && make cluster
# then phase 2, which needs only the age key and the two encrypted files already in git
cluster/bootstrap/bootstrap.sh
```
Time it; the number goes on the site (phase 7).
