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

### 4.0 Placeholders

Four placeholders are committed on purpose, because the repository is public and the manifests exist
before the accounts do. Replace them first:

```sh
grep -rn 'REPLACE-ME-\|AGE_PUBLIC_KEY_PLACEHOLDER' cluster/ .sops.yaml
```

| Placeholder | Where | Value |
|-------------|-------|-------|
| `HubertMJ` | `cluster/apps/*.yaml`, `cluster/bootstrap/argocd/root-application.yaml` | GitHub owner (change only in a fork) |
| `AGE_PUBLIC_KEY_PLACEHOLDER` | `.sops.yaml` | age public key from 4.1 |
| `REPLACE-ME-ACME-CONTACT-EMAIL` | `cluster/infra/cert-manager-issuers/clusterissuer-*.yaml` | your email |
| `REPLACE-ME-TUNNEL-UUID` | `cluster/infra/cloudflared/config.yaml` | tunnel UUID from 4.2 |

### 4.1 age key and `.sops.yaml`

One key pair for this environment. The private half stays on the operator machine and, as a Secret,
in the cluster; nothing else ever sees it (ADR 0006).

```sh
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt        # prints the public key on stderr
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt

# paste the public key (age1...) into .sops.yaml, replacing AGE_PUBLIC_KEY_PLACEHOLDER
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

Both directories ship a `.example` template and no real file. `kustomize build` — and therefore the
Argo CD sync — fails until the real encrypted file exists. That is deliberate; see
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
# the Gateway is programmed; its Service has no EXTERNAL-IP and that is correct (ADR 0010)
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
$EDITOR cluster/infra/hello/index.html
git commit -am 'hello: reword' && git push
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
Kyverno v1.19.1) and its three ClusterPolicies in wave 2
(`cluster/apps/kyverno-policies.yaml` -> `cluster/infra/kyverno-policies/`). Nothing below has to be
done to bring the cluster up; it is the ordered handover from "policies installed and watching" to
"policies gating", which cannot happen before a signed image exists.

Two of the three policies are committed as **Audit**: they record violations in PolicyReports and
admit the Pod. `disallow-latest-tag` is **Enforce** from the start, because nothing in `cluster/`
uses a floating tag.

```sh
grep -n 'failureAction' cluster/infra/kyverno-policies/*.yaml
```

| Policy | Committed action | Scope |
|--------|------------------|-------|
| `verify-portfolio-images` | Audit → Enforce (below) | Pods in `hello`, `sandbox` |
| `restrict-image-registries` | Audit → Enforce (below) | Pods in `hello`, `sandbox` |
| `disallow-latest-tag` | Enforce | Pods everywhere except kube-system, kyverno, argocd, cilium-secrets, cert-manager, gateway, cloudflared |

### 5.1 The first build must run

Verification is an assertion about a signature that does not exist yet. Push to `main` and let
`.github/workflows/build-web.yml` complete at least once; it builds the image, pushes it to
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
  --certificate-identity-regexp '^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/build-web\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation ghcr.io/hubertmj/self-defending-portfolio/web:<tag> --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/build-web\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Both commands must succeed from a machine that is not logged in to GHCR. The identity regexp and
issuer above are character-for-character what `cluster/infra/kyverno-policies/verify-portfolio-images.yaml`
asserts, so if `cosign` is happy, Kyverno will be.

### 5.3 Point `hello` at the signed digest

`cluster/infra/hello/deployment.yaml` runs `nginxinc/nginx-unprivileged`, which is not ours and which
nobody signed. Replace it with our own image, pinned by digest, using a kustomize `images:`
transformer in `cluster/infra/hello/kustomization.yaml` rather than by editing the Deployment: the
image reference then has one home, the diff of a rebuild is one line, and nothing else in the
Deployment moves.

```yaml
# cluster/infra/hello/kustomization.yaml
images:
  - name: nginxinc/nginx-unprivileged
    newName: ghcr.io/hubertmj/self-defending-portfolio/web
    newTag: <version>
    digest: <sha256:...>   # use digest OR newTag; digest is what ADR 0008 wants
```

The image must listen on 8080 as a non-root uid and run with a read-only root filesystem, because the
`hello` namespace enforces Pod Security Standards `restricted` and the Deployment's `securityContext`
already says so. Check `runAsUser` in the Deployment against the uid the new image actually uses.

### 5.4 Flip Audit → Enforce, in the same commit

This is one commit with 5.3, not a follow-up. Enforce before the image is ours stops the site;
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
