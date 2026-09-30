# Bootstrap: from nothing to a hardened k3s node

Everything below is one-time and runs from an operator machine (any Linux/macOS with `curl`, `jq`,
`python3`, `ansible`). After bootstrap, no manual step touches the cluster: changes go through git.

## 0. Prerequisites (human, once)

| What | Where | Why |
|------|-------|-----|
| Proxmox API token | Proxmox UI → Datacenter → Permissions → API Tokens | `scripts/pve-create-vm.sh` creates the VM |
| SSH key pair | `ssh-keygen -t ed25519` | cloud-init injects the public key for user `ansible` |
| Cloudflare API token (zone: DNS edit, Tunnel edit) | Cloudflare dashboard | cert-manager DNS-01 + tunnel (phase 2) |
| age key pair | `age-keygen -o ~/.config/sops/age/keys.txt` | SOPS secrets (phase 2) |

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

## 1. Create the VM

```sh
make vm            # or: scripts/pve-create-vm.sh  (VMID 120, k3s01, 10.2.1.20)
ssh ansible@10.2.1.20 true   # accept the host key after checking the fingerprint on the Proxmox console
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

## 3. Cluster (phase 2)

```sh
make cluster       # k3s (no flannel, no kube-proxy) + Cilium
make verify        # read-only assertions
export KUBECONFIG=$PWD/kubeconfig   # fetched by the k3s role, gitignored
kubectl get nodes
```

## Rebuild from zero

```sh
# on the Proxmox node
qm stop 120 && qm destroy 120 --purge
# from the operator machine
make vm && make hardening && make cluster
```
Time it; the number goes on the site (phase 7).
