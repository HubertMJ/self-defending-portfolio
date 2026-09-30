#!/usr/bin/env bash
# Create the k3s VM on Proxmox from the official Debian 13 generic cloud image via the REST API.
#
# Requires: curl, jq. Credentials only from the environment (see docs/bootstrap.md):
#   PVE_HOST      e.g. 10.2.1.2
#   PVE_TOKEN_ID  e.g. 'ansible@pve!portfolio'
#   PVE_TOKEN     the token secret
# Optional overrides (defaults match ansible/inventory):
#   PVE_NODE (auto-detected if the host has a single node), VMID (default 120), VM_NAME (k3s01),
#   VM_CORES (4), VM_MEMORY_MB (8192), VM_DISK_GB (60), VM_STORAGE (local-lvm), VM_BRIDGE (vmbr0),
#   VM_VLAN (empty = untagged), VM_IP (10.2.1.20/24), VM_GW (10.2.1.1), VM_DNS (10.2.1.6),
#   VM_USER (ansible), SSH_PUBKEY_FILE (~/.ssh/id_ed25519.pub), DEBIAN_IMAGE_URL, PVE_INSECURE (0/1)
#
# Idempotent-ish: refuses to run if VMID already exists. Destroy with: qm destroy <VMID> --purge (on the node).
set -euo pipefail

: "${PVE_HOST:?set PVE_HOST}"; : "${PVE_TOKEN_ID:?set PVE_TOKEN_ID}"; : "${PVE_TOKEN:?set PVE_TOKEN}"
VMID="${VMID:-120}"
VM_NAME="${VM_NAME:-k3s01}"
VM_CORES="${VM_CORES:-4}"
VM_MEMORY_MB="${VM_MEMORY_MB:-8192}"
VM_DISK_GB="${VM_DISK_GB:-60}"
VM_STORAGE="${VM_STORAGE:-local-lvm}"
VM_BRIDGE="${VM_BRIDGE:-vmbr0}"
VM_VLAN="${VM_VLAN:-}"
VM_IP="${VM_IP:-10.2.1.20/24}"
VM_GW="${VM_GW:-10.2.1.1}"
VM_DNS="${VM_DNS:-10.2.1.6}"
VM_USER="${VM_USER:-ansible}"
SSH_PUBKEY_FILE="${SSH_PUBKEY_FILE:-$HOME/.ssh/id_ed25519.pub}"
DEBIAN_IMAGE_URL="${DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
DEBIAN_SUMS_URL="${DEBIAN_SUMS_URL:-https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS}"
CURL_OPTS=(-sS --fail-with-body -H "Authorization: PVEAPIToken=${PVE_TOKEN_ID}=${PVE_TOKEN}")
[[ "${PVE_INSECURE:-0}" == "1" ]] && CURL_OPTS+=(-k)
API="https://${PVE_HOST}:8006/api2/json"

api() { # method path [form-data...]
  local m="$1" p="$2"; shift 2
  local args=()
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl "${CURL_OPTS[@]}" -X "$m" "${API}${p}" "${args[@]}"
}
wait_task() { # upid
  local upid="$1" status
  while :; do
    status=$(api GET "/nodes/${PVE_NODE}/tasks/${upid}/status" | jq -r '.data.status')
    [[ "$status" == "stopped" ]] && break
    sleep 2
  done
  local exit; exit=$(api GET "/nodes/${PVE_NODE}/tasks/${upid}/status" | jq -r '.data.exitstatus')
  [[ "$exit" == "OK" ]] || { echo "task ${upid} failed: ${exit}" >&2; exit 1; }
}

[[ -r "$SSH_PUBKEY_FILE" ]] || { echo "SSH public key not found: $SSH_PUBKEY_FILE" >&2; exit 1; }

PVE_NODE="${PVE_NODE:-$(api GET /nodes | jq -r '.data[].node' | head -1)}"
echo "node=${PVE_NODE} vmid=${VMID} name=${VM_NAME} ip=${VM_IP}"

if api GET "/nodes/${PVE_NODE}/qemu/${VMID}/status/current" >/dev/null 2>&1; then
  echo "VMID ${VMID} already exists on ${PVE_NODE}; refusing to touch it." >&2; exit 1
fi

# 1. Download the cloud image into the node's ISO/import storage ("local" by default) with checksum.
IMG_NAME=$(basename "$DEBIAN_IMAGE_URL")
IMPORT_STORAGE="${IMPORT_STORAGE:-local}"
SHA512=$(curl -sS --fail "$DEBIAN_SUMS_URL" | awk -v f="$IMG_NAME" '$2==f {print $1}')
[[ -n "$SHA512" ]] || { echo "checksum for ${IMG_NAME} not found in SHA512SUMS" >&2; exit 1; }
echo "downloading ${IMG_NAME} to ${IMPORT_STORAGE} (sha512 verified by Proxmox)"
UPID=$(api POST "/nodes/${PVE_NODE}/storage/${IMPORT_STORAGE}/download-url" \
  "content=import" "filename=${IMG_NAME}" "url=${DEBIAN_IMAGE_URL}" \
  "checksum-algorithm=sha512" "checksum=${SHA512}" | jq -r '.data')
wait_task "$UPID"

# 2. Create the VM: q35, UEFI (OVMF), virtio-scsi-single, cloud-init drive, serial console, guest agent.
NET="virtio,bridge=${VM_BRIDGE}"; [[ -n "$VM_VLAN" ]] && NET+=",tag=${VM_VLAN}"
SSHKEYS=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read().strip(),safe=""))' "$SSH_PUBKEY_FILE")
UPID=$(api POST "/nodes/${PVE_NODE}/qemu" \
  "vmid=${VMID}" "name=${VM_NAME}" "ostype=l26" "machine=q35" "bios=ovmf" \
  "cpu=host" "cores=${VM_CORES}" "memory=${VM_MEMORY_MB}" "balloon=0" \
  "scsihw=virtio-scsi-single" "agent=1" "serial0=socket" "vga=serial0" \
  "net0=${NET}" \
  "efidisk0=${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0" \
  "scsi0=${VM_STORAGE}:0,import-from=${IMPORT_STORAGE}:import/${IMG_NAME},discard=on,ssd=1,iothread=1" \
  "ide2=${VM_STORAGE}:cloudinit" "boot=order=scsi0" \
  "ciuser=${VM_USER}" "ipconfig0=ip=${VM_IP},gw=${VM_GW}" "nameserver=${VM_DNS}" \
  "sshkeys=${SSHKEYS}" "ciupgrade=1" "onboot=1" \
  "description=self-defending-portfolio k3s node. Managed by Ansible; do not edit by hand." | jq -r '.data')
wait_task "$UPID"

# 3. Grow the root disk (image is 3 GB); cloud-init growpart expands the filesystem on first boot.
api PUT "/nodes/${PVE_NODE}/qemu/${VMID}/resize" "disk=scsi0" "size=${VM_DISK_GB}G" >/dev/null

# 4. Start.
UPID=$(api POST "/nodes/${PVE_NODE}/qemu/${VMID}/status/start" | jq -r '.data')
wait_task "$UPID"
echo "VM ${VMID} started. Wait ~60 s for cloud-init, then:"
echo "  ssh ${VM_USER}@${VM_IP%%/*}"
echo "  cd ansible && ansible-playbook playbooks/site.yml"
