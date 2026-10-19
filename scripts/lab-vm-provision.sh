#!/usr/bin/env bash
# Provision the detection lab's isolated VM (variant B), idempotently, over `ssh pve` with qm/pvesh —
# no Proxmox API token anywhere. One reviewable script: it downloads the image, creates VM 122 on
# VLAN 42, installs Sysmon for Linux + Fluent Bit + the scenario through cloud-init, injects only the
# shipper certificate, locks the VM's egress to siem01, takes a clean snapshot, and installs the daily
# rollback/run timer on the PVE host. The VM never compiles or runs during provisioning; the first
# real run is the timer's (or a manual `qm rollback 122 lab-clean && qm start 122`).
#
# The VM is isolated: static IP (no DHCP/DNS), per-VM PVE firewall DROP in/out except siem01
# tcp/9200 (events) and tcp/8080 (the beacon sink), ipfilter on (no address spoofing on VLAN 42).
#
# Run it from a host that can `ssh pve` (the Proxmox node) with qm rights, e.g. docker01:
#   SHIPPER_CERT_DIR=~/lab-vm-shipper DETLAB_REF=<detection-lab commit> scripts/lab-vm-provision.sh
# SHIPPER_CERT_DIR must hold tls.crt, tls.key and ca.crt for the lab-vm-shipper identity (made by the
# siem01 apply). Preview everything without touching Proxmox: scripts/lab-vm-provision.sh --dry-run.
set -euo pipefail

# ---- parameters (defaults match ADR 0034 amendment: VLAN 42, siem01 10.4.2.10) ----
PVE_SSH="${PVE_SSH:-pve}"                     # ssh alias / host of the Proxmox node
VMID="${VMID:-122}"
VM_NAME="${VM_NAME:-lab-vm}"
VM_CORES="${VM_CORES:-1}"
VM_MEMORY_MB="${VM_MEMORY_MB:-1536}"
VM_DISK_GB="${VM_DISK_GB:-8}"
VM_STORAGE="${VM_STORAGE:-local-lvm}"         # the VM disk (lvmthin)
IMPORT_STORAGE="${IMPORT_STORAGE:-local}"     # advertises 'import' content
SNIPPET_STORAGE="${SNIPPET_STORAGE:-Lexar}"   # advertises 'snippets' content
VM_BRIDGE="${VM_BRIDGE:-vmbr0}"
# The VM sits on its own lab VLAN (43) and reaches siem01 (10.4.2.10, VLAN 42) across the router.
VM_VLAN="${LAB_VLAN:-${VM_VLAN:-43}}"
VM_IP="${VM_IP:-10.4.3.20/24}"
VM_GW="${VM_GW:-10.4.3.1}"
# Public resolver (mirrors pve-create-vm.sh): the lab VLAN is intentionally not allowed to reach the
# internal resolver, and the gateway resolver would leak internal names. Set explicitly so cloud-init
# never falls back to the Proxmox host's DNS (10.2.1.x), which the VM cannot reach from the lab VLAN.
VM_DNS="${LAB_DNS:-${VM_DNS:-1.1.1.1}}"
SIEM_IP="${SIEM_IP:-10.4.2.10}"
SIEM_PORT="${SIEM_PORT:-9200}"
SINK_PORT="${SINK_PORT:-8080}"
VM_USER="${VM_USER:-labadmin}"
SSH_PUBKEY_FILE="${SSH_PUBKEY_FILE:-$HOME/.ssh/id_ed25519.pub}"
SNAPSHOT="${SNAPSHOT:-lab-clean}"
# Pinned Debian 13 genericcloud (same build pve-create-vm.sh uses; bump deliberately).
DEBIAN_BUILD="${DEBIAN_BUILD:-20260914-2601}"
DEBIAN_IMAGE_URL="${DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/${DEBIAN_BUILD}/debian-13-genericcloud-amd64-${DEBIAN_BUILD}.qcow2}"
DEBIAN_SUMS_URL="${DEBIAN_SUMS_URL:-https://cloud.debian.org/images/cloud/trixie/${DEBIAN_BUILD}/SHA512SUMS}"
# detection-lab at a pinned commit (must contain vm/): the VM clones it during setup and builds the
# canary itself, so copy 1's hash is the VM toolchain's. Required.
DETLAB_REPO="${DETLAB_REPO:-https://github.com/HubertMJ/detection-lab.git}"
# detection-lab main merge of the VM side (feat/vm-scenario -> #12/#13/#14). Bump deliberately.
DETLAB_REF="${DETLAB_REF:-caff27b23f753f19fe26c4f8b64b15bcc063f63c}"
SHIPPER_CERT_DIR="${SHIPPER_CERT_DIR:-}"      # tls.crt, tls.key, ca.crt (lab-vm-shipper); required unless --dry-run
# Dry-run prints the pve writes instead of running them. Honoured from the environment (DRY_RUN=1) as
# well as the --dry-run flag, so an env-var invocation never falls through to a real run by surprise.
DRY_RUN="${DRY_RUN:-0}"
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

IMG_NAME="$(basename "$DEBIAN_IMAGE_URL")"
SNIPPET_NAME="lab-vm-user.yaml"

say() { printf '\n== %s ==\n' "$*"; }
# Run a command on the Proxmox node (or print it under --dry-run). The command string is built on
# this side on purpose (it carries this run's VMID, paths, etc.), so client-side expansion is wanted.
# shellcheck disable=SC2029
pve() { if [[ $DRY_RUN == 1 ]]; then printf 'ssh %s %q ' "$PVE_SSH" "$*"; printf '\n'; else ssh "$PVE_SSH" "$@"; fi; }
# Run and always capture output (for existence checks); never printed in dry-run.
# shellcheck disable=SC2029
pveq() { ssh "$PVE_SSH" "$@" 2>/dev/null; }

vm_exists() { [[ $DRY_RUN == 1 ]] && return 1; pveq qm status "$VMID" >/dev/null 2>&1; }
snap_exists() { [[ $DRY_RUN == 1 ]] && return 1; pveq qm listsnapshot "$VMID" 2>/dev/null | grep -q " ${SNAPSHOT} "; }

# ---- preflight ----
[[ -r "$SSH_PUBKEY_FILE" ]] || { echo "ssh pubkey not found: $SSH_PUBKEY_FILE" >&2; exit 1; }
if [[ $DRY_RUN == 0 ]]; then
  [[ -n "$SHIPPER_CERT_DIR" ]] || { echo "set SHIPPER_CERT_DIR (tls.crt tls.key ca.crt for lab-vm-shipper)" >&2; exit 1; }
  for f in tls.crt tls.key ca.crt; do
    [[ -r "$SHIPPER_CERT_DIR/$f" ]] || { echo "missing $SHIPPER_CERT_DIR/$f" >&2; exit 1; }
  done
fi
SSH_PUBKEY="$(cat "$SSH_PUBKEY_FILE")"

# ---- 1. image on the node (skip if already imported) ----
say "image ${IMG_NAME} on ${IMPORT_STORAGE}"
if [[ $DRY_RUN == 1 ]] || ! pveq test -f "/var/lib/vz/import/${IMG_NAME}"; then
  if [[ $DRY_RUN == 1 ]]; then
    SHA512='<sha512>'
  else
    SHA512="$(curl -sS --fail "$DEBIAN_SUMS_URL" | awk -v f="$IMG_NAME" '$2==f{print $1}')"
  fi
  pve "mkdir -p /var/lib/vz/import && cd /var/lib/vz/import && \
    curl -fsSL -o ${IMG_NAME}.part '${DEBIAN_IMAGE_URL}' && \
    echo '${SHA512}  ${IMG_NAME}.part' | sha512sum -c - && mv ${IMG_NAME}.part ${IMG_NAME}"
else
  echo "already present"
fi

# ---- 2. cloud-init user-data (installs sysmon + fluent-bit + the scenario; no secret) ----
say "cloud-init snippet ${SNIPPET_STORAGE}:snippets/${SNIPPET_NAME}"
SNIPPET_DIR="$(pveq pvesm path "${SNIPPET_STORAGE}:snippets/${SNIPPET_NAME}" 2>/dev/null | xargs dirname 2>/dev/null || true)"
SNIPPET_DIR="${SNIPPET_DIR:-/mnt/pve/${SNIPPET_STORAGE}/snippets}"
USERDATA="$(cat <<YAML
#cloud-config
# Managed by scripts/lab-vm-provision.sh (detection-lab variant B). The VM is isolated; this installs
# the sensor and the scenario but runs nothing. The shipper certificate is injected after boot, not here.
hostname: ${VM_NAME}
manage_etc_hosts: true
users:
  - name: ${VM_USER}
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${SSH_PUBKEY}
package_update: true
packages: [curl, ca-certificates, gnupg, git, make, gcc, build-essential, python3, qemu-guest-agent]
write_files:
  - path: /etc/lab/env
    permissions: '0644'
    content: |
      LAB_SINK_IP=${SIEM_IP}
      LAB_SINK_PORT=${SINK_PORT}
      SIEM_ENDPOINT=https://${SIEM_IP}:${SIEM_PORT}
      SIEM_CLIENT_CERT=/etc/lab/siem/tls.crt
      SIEM_CLIENT_KEY=/etc/lab/siem/tls.key
      SIEM_CA_CERT=/etc/lab/siem/ca.crt
      LAB_BASE=/opt/lab/lab-canary
  - path: /etc/systemd/system/lab-run.service
    permissions: '0644'
    content: |
      [Unit]
      Description=detection lab variant B run (run scenario, ship, power off)
      After=network-online.target sysmon.service fluent-bit.service
      Wants=network-online.target
      [Service]
      Type=oneshot
      EnvironmentFile=/etc/lab/env
      ExecStart=/opt/lab/run-and-ship.sh
      [Install]
      WantedBy=multi-user.target
  - path: /opt/lab/sysmon-config.xml
    permissions: '0644'
    content: |
      <Sysmon schemaversion="4.81">
        <EventFiltering>
          <RuleGroup groupRelation="or">
            <ProcessCreate onmatch="include">
              <Image condition="begin with">/tmp/</Image>
            </ProcessCreate>
            <FileCreate onmatch="include">
              <Image condition="begin with">/tmp/</Image>
            </FileCreate>
            <NetworkConnect onmatch="include">
              <Image condition="begin with">/tmp/</Image>
            </NetworkConnect>
          </RuleGroup>
        </EventFiltering>
      </Sysmon>
runcmd:
  - systemctl enable --now qemu-guest-agent
  # Microsoft repo for sysmonforlinux
  - curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
  - echo "deb [signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/microsoft-prod.list
  # Fluent Bit official repo
  - curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor -o /usr/share/keyrings/fluentbit.gpg
  - echo "deb [signed-by=/usr/share/keyrings/fluentbit.gpg] https://packages.fluentbit.io/debian/bookworm bookworm main" > /etc/apt/sources.list.d/fluentbit.list
  - apt-get update
  - DEBIAN_FRONTEND=noninteractive apt-get install -y sysmonforlinux fluent-bit
  # the scenario, built with THIS VM's toolchain so copy 1's hash is the deployed one
  - git clone ${DETLAB_REPO} /opt/lab-src
  - git -C /opt/lab-src checkout ${DETLAB_REF}
  - make -C /opt/lab-src/vm
  - mkdir -p /opt/lab /etc/lab/siem /var/lib/fluent-bit /run/lab
  - install -m0755 /opt/lab-src/vm/dist/lab-canary /opt/lab/lab-canary
  - cp /opt/lab-src/vm/dist/lab-canary.sha256 /opt/lab/lab-canary.sha256
  - install -m0755 /opt/lab-src/vm/run_scenario.py /opt/lab/run_scenario.py
  - install -m0755 /opt/lab-src/vm/ship_marker.py /opt/lab/ship_marker.py
  - install -m0755 /opt/lab-src/vm/run-and-ship.sh /opt/lab/run-and-ship.sh
  - install -d /etc/fluent-bit
  - install -m0644 /opt/lab-src/vm/fluent-bit/fluent-bit.conf /etc/fluent-bit/fluent-bit.conf
  - install -m0644 /opt/lab-src/vm/fluent-bit/sysmon_to_lab.lua /etc/fluent-bit/sysmon_to_lab.lua
  # start the sensor; the shipper waits for its cert (injected after boot) and is enabled before snapshot
  - sysmon -accepteula -i /opt/lab/sysmon-config.xml || sysmon -i /opt/lab/sysmon-config.xml
  - systemctl enable --now sysmon || true
  - touch /run/lab/cloud-init-done
YAML
)"
if [[ $DRY_RUN == 1 ]]; then
  echo "--- would write ${SNIPPET_DIR}/${SNIPPET_NAME}:"; printf '%s\n' "$USERDATA" | sed 's/^/  | /'
else
  # shellcheck disable=SC2029  # the snippet path is built here and must expand on this side
  printf '%s\n' "$USERDATA" | ssh "$PVE_SSH" "mkdir -p '${SNIPPET_DIR}' && cat > '${SNIPPET_DIR}/${SNIPPET_NAME}'"
fi

# ---- 3. create or reconcile the VM (idempotent) ----
# A VM with a clean snapshot is a good one: migrate its VLAN tag / IP in place and force cloud-init to
# re-run (new NoCloud instance id via a fresh system uuid), then drop the snapshot so it is recaptured
# after the isolation check. A VM with no snapshot is incomplete (e.g. cloud-init failed on a wrong
# network): destroy it and recreate clean. Either way the end state is the same (idempotent).
say "VM ${VMID} (${VM_NAME})"
if vm_exists && snap_exists; then
  echo "VMID ${VMID} is provisioned; migrating net0 tag=${VM_VLAN} and ipconfig0 ${VM_IP}, re-running setup"
  if [[ $DRY_RUN == 1 ]]; then
    echo "would: qm stop ${VMID}; set net0 tag=${VM_VLAN}; set ipconfig0 ip=${VM_IP},gw=${VM_GW}; set nameserver ${VM_DNS}; refresh cicustom; new smbios uuid; qm cloudinit update; delete snapshot ${SNAPSHOT}"
  else
    pveq qm stop "$VMID" >/dev/null 2>&1 || true
    MAC="$(pveq qm config "$VMID" | sed -n 's/^net0:.*virtio=\([0-9A-Fa-f:]*\).*/\1/p')"
    [[ -n "$MAC" ]] && pveq qm set "$VMID" --net0 "virtio=${MAC},bridge=${VM_BRIDGE},tag=${VM_VLAN},firewall=1"
    pveq qm set "$VMID" --ipconfig0 "ip=${VM_IP},gw=${VM_GW}"
    pveq qm set "$VMID" --nameserver "${VM_DNS}"
    pveq qm set "$VMID" --cicustom "user=${SNIPPET_STORAGE}:snippets/${SNIPPET_NAME}"
    pveq qm set "$VMID" --smbios1 "uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
    pveq qm cloudinit update "$VMID" >/dev/null 2>&1 || true
    pveq qm delsnapshot "$VMID" "$SNAPSHOT" >/dev/null 2>&1 || true
  fi
elif vm_exists; then
  echo "VMID ${VMID} exists but has no ${SNAPSHOT} snapshot (incomplete); destroying and recreating"
  pve "qm stop ${VMID}; sleep 2; qm destroy ${VMID} --purge --destroy-unreferenced-disks 1"
fi
if ! vm_exists; then
  pve "qm create ${VMID} --name ${VM_NAME} --ostype l26 --machine q35 --bios ovmf \
    --cpu host --cores ${VM_CORES} --memory ${VM_MEMORY_MB} --balloon 0 \
    --scsihw virtio-scsi-single --agent 1 --serial0 socket --vga serial0 \
    --net0 virtio,bridge=${VM_BRIDGE},tag=${VM_VLAN},firewall=1 \
    --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0 \
    --scsi0 ${VM_STORAGE}:0,import-from=${IMPORT_STORAGE}:import/${IMG_NAME},discard=on,ssd=1 \
    --ide2 ${VM_STORAGE}:cloudinit --boot order=scsi0 \
    --ciuser ${VM_USER} --ipconfig0 ip=${VM_IP},gw=${VM_GW} --nameserver ${VM_DNS} \
    --cicustom user=${SNIPPET_STORAGE}:snippets/${SNIPPET_NAME} \
    --ciupgrade 0 --onboot 0 \
    --description 'detection-lab variant B isolated VM. Managed by scripts/lab-vm-provision.sh.'"
  pve "qm resize ${VMID} scsi0 ${VM_DISK_GB}G"
fi

# ---- 4. first boot with SETUP egress (firewall not yet enabled) so apt+git can run ----
say "first boot (setup)"
pve "qm start ${VMID}"
echo "waiting for cloud-init to finish on the guest (apt + git clone + build)..."
if [[ $DRY_RUN == 1 ]]; then
  echo "ssh ${PVE_SSH} 'until qm guest exec ${VMID} -- test -f /run/lab/cloud-init-done; do sleep 10; done'"
else
  for _ in $(seq 1 90); do
    pveq qm guest exec "$VMID" -- test -f /run/lab/cloud-init-done >/dev/null 2>&1 && break
    sleep 10
  done
fi

# ---- 5. inject the shipper certificate (the only secret; not stored on Proxmox storage) ----
say "inject shipper certificate"
if [[ $DRY_RUN == 1 ]]; then
  echo "qm guest exec ${VMID} -- install -d -m0750 /etc/lab/siem   # then write tls.crt/tls.key/ca.crt (base64 via guest exec)"
else
  pveq qm guest exec "$VMID" -- install -d -m0750 /etc/lab/siem
  for f in ca.crt tls.crt tls.key; do
    mode=0644; [[ "$f" == tls.key ]] && mode=0600
    b64="$(base64 -w0 "$SHIPPER_CERT_DIR/$f")"
    pveq qm guest exec "$VMID" -- /bin/sh -c "echo '$b64' | base64 -d > /etc/lab/siem/$f && chmod $mode /etc/lab/siem/$f"
  done
fi

# ---- 6. report copy-1 hash (for the ioc-lab-known-hash rule), then enable the run for next boot ----
say "copy-1 hash + enable run"
if [[ $DRY_RUN == 1 ]]; then
  echo "qm guest exec ${VMID} -- cat /opt/lab/lab-canary.sha256   # -> pin into siem/rules/ioc-lab-known-hash"
else
  HASH="$(pveq qm guest exec "$VMID" -- cat /opt/lab/lab-canary.sha256 | python3 -c 'import sys,json;print(json.load(sys.stdin).get("out-data","").strip())' 2>/dev/null || true)"
  echo "COPY1_SHA256=${HASH:-<read it from the guest>}"
fi
pveq qm guest exec "$VMID" -- systemctl enable lab-run.service >/dev/null 2>&1 || \
  [[ $DRY_RUN == 1 ]] && echo "qm guest exec ${VMID} -- systemctl enable lab-run.service"

# ---- 7. lock the VM's egress (DROP in/out except siem01:9200 and the sink:8080), ipfilter on ----
say "per-VM firewall (egress = siem01 only)"
FW="$(cat <<EOF
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: DROP
ipfilter: 1

[IPSET ipfilter-net0]
${VM_IP%%/*}/32

[RULES]
OUT ACCEPT -dest ${SIEM_IP} -p tcp -dport ${SIEM_PORT} -log nolog
OUT ACCEPT -dest ${SIEM_IP} -p tcp -dport ${SINK_PORT} -log nolog
EOF
)"
if [[ $DRY_RUN == 1 ]]; then
  echo "--- would write /etc/pve/firewall/${VMID}.fw:"; printf '%s\n' "$FW" | sed 's/^/  | /'
else
  # shellcheck disable=SC2029  # the VMID in the remote path is built here and must expand on this side
  printf '%s\n' "$FW" | ssh "$PVE_SSH" "cat > /etc/pve/firewall/${VMID}.fw"
  pveq pve-firewall compile >/dev/null 2>&1 || true
fi

# Per-VM rules only take effect when the Proxmox DATACENTER firewall is on. Enabling it is host-wide,
# so do it the lockout-safe way: datacenter policy ACCEPT in/out leaves the node and every other guest
# accepting everything exactly as today — only VM ${VMID}'s own .fw (policy DROP) bites. Refuse if
# another guest already has a NIC firewall that would suddenly start applying, and revert if the node
# stops answering. Hubert pasting this script is the OK for this host change.
PVE_ADDR="${PVE_ADDR:-10.2.1.2}"
mgmt_ok() { ssh -o ConnectTimeout=8 "$PVE_SSH" true >/dev/null 2>&1 \
  && timeout 5 bash -c "echo > /dev/tcp/${PVE_ADDR}/8006" 2>/dev/null; }
if [[ $DRY_RUN == 1 ]]; then
  echo "would enable the datacenter firewall (policy ACCEPT in/out) only after checking no other guest"
  echo "has a NIC firewall, then verify ssh+:8006 and revert cluster.fw on failure"
elif pveq pve-firewall status 2>/dev/null | grep -qi "enabled"; then
  echo "datacenter firewall already enabled"
elif pveq test -f /etc/pve/firewall/cluster.fw; then
  echo "STOP: /etc/pve/firewall/cluster.fw exists but the firewall is not enabled; not mangling it." >&2
  echo "Add to its [OPTIONS]:  enable: 1 / policy_in: ACCEPT / policy_out: ACCEPT  then re-run." >&2
  exit 2
else
  # No cluster.fw yet: with the firewall off, no guest's NIC firewall bites. Turning it on makes every
  # NIC with firewall=1 start applying its rules, so refuse if any OTHER guest has one.
  OTHERS="$(ssh "$PVE_SSH" '
    for id in $(qm list 2>/dev/null | awk "NR>1{print \$1}"); do
      [ "$id" = "'"$VMID"'" ] && continue
      qm config "$id" 2>/dev/null | grep -q "firewall=1" && echo "qemu/$id"
    done
    for id in $(pct list 2>/dev/null | awk "NR>1{print \$1}"); do
      pct config "$id" 2>/dev/null | grep -q "firewall=1" && echo "lxc/$id"
    done' 2>/dev/null || true)"
  if [[ -n "$OTHERS" ]]; then
    echo "STOP: these guests already have a NIC firewall and would be affected by enabling it:" >&2
    # shellcheck disable=SC2086  # intentional word-split: one id per line
    printf '  %s\n' $OTHERS >&2
    echo "Review them first; aborting without changing the datacenter firewall." >&2
    exit 2
  fi
  echo "enabling the datacenter firewall (policy ACCEPT in/out; only VM ${VMID} is filtered)"
  printf '[OPTIONS]\nenable: 1\npolicy_in: ACCEPT\npolicy_out: ACCEPT\n' \
    | ssh "$PVE_SSH" "cat > /etc/pve/firewall/cluster.fw"
  sleep 3
  if ! mgmt_ok; then
    echo "node stopped answering after enabling the firewall; reverting cluster.fw" >&2
    ssh "$PVE_SSH" "rm -f /etc/pve/firewall/cluster.fw" 2>/dev/null || true
    exit 3
  fi
  echo "datacenter firewall enabled; ssh + :8006 still answer"
fi

# ---- 8. verify the lock REALLY took effect (from inside the VM) before trusting the snapshot ----
say "verify egress lock (siem01 reachable, everything else blocked)"
if [[ $DRY_RUN == 1 ]]; then
  echo "qm guest exec ${VMID} -- python3 -c '<connect siem01:9200 ok AND 1.1.1.1:443 / gw:53 blocked, else exit 1>'"
else
  PROBE='import socket,sys
def ok(h,p):
 try:
  s=socket.create_connection((h,p),3); s.close(); return True
 except Exception:
  return False
siem=ok("'"$SIEM_IP"'",'"$SIEM_PORT"')
leak=ok("1.1.1.1",443) or ok("'"$VM_GW"'",53)
sys.exit(0 if (siem and not leak) else 1)'
  RES="$(pveq qm guest exec "$VMID" -- python3 -c "$PROBE" || true)"
  CODE="$(printf '%s' "$RES" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("exitcode",99))' 2>/dev/null || echo 99)"
  if [[ "$CODE" != "0" ]]; then
    echo "FIREWALL VERIFICATION FAILED (code ${CODE}): the VM is NOT correctly isolated." >&2
    echo "Refusing to snapshot. Leaving the VM stopped for inspection; fix the firewall and re-run." >&2
    pveq qm stop "$VMID" >/dev/null 2>&1 || true
    exit 3
  fi
  echo "verified: siem01:${SIEM_PORT} reachable, other egress blocked"
fi

# ---- 9. clean snapshot (what every run is reverted to) ----
say "snapshot ${SNAPSHOT}"
pve "qm shutdown ${VMID} --timeout 120 || qm stop ${VMID}"
# Always take a fresh snapshot of the verified-isolated state: drop any stale one first.
if snap_exists; then pve "qm delsnapshot ${VMID} ${SNAPSHOT}"; fi
pve "qm snapshot ${VMID} ${SNAPSHOT} --description 'clean lab state; reverted before each run'"

# ---- 10. the daily timer on the PVE host: markers -> rollback -> start -> inject markers ----
say "daily rollback/run timer on the Proxmox node"
RUNNER="$(cat <<EOF
#!/bin/sh
# detection-lab variant B: revert VM ${VMID} to ${SNAPSHOT} and run it. Managed by lab-vm-provision.sh.
set -e
VMID=${VMID}; SNAP=${SNAPSHOT}
rollback_epoch=\$(date +%s)
qm rollback \$VMID \$SNAP
start_epoch=\$(date +%s)
qm start \$VMID
# hand the PVE-side timestamps to the guest for the run's timeline (t0 = rollback)
for i in \$(seq 1 60); do qm guest exec \$VMID -- true >/dev/null 2>&1 && break; sleep 5; done
qm guest exec \$VMID -- /bin/sh -c "mkdir -p /run/lab && printf 'rollback_epoch=%s\nstart_epoch=%s\n' \$rollback_epoch \$start_epoch > /run/lab/pve-markers"
EOF
)"
UNIT="$(cat <<EOF
[Unit]
Description=detection-lab variant B daily run (rollback + start VM ${VMID})
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lab-vm-run.sh
EOF
)"
TIMER="$(cat <<EOF
[Unit]
Description=detection-lab variant B daily run
[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
EOF
)"
if [[ $DRY_RUN == 1 ]]; then
  echo "--- would write /usr/local/sbin/lab-vm-run.sh, /etc/systemd/system/lab-vm-run.{service,timer} and enable the timer"
  printf '%s\n' "$RUNNER" | sed 's/^/  runner| /'
else
  printf '%s\n' "$RUNNER" | ssh "$PVE_SSH" "cat > /usr/local/sbin/lab-vm-run.sh && chmod 0755 /usr/local/sbin/lab-vm-run.sh"
  printf '%s\n' "$UNIT"   | ssh "$PVE_SSH" "cat > /etc/systemd/system/lab-vm-run.service"
  printf '%s\n' "$TIMER"  | ssh "$PVE_SSH" "cat > /etc/systemd/system/lab-vm-run.timer"
  pve "systemctl daemon-reload && systemctl enable --now lab-vm-run.timer"
fi

say "done"
echo "VM ${VMID} is provisioned, locked down and snapshotted as ${SNAPSHOT}."
echo "First run: it fires at 03:00 UTC, or now with:  ssh ${PVE_SSH} 'systemctl start lab-vm-run.service'"
echo "Pin COPY1_SHA256 above into siem/rules/ioc-lab-known-hash (placeholder until the first run)."
