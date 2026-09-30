# ADR 0007: VM from a cloud image via Proxmox API, everything else Ansible

Date: 2026-09-30 · Status: accepted

## Context
Options for creating the VM: manual in the Proxmox UI, OpenTofu with the `bpg/proxmox` provider,
or a small script against the Proxmox API. The VM is created once and rebuilt rarely.

## Decision
`scripts/pve-create-vm.sh`: a shell script that uses the Proxmox REST API with an API token
(read from the environment, never from the repo) to import the official Debian 13 generic cloud image,
attach cloud-init (user `ansible`, SSH key, static IP) and start the VM. Everything after first boot is Ansible.

## Consequences
- Reproducible in one command, no state file to store, no extra tool to install on the operator machine (curl + jq).
- If the cluster ever grows to more VMs, OpenTofu replaces the script; the cloud-init contract stays the same.
- The API token needs `VM.Allocate, VM.Config.*, VM.PowerMgmt, Datastore.AllocateSpace, Datastore.AllocateTemplate`
  on the target node/storage only, not root.
