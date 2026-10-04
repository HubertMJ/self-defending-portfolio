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

## Amendment 2026-10-04: a second inventory group and Ansible from the tooling container

**Context.** ADR 0034 adds the SIEM host siem01, created by the same script and configured by Ansible.
Ansible was never installed on the operator machine (docker01); every run already happened in the
repository's tooling container.

**Decision.** The inventory has a second group, `siem_nodes` (siem01, 10.4.2.10), with its own
group_vars and playbook `playbooks/siem.yml` (imported by `site.yml`): the shared hardening roles,
switched by group, then the snapshot disk, OpenSearch, Dashboards and the configuration inside
OpenSearch. `make siem` runs it in the tooling container (`ARGS=` passes `--check --diff`, tags and
extra variables through); the container gets a copy of `~/.ssh`, because ssh refuses a configuration
owned by another user id. The same play signs client CSRs made elsewhere, on request only
(`--tags client-cert` / `--tags api-cert`).

**Consequences.** One command per host, the same container as CI's linters; the smoke test applies
siem.yml's base, ssh, firewall and patching roles to a container in `siem_nodes` twice, like
hardening.yml.
