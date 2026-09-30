.PHONY: lint smoke vm hardening cluster verify
DOCKER ?= docker

lint:            ## run yamllint, ansible-lint, shellcheck, syntax-check (in container)
	@DOCKER=$(DOCKER) scripts/lint.sh

smoke:           ## idempotency smoke test in a container
	@DOCKER=$(DOCKER) tests/smoke.sh

vm:              ## create the VM on Proxmox (needs PVE_HOST/PVE_TOKEN_ID/PVE_TOKEN)
	@scripts/pve-create-vm.sh

hardening:       ## phase 1: host hardening
	@cd ansible && ansible-playbook playbooks/hardening.yml

cluster:         ## phase 2: k3s + cilium
	@cd ansible && ansible-playbook playbooks/cluster.yml

verify:          ## read-only checks
	@cd ansible && ansible-playbook playbooks/verify.yml
