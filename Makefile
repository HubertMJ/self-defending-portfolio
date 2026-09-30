.PHONY: lint validate smoke vm hardening cluster verify bootstrap
DOCKER ?= docker

lint:            ## run yamllint, ansible-lint, shellcheck, syntax-check (in container)
	@DOCKER="$(DOCKER)" scripts/lint.sh

validate:        ## render every kustomization under cluster/ and validate it against real schemas
	@scripts/check-secrets-encrypted.sh
	@scripts/check-cilium-values.sh
	@DOCKER="$(DOCKER)" scripts/validate-cluster.sh

smoke:           ## idempotency smoke test in a container
	@DOCKER="$(DOCKER)" tests/smoke.sh

vm:              ## create the VM on Proxmox (needs PVE_HOST/PVE_TOKEN_ID/PVE_TOKEN)
	@scripts/pve-create-vm.sh

hardening:       ## phase 1: host hardening
	@cd ansible && ansible-playbook playbooks/hardening.yml

cluster:         ## phase 1 -> 2: k3s + Cilium (the seed install; Argo CD adopts the Cilium release)
	@cd ansible && ansible-playbook playbooks/cluster.yml

verify:          ## read-only checks
	@cd ansible && ansible-playbook playbooks/verify.yml

bootstrap:       ## phase 2: install Argo CD once (needs KUBECONFIG and SOPS_AGE_KEY_FILE)
	@cluster/bootstrap/bootstrap.sh
