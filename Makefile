.PHONY: lint gitleaks validate smoke runtime-test abuse-test scenario-offline scenario-test vm hardening cluster verify bootstrap
DOCKER ?= docker

lint:            ## run yamllint, ansible-lint, shellcheck, syntax-check (in container)
	@DOCKER="$(DOCKER)" scripts/lint.sh

gitleaks:        ## scan full git history for secrets
	@$(DOCKER) run --rm -v "$(CURDIR)":/repo zricethezav/gitleaks:v8.24.3@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055 git /repo --redact --no-banner

validate:        ## render every kustomization under cluster/ and validate it against real schemas
	@scripts/check-secrets-encrypted.sh
	@scripts/check-cilium-values.sh
	@DOCKER="$(DOCKER)" scripts/validate-cluster.sh

smoke:           ## idempotency smoke test in a container
	@DOCKER="$(DOCKER)" tests/smoke.sh

runtime-test:    ## phase 4 DoD against the live cluster: shell -> Falco -> Talon kill, quarantine, RBAC (needs KUBECONFIG)
	@tests/runtime/run.sh

abuse-test:      ## phase 5: the API's 404/403/409/429 limits over HTTP (API=..., FAKE_IPS=1 via port-forward)
	@tests/abuse/run.sh

scenario-offline: ## phase 5 scenarios without a cluster: Falco/Talon rules load and line up, each scenario meets its rule's preconditions
	@DOCKER="$(DOCKER)" tests/scenarios/offline.sh

scenario-test:   ## phase 5 scenarios against the live cluster: each attack -> Falco alert -> Talon action -> end state (needs KUBECONFIG)
	@tests/scenarios/run.sh

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
