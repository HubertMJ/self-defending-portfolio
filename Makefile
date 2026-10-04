.PHONY: lint gitleaks validate smoke runtime-test abuse-test scenario-offline scenario-test vm hardening cluster verify bootstrap \
	siem siem-verify golden siem-csr-test siem-acceptance siem-mutations ingest
DOCKER ?= docker

# Ansible in the tooling container (scripts/Dockerfile.tooling); Ansible is not installed on the
# operator host. ~/.ssh is copied into the container rather than used in place, because ssh refuses
# a config owned by another uid. Arguments after the playbook come from ARGS, e.g.
# make siem ARGS="--check --diff".
ANSIBLE_IN_TOOLING = $(DOCKER) run --rm -i -v "$(CURDIR)":/work -w /work/ansible -v "$(HOME)/.ssh":/ssh-src:ro \
	-e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections sdp-tooling sh -ec \
	'cp -r /ssh-src /root/.ssh && chmod -R go-rwx /root/.ssh \
	&& ansible-galaxy collection install -r requirements.yml -p /work/.ansible/collections >/dev/null \
	&& ansible-playbook "$$@"' ansible-playbook

lint:            ## run yamllint, ansible-lint, shellcheck, syntax-check (in container)
	@DOCKER="$(DOCKER)" scripts/lint.sh

gitleaks:        ## scan full git history for secrets
	@$(DOCKER) run --rm -v "$(CURDIR)":/repo zricethezav/gitleaks:v8.24.3@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055 git /repo --redact --no-banner

validate:        ## render every kustomization under cluster/ and validate it against real schemas
	@scripts/check-secrets-encrypted.sh
	@scripts/check-cilium-values.sh
	@scripts/check-web-csp.sh
	@scripts/check-web-identity.sh
	@scripts/check-image-digests.sh
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

siem:            ## SIEM host siem01: hardening, snapshot disk, OpenSearch, Dashboards (ADR 0034; ARGS="--check --diff")
	@$(ANSIBLE_IN_TOOLING) playbooks/siem.yml $(ARGS)

siem-verify:     ## read-only checks of siem01
	@$(ANSIBLE_IN_TOOLING) playbooks/verify.yml --limit siem_nodes $(ARGS)

ingest:          ## k3s01's SIEM shipper: Fluent Bit, certificate signed on siem01 (ADR 0034; maintenance window; ARGS="--check --diff")
	@$(ANSIBLE_IN_TOOLING) playbooks/ingest.yml $(ARGS)

golden:          ## the shared host roles render byte-identically for k3s01 (goldens from b374c0e) and siem01-shaped for siem01; k3s01's audit policy
	@DOCKER="$(DOCKER)" tests/golden/render.sh
	@DOCKER="$(DOCKER)" tests/golden/audit-policy.sh

siem-csr-test:   ## the remote CSR entry point signs exactly the expected client identity and nothing more (in container)
	@DOCKER="$(DOCKER)" tests/siem/csr-signer.sh

siem-acceptance: ## P1 live acceptance on siem01: shipper refusals, rewrites refused, audit log, TLS, settings, restore (ADR 0034)
	@DOCKER="$(DOCKER)" tests/siem/p1-acceptance.sh

siem-mutations:  ## mutation proof of the P1 tests: each mutation on a scratch copy must make its test fail
	@DOCKER="$(DOCKER)" tests/siem/p1-mutations.sh

