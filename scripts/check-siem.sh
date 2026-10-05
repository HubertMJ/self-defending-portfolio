#!/usr/bin/env bash
# The siem/ tree is what the rules sync applies to siem01 (ADR 0034 "Rules from git"): lint it with the
# very program the sync runs before it applies a commit, then prove the lint still refuses each thing
# it must (one broken copy of the tree per check), and the sync's offline guards (tests/siem/sync_unit_test.py).
# Needs python3 with PyYAML and git, like the other checks.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 ansible/roles/siem_sync/files/siem_lint.py siem
python3 tests/siem/lint_test.py | tail -n 1
python3 tests/siem/sync_unit_test.py | tail -n 1
