#!/usr/bin/env bash
# The siem/ tree is what the rules sync applies to siem01 (ADR 0034 "Rules from git"): lint it with the
# very program the sync runs before it applies a commit, then prove the lint still refuses each thing
# it must (one broken copy of the tree per check), the sync's offline guards (tests/siem/sync_unit_test.py), and
# that contained-intrusion names exactly the Falco rules Talon answers (tests/siem/talon_slugs_test.py).
# Needs python3 with PyYAML and git, like the other checks.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 ansible/roles/siem_sync/files/siem_lint.py siem
python3 tests/siem/lint_test.py | grep -E "^FAIL |passed, [0-9]+ failed$"
python3 tests/siem/sync_unit_test.py | grep -E "^FAIL |passed, [0-9]+ failed$"
python3 tests/siem/talon_slugs_test.py
