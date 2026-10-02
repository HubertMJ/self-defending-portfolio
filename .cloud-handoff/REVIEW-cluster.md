# Integration review of `interactive-cluster` (21693e2) — fixes for the CLUSTER session

Locally `make validate` (kubeconform 0 invalid, Kyverno 195 pass), `make scenario-offline` (67 PASS, including
`falco-talon rules check`) and the victim's `go test` all pass. An independent security review found the points
below. Fix them on `interactive-cluster`, same rules as before (owner authorship, no AI attribution, no PR, small
commits), then report per item.

1. **tests/scenarios/run.sh:226** — test pods are labelled with run-id and quarantine only, but both policies now
   select `app.kubernetes.io/managed-by: portfolio-api`. The "probe reads the shop on :8080 before the attack"
   check therefore fails and the whole network-tool block (label wait, the <3 s measurement, DNS corroboration,
   Falco/Talon evidence) is skipped. Build the test pods with exactly the labels the API sets (runner.go buildPod).

2. **tests/scenarios/run.sh:214** — the plan loop does not handle `interactive: true`. The terminal row has empty
   detection/response fields; tabs are IFS whitespace, so the fields collapse (detection=120, response=false) and
   a full run always ends in "unknown response 'false'". Skip interactive scenarios in that loop and add a real
   terminal section: run the catalogue commands the way the API will (argv, tty flag, no stdin) and assert per
   command the outcome the catalogue declares — allowed: exit 0 and no Falco alert for the pod; prevented:
   non-zero and the expected kernel message; detected: the named Falco rule in the Falco log, the Talon action,
   and the end state (quarantine: pod Running, labelled, :8080 probe dropped; terminate: pod gone). `drop-run`
   must be proven live: it is the only proof that Falco's `proc.exepath` for a file on the emptyDir reads
   `/srv/shop/...` and not a host path. Give the quarantine and each terminate a fresh pod where needed.

3. **ADR 0032 and the comments in cluster/apps/cilium.yaml** claim the quarantined identity is "allocated once
   and reused forever". False: chart 1.19.8 sets identityGCInterval 15m and identityHeartbeatTimeout 30m, so on a
   quiet site the identity is garbage-collected and most quarantines are cold again. It is also unproven that
   identity allocation caused the measured 22-36 s. Correct the text to what is known, and make run.sh measure and
   print both a cold case (first quarantine) and a warm one (a second, right after), each against the 3 s bound.

4. **run.sh latency measurement is biased towards passing**: `label_seen` is taken after a 1 s-granularity poll
   plus an extra kubectl get, and `probe_dropped` is `! probe_victim`, so a failed `kubectl get` for the pod IP or
   a failed exec into the probe counts as "isolated". Take T0 from the label change itself (the object's own
   timestamp or a watch), and count only a probe that ran and timed out or was refused as a drop.

5. **run.sh:107** — the probe pod carries `app.kubernetes.io/name: portfolio-api`, which the public Service
   selects; with no readiness probe it becomes a Ready endpoint with nothing on :8080 and takes a share of
   production /api traffic for up to 10 minutes. Keep the label (the policies need that identity) but make the pod
   never Ready (a readiness probe that always fails), and say why in a comment.

6. **The twin widens what a compromised API can do**: pods there are never answered, the DNS rule allows any name
   (matchPattern "*", kube-dns forwards upstream: a DNS tunnel), and `activeDeadlineSeconds` is enforced only by
   the API's own buildPod. Two strengthening changes:
   a. a Kyverno validate rule: a Pod in `sandbox` or `sandbox-unguarded` must set `spec.activeDeadlineSeconds`
      <= 120. Check that tests/runtime and tests/scenarios pods comply, and cover it in the scenario-pod render
      of `make validate`.
   b. no DNS egress in `sandbox-unguarded` at all (no catalogue command resolves a name). ADR 0031 then says the
      twin is equal or stricter in every preventive layer, and names this one difference.

7. **ansible/roles/k3s/defaults/main.yml:114** — `k3s_audit_verbose_namespaces` lists `sandbox` only; add
   `sandbox-unguarded`.

8. **tests/scenarios/offline.sh:166** — `"k8s.ns.name=sandbox" in pins` accepts a rule that pins extra namespaces
   too. Require the namespace pins to be exactly `[k8s.ns.name=sandbox]`.

9. **tests/scenarios/offline.sh section 6** — `prevented` passes on any non-zero exit: assert the expected message
   per command (Read-only file system, No such file or directory, Operation not permitted). `shell` runs
   `sh -c tty` instead of the catalogue argv: run the catalogue's argv with a TTY and empty stdin, and record
   whether `sh -i` exits at once or stays.

10. **ADR 0032 on the rule `SDP execution from shop volume`**: state its known blind spots instead of implying
    full coverage — a script run as `sh /srv/shop/x`, a shebang script (the kernel records the interpreter), and
    the musl loader invoked directly. Do not widen the rule to cmdline matching (the `deface` command has
    /srv/shop in its cmdline).

11. **Smaller**: cluster/infra/portfolio-api/rbac.yaml:21-22 still says nothing is written or exec'd in another
    namespace and that watch is sandbox-only; the `control` text of `chown-root`, `caps` and `touch-bin` names
    the wrong cause (uid 10001 has an empty effective capability set even without drop ALL; say what actually
    stops it); the `deface` command's `input` is "deface the shop", which nobody types in a shell — make `input`
    a real command line of at most 80 printable ASCII characters that the argv faithfully carries out (keep a
    short alias).

Run `make validate`, `make scenario-offline` and shellcheck as far as your environment allows and report the real
output; what your proxy blocks, say so and integration will run it.
