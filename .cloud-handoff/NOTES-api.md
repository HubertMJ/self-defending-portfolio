# Notes for the API session from the review of `interactive-cluster`

The CLUSTER branch is pushed (`origin/interactive-cluster`); read its `cluster/infra/sandbox/scenarios/scenarios.yaml`
(scenario `terminal`), `cluster/infra/portfolio-api/rbac.yaml` and ADRs 0031/0032 before you finish. Points its
review raised that land in your code:

1. **Selectors moved to `app.kubernetes.io/managed-by: portfolio-api`.** Both victim policies now select that
   label, not the run-id. Every pod the runner creates, in `sandbox` and in `sandbox-unguarded`, must carry it
   (buildPod already sets it: keep it, and test for it).
2. **`compare` must be refused for `terminal`** (and for any `interactive: true` scenario) with a 4xx, tested.
   Otherwise a visitor gets the detected commands in a namespace where nothing answers.
3. **Orphan cleanup** lists only `cfg.Namespace` today (runner.go, the start-up sweep). It must also sweep
   `sandbox-unguarded`, or twin pods outlive an API crash.
4. **Stats ConfigMap**: the Role grants `get` and `update` on `portfolio-stats` with resourceNames and nothing
   else. Use Get + Update (with resourceVersion, retry on conflict); Patch, server-side apply, Create, List and
   Watch all return 403. A missing or unreadable ConfigMap must not stop the API from starting or serving.
5. **`activeDeadlineSeconds`**: a Kyverno rule will require it to be set and <= 120 on every pod in both
   namespaces. Keep forcing it in buildPod for both arms and for terminal runs.
6. **`SDP_FLAG`** goes in the env of container `target` only, generated per run with crypto/rand, never logged,
   never in an event except as command output the visitor produced by reading it.
7. **`sh -i` (command `shell`, tty: true)** gets an empty stdin and may exit at once or stay until Talon deletes
   the pod. TTY commands must still be bounded: if neither an exit nor a pod deletion arrives, end the command at
   the run's own deadline and never block the next command slot forever.
8. A terminal run's pod can be **quarantined and keep running**: commands after a quarantine must still work
   (exec goes through the API server, not the pod network), and the victim poller must keep reporting
   `unreachable` rather than ending the run.
