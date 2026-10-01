# ADR 0022: The scenario pod is a victim shop the visitor watches being attacked

Date: 2026-10-01 · Status: accepted

## Context
The live attack demo (ADR 0015, ADR 0017, ADR 0018) shows a timeline of real events: pod created, exec,
Falco alert, Talon action. Visitors read it as a well-made mockup, because nothing they can *see* is
attacked: the scenario pod runs `sleep` and the exec's effect is invisible. The owner asked for a
victim that visibly changes when attacked and then visibly dies (terminate) or goes dark (quarantine),
with no change to what Falco detects or what Talon does, and without weakening any policy.

Constraints: the scenario pod stays PSS `restricted` (non-root, read-only root filesystem, no
capabilities), passes the four Kyverno policies, lives at most 120 s, fits the sandbox LimitRange
(100m CPU, 32 MiB), and the sandbox network stays default-deny. The portfolio API is the only reader;
nothing about the victim may be reachable from the internet.

Options for the server:
- **busybox `httpd`** - not in Alpine's busybox; it ships in `busybox-extras` together with telnet,
  ftpd and friends, which is more attack-adjacent surface than a demo target should carry. It also
  serves files verbatim, so the API would relay whatever an exec wrote, unbounded.
- **A static Go binary, standard library only, built in a pinned builder stage** - about 200 lines,
  tested in the build (as app/api), bounded output.
- **The API reads state over `pods/exec`** (e.g. `cat state.json`) - no network change at all, but
  every 500 ms poll is an exec Falco records, and an exec cannot show the one thing the network path
  shows for free: that a quarantined pod stops answering.

## Decision
**The scenario image serves an "SDP Shop" on :8080** (`app/scenario/victim`, Go, standard library,
`CGO_ENABLED=0`, root-owned 0755 at `/usr/local/bin/victim`, built and `go test`ed in the
`golang:1.26.8` stage pinned like app/api's). On start it writes a healthy `index.html` and
`state.json` into its docroot, an emptyDir (`sizeLimit: 1Mi`) at `/srv/shop`, and serves:

| path | body |
|---|---|
| `/` | the docroot's `index.html`, `text/html`, CSP `default-src 'none'; style-src 'unsafe-inline'` (the page is attacker-writable by design; nothing in it may run) |
| `/state.json` | `{"status","title","banner","checksum"}`, compact JSON, `Cache-Control: no-store` |

`status` is `up`, `defaced` or `compromised`; any other value in the file reads `compromised` (a state
this program did not write is a tampered one). `title` <= 80 and `banner` <= 120 runes, one line of
printable text. `checksum` is the first 16 hex digits of SHA-256 over `index.html`, so a defacement is
visible even if the attacker leaves `state.json` alone. A state file that does not parse serves the
last good one. Only GET/HEAD; every other path is 404. The server exits after 120 s on its own (the
`sleep 120` it replaces); in the cluster `activeDeadlineSeconds` ends it first.

**The server never changes its own state; the execs do.** Each scenario's exec (cluster/infra/sandbox/
scenarios/scenarios.yaml) rewrites the docroot with busybox `echo` and `mv` (temp file + rename, so a
poll never sees half a file), sleeps one second so the API's 500 ms poll sees the change while the pod
is still up, then `exec`s the same detected program as before (ADR 0018, amendment):

| id | victim after the exec | then |
|---|---|---|
| `shell-in-container` | `defaced`, page rewritten, title "H4CK3D - SDP Shop" | killed: `gone` |
| `network-tool` | `compromised`, "Beaconing to a command-and-control server" | quarantined: `unreachable` |
| `sensitive-file-read` | `compromised`, "Customer data exfiltrated" | killed: `gone` |
| `drop-and-execute` | `compromised`, "Compromised: unknown binary running" | killed: `gone` |

(`unreachable` and `gone` are the API's conclusions when it cannot ask; the pod never reports them.)

**Ready means the shop is up.** The container has an exec readiness probe, `victim -check`, which
GETs its own `/state.json` over loopback. Not `httpGet`: kubelet probes arrive from the host, and the
sandbox policy does not admit the host to :8080. The API (and tests/scenarios/run.sh) exec only once
the pod is Ready, so the exec never races the server writing the healthy page.

**One flow, both ends, and the quarantine still wins.** `sandbox-victim-from-api`
(cluster/infra/sandbox/ciliumnetworkpolicy-victim.yaml) admits TCP 8080 to pods carrying the API's
`sdp.hubertjablon.ski/run-id` label from pods with namespace `portfolio-api` and
`app.kubernetes.io/name: portfolio-api` only; the portfolio-api CNP gets the matching egress rule. No
Service, no HTTPRoute: the API dials the pod IP from the Pod object it already watches and never
publishes it. The quarantine CCNP's `ingressDeny` from all entities beats this allow (in Cilium a
deny wins over every allow), so the API's poll of a quarantined pod fails, and the visitor's
"network cut by Cilium" is the policy working, not an animation.

`make validate` renders the new pod specs into the Kyverno gate (pod-security-restricted,
require-pod-resources, restrict-image-registries, verify-portfolio-images all pass);
`tests/scenarios/offline.sh` checks, under each pod's own security context, that the probe reads `up`
and that the exec changes the state, and still checks every rule precondition against the program
the shell `exec`s.

## Consequences
- The API gains one direct flow into `sandbox`, read-only and port-scoped. Its client must treat the
  body as untrusted input (300 ms timeout, 4 KiB cap, JSON only, no redirects, strings re-capped): the
  file behind it is writable by whatever runs in the pod, which is the point of the demo.
- The scenario image now contains a Go binary, which Trivy scans like any other (gobinary); a Go
  stdlib CVE can fail the image's gate and needs a builder bump, as for app/api.
- Each scenario pod runs a server instead of `sleep`: about 3 MiB of RSS against its 32 MiB limit,
  plus one probe process per second.
- A unique run-id label per pod means a new Cilium identity per run, which the quarantine label
  already implied; one run at a time keeps that negligible.
- The shell-in-container defacement follows the detection by milliseconds rather than preceding it:
  the shell starting *is* what Falco detects. Talon's kill takes a second or more, so the poll still
  shows the defaced shop first.
- The pinned scenario digest in scenarios.yaml must be bumped to a `build-images.yml` build of this
  image (`scripts/bump-image-digest.sh scenario sha256:...`) before the cluster runs the victim; until
  then the pods would run the old image, which has no `/usr/local/bin/victim` and would fail to start.
