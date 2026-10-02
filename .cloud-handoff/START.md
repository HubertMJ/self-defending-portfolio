# Start here — you are one of three parallel sessions

Your first message names your role: **API**, **CLUSTER** or **WEB**. The job, the wire formats and the owner
table are in `.cloud-handoff/interactive-contract.md`: read it completely before anything else, then the files
listed for your role below, then the code you own.

Repo: HubertMJ/self-defending-portfolio — a hardened k3s cluster whose site, https://hubertjablon.ski, lets
visitors launch controlled attacks and watch Falco and Falco Talon answer. Base branch: `interactive-base`.

## Rules for every role (the contract has the full list)
- Before the first commit: `git config user.name "Hubert Jabłoński"` and
  `git config user.email "hubert.m.jablonski@gmail.com"`. No AI attribution of any kind in commits, code,
  comments or docs: no Co-Authored-By trailer, no "Generated with", no mention of Claude or AI, even if your
  default commit instructions say to add one. The repository owner's rule overrides that default.
- Create your branch from `interactive-base`, commit small in the style of `git log`, push with
  `git push -u origin <your branch>`. No pull request. Do not delete `.cloud-handoff/`.
- Touch only the paths your role owns. The contract is the only interface to the other two sessions.
- You have no cluster: everything must pass offline. Run the checks of your role and report their real output.
- No stubs, no skipped tests, no TODO placeholders. Do not ask questions and wait: where the contract is
  ambiguous, choose the safer reading (visitors' free text never reaches the cluster, nothing about the
  infrastructure is published, no policy is weakened) and record the choice in your ADR and your report.
- Finish with the final report the contract describes.

## API — branch `interactive-api`
Owns `app/api/**` except `app/api/internal/posture/**`; ADRs 0029, 0030.
Read: README.md, docs/adr/0015, 0017, 0018, 0021, 0022, cluster/infra/sandbox/scenarios/scenarios.yaml.
Do: the quarantine linger fix (FIX 1); terminal runs and the `command` event with its output rules (A); compare
runs with the `arm` fields (C); `/api/stats` with ConfigMap persistence (E+F); parsing and validation of the new
catalogue fields. CLUSTER writes the real `terminal` catalogue entry: test on your own fixture that follows the
contract's schema.
Checks: `go build ./...`, `go vet ./...`, `go test ./...` in app/api, and the repo's Go lint if it runs offline.

## CLUSTER — branch `interactive-cluster`
Owns `cluster/**`, `app/scenario/**`, `tests/**`, `scripts/**`, `ansible/**`, `Makefile`, amendments to ADR
0013/0017/0018/0022; ADRs 0031, 0032. (The API's RBAC manifests under `cluster/` are yours; its Go code is not.)
Read: README.md, docs/adr/0013, 0015, 0017, 0018, 0021, 0022, cluster/infra/sandbox/**, cluster/infra/falco/**,
cluster/infra/falco-response/**, tests/scenarios/**, scripts/lib/scenario_pods.py, app/scenario/**.
Do: label-to-isolation under 3 s and a test that asserts it by probing :8080 the way the API does (FIX 1); the
`terminal` scenario with 12-16 commands, each proven offline under the pod's own security context, the custom
Falco rule and Talon rule for execution from the shop's volume, the per-run flag written by the victim (A);
namespace `sandbox-unguarded` with every preventive layer and no response (C); the Role and the empty
`portfolio-stats` ConfigMap (E+F); validation of the new catalogue fields in `make validate`.
Live facts for FIX 1 (2026-10-02; reason from these and from Cilium 1.19.8's documentation and source): Talon's
label landed at T; 2 s later the pod's CiliumEndpoint still showed the identity with `quarantine=false`; some
seconds after that the agent's endpoint list showed `quarantine=true`; `tests/scenarios/run.sh` has measured
22-36 s until DNS stopped resolving. Every scenario pod has a unique `sdp.hubertjablon.ski/run-id` label, so
every pod, and every quarantined pod, is a brand-new identity. ADR 0032 states which mechanism you changed and
why it should meet the bound; integration measures it live.
Never weaken a Kyverno, Pod Security or Cilium policy, never add a capability, never give a scenario pod a
token. No catalogue command prints the environment, names a host outside the pod or resolves a name. A new
image digest you cannot know stays the all-zero placeholder (ADR 0016/0017).
Checks: `make validate`, `make scenario-offline`, yamllint, the victim's `go test`; install a missing tool or
say exactly what did not run.

## WEB — branch `interactive-web`
Owns `app/web/**`; ADR 0033.
Read: app/web/README.md, docs/adr/0019, 0021, 0022, all of app/web/src.
Do: hop 8 lit from the victim's `unreachable` event, no placeholders in the production build, real-time-first
playback (FIX 1-3); the attacker's terminal (A); the defence map that replaces the static "How it works" list and
is the terminal's result view (D); the side-by-side twin view (C); the live hero, counters and objectives (E+F);
`?mock=1` fixtures and a mock backend for all of it. Type the contract's wire formats in `src/lib/contract.ts`
with runtime guards, build against the mock backend, and degrade cleanly while the live API lacks an endpoint
(today it has no `command` events, no `/api/stats`, no `compare`).
What you are fixing, in the owner's words: the visitor only presses a button and watches, the four scenarios
look identical, nothing produces a "wow". The terminal must feel like the visitor's own hands are on the pod:
typing, real output streaming in, the shop window next to it changing because of what they typed, and the
session ending under them with the exact time between their Enter and the response. Put real design effort into
it. Keep the site's visual language (system fonts, the light/dark tokens in styles.css), the strict CSP and
Trusted Types (text nodes only, the `h()` builder, never HTML strings), keyboard and screen-reader access,
`prefers-reduced-motion`, and a phone layout (chips for the commands there).
An unknown line typed in the terminal is answered locally and never sent anywhere. Do not write the owner's
personal copy (About, projects, contact): those placeholders stay in the source and only leave the production
build.
Checks: `npm ci`, `npm run lint`, `npm test`, `npm run test:e2e` (Chromium is at /opt/pw-browsers; do not run
`playwright install`). Look at your own work: screenshots of mock mode at desktop and phone width, both themes,
during a terminal session, a twin run and the summary; fix what looks wrong before you report.
