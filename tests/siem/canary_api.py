#!/usr/bin/env python3
"""Runs the `api` canaries of siem/canaries.yaml through the public API (siem contract P3, MJ6), the way
a visitor does: POST /api/attack/terminal, then POST /api/runs/{id}/commands per command with the run's
token, DELETE to leave; one-click scenarios with POST /api/attack/{id}. Helper of tests/siem/canaries.sh.

Sessions: every rule canary's terminal commands whose catalogue outcome is not `detected` run in ONE
session (a detected command ends the run - Talon terminates or quarantines the pod); each canary that
contains a detected command, and each monitor canary (its bucket is the pod, so no other command may
share it), gets its own session, its commands in the canary's order. Refuses to start
while /api/runs shows a run in progress, and stays far inside the attack limits (60 per IP; a pass is
about ten runs). Prints one JSON line: {"start_ms": ..., "runs": [{"run_id", "kind", "what", "state"}]}.

Usage: canary_api.py <base url, e.g. https://hubertjablon.ski> <siem dir> <scenarios.yaml>
"""
import json
import sys
import time
import urllib.error
import urllib.request

import yaml

FINAL = {"finished", "failed", "timeout"}


def call(base, method, path, body=None, token=None):
    headers = {"Content-Type": "application/json", "Origin": base}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode(errors="replace")[:200]}


def run_state(base, run_id):
    code, run = call(base, "GET", f"/api/runs/{run_id}")
    states, commands = [], {}
    for ev in run.get("events", []) if code == 200 else []:
        if ev.get("type") == "run":
            states.append(ev["data"].get("state"))
        elif ev.get("type") == "command":
            commands[ev["data"].get("seq")] = ev["data"].get("state")
    return states, commands


def wait(pred, timeout, step=1.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def terminal(base, commands):
    code, out = call(base, "POST", "/api/attack/terminal")
    if code != 202:
        raise SystemExit(f"POST /api/attack/terminal -> {code} {out}")
    rid, token = out["run_id"], out["token"]
    if not wait(lambda: "pod_ready" in run_state(base, rid)[0] or set(run_state(base, rid)[0]) & FINAL, 120):
        raise SystemExit(f"run {rid}: pod not ready in 120 s")
    for cmd in commands:
        code, out = call(base, "POST", f"/api/runs/{rid}/commands", {"id": cmd}, token)
        if code != 202:
            print(f"run {rid}: command {cmd} -> {code} {out}", file=sys.stderr)
            break
        seq = out["seq"]
        wait(lambda: run_state(base, rid)[1].get(seq) in ("exited", "killed") or set(run_state(base, rid)[0]) & FINAL, 30)
        if set(run_state(base, rid)[0]) & FINAL:
            break
    time.sleep(3)  # let Falco and Talon answer the last command before leaving
    call(base, "DELETE", f"/api/runs/{rid}", token=token)
    wait(lambda: set(run_state(base, rid)[0]) & FINAL, 60)
    states = run_state(base, rid)[0]
    return {"run_id": rid, "kind": "terminal", "what": commands, "state": states[-1] if states else "?"}


def scenario(base, sid):
    code, out = call(base, "POST", f"/api/attack/{sid}")
    if code != 202:
        raise SystemExit(f"POST /api/attack/{sid} -> {code} {out}")
    rid = out["run_id"]
    wait(lambda: set(run_state(base, rid)[0]) & FINAL, 150, 2.0)
    states = run_state(base, rid)[0]
    return {"run_id": rid, "kind": "scenario", "what": sid, "state": states[-1] if states else "?"}


def main():
    base, siem, catalogue = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
    with open(f"{siem}/canaries.yaml", encoding="utf-8") as fh:
        canaries = yaml.safe_load(fh)
    with open(catalogue, encoding="utf-8") as fh:
        cat = yaml.safe_load(fh)
    outcome = {c["id"]: c.get("outcome") for s in cat if s.get("id") == "terminal" for c in s.get("commands", [])}
    api = [(sec, c) for sec, objs in canaries.items() for c in (objs or {}).values() if c.get("kind") == "api"]
    sessions, scenarios = [], []
    quiet = []
    for sec, c in api:
        if c.get("scenario"):
            if c["scenario"] not in scenarios:
                scenarios.append(c["scenario"])
            continue
        unknown = [x for x in c["terminal"] if x not in outcome]
        if unknown:
            raise SystemExit(f"canary commands not in the catalogue: {unknown}")
        if sec == "monitors" or any(outcome[x] == "detected" for x in c["terminal"]):
            if c["terminal"] not in sessions:
                sessions.append(c["terminal"])
        else:
            quiet += [x for x in c["terminal"] if x not in quiet]
    code, runs = call(base, "GET", "/api/runs")
    active = [r for r in runs.get("runs", []) if r.get("state") not in FINAL]
    if code != 200 or active:
        raise SystemExit(f"refusing to start: /api/runs -> {code}, runs in progress: {active}")
    start_ms = int(time.time() * 1000)
    done = [terminal(base, quiet)] + [terminal(base, s) for s in sessions] + [scenario(base, s) for s in scenarios]
    print(json.dumps({"start_ms": start_ms, "runs": done}))


if __name__ == "__main__":
    main()
