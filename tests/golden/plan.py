#!/usr/bin/env python3
"""Turn a role's tasks/main.yml into a Jinja program that Ansible renders into the role's plan.

Used by tests/golden/render.sh. For every task that writes or removes a file (template, copy,
file, ansible.posix.sysctl) the program evaluates the task's own `loop` and `when` with the host's
real variables and prints one line per item that would run:

    template | dest | src
    copy     | dest | base64(content)
    file     | state | path
    sysctl   | sysctl_file | name=value

So the comparison covers the task gates themselves (a dropped `when`, a changed loop), not only
the templates. Tasks whose loop or condition depends on facts registered at run time (stat
results, set_fact) cannot be evaluated without a host and are left out; they are listed as
Jinja comments at the top of the generated program.

Usage: plan.py <role dir>   -> writes <role dir>/templates/golden-plan.j2
"""
import base64
import json
import os
import re
import sys

import yaml

MODULES = {
    "ansible.builtin.template": "template",
    "ansible.builtin.copy": "copy",
    "ansible.builtin.file": "file",
    "ansible.posix.sysctl": "sysctl",
}


def tasks_of(items, outer_when=()):
    """Flatten blocks; a block's when applies to its tasks (rescue/always do not write here)."""
    for task in items or []:
        when = list(outer_when) + as_list(task.get("when"))
        if "block" in task:
            yield from tasks_of(task["block"], when)
        else:
            yield task, when


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def expr(value):
    """A loop value as a Jinja expression: "{{ x }}" -> x, a YAML list -> its JSON."""
    if isinstance(value, str):
        m = re.fullmatch(r"\s*\{\{(.*)\}\}\s*", value, re.S)
        return m.group(1).strip() if m else json.dumps(value)
    return json.dumps(value)


def cond(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return "(" + str(value).strip() + ")"


def main(role_dir):
    tasks = yaml.safe_load(open(os.path.join(role_dir, "tasks", "main.yml"))) or []
    runtime = set()
    for task, _ in tasks_of(tasks):
        if "register" in task:
            runtime.add(task["register"])
        if "ansible.builtin.set_fact" in task:
            runtime.update(task["ansible.builtin.set_fact"].keys())
    out, skipped = [], []
    for task, when in tasks_of(tasks):
        module = next((MODULES[k] for k in task if k in MODULES), None)
        if module is None:
            continue
        args = task[next(k for k in task if k in MODULES)]
        text = " ".join([str(task.get("loop", ""))] + [str(w) for w in when])
        if any(re.search(r"\b%s\b" % re.escape(name), text) for name in runtime):
            skipped.append(task.get("name", "?"))
            continue
        loop_var = (task.get("loop_control") or {}).get("loop_var", "item")
        if module == "template":
            line = "template|%s|%s" % (args["dest"], args["src"])
        elif module == "copy":
            content = base64.b64encode(args.get("content", "").encode()).decode()
            line = "copy|%s|%s" % (args["dest"], content if "content" in args else "src:" + str(args.get("src")))
        elif module == "file":
            line = "file|%s|%s" % (args.get("state", "file"), args["path"])
        else:
            line = "sysctl|%s|%s=%s" % (args.get("sysctl_file", "/etc/sysctl.conf"), args["name"], args["value"])
        loop = expr(task["loop"]) if "loop" in task else "[none]"
        test = " and ".join(cond(w) for w in when) or "true"
        # No whitespace control: Ansible renders with trim_blocks, which eats the newline after
        # each block tag, so only the newline that ends a plan line survives.
        out.append("{%% for %s in %s %%}{%% if %s %%}%s\n{%% endif %%}{%% endfor %%}" % (loop_var, loop, test, line))
    header = "".join("{# not evaluated (needs run-time facts): %s #}\n" % name for name in skipped)
    os.makedirs(os.path.join(role_dir, "templates"), exist_ok=True)
    with open(os.path.join(role_dir, "templates", "golden-plan.j2"), "w") as f:
        f.write(header + "\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
