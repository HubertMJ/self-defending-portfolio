#!/usr/bin/env python3
"""Lint of the siem/ tree (ADR 0034 "Rules from git", siem contract P3).

One program for CI (scripts/check-siem.sh, make validate) and for the rules sync on siem01, which
runs it on every fetched commit before anything is applied. It reads the tree as data only (a
safe YAML loader without explicit tags and, outside siem/fields, without aliases; json) and never
executes or imports anything from it. What the tree may name is pinned here, not in the tree: the
known sources and the streams monitors may read (siem contract P3 review, M1).

Usage: siem_lint.py <siem dir>            lint; exit 0 clean, 1 findings, 2 usage
       siem_lint.py --index <siem dir>    lint, then print the rule/monitor/correlation index as JSON

Security Analytics matches differently from the Sigma specification (S0-b, S0-k): values are
case-sensitive, a value containing a space never matches, and `|re` is a Lucene regular expression
matched against the whole value (no ^ or $, backslashes unusable). The checks below refuse what
can never fire; siem/README.md documents the rest.

Each check is one function registered with @check; tests/siem/p3-mutations.sh disables them one by
one and expects tests/siem/lint_test.py to notice.
"""
import json
import os
import re
import sys

import yaml

MONITOR_PREFIX = "sdp-git: "
# The seven sources of ADR 0034. A fields file or log type for anything else is refused, so a commit
# cannot point a detector or a correlation at an index of its own choosing.
KNOWN_SOURCES = {"falco", "talon", "hubble", "k8s-audit", "api", "host", "siem01"}
# Monitors' alerts are readable by the portfolio API, so a monitor may read only what the API may read
# (sdp_api_read): the six k3s01 streams, never sdp-siem01, never a pattern.
MONITOR_STREAMS = {"sdp-falco", "sdp-talon", "sdp-hubble", "sdp-k8s-audit", "sdp-api", "sdp-host"}
# Mapped in every template besides the allow-list (opensearch_config, F1).
COMMON_FIELDS = {"@timestamp", "event.kind", "event.dataset", "event.ingested", "event.overwrite"}
# Published on the page (ADR 0036, gen-siem-index.sh): titles, file names, canaries. ADR 0021 never
# publishes node names, addresses or cluster DNS names.
UNPUBLISHABLE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b|k3s01|siem01|\.svc\b|cluster\.local")
# fields/ is the ingest area's and uses anchors for repeated paths; elsewhere an alias is refused.
MAX_FIELDS_ALIASES = 8
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
LOG_TYPE_RE = re.compile(r"^sdp_[a-z0-9_]+$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DATE_RE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
}
RULE_REQUIRED = {"title", "id", "status", "level", "description", "author", "date", "logsource", "detection"}
RULE_OPTIONAL = {"tags", "falsepositives", "references", "modified", "fields"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
CONDITION_WORDS = {"and", "or", "not", "of", "them", "1", "all"}
MONITOR_TYPES = {"query_level_monitor", "bucket_level_monitor"}
# Keys of a monitor body in git. ui_metadata is Dashboards' (Alerting never returns it); ids, owner,
# timestamps and data sources are Alerting's.
MONITOR_KEYS = {"type", "monitor_type", "name", "enabled", "schedule", "inputs", "triggers"}
CANARY_KINDS = {
    "api": ({"kind"}, {"terminal", "scenario"}),
    "exec": ({"kind", "run", "step"}, set()),
    "synthetic": ({"kind", "docs"}, set()),
}
# The P3-owned parts of the tree and the file suffix each holds.
DIRS = {"log-types": ".yaml", "rules": ".yml", "detectors": ".yaml", "correlations": ".yaml", "monitors": ".json"}

CHECKS = []


class StrictLoader(yaml.SafeLoader):
    """SafeLoader without explicit tags and with a cap on aliases (0 outside siem/fields): no
    !!binary/!!set surprises and no alias fan-out ("billion laughs") from a commit."""

    max_aliases = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent):
            self.aliases_seen = getattr(self, "aliases_seen", 0) + 1
            if self.aliases_seen > self.max_aliases:
                raise yaml.composer.ComposerError(None, None, "YAML aliases are not allowed here", event.start_mark)
        elif getattr(event, "tag", None) not in (None, "!"):
            raise yaml.composer.ComposerError(None, None, f"explicit YAML tag {event.tag} is not allowed", event.start_mark)
        return super().compose_node(parent, index)


class FieldsLoader(StrictLoader):
    max_aliases = MAX_FIELDS_ALIASES


def strict_yaml(text):
    return yaml.load(text, Loader=StrictLoader)  # noqa: S506 - StrictLoader is a SafeLoader


def fields_yaml(text):
    return yaml.load(text, Loader=FieldsLoader)  # noqa: S506 - FieldsLoader is a SafeLoader


def check(fn):
    CHECKS.append(fn)
    return fn


class Tree:
    """The siem/ tree, parsed. Unparsable files are recorded in parse_errors and left out."""

    def __init__(self, root):
        self.root = root
        self.parse_errors = []
        self.stray = []
        self.unknown_fields = []
        self.fields = {}  # source -> allow-list file (dict)
        self.log_types = {}  # rel path -> dict
        self.rules = {}  # rel path -> dict
        self.rule_text = {}  # rel path -> raw text (what the sync uploads)
        self.detectors = {}
        self.correlations = {}
        self.monitors = {}
        self.canaries = None
        fields_dir = os.path.join(root, "fields")
        if os.path.isdir(fields_dir):
            for name in sorted(os.listdir(fields_dir)):
                if name.endswith(".yaml"):
                    src = name[: -len(".yaml")]
                    if src not in KNOWN_SOURCES or not SOURCE_RE.match(src):
                        self.unknown_fields.append(f"fields/{name}")
                        continue
                    data = self._load(os.path.join("fields", name), fields_yaml)
                    if isinstance(data, dict):
                        self.fields[src] = data
        for d, suffix in DIRS.items():
            path = os.path.join(root, d)
            if not os.path.isdir(path):
                continue
            for name in sorted(os.listdir(path)):
                rel = f"{d}/{name}"
                if not name.endswith(suffix) or not os.path.isfile(os.path.join(path, name)):
                    self.stray.append(rel)
                    continue
                loader = json.loads if suffix == ".json" else strict_yaml
                data = self._load(rel, loader)
                if data is None:
                    continue
                if d == "rules":
                    with open(os.path.join(root, rel), encoding="utf-8") as fh:
                        self.rule_text[rel] = fh.read()
                {"log-types": self.log_types, "rules": self.rules, "detectors": self.detectors,
                 "correlations": self.correlations, "monitors": self.monitors}[d][rel] = data
        if os.path.isfile(os.path.join(root, "canaries.yaml")):
            self.canaries = self._load("canaries.yaml", strict_yaml)

    def _load(self, rel, loader):
        try:
            with open(os.path.join(self.root, rel), encoding="utf-8") as fh:
                data = loader(fh.read())
        except (OSError, ValueError, yaml.YAMLError) as exc:
            self.parse_errors.append((rel, f"does not parse: {(str(exc).splitlines() or [type(exc).__name__])[0]}"))
            return None
        except RecursionError:
            self.parse_errors.append((rel, "does not parse: nested too deeply"))
            return None
        if not isinstance(data, dict):
            self.parse_errors.append((rel, "is not a mapping"))
            return None
        return data

    # Helpers shared by the checks and the sync.
    def sources(self):
        """Sources with both an allow-list and a log type."""
        lt = {d.get("source") for d in self.log_types.values()}
        return {s for s in self.fields if s in lt}

    def log_type_of(self, source):
        for d in self.log_types.values():
            if d.get("source") == source:
                return d.get("name")
        return None

    def allowed_fields(self, source):
        return set((self.fields.get(source) or {}).get("fields") or {})

    def rule_ids(self):
        return {d.get("id"): rel for rel, d in self.rules.items()}

    def monitor_names(self):
        return {d.get("name"): rel for rel, d in self.monitors.items()}

    def correlation_names(self):
        return {d.get("name"): rel for rel, d in self.correlations.items()}


def _selections(detection):
    """(name, list of {field: value}) per selection; keyword lists come back as None."""
    out = []
    for name, sel in detection.items():
        if name == "condition":
            continue
        if isinstance(sel, dict):
            out.append((name, [sel]))
        elif isinstance(sel, list) and sel and all(isinstance(m, dict) for m in sel):
            out.append((name, sel))
        else:
            out.append((name, None))
    return out


def _values(value):
    return value if isinstance(value, list) else [value]


@check
def check_parse(t):
    errs = list(t.parse_errors)
    errs += [(rel, f"not a known source ({', '.join(sorted(KNOWN_SOURCES))})") for rel in t.unknown_fields]
    errs += [(rel, f"unexpected file (this directory holds *{DIRS[rel.split('/')[0]]} only)") for rel in t.stray]
    if t.canaries is None:
        errs.append(("canaries.yaml", "missing"))
    return errs


@check
def check_log_types(t):
    errs, seen = [], {}
    for rel, d in t.log_types.items():
        if set(d) != {"name", "source", "description"}:
            errs.append((rel, "keys must be exactly name, source, description"))
        name, source = d.get("name"), d.get("source")
        if not isinstance(name, str) or not LOG_TYPE_RE.match(name):
            errs.append((rel, f"name {name!r} must match {LOG_TYPE_RE.pattern} (no hyphen, S0-#2)"))
        if source not in KNOWN_SOURCES:
            errs.append((rel, f"source {source!r} is not one of {', '.join(sorted(KNOWN_SOURCES))}"))
        if rel != f"log-types/{source}.yaml":
            errs.append((rel, f"file name must be the source ({source}.yaml)"))
        if source not in t.fields:
            errs.append((rel, f"source {source!r} has no allow-list in siem/fields"))
        elif t.fields[source].get("log_type") != name:
            errs.append((rel, f"name {name!r} differs from siem/fields/{source}.yaml log_type"))
        if not isinstance(d.get("description"), str) or not d.get("description"):
            errs.append((rel, "description must be a non-empty string"))
        if name in seen:
            errs.append((rel, f"log type {name} also defined in {seen[name]}"))
        seen[name] = rel
    return errs


@check
def check_rule_form(t):
    errs = []
    for rel, d in t.rules.items():
        slug = rel[len("rules/"): -len(".yml")]
        if not SLUG_RE.match(slug):
            errs.append((rel, f"file name must match {SLUG_RE.pattern}"))
        missing = RULE_REQUIRED - set(d)
        extra = set(d) - RULE_REQUIRED - RULE_OPTIONAL
        if missing:
            errs.append((rel, f"missing Sigma fields: {', '.join(sorted(missing))}"))
        if extra:
            errs.append((rel, f"unknown Sigma fields: {', '.join(sorted(extra))}"))
        for key in ("title", "description", "author"):
            if key in d and (not isinstance(d[key], str) or not d[key].strip()):
                errs.append((rel, f"{key} must be a non-empty string"))
        if "status" in d and d["status"] not in STATUSES:
            errs.append((rel, f"status {d['status']!r} not one of {', '.join(sorted(STATUSES))}"))
        if "level" in d and d["level"] not in LEVELS:
            errs.append((rel, f"level {d['level']!r} not one of {', '.join(sorted(LEVELS))}"))
        if "date" in d and not (isinstance(d["date"], str) and DATE_RE.match(d["date"])):
            errs.append((rel, "date must be YYYY/MM/DD (a quoted string)"))
        ls = d.get("logsource")
        if "logsource" in d and not (isinstance(ls, dict) and set(ls) == {"product", "service"} and ls.get("product") == "sdp"):
            errs.append((rel, "logsource must be exactly {product: sdp, service: <source>}"))
        det = d.get("detection")
        if "detection" in d and not (isinstance(det, dict) and isinstance(det.get("condition"), str) and len(det) >= 2):
            errs.append((rel, "detection must be a mapping with at least one selection and a condition string"))
        for key in ("tags", "falsepositives", "references"):
            if key in d and not (isinstance(d[key], list) and all(isinstance(x, str) for x in d[key])):
                errs.append((rel, f"{key} must be a list of strings"))
    return errs


@check
def check_rule_ids(t):
    errs, seen, titles = [], {}, {}
    for rel, d in t.rules.items():
        title = d.get("title")
        if title in titles:
            # SA hands back the rule title with a finding; the API maps it to the Sigma id (ADR 0036).
            errs.append((rel, f"title {title!r} is also the title of {titles[title]}"))
        titles[title] = rel
        rid = d.get("id")
        if not isinstance(rid, str) or not UUID_RE.match(rid):
            errs.append((rel, f"id {rid!r} is not a lower-case UUID"))
            continue
        if rid in seen:
            errs.append((rel, f"id {rid} is also the id of {seen[rid]} (SA accepts duplicates, S0-#12)"))
        seen[rid] = rel
    return errs


@check
def check_rule_tags(t):
    errs = []
    for rel, d in t.rules.items():
        tags = d.get("tags") or []
        if not isinstance(tags, list):
            continue
        for tag in tags:
            if not isinstance(tag, str) or not (TECHNIQUE_RE.match(tag) or tag.removeprefix("attack.") in TACTICS
                                                and tag.startswith("attack.")):
                errs.append((rel, f"tag {tag!r} is neither attack.tNNNN[.NNN] nor attack.<tactic>"))
        if d.get("level") != "informational" and not any(isinstance(x, str) and TECHNIQUE_RE.match(x) for x in tags):
            errs.append((rel, "a rule above informational names at least one ATT&CK technique (attack.tNNNN)"))
    return errs


@check
def check_rule_source(t):
    errs = []
    for rel, d in t.rules.items():
        src = (d.get("logsource") or {}).get("service") if isinstance(d.get("logsource"), dict) else None
        if src not in t.sources():
            errs.append((rel, f"logsource.service {src!r} is not a source with an allow-list and a log type"))
    return errs


@check
def check_rule_fields(t):
    errs = []
    for rel, d in t.rules.items():
        det, ls = d.get("detection"), d.get("logsource")
        if not isinstance(det, dict) or not isinstance(ls, dict):
            continue
        allowed = t.allowed_fields(ls.get("service"))
        for name, maps in _selections(det):
            for m in maps or []:
                for key in m:
                    field, *mods = str(key).split("|")
                    if field not in allowed:
                        errs.append((rel, f"selection {name}: field {field!r} is not in siem/fields/{ls.get('service')}.yaml"))
                    for mod in mods:
                        if mod not in MODIFIERS:
                            errs.append((rel, f"selection {name}: modifier {mod!r} not one of {', '.join(sorted(MODIFIERS))}"))
    return errs


@check
def check_rule_condition(t):
    errs = []
    for rel, d in t.rules.items():
        det = d.get("detection")
        if not isinstance(det, dict) or not isinstance(det.get("condition"), str):
            continue
        cond = det["condition"]
        if "|" in cond or re.search(r"\b(count|near|timeframe)\b", cond) or "timeframe" in det:
            errs.append((rel, "aggregation (| count(), near, timeframe) is not allowed: counting is a monitor's job"))
            continue
        names = [n for n, _ in _selections(det)]
        for name, maps in _selections(det):
            if maps is None:
                errs.append((rel, f"selection {name}: must be a field map or a list of field maps (no keyword search)"))
        for token in re.findall(r"[A-Za-z0-9_*]+|\S", cond):
            if token in CONDITION_WORDS or token in "()":
                continue
            pattern = "^" + re.escape(token).replace(r"\*", ".*") + "$"
            if not any(re.match(pattern, n) for n in names):
                errs.append((rel, f"condition names {token!r}, which is no selection"))
    return errs


@check
def check_rule_values(t):
    errs = []
    for rel, d in t.rules.items():
        det = d.get("detection")
        if not isinstance(det, dict):
            continue
        for name, maps in _selections(det):
            for m in maps or []:
                for key, value in m.items():
                    for v in _values(value):
                        if v is None or isinstance(v, (dict, list, float)):
                            errs.append((rel, f"selection {name}: {key}: value {v!r} must be a string, integer or boolean"))
                        elif isinstance(v, str) and (" " in v or "\t" in v):
                            errs.append((rel, f"selection {name}: {key}: value {v!r} contains a space and can never match"
                                              " (S0-b; match the slug field)"))
    return errs


@check
def check_rule_regex(t):
    errs = []
    for rel, d in t.rules.items():
        det = d.get("detection")
        if not isinstance(det, dict):
            continue
        for name, maps in _selections(det):
            for m in maps or []:
                for key, value in m.items():
                    if "re" not in str(key).split("|")[1:]:
                        continue
                    for v in _values(value):
                        if isinstance(v, str) and re.search(r"[\^$\\]", v):
                            errs.append((rel, f"selection {name}: {key}: ^, $ and \\ never work in SA's |re: it is a"
                                              " Lucene regex over the whole value (S0-k; use [.] for a dot)"))
    return errs


@check
def check_detectors(t):
    errs, names = [], {}
    ids = t.rule_ids()
    for rel, d in t.detectors.items():
        if set(d) != {"name", "source", "interval_minutes", "rules"}:
            errs.append((rel, "keys must be exactly name, source, interval_minutes, rules"))
        name, src = d.get("name"), d.get("source")
        if not isinstance(name, str) or not name or name.startswith(MONITOR_PREFIX):
            errs.append((rel, f"name {name!r} must be a non-empty string without the {MONITOR_PREFIX!r} prefix"
                              " (SA names the detector's workflow after it, and the sync manages that prefix)"))
        elif name in names:
            errs.append((rel, f"detector name {name} also used by {names[name]}"))
        names[name] = rel
        if rel != f"detectors/{src}.yaml":
            errs.append((rel, f"file name must be the source ({src}.yaml)"))
        if src not in t.sources():
            errs.append((rel, f"source {src!r} has no allow-list and log type"))
        if d.get("interval_minutes") != 1:
            errs.append((rel, "interval_minutes must be 1 (ADR 0034)"))
        rules = d.get("rules")
        if not isinstance(rules, list) or not rules:
            errs.append((rel, "rules must be a non-empty list of Sigma ids"))
            continue
        for rid in rules:
            if rid not in ids:
                errs.append((rel, f"rule {rid!r} is not the id of any rule in siem/rules"))
                continue
            rsrc = (t.rules[ids[rid]].get("logsource") or {}).get("service")
            if rsrc != src:
                errs.append((rel, f"rule {rid} ({ids[rid]}) is of source {rsrc!r}, not {src!r}"))
    return errs


@check
def check_rule_in_one_detector(t):
    errs, count = [], {}
    for d in t.detectors.values():
        for rid in d.get("rules") or []:
            count[rid] = count.get(rid, 0) + 1
    for rel, d in t.rules.items():
        n = count.get(d.get("id"), 0)
        if n != 1:
            errs.append((rel, f"rule is in {n} detectors, must be in exactly one"))
    return errs


@check
def check_correlations(t):
    errs, names = [], {}
    for rel, d in t.correlations.items():
        if set(d) != {"name", "time_window_ms", "field", "correlate"}:
            errs.append((rel, "keys must be exactly name, time_window_ms, field, correlate"))
        name = d.get("name")
        if not isinstance(name, str) or not SLUG_RE.match(name) or rel != f"correlations/{name}.yaml":
            errs.append((rel, "name must match the file name and " + SLUG_RE.pattern))
        elif name in names:
            errs.append((rel, f"correlation name {name} also used by {names[name]}"))
        names[name] = rel
        tw = d.get("time_window_ms")
        if not isinstance(tw, int) or isinstance(tw, bool) or not 60000 <= tw <= 3600000:
            errs.append((rel, "time_window_ms must be an integer between 60000 and 3600000"))
        entries = d.get("correlate")
        if not isinstance(entries, list) or len(entries) < 2:
            errs.append((rel, "correlate must list at least two sources"))
            continue
        field = d.get("field")
        for e in entries:
            if not isinstance(e, dict) or set(e) != {"source", "query"} or not isinstance(e.get("query"), str):
                errs.append((rel, "each correlate entry is exactly {source, query (string)}"))
                continue
            src = e["source"]
            if src not in t.sources():
                errs.append((rel, f"source {src!r} has no allow-list and log type"))
                continue
            allowed = t.allowed_fields(src)
            if field not in allowed:
                errs.append((rel, f"join field {field!r} is not in siem/fields/{src}.yaml"))
            for f in re.findall(r"([A-Za-z_@][A-Za-z0-9_.@]*):", e["query"]):
                if f not in allowed and f != "_exists_":
                    errs.append((rel, f"query field {f!r} is not in siem/fields/{src}.yaml"))
            for f in re.findall(r"_exists_:([A-Za-z@][A-Za-z0-9_.@]*)", e["query"]):
                if f not in allowed:
                    errs.append((rel, f"query field {f!r} is not in siem/fields/{src}.yaml"))
    return errs


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


@check
def check_monitors(t):
    errs, names = [], {}
    for rel, d in t.monitors.items():
        extra = set(d) - MONITOR_KEYS
        if extra:
            errs.append((rel, f"keys not allowed in git: {', '.join(sorted(extra))} (Alerting's or the sync's)"))
        name = d.get("name")
        if not isinstance(name, str) or not name.startswith(MONITOR_PREFIX) or len(name) <= len(MONITOR_PREFIX):
            errs.append((rel, f"name {name!r} must start with {MONITOR_PREFIX!r}"))
        elif name in names:
            errs.append((rel, f"monitor name {name!r} also used by {names[name]}"))
        elif name != MONITOR_PREFIX + rel[len("monitors/"): -len(".json")]:
            # The API recognises a monitor's kind by this slug (ADR 0036).
            errs.append((rel, f"name {name!r} must be {MONITOR_PREFIX!r} + the file name without .json"))
        names[name] = rel
        if d.get("type") != "monitor" or d.get("monitor_type") not in MONITOR_TYPES:
            errs.append((rel, f"type must be monitor and monitor_type one of {', '.join(sorted(MONITOR_TYPES))}"))
        if d.get("enabled") is not True or not isinstance(d.get("schedule"), dict):
            # A monitor switched off in git is a detection removed without the delete cap noticing.
            errs.append((rel, "enabled must be true and schedule is required"))
        inputs = d.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            errs.append((rel, "inputs must be a non-empty list"))
        else:
            for inp in inputs:
                indices = ((inp or {}).get("search") or {}).get("indices") if isinstance(inp, dict) else None
                if not isinstance(indices, list) or not indices:
                    errs.append((rel, "every input is a search with a non-empty indices list"))
                    continue
                for idx in indices:
                    if idx not in MONITOR_STREAMS:
                        errs.append((rel, f"index {idx!r} is not one of the streams a monitor may read"
                                          f" ({', '.join(sorted(MONITOR_STREAMS))})"))
        triggers = d.get("triggers")
        if not isinstance(triggers, list) or not triggers:
            errs.append((rel, "triggers must be a non-empty list"))
            continue
        for node in _walk(triggers):
            if "actions" in node and node["actions"] != []:
                errs.append((rel, "trigger actions must be empty (alarms stay in OpenSearch, decision D1)"))
    return errs


@check
def check_canaries(t):
    errs = []
    c = t.canaries
    if c is None:
        return errs
    if set(c) != {"rules", "correlations", "monitors"} or not all(isinstance(c[k] or {}, dict) for k in c):
        return [("canaries.yaml", "must hold exactly the mappings rules, correlations, monitors")]
    want = {"rules": set(t.rule_ids()), "correlations": set(t.correlation_names()), "monitors": set(t.monitor_names())}
    for section, ids in want.items():
        have = c[section] or {}
        for oid in sorted(ids - set(have), key=str):
            errs.append(("canaries.yaml", f"{section}: {oid} has no canary"))
        for oid in sorted(set(have) - ids, key=str):
            errs.append(("canaries.yaml", f"{section}: canary for {oid}, which does not exist"))
        for oid, can in have.items():
            kind = (can or {}).get("kind") if isinstance(can, dict) else None
            if kind not in CANARY_KINDS:
                errs.append(("canaries.yaml", f"{section}: {oid}: kind must be one of {', '.join(sorted(CANARY_KINDS))}"))
                continue
            if UNPUBLISHABLE.search(json.dumps(can)):
                # The page publishes canaries (ADR 0036); ADR 0021 never publishes addresses or node names.
                errs.append(("canaries.yaml", f"{section}: {oid}: names an address or a node; canaries are published"))
            required, optional = CANARY_KINDS[kind]
            if not required <= set(can) or set(can) - required - optional:
                errs.append(("canaries.yaml", f"{section}: {oid}: a {kind} canary has {', '.join(sorted(required))}"
                                              f"{' and ' + '/'.join(sorted(optional)) if optional else ''} only"))
            if kind == "api":
                term, scen = can.get("terminal"), can.get("scenario")
                ok_term = isinstance(term, list) and term and all(isinstance(x, str) and SLUG_RE.match(x) for x in term)
                ok_scen = isinstance(scen, str) and SLUG_RE.match(scen)
                if bool(ok_term) == bool(ok_scen) or (term is not None and not ok_term) or (scen is not None and not ok_scen):
                    errs.append(("canaries.yaml", f"{section}: {oid}: an api canary names either terminal: [<command id>, ...]"
                                                  " or scenario: <id>"))
    return errs


def _query_fields(node):
    """Field names a monitor query or aggregation reads: term/terms/range/exists/match keys, and the
    "field" of an aggregation."""
    out = set()
    for d in _walk(node):
        for key in ("term", "terms", "range", "match", "match_phrase", "prefix", "wildcard"):
            v = d.get(key)
            if isinstance(v, dict):
                if "field" in v and isinstance(v["field"], str):
                    out.add(v["field"])
                else:
                    out |= {k for k in v if k not in ("boost", "_name")}
        for key in ("exists", "min", "max", "avg", "sum", "value_count", "cardinality"):
            v = d.get(key)
            if isinstance(v, dict) and isinstance(v.get("field"), str):
                out.add(v["field"])
    return out


@check
def check_monitor_fields(t):
    errs = []
    for rel, d in t.monitors.items():
        for inp in d.get("inputs") or []:
            search = (inp or {}).get("search") if isinstance(inp, dict) else None
            if not isinstance(search, dict):
                continue
            allowed = set(COMMON_FIELDS)
            for idx in search.get("indices") or []:
                if isinstance(idx, str) and idx.startswith("sdp-"):
                    allowed |= t.allowed_fields(idx[len("sdp-"):])
            for f in sorted(_query_fields(search.get("query"))):
                if f not in allowed:
                    errs.append((rel, f"query field {f!r} is in no allow-list of the monitor's indices"))
    return errs


@check
def check_published(t):
    """What the page publishes (titles and file names of rules, monitors and correlations)."""
    errs = []
    for kind, objs, key in (("rule", t.rules, "title"), ("monitor", t.monitors, "name"),
                            ("correlation", t.correlations, "name")):
        for rel, d in objs.items():
            if UNPUBLISHABLE.search(rel) or UNPUBLISHABLE.search(str(d.get(key, ""))):
                errs.append((rel, f"the {kind}'s {key} or file name names an address or a node; both are published"))
    return errs


def lint_detailed(root):
    """Returns ([(path, check name, message)], tree)."""
    tree = Tree(root)
    findings = []
    for fn in CHECKS:
        findings += [(f"siem/{rel}", fn.__name__, msg) for rel, msg in fn(tree)]
    return findings, tree


def lint(root):
    """Returns (findings, tree); findings are 'path: message' strings."""
    findings, tree = lint_detailed(root)
    return [f"{path}: {msg}" for path, _, msg in findings], tree


def index(tree):
    """What the page's rule library and ATT&CK matrix show (ADR 0036): no field values, no queries."""
    canaries = tree.canaries or {}
    rules = []
    for rel, d in sorted(tree.rules.items()):
        line = next((n for n, text in enumerate(tree.rule_text[rel].split("\n"), 1) if text.startswith("title:")), 1)
        rules.append({
            "id": d["id"], "title": d["title"], "level": d["level"], "status": d["status"],
            "source": d["logsource"]["service"], "log_type": tree.log_type_of(d["logsource"]["service"]),
            "attack": sorted(x[len("attack."):].upper() for x in d.get("tags") or [] if TECHNIQUE_RE.match(x)),
            "file": f"siem/{rel}", "line": line, "canary": (canaries.get("rules") or {}).get(d["id"]),
        })
    monitors = [{"name": d["name"], "file": f"siem/{rel}", "canary": (canaries.get("monitors") or {}).get(d["name"])}
                for rel, d in sorted(tree.monitors.items())]
    correlations = [{"name": d["name"], "sources": [e["source"] for e in d["correlate"]], "file": f"siem/{rel}",
                     "canary": (canaries.get("correlations") or {}).get(d["name"])}
                    for rel, d in sorted(tree.correlations.items())]
    return {"rules": rules, "monitors": monitors, "correlations": correlations}


def main(argv):
    args = argv[1:]
    want_index = bool(args) and args[0] == "--index"
    if want_index:
        args = args[1:]
    if len(args) != 1 or not os.path.isdir(args[0]):
        print("usage: siem_lint.py [--index] <siem dir>", file=sys.stderr)
        return 2
    findings, tree = lint(args[0])
    for f in findings:
        print(f, file=sys.stderr)
    if findings:
        print(f"siem_lint: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    if want_index:
        print(json.dumps(index(tree), indent=2, sort_keys=True))
    else:
        print(f"siem_lint: {len(tree.log_types)} log types, {len(tree.rules)} rules, {len(tree.detectors)} detectors,"
              f" {len(tree.correlations)} correlations, {len(tree.monitors)} monitors - clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
