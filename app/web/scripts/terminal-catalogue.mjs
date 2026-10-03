// Generates the `?mock=1` terminal catalogue (src/lib/terminal-catalogue.json) from the real one: the
// `terminal` scenario of cluster/infra/sandbox/scenarios/scenarios.yaml, which the cluster side owns.
// The mock then serves exactly the objectives and commands the live API serves, instead of a retyped
// copy that drifts.
//
//   node scripts/terminal-catalogue.mjs <scenarios.yaml>           write the fixture
//   node scripts/terminal-catalogue.mjs <scenarios.yaml> --check   exit 1 if the fixture has drifted
//
// The YAML is read with a small reader for the subset that file uses (block maps and sequences, flow
// sequences and maps of scalars, quoted and folded scalars, comments): no dependency reaches the
// build (ADR 0019). Only the `terminal` entry is parsed. Anything the reader does not understand, or
// a command missing a field the page needs, throws, so a format change fails loudly here.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "lib", "terminal-catalogue.json");

/** Drops a `#` comment (outside quotes, after whitespace) and trailing blanks. */
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i).trimEnd();
  }
  return line.trimEnd();
}

/** A scalar, quoted or plain. Anchors are dropped; an alias is kept as its text. */
function scalar(text) {
  const t = text.trim().replace(/^&[\w-]+\s+/, "");
  if (t.startsWith('"')) {
    if (!t.endsWith('"') || t.length < 2) throw new Error(`terminal-catalogue: unterminated string ${t}`);
    return JSON.parse(t.replace(/\\'/g, "'"));
  }
  if (t.startsWith("'")) {
    if (!t.endsWith("'") || t.length < 2) throw new Error(`terminal-catalogue: unterminated string ${t}`);
    return t.slice(1, -1).replace(/''/g, "'");
  }
  if (t === "true" || t === "false") return t === "true";
  if (t === "null" || t === "~" || t === "") return null;
  if (/^-?\d+$/.test(t)) return Number(t);
  return t;
}

/** A flow collection (`[a, "b"]`, `{id: x, title: "y"}`), possibly nested. */
function flow(text) {
  let i = 0;
  const ws = () => {
    while (/\s/.test(text[i] ?? "")) i++;
  };
  const item = () => {
    ws();
    if (text[i] === "[" || text[i] === "{") return collection();
    const start = i;
    if (text[i] === '"' || text[i] === "'") {
      const q = text[i++];
      while (i < text.length && text[i] !== q) i += text[i] === "\\" && q === '"' ? 2 : 1;
      i++;
    } else {
      while (i < text.length && !",]}:".includes(text[i])) i++;
    }
    return text.slice(start, i).trim();
  };
  const collection = () => {
    const open = text[i++];
    const close = open === "[" ? "]" : "}";
    const out = open === "[" ? [] : {};
    for (;;) {
      ws();
      if (text[i] === close) {
        i++;
        return out;
      }
      const k = item();
      ws();
      if (open === "{") {
        if (text[i] !== ":") throw new Error(`terminal-catalogue: expected ':' in ${text}`);
        i++;
        const v = item();
        out[scalar(k)] = typeof v === "string" ? scalar(v) : v;
      } else {
        out.push(typeof k === "string" ? scalar(k) : k);
      }
      ws();
      if (text[i] === ",") i++;
      else if (text[i] !== close) throw new Error(`terminal-catalogue: cannot read ${text}`);
    }
  };
  const v = collection();
  ws();
  if (i !== text.length) throw new Error(`terminal-catalogue: trailing text in ${text}`);
  return v;
}

/** Parses a block of YAML lines ({indent, text, raw}) into a value. */
function parseBlock(lines) {
  let pos = 0;

  // A folded (>) or literal (|) block scalar: every following line indented deeper than `parent`.
  // Blank lines are not kept (toLines), so a folded scalar is one paragraph, as every one here is.
  const blockScalar = (header, parent) => {
    const body = [];
    while (pos < lines.length && lines[pos].indent > parent) body.push(lines[pos++]);
    if (!body.length) throw new Error(`terminal-catalogue: empty block scalar after line ${pos}`);
    const base = Math.min(...body.map((l) => l.indent));
    const out = body.map((l) => l.raw.slice(base)).join(header[0] === ">" ? " " : "\n");
    return header.includes("-") ? out : `${out}\n`;
  };

  // The value after `key:` or `- `, on the same line or as a nested block below it.
  const value = (rest, parent) => {
    const r = rest.trim();
    if (r === "") {
      if (pos < lines.length && lines[pos].indent > parent) return node(lines[pos].indent);
      return null;
    }
    if (r.startsWith("[") || r.startsWith("{")) return flow(r);
    if (/^[>|][-+]?$/.test(r)) return blockScalar(r, parent);
    return scalar(r);
  };

  const mapping = (indent, first) => {
    const out = {};
    let line = first;
    for (;;) {
      const m = /^([\w-]+):(?:\s+(.*)|$)/.exec(line);
      if (!m) throw new Error(`terminal-catalogue: cannot read "${line}"`);
      out[m[1]] = value(m[2] ?? "", indent);
      if (pos >= lines.length || lines[pos].indent !== indent || lines[pos].text.startsWith("- ")) return out;
      line = lines[pos++].text;
    }
  };

  const node = (indent) => {
    const l = lines[pos];
    if (l.text.startsWith("- ") || l.text === "-") {
      const out = [];
      while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text.startsWith("- ") || lines[pos].text === "-")) {
        const rest = lines[pos++].text.slice(2);
        // `- key: value` opens a mapping whose further keys sit two columns in.
        if (/^[\w-]+:(\s|$)/.test(rest)) out.push(mapping(indent + 2, rest));
        else out.push(value(rest, indent));
      }
      return out;
    }
    pos++;
    return mapping(indent, l.text);
  };

  const v = node(lines[0].indent);
  if (pos !== lines.length) throw new Error(`terminal-catalogue: unread line "${lines[pos].raw}"`);
  return v;
}

/**
 * The non-blank lines, with comments removed — except inside a block scalar (`>-`, `|`), where a
 * `#` is text: `explain: >-` followed by "see #42" keeps "see #42".
 */
function toLines(text) {
  const out = [];
  let blockAt = -1; // the indentation of the key that opened a block scalar, or -1 outside one
  for (const raw of text.split("\n")) {
    const indent = raw.length - raw.trimStart().length;
    if (raw.trim() === "") continue;
    if (blockAt >= 0 && indent > blockAt) {
      out.push({ raw: raw.trimEnd(), indent, text: raw.trim() });
      continue;
    }
    blockAt = -1;
    const stripped = stripComment(raw);
    if (stripped.trim() === "") continue;
    out.push({ raw: stripped, indent, text: stripped.trim() });
    if (/(:\s+|^-\s+)[>|][-+]?$/.test(stripped.trim())) blockAt = indent;
  }
  return out;
}

const REQUIRED = ["id", "input", "aliases", "technique", "command", "tty", "outcome", "layer", "control", "explain"];

/** The `terminal` scenario's catalogue, from the whole scenarios.yaml text. */
export function terminalCatalogue(yaml) {
  const all = yaml.split("\n");
  const start = all.findIndex((l) => /^- id: terminal\s*$/.test(l));
  if (start === -1) throw new Error("terminal-catalogue: no `- id: terminal` scenario in the file");
  let end = all.findIndex((l, i) => i > start && /^- /.test(l));
  if (end === -1) end = all.length;
  const lines = toLines(all.slice(start, end).join("\n"));
  const [sc] = parseBlock(lines);
  if (!sc || sc.interactive !== true || !Array.isArray(sc.objectives) || !Array.isArray(sc.commands)) {
    throw new Error("terminal-catalogue: the terminal scenario has no objectives/commands");
  }
  const commands = sc.commands.map((c) => {
    for (const k of REQUIRED) if (c[k] === undefined || c[k] === null) throw new Error(`terminal-catalogue: command ${c.id ?? "?"} has no ${k}`);
    const out = {};
    for (const k of ["id", "input", "aliases", "objective", "technique", "command", "tty", "outcome", "layer", "control", "detection", "response", "explain"]) {
      if (c[k] !== undefined && c[k] !== null) out[k] = c[k];
    }
    return out;
  });
  return {
    timeout_seconds: sc.timeout_seconds,
    idle_seconds: sc.idle_seconds,
    objectives: sc.objectives.map((o) => ({ id: o.id, title: o.title })),
    commands,
  };
}

export const render = (catalogue) => `${JSON.stringify(catalogue, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const src = process.argv[2];
  if (!src) {
    console.error("usage: node scripts/terminal-catalogue.mjs <scenarios.yaml> [--check]");
    process.exit(2);
  }
  const want = render(terminalCatalogue(await readFile(src, "utf8")));
  if (process.argv.includes("--check")) {
    const have = await readFile(FIXTURE, "utf8").catch(() => "");
    if (have !== want) {
      console.error(`${FIXTURE} differs from ${src}: run node scripts/terminal-catalogue.mjs ${src}`);
      process.exit(1);
    }
    console.log("terminal catalogue: in step with", src);
  } else {
    await writeFile(FIXTURE, want);
    console.log("wrote", FIXTURE);
  }
}
