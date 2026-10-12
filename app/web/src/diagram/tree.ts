// A plain description of an SVG: tags, attributes and text, nothing that needs a DOM. The page walks
// it with lib/dom.ts svg() (Trusted Types, CSP 'self'); scripts/diagram.mjs serialises it to a file.
// Keeping the drawing as data is what lets one layout feed both without an HTML sink anywhere.

export interface Tree {
  tag: string;
  attrs: Record<string, string | number>;
  children: (Tree | string)[];
}

export const t = (tag: string, attrs: Record<string, string | number> = {}, ...children: (Tree | string | null | undefined | false)[]): Tree => ({
  tag,
  attrs,
  children: children.filter((c): c is Tree | string => c !== null && c !== undefined && c !== false),
});

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const escape = (s: string): string => s.replace(/[&<>"']/g, (c) => ESC[c]);

/** The tree as SVG markup, every attribute and text node escaped; `indent` for a readable file. */
export function serialise(node: Tree | string, indent = ""): string {
  if (typeof node === "string") return escape(node);
  const attrs = Object.entries(node.attrs)
    .map(([k, v]) => ` ${k}="${escape(String(v))}"`)
    .join("");
  if (!node.children.length) return `${indent}<${node.tag}${attrs}/>`;
  const inline = node.children.every((c) => typeof c === "string");
  if (inline) return `${indent}<${node.tag}${attrs}>${node.children.map((c) => serialise(c)).join("")}</${node.tag}>`;
  const inner = node.children.map((c) => (typeof c === "string" ? `${indent}  ${escape(c)}` : serialise(c, `${indent}  `))).join("\n");
  return `${indent}<${node.tag}${attrs}>\n${inner}\n${indent}</${node.tag}>`;
}
