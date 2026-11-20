// Tiny DOM builder. Text always goes in through text nodes (never HTML parsing), attributes
// through setAttribute with an allow-list, events through addEventListener. Nothing in this
// app assigns innerHTML/outerHTML or uses insertAdjacentHTML (a test enforces that).

export type Child = Node | string | number | null | undefined | false | Child[];

export interface Attrs {
  class?: string;
  id?: string;
  role?: string;
  type?: string;
  name?: string;
  value?: string;
  for?: string;
  title?: string;
  hidden?: boolean;
  disabled?: boolean;
  checked?: boolean;
  autocomplete?: string;
  inputmode?: string;
  enterkeyhint?: string;
  spellcheck?: string;
  tabindex?: string;
  dir?: string;
  datetime?: string;
  open?: boolean;
  placeholder?: string;
  maxlength?: string;
  [aria: `aria-${string}`]: string | undefined;
  [data: `data-${string}`]: string | undefined;
  on?: { [K in keyof HTMLElementEventMap]?: (ev: HTMLElementEventMap[K]) => void };
}

const BOOL = new Set(["hidden", "disabled", "checked", "open"]);
const ALLOWED = new Set([
  "class", "id", "role", "type", "name", "value", "for", "title", "autocomplete", "inputmode",
  "enterkeyhint", "spellcheck", "tabindex", "dir", "datetime", "placeholder", "maxlength",
]);

export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(parent, c);
    else if (typeof c === "string" || typeof c === "number") parent.appendChild(document.createTextNode(String(c)));
    else parent.appendChild(c);
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs?: Attrs | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "on") {
        for (const [ev, fn] of Object.entries(v as Record<string, EventListener>)) el.addEventListener(ev, fn);
      } else if (BOOL.has(k)) {
        if (v) el.setAttribute(k, "");
      } else if (v !== undefined && v !== null) {
        if (!ALLOWED.has(k) && !/^(aria|data)-[a-z-]+$/.test(k)) throw new Error(`dom: attribute ${k} not allowed`);
        el.setAttribute(k, String(v));
      }
    }
  }
  append(el, children);
  return el;
}

export function replace(el: Element, ...children: Child[]): void {
  el.replaceChildren();
  append(el, children);
}

export function $(sel: string, root: ParentNode = document): HTMLElement {
  const el = root.querySelector(sel);
  if (!el) throw new Error(`missing ${sel}`);
  return el as HTMLElement;
}

/** obj[key] only when key is obj's own property: lookups keyed by server or browser strings
 * must not reach Object.prototype ("constructor", "__proto__", ...). */
export function own<V>(obj: Record<string, V>, key: string): V | undefined {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}
