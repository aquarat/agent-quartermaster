// Small line glyphs, built with createElementNS from constant path data (no markup parsing).
// Generic shapes, not brand logos: they help tell passkeys and events apart at a glance, and
// every one comes with text next to it.

import type { EventKind } from "./audit";
import { own } from "./dom";

const NS = "http://www.w3.org/2000/svg";

type Shape = { d: string } | { c: [number, number, number] } | { r: [number, number, number, number, number] };

function draw(shapes: Shape[], cls: string): SVGSVGElement {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "24");
  svg.setAttribute("height", "24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("class", cls);
  for (const s of shapes) {
    let el: SVGElement;
    if ("d" in s) {
      el = document.createElementNS(NS, "path");
      el.setAttribute("d", s.d);
    } else if ("c" in s) {
      el = document.createElementNS(NS, "circle");
      el.setAttribute("cx", String(s.c[0]));
      el.setAttribute("cy", String(s.c[1]));
      el.setAttribute("r", String(s.c[2]));
    } else {
      el = document.createElementNS(NS, "rect");
      el.setAttribute("x", String(s.r[0]));
      el.setAttribute("y", String(s.r[1]));
      el.setAttribute("width", String(s.r[2]));
      el.setAttribute("height", String(s.r[3]));
      el.setAttribute("rx", String(s.r[4]));
    }
    svg.appendChild(el);
  }
  return svg;
}

const KEY: Shape[] = [{ c: [8, 15, 4] }, { d: "M10.8 12.2 20 3" }, { d: "M16 7l3 3" }, { d: "M14 9l2 2" }];

const PASSKEY_GLYPHS: Record<string, Shape[]> = {
  // Synced platform keychain: a cloud.
  apple: [{ d: "M7 18h10a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.1 9.2 4.5 4.5 0 0 0 7 18z" }],
  // Password managers: a shield, a numbered vault, a lock...
  bitwarden: [{ d: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" }, { d: "M12 7v10" }],
  onepassword: [{ c: [12, 12, 9] }, { d: "M11 8.5h1.5v7" }],
  google: [{ c: [12, 12, 9] }, { d: "M12 12h5" }, { d: "M16.5 8a6 6 0 1 0 .5 6" }],
  chrome: [{ c: [12, 12, 9] }, { c: [12, 12, 3.5] }, { d: "M12 8.5h8" }, { d: "M9 14l-4 6.5" }, { d: "M15 14l-4 7" }],
  windows: [{ r: [4, 4, 7, 7, 1] }, { r: [13, 4, 7, 7, 1] }, { r: [4, 13, 7, 7, 1] }, { r: [13, 13, 7, 7, 1] }],
  microsoft: [{ r: [4, 4, 7, 7, 1] }, { r: [13, 4, 7, 7, 1] }, { r: [4, 13, 7, 7, 1] }, { r: [13, 13, 7, 7, 1] }],
  samsung: [{ r: [6, 2.5, 12, 19, 2.5] }, { d: "M10.5 18.5h3" }],
  // Hardware key: a USB stick with a touch pad.
  yubikey: [{ r: [7, 8, 10, 13, 2] }, { r: [9, 3, 6, 5, 1] }, { c: [12, 14.5, 2] }],
  manager: [{ r: [4, 10, 16, 11, 2] }, { d: "M8 10V7a4 4 0 0 1 8 0v3" }, { d: "M12 14.5v2.5" }],
  unknown: KEY,
};

export function passkeyIcon(icon: string): SVGSVGElement {
  return draw(own(PASSKEY_GLYPHS, icon) ?? KEY, "glyph");
}

const EVENT_GLYPHS: Record<EventKind, Shape[]> = {
  approve: [{ d: "M5 12.5l4.5 4.5L19 7.5" }],
  deny: [{ d: "M6 6l12 12" }, { d: "M18 6L6 18" }],
  revoke: [{ c: [12, 12, 8.5] }, { d: "M8 12h8" }],
  request: [{ d: "M12 4v11" }, { d: "M7.5 10.5 12 15l4.5-4.5" }, { d: "M5 20h14" }],
  auto: [{ d: "M4 12a8 8 0 0 1 13.7-5.6L20 9" }, { d: "M20 4v5h-5" }, { d: "M20 12a8 8 0 0 1-13.7 5.6L4 15" }, { d: "M4 20v-5h5" }],
  passkey: KEY,
  system: [{ c: [12, 12, 3] }, { c: [12, 12, 8.5] }],
  warning: [{ d: "M12 3.5 22 20H2z" }, { d: "M12 10v4.5" }, { d: "M12 17.5v.01" }],
  // Cloudflare: a write through the proxy (a pen), a child API token (a tag).
  cfwrite: [{ d: "M4 20h4L19 9l-4-4L4 16z" }, { d: "M13.5 6.5l4 4" }],
  token: [{ d: "M3 3h8l10 10-8 8L3 11z" }, { c: [7.5, 7.5, 1.5] }],
};

export function eventIcon(kind: EventKind): SVGSVGElement {
  return draw(EVENT_GLYPHS[kind], "glyph");
}

/** The small cloud mark on Cloudflare activity rows. */
export function cloudIcon(): SVGSVGElement {
  return draw(PASSKEY_GLYPHS["apple"]!, "glyph cf-mark");
}

/** Synced (cloud) / device-bound (chip) badge glyphs. */
export function syncIcon(synced: boolean): SVGSVGElement {
  return draw(synced ? PASSKEY_GLYPHS["apple"]! : [{ r: [6, 6, 12, 12, 2] }, { d: "M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" }], "glyph small");
}

export function chevronIcon(): SVGSVGElement {
  return draw([{ d: "M9 6l6 6-6 6" }], "glyph chevron");
}

const NAV_GLYPHS: Record<string, Shape[]> = {
  approvals: [{ r: [4, 4, 16, 16, 3] }, { d: "M8.5 12.5l2.5 2.5 4.5-5" }],
  vault: [{ r: [3, 4, 18, 15, 2] }, { c: [12, 11.5, 3] }, { d: "M12 8.5v-1M7 19v2M17 19v2" }],
  hosts: [{ r: [3, 4, 18, 6, 1.5] }, { r: [3, 14, 18, 6, 1.5] }, { d: "M7 7h.01M7 17h.01" }],
  activity: [{ d: "M3 12h4l3-7 4 14 3-7h4" }],
  security: [{ d: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" }, { d: "M9 12l2 2 4-4" }],
  settings: [{ d: "M4 7h10M18 7h2M4 17h2M10 17h10" }, { c: [16, 7, 2] }, { c: [8, 17, 2] }],
  help: [{ c: [12, 12, 9] }, { d: "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7" }, { d: "M12 17v.01" }],
  search: [{ c: [11, 11, 6.5] }, { d: "M16 16l4.5 4.5" }],
};
export function navIcon(name: string): SVGSVGElement {
  return draw(own(NAV_GLYPHS, name) ?? NAV_GLYPHS["help"]!, "glyph nav-glyph");
}

/** Vault item types: each also has its words next to it. */
const ITEM_GLYPHS: Record<string, Shape[]> = {
  "env-set": [{ r: [4, 3, 16, 18, 2] }, { d: "M8 8h8M8 12h8M8 16h5" }],
  signer: [{ d: "M4 20h4L19 9l-4-4L4 16z" }, { d: "M13.5 6.5l4 4" }, { d: "M12 20h8" }],
  cloudflare: PASSKEY_GLYPHS["apple"]!,
  "ssh-ca": [{ r: [3, 5, 18, 14, 2] }, { d: "M7 10l3 2-3 2M12 14h4" }],
  "internal-ca": [{ c: [12, 9, 5] }, { d: "M9 13.5 8 21l4-2 4 2-1-7.5" }],
  access: KEY,
};
export function itemIcon(type: string): SVGSVGElement {
  return draw(own(ITEM_GLYPHS, type) ?? KEY, "glyph item-glyph");
}
