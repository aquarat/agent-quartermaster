// The header's status button, on every page: how many buckets are decrypted right now and how
// many requests wait. Its panel lists what is open and has the two things one reaches for in a
// hurry: go to what is waiting, and Close all (the same signed tap as Security → Buckets).
import { type Api } from "./api";
import { h, replace, type Child } from "./dom";
import { visibleText as vt } from "./format";
import { CLOSE_ALL_TEXT, beginControl, kindWords, openCount, openSummary, serving, type SealView } from "./sealPanel";
import type { Authenticator } from "./webauthn";

export class Tray {
  readonly el = h("div", { class: "tray" });
  private button = h("button", { class: "badge buckets-open tray-button", type: "button", "aria-expanded": "false", "aria-controls": "tray-panel" });
  private panel = h("div", { class: "tray-panel", id: "tray-panel", hidden: true, role: "region", "aria-label": "Open buckets and waiting requests" });
  private body = h("div", { class: "tray-body" });
  private review = h("div", { class: "tray-review", role: "status" });
  private seal?: SealView;
  private key = "";

  constructor(private api: Api, private auth: Authenticator, private changed: () => void) {
    this.panel.append(this.body, this.review);
    this.el.append(this.button, this.panel);
    this.button.addEventListener("click", () => this.toggle(!!this.panel.hidden));
    this.el.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && !this.panel.hidden) {
        this.toggle(false);
        this.button.focus();
      }
    });
    // A click inside the tray is noted on the way down: a button that removes itself in its
    // own click (Cancel) is no longer inside by the time the click reaches the document.
    let inside = false;
    this.el.addEventListener("click", () => (inside = true), true);
    document.addEventListener("click", () => {
      if (!inside && !this.panel.hidden && !this.review.querySelector("button.confirm")) this.toggle(false);
      inside = false;
    });
  }

  toggle(open: boolean): void {
    this.panel.hidden = !open;
    this.button.setAttribute("aria-expanded", String(open));
    if (!open) replace(this.review);
  }

  /** `note`: one more line (passkeys that cannot open buckets yet), or null. */
  update(seal: SealView | undefined, waiting: number, note: Child): void {
    this.seal = seal;
    const live = serving(seal);
    this.el.hidden = !live;
    if (!live) return;
    const n = openCount(seal!);
    const text = openSummary(seal!);
    if (this.button.textContent !== text) this.button.textContent = text;
    this.button.classList.toggle("open", n > 0);
    this.button.dataset["open"] = String(n);
    this.button.title = "What is decrypted right now; Close all";
    const open = (seal!.buckets ?? []).filter((b) => b.open);
    const key = JSON.stringify([open, waiting, !!note, seal!.epoch]);
    // A Close all waiting for its tap keeps the panel as it is.
    if (key === this.key || this.review.querySelector("button.confirm")) return;
    this.key = key;
    const link = (text2: string, href: string, cls = "") => {
      const a = h("a", { class: cls, on: { click: () => this.toggle(false) } }, text2);
      a.href = href;
      return a;
    };
    replace(
      this.body,
      waiting > 0 ? h("p", { class: "tray-waiting" }, link(waiting === 1 ? "1 request is waiting for you" : `${waiting} requests are waiting for you`, "#/", "btn approve small")) : h("p", { class: "muted" }, "Nothing is waiting for you."),
      h("h3", null, n === 0 ? "No bucket is open" : n === 1 ? "1 bucket is open" : `${n} buckets are open`),
      open.length
        ? h("ul", { class: "tray-list" }, open.map((b) => h("li", null, h("strong", null, vt(b.label)), " ", h("span", { class: "muted" }, vt(kindWords(b.kind)), b.holds.length ? vt(` · ${b.holds.map((x) => x.reason || x.kind).join("; ")}`) : ""))))
        : h("p", { class: "muted" }, "Every credential is encrypted at rest. A bucket opens only for the approval that needs it."),
      note ? h("p", { class: "tray-note" }, note) : null,
      h(
        "div",
        { class: "actions start" },
        h("button", { class: "btn deny small", type: "button", disabled: n === 0 && !(seal!.active_windows ?? []).length, on: { click: () => void this.closeAll() } }, "Close all…"),
        link("Manage buckets", "#/security", "btn small"),
      ),
    );
  }

  private async closeAll(): Promise<void> {
    const v = this.seal!;
    replace(this.review, h("p", { class: "muted" }, "Checking with aqmas…"));
    try {
      const c = await beginControl(this.api, v, "close-all");
      const sign = h("button", { type: "button", class: "btn deny confirm" }, "Close all with passkey");
      sign.addEventListener("click", () => {
        sign.disabled = true;
        c.finish(this.auth).then(
          () => {
            replace(this.review, h("p", null, "Closed."));
            this.changed();
          },
          (e) => replace(this.review, h("p", { class: "error", role: "alert" }, vt((e as Error).message))),
        );
      });
      replace(
        this.review,
        h("p", { class: "warn" }, CLOSE_ALL_TEXT),
        c.facts.length ? h("dl", { class: "facts" }, c.facts.map(([k, x]) => [h("dt", null, vt(k)), h("dd", null, h("span", { class: "mono" }, vt(x)))])) : null,
        h("details", { class: "signed" }, h("summary", null, "Exactly what your passkey signs"), h("pre", { class: "cmd" }, vt(c.detail))),
        h("div", { class: "actions" }, h("button", { class: "btn small", type: "button", on: { click: () => replace(this.review) } }, "Cancel"), sign),
      );
      sign.focus();
    } catch (e) {
      replace(this.review, h("p", { class: "error", role: "alert" }, vt((e as Error).message)));
    }
  }
}
