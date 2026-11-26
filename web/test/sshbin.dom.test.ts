// 0.11.0 in happy-dom against the mock: Add item → SSH key (generate and paste), the key's
// page (public line with Copy, fingerprint, hand-out setting), the approval cards for SSH
// logins and for a private-key hand-out, Delete on an item's page and Vault → Deleted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth, testOpenSSHKey } from "./helpers";
import type { VaultHost } from "../src/vaultPage";
import type { VaultView as Page } from "../src/vaultView";
import type { Catalogue } from "../src/catalogue";
import { sshPublic, type VaultState } from "../src/vault";
import type { SealView } from "../src/sealPanel";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator"];
const KEY = "client-a/paas/deploy-key";
const PASTED = "client-a/paas/pasted-key";

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error, [role=status]")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("SSH keys and the bin in a DOM", () => {
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  let page: Page;
  let state: VaultState;
  let seal: SealView;
  let host: VaultHost;
  let catalogue: Catalogue | null = null;
  let sel: string | undefined;
  let loads = 0;
  let asked = 0;
  const copied: string[] = [];
  const settled = () => until(() => loads === asked);
  const refresh = () => (asked++, reload());
  const body = () => win.document.body as unknown as HTMLElement;
  const click = (root: ParentNode, text: string) => {
    const b = [...root.querySelectorAll("button")].find((x) => x.textContent === text);
    if (!b) throw new Error("no button " + text + " among " + [...root.querySelectorAll("button")].map((x) => x.textContent).join(" | "));
    b.click();
  };
  const fire = (el: Element, ev: string) => el.dispatchEvent(new win.Event(ev) as unknown as Event);
  const reload = async () => {
    state = await api.vaultState!();
    seal = await api.sealStatus!();
    catalogue = (await api.catalogue!()) ?? null;
    page.update(state, seal, catalogue, sel);
    loads++;
  };
  const setOf = (path: string) => state.sets.find((s) => `${s.org_slug}/${s.service_slug}/${s.set_slug}` === path);
  const select = (path: string | undefined) => {
    sel = path === undefined || path === "new" || path === "deleted" ? path : setOf(path)!.set_id;
    page.update(state, seal, catalogue, sel);
  };
  const addForm = (type: string) => {
    select(undefined);
    select("new");
    const form = page.el.querySelector<HTMLElement>(".vault-add-form")!;
    const org = form.querySelector<HTMLSelectElement>("#add-org")!;
    org.value = state.organisations.find((o) => o.slug === "client-a")!.id;
    fire(org, "change");
    const radio = form.querySelector<HTMLInputElement>("#add-type-" + type)!;
    radio.checked = true;
    fire(radio, "change");
    return form;
  };
  const setIn = (form: HTMLElement, id: string, value: string, ev = "input") => {
    const el = form.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(id)!;
    el.value = value;
    fire(el, ev);
  };

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    Object.defineProperty(win.navigator, "clipboard", { configurable: true, value: { writeText: async (t: string) => void copied.push(t) } });
    await completeLogin(api, auth, await prepareLogin(api));
    host = { api, auth, changed: () => void refresh(), propose: () => {} };
    page = new (await import("../src/vaultView")).VaultView(host);
    body().append(page.el);
    seal = await api.sealStatus!();
    await refresh();
  });
  afterAll(async () => {
    await settled();
    page.clearSecrets();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("Add item → SSH key, generated in aqmas: the confirmation shows the public line and fingerprint", async () => {
    const form = addForm("ssh-key");
    const f = form.querySelector<HTMLElement>(".vault-new-ssh")!;
    expect(f.textContent).toContain("New SSH key in Client A › PaaS");
    expect([...f.querySelectorAll("#sk-type option")].map((o) => o.textContent)).toEqual(["Ed25519", "ECDSA P-256"]);
    expect(f.querySelector<HTMLSelectElement>("#sk-type")!.value).toBe("ssh-ed25519");
    expect(f.querySelector<HTMLInputElement>("#sk-handout")!.checked).toBe(false);
    expect(f.querySelector<HTMLInputElement>("#sk-generate")!.checked).toBe(true);
    click(f, "Review…");
    expect(f.querySelector(".error")!.textContent).toContain("Slug:");
    setIn(form, "#sk-title", "Deploy key");
    expect(form.querySelector<HTMLInputElement>("#sk-slug")!.value).toBe("deploy-key");
    expect(form.querySelector<HTMLInputElement>("#sk-comment")!.value).toBe("aqmas:" + KEY);
    setIn(form, "#sk-comment", "badécomment");
    click(f, "Review…");
    expect(f.querySelector(".error")!.textContent).toContain("Comment:");
    setIn(form, "#sk-comment", "aqmas:" + KEY);
    const taps = auth.gets.length;
    click(f, "Review…");
    await until(() => !!f.querySelector(".vault-confirm .confirm"));
    const confirm = f.querySelector<HTMLElement>(".vault-confirm")!;
    const line = confirm.querySelector(".ssh-line")!.textContent!;
    expect(line).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43} aqmas:client-a\/paas\/deploy-key$/);
    expect(confirm.querySelector(".ssh-fp")!.textContent).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(confirm.textContent).toContain("aqmas generated this key pair");
    expect(confirm.textContent).toContain("Not handed out");
    expect(form.querySelector<HTMLInputElement>("#sk-title")!.disabled).toBe(true); // frozen until the tap
    expect(auth.gets.length).toBe(taps);
    click(f, "Create with passkey");
    await until(() => setOf(KEY)?.kind === "ssh-key");
    await settled();
    expect(auth.gets.length).toBe(taps + 1);
    expect(setOf(KEY)).toMatchObject({ authorized_key: line, handout: false, origin: "generated" });
    expect((win.location as unknown as Location).hash).toBe("#/vault/" + setOf(KEY)!.set_id);
  });

  test("the key's page: public line with Copy, fingerprint, where to add it, how hosts use it", async () => {
    select(KEY);
    const s = setOf(KEY)!;
    expect(page.el.querySelector(".vault-title")!.textContent).toContain("SSH key · " + KEY);
    const main = page.el.querySelector<HTMLElement>(".vault-ssh-key")!;
    expect(main.textContent).toContain("Created. Add the public key below");
    expect(main.querySelector(".ssh-line")!.textContent).toBe(s.authorized_key!);
    expect(main.querySelector(".ssh-fp")!.textContent).toBe(s.fingerprint!);
    expect(main.textContent).toContain("As ssh-keygen -lf prints it");
    expect(main.textContent).toContain("deploy key of one repository");
    expect(main.textContent).toContain("~/.ssh/authorized_keys");
    expect(main.textContent).toContain(`aqmas ssh-agent ${KEY} --why "…" -- git clone ssh://git@forge.example.com/owner/repo.git`);
    expect(main.textContent).not.toContain("aqmas ssh-key ");
    expect(main.textContent).toContain("no reveal and no export");
    click(main, "Copy public key");
    await until(() => copied.length === 1);
    expect(copied[0]).toBe(s.authorized_key!);
    // In the list and the filters it is its own type; it has no values, limit or conversion.
    expect(page.el.querySelector(`.vault-item[data-item="${s.set_id}"]`)!.textContent).toContain("SSH key · Ed25519 · 0 logins");
    expect([...page.el.querySelectorAll(".vault-side .side-label")].map((e) => e.textContent)).toContain("SSH keys");
    const extra = page.el.querySelector<HTMLElement>(".vault-extra")!;
    expect(extra.textContent).toContain("Who may ask for it");
    expect(extra.querySelector(".vault-more summary")!.textContent).toBe("More: reveal policy");
    expect(extra.querySelector(".vault-standing")).toBeNull();
    expect(extra.textContent).not.toContain("aqmas run");
  });

  test("May be handed out: off by default, turned on and off with a signed action", async () => {
    select(KEY);
    let box = page.el.querySelector<HTMLElement>(".vault-handout")!;
    expect(box.textContent).toContain("May be handed out: no");
    const taps = auth.gets.length;
    click(box, "Allow hand-out…");
    await until(() => !!box.querySelector(".vault-confirm .confirm"));
    expect(box.querySelector(".vault-confirm")!.textContent).toContain("cannot be recalled");
    click(box, "Allow with passkey");
    await until(() => setOf(KEY)?.handout === true);
    await settled();
    expect(auth.gets.length).toBe(taps + 1);
    const main = page.el.querySelector<HTMLElement>(".vault-ssh-key")!;
    expect(main.textContent).toContain(`aqmas ssh-key ${KEY} --why "…" --out ~/.ssh/deploy-key`);
    expect(main.textContent).toContain("Hand-out is on");
    expect(page.el.querySelector(`.vault-item[data-item="${setOf(KEY)!.set_id}"]`)!.textContent).toContain("may be handed out");
    box = page.el.querySelector<HTMLElement>(".vault-handout")!;
    expect(box.textContent).toContain("May be handed out: yes");
    click(box, "Stop handing out…");
    await until(() => !!box.querySelector(".vault-confirm .confirm"));
    click(box, "Turn off with passkey");
    await until(() => setOf(KEY)?.handout === false);
    await settled();
    expect(page.el.querySelector(".vault-ssh-key")!.textContent).not.toContain("aqmas ssh-key ");
  });

  test("Add item → SSH key, pasted: sealed in this tab, the field is cleared, hand-out chosen at creation", async () => {
    const k = testOpenSSHKey();
    const form = addForm("ssh-key");
    const f = form.querySelector<HTMLElement>(".vault-new-ssh")!;
    setIn(form, "#sk-title", "Pasted key");
    const imp = form.querySelector<HTMLInputElement>("#sk-import")!;
    const field = form.querySelector<HTMLElement>("#sk-key")!.closest<HTMLElement>(".field")!;
    expect(field.hidden).toBe(true);
    imp.checked = true;
    fire(imp, "change");
    expect(field.hidden).toBe(false);
    expect(field.textContent).toContain("without a passphrase");
    click(f, "Review…");
    expect(f.querySelector(".error")!.textContent).toContain("Paste the private key");
    setIn(form, "#sk-key", "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----\n");
    click(f, "Review…");
    await until(() => !!f.querySelector(".vault-slot .error"));
    expect(f.querySelector(".vault-slot .error")!.textContent).toContain("OpenSSH private key");
    setIn(form, "#sk-key", k.pem);
    const handout = form.querySelector<HTMLInputElement>("#sk-handout")!;
    handout.checked = true;
    click(f, "Review…");
    await until(() => !!f.querySelector(".vault-confirm .confirm"));
    const confirm = f.querySelector<HTMLElement>(".vault-confirm")!;
    expect(form.querySelector<HTMLTextAreaElement>("#sk-key")!.value).toBe("");
    expect(confirm.textContent).toContain("Compare this public key");
    expect(confirm.textContent).toContain("May be handed out");
    expect(confirm.querySelector(".ssh-line")!.textContent).toBe((await sshPublic("ssh-ed25519", new Uint8Array(k.pub), "aqmas:" + PASTED)).authorizedKey);
    expect(body().textContent).not.toContain("OPENSSH PRIVATE KEY-----\n" + k.pem.split("\n")[1]);
    click(f, "Create with passkey");
    await until(() => setOf(PASTED)?.kind === "ssh-key");
    await settled();
    expect(setOf(PASTED)).toMatchObject({ origin: "imported", handout: true, comment: "aqmas:" + PASTED });
  });

  test("approval card for SSH logins: plain words, limits that can only be lowered", async () => {
    m.store.vault.addSshRequest(KEY, "ssh-agent", "build-1", 3600, 20, "push the release branch");
    await refresh();
    select(KEY);
    const extra = page.el.querySelector<HTMLElement>(".vault-extra")!;
    expect(extra.textContent).toContain("Requests and grants for this SSH key");
    const card = extra.querySelector<HTMLElement>(".ssh-card")!;
    expect(card.classList.contains("key-leaves")).toBe(false);
    expect(card.querySelector(".badge")!.textContent).toBe("SSH key request");
    expect(card.textContent).toContain("Host build-1 asks to log in over SSH with key Deploy key");
    expect(card.textContent).toContain("SSH logins with key Deploy key from host build-1 for 1 hour: at most 20 logins");
    expect(card.textContent).toContain(setOf(KEY)!.fingerprint!);
    expect(card.textContent).toContain("push the release branch");
    expect(card.querySelector(".sign-items")).toBeNull(); // no artifacts
    expect(card.textContent).not.toContain("don't ask again");
    const minutes = card.querySelector<HTMLInputElement>(`[id^="sg-min-"]`)!;
    const count = card.querySelector<HTMLInputElement>(`[id^="sg-max-"]`)!;
    minutes.value = "90";
    fire(minutes, "input");
    click(card, "Approve…");
    expect(card.querySelector(".vault-slot .error")!.textContent).toContain("within what was asked");
    minutes.value = "10";
    fire(minutes, "input");
    count.value = "3";
    fire(count, "input");
    expect(card.textContent).toContain("for 10 min: at most 3 logins");
    click(card, "Approve…");
    await until(() => !!card.querySelector(".vault-confirm .confirm"));
    expect(card.querySelector(".vault-confirm")!.textContent).toContain("SSH logins with key Deploy key from host build-1 for 10 min: at most 3 logins");
    click(card, "Approve with passkey");
    await until(() => state.requests.some((r) => r.use === "ssh-agent" && r.status === "approved"));
    await settled();
    const live = page.el.querySelector<HTMLElement>(".vault-extra .ssh-card")!;
    expect(live.querySelector(".badge")!.textContent).toBe("SSH login grant");
    expect(live.textContent).toContain("0 of 3 logins used");
    expect(state.requests.find((r) => r.use === "ssh-agent")).toMatchObject({ ttl_seconds: 600, max_signatures: 3 });
  });

  test("approval card for a hand-out: red, says the key leaves aqmas and cannot be recalled, once", async () => {
    m.store.vault.addSshRequest(PASTED, "ssh-handout", "web-1");
    await refresh();
    select(PASTED);
    const card = page.el.querySelector<HTMLElement>(".vault-extra .ssh-card")!;
    expect(card.classList.contains("key-leaves")).toBe(true);
    expect(card.querySelector(".root-band")!.textContent).toBe("THE PRIVATE KEY LEAVES AQMAS");
    expect(card.querySelector(".badge")!.textContent).toBe("Private key hand-out request");
    expect(card.textContent).toContain("Host web-1 asks for the private key of Pasted key itself");
    expect(card.textContent).toContain("cannot be recalled");
    expect(card.querySelector("input")).toBeNull(); // nothing to tune: once, or not at all
    expect(card.textContent).not.toContain("don't ask again");
    click(card, "Hand out the private key…");
    await until(() => !!card.querySelector(".vault-confirm .confirm"));
    expect(card.querySelector(".vault-confirm .bad")!.textContent).toContain("It leaves aqmas and cannot be recalled");
    click(card, "Hand out with passkey");
    await until(() => state.requests.some((r) => r.use === "ssh-handout" && r.status === "approved"));
    await settled();
    const live = page.el.querySelector<HTMLElement>(".vault-extra .ssh-card")!;
    expect(live.textContent).toContain("the host can collect the private key, once");
    expect(state.requests.find((r) => r.use === "ssh-handout")).toMatchObject({ ttl_seconds: 0, max_signatures: 1 });
    // Deny works like for signing.
    m.store.vault.addSshRequest(PASTED, "ssh-handout", "build-1");
    await refresh();
    const pending = [...page.el.querySelectorAll<HTMLElement>(".vault-extra .ssh-card")].find((c) => c.querySelector(".badge")!.textContent === "Private key hand-out request")!;
    click(pending, "Deny…");
    await until(() => !!pending.querySelector(".vault-confirm .confirm"));
    click(pending, "Deny with passkey");
    await until(() => state.requests.filter((r) => r.use === "ssh-handout").length === 1);
    await settled();
  });

  test("Delete on the item page: one tap, says what ends, then the item is in Vault → Deleted", async () => {
    select(KEY);
    const id = setOf(KEY)!.set_id;
    expect(page.el.querySelector(".side-deleted")).toBeNull(); // nothing in the bin yet
    const box = page.el.querySelector<HTMLElement>(".vault-extra .vault-delete")!;
    expect(box.textContent).toContain("restorable for 7 days");
    const taps = auth.gets.length;
    click(box, "Delete…");
    await until(() => !!box.querySelector(".vault-confirm .confirm"));
    const confirm = box.querySelector(".vault-confirm")!.textContent!;
    expect(confirm).toContain("Delete " + KEY);
    expect(confirm).toContain("Agents cannot use it from this tap on");
    expect(confirm).toContain("grants, “don't ask again” rules and requests waiting for you end now");
    expect(confirm).toContain("for 7 days");
    expect(auth.gets.length).toBe(taps);
    click(box, "Delete with passkey");
    await until(() => !setOf(KEY) && state.deleted!.length === 1);
    await settled();
    expect(auth.gets.length).toBe(taps + 1);
    expect((win.location as unknown as Location).hash).toBe("#/vault/deleted");
    expect(state.requests.some((r) => r.set === id)).toBe(false); // its grant ended
    expect(page.el.querySelector(`.vault-item[data-item="${id}"]`)).toBeNull();
    const chip = page.el.querySelector<HTMLElement>(".side-deleted")!;
    expect(chip.textContent).toBe("Deleted1");
    select("deleted");
    expect(page.el.querySelector(".vault-title")!.textContent).toContain("Deleted");
    const item = page.el.querySelector<HTMLElement>(`.deleted-item[data-id="${id}"]`)!;
    expect(item.textContent).toContain(KEY);
    expect(item.textContent).toContain("SSH key");
    expect(item.textContent).toContain("by Mock passkey");
    expect(item.querySelector(".deleted-left")!.textContent).toMatch(/^(7 days|6 days 2[34] hours)$/);
    expect(item.textContent).toContain(state.deleted![0]!.fingerprint!);
    expect([...item.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Restore…", "Purge now…"]);
  });

  test("every deletable kind has Delete; the broker's own items do not", async () => {
    for (const path of ["client-a/paas/staging", "personal/firmware/release-key", PASTED]) {
      select(path);
      expect(page.el.querySelector(".vault-extra .vault-delete")).not.toBeNull();
    }
    const ca = [...page.el.querySelectorAll<HTMLElement>(".vault-item")].find((a) => a.dataset["type"] === "ssh-ca");
    if (ca) {
      sel = ca.dataset["item"];
      page.update(state, seal, catalogue, sel);
      expect(page.el.querySelector(".vault-extra .vault-delete")).toBeNull();
    }
  });

  test("Restore: disabled with an explanation while the path is taken; otherwise one tap", async () => {
    const id = state.deleted![0]!.set_id;
    m.store.vault.addSshKey(KEY, "Deploy key again");
    await refresh();
    select("deleted");
    let item = page.el.querySelector<HTMLElement>(`.deleted-item[data-id="${id}"]`)!;
    const restore = () => [...item.querySelectorAll("button")].find((b) => b.textContent === "Restore…")!;
    expect(restore().disabled).toBe(true);
    expect(item.querySelector(".warn")!.textContent).toContain(`Another item has the path ${KEY} now`);
    // The newcomer goes to the bin too; the first can then come back.
    select(KEY);
    const box = page.el.querySelector<HTMLElement>(".vault-extra .vault-delete")!;
    click(box, "Delete…");
    await until(() => !!box.querySelector(".vault-confirm .confirm"));
    click(box, "Delete with passkey");
    await until(() => state.deleted!.length === 2);
    await settled();
    select("deleted");
    expect(page.el.querySelector(".side-deleted")!.textContent).toBe("Deleted2");
    item = page.el.querySelector<HTMLElement>(`.deleted-item[data-id="${id}"]`)!;
    expect(restore().disabled).toBe(false);
    click(item, "Restore…");
    await until(() => !!item.querySelector(".vault-confirm .confirm"));
    expect(item.querySelector(".vault-confirm")!.textContent).toContain("former grants and “don't ask again” rules do not come back");
    click(item, "Restore with passkey");
    await until(() => setOf(KEY)?.set_id === id);
    await settled();
    expect(state.deleted!.length).toBe(1);
    expect(page.el.querySelector(`.deleted-item[data-id="${id}"]`)).toBeNull();
    expect(state.requests.some((r) => r.set === id)).toBe(false);
    select(KEY);
    expect(page.el.querySelector(".vault-ssh-key .ssh-line")!.textContent).toBe(setOf(KEY)!.authorized_key!);
  });

  test("Purge now: red, irreversible, one tap; the bin empties and its entry leaves the side", async () => {
    select("deleted");
    const item = page.el.querySelector<HTMLElement>(".deleted-item")!;
    const purge = [...item.querySelectorAll("button")].find((b) => b.textContent === "Purge now…")!;
    expect(purge.classList.contains("deny")).toBe(true);
    purge.click();
    await until(() => !!item.querySelector(".vault-confirm .confirm"));
    const confirm = item.querySelector<HTMLElement>(".vault-confirm")!;
    expect(confirm.querySelector(".bad")!.textContent).toContain("for good, now");
    expect(confirm.textContent).toContain("This cannot be undone");
    expect(confirm.textContent).toContain("backup of the store made before this moment still contains");
    expect(confirm.querySelector(".confirm")!.classList.contains("deny")).toBe(true);
    click(item, "Purge with passkey");
    await until(() => state.deleted!.length === 0);
    await settled();
    expect(page.el.querySelector(".vault-deleted")!.textContent).toContain("Nothing is in the bin");
    select(undefined);
    expect(page.el.querySelector(".side-deleted")).toBeNull();
  });

  test("an env set goes to the bin with its key names, never its values", async () => {
    select("club/website/deploy");
    const box = page.el.querySelector<HTMLElement>(".vault-extra .vault-delete")!;
    click(box, "Delete…");
    await until(() => !!box.querySelector(".vault-confirm .confirm"));
    click(box, "Delete with passkey");
    await until(() => state.deleted!.length === 1);
    await settled();
    select("deleted");
    const item = page.el.querySelector<HTMLElement>(".deleted-item")!;
    expect(item.textContent).toContain("Env set · revision 2");
    expect(item.textContent).toContain("APP_ID, DEPLOY_TOKEN");
    expect(body().textContent).not.toContain("mock-deploy-token");
  });
});
