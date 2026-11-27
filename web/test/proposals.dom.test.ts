// The approval card for an env proposal, in happy-dom against the mock: the wording, that
// what the host supplied (reason, key names) is only ever text, that the card offers no
// duration, "don't ask again" or batch checkbox, and that Commit is one passkey tap.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { createApi } from "../src/api";
import { completeLogin, prepareLogin } from "../src/flows";
import { startMock } from "../mock/server";
import { jarFetch, prfAuth } from "./helpers";
import type { SealView } from "../src/sealPanel";
import type { EnvState } from "../src/envsets";

const m = startMock({ port: 0, distDir: null, vault: true });
const win = new Window({ url: m.url + "/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "location", "HTMLElement", "Node", "Event", "navigator"];
const STAGING = "client-a/paas/staging";
const HOSTILE_REASON = 'routine <img src=x onerror="alert(1)"> ‮gnp.exe</p><script>alert(2)</script>';
const HOSTILE_KEY = "EVIL<b onmouseover=alert(3)>KEY</b>";

async function until(cond: () => boolean, ms = 3000): Promise<void> {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > ms) throw new Error("timed out: " + [...(win.document as unknown as Document).querySelectorAll(".error, [role=status]")].map((e) => e.textContent).join(" | "));
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("env proposal card in a DOM", () => {
  const vault = m.store.vault;
  const api = createApi({ base: m.url, fetch: jarFetch() });
  const auth = prfAuth(m.url);
  m.store.addPasskey("apple", "PRF test passkey", Date.now(), undefined, auth.id);
  m.store.buckets.enableAll(auth.id);
  let seal: SealView;
  let env: EnvState;
  let refreshed = 0;
  const body = () => win.document.body as unknown as HTMLElement;
  const click = (root: ParentNode, text: string) => {
    const b = [...root.querySelectorAll("button")].find((x) => x.textContent === text);
    if (!b) throw new Error("no button " + text + " among " + [...root.querySelectorAll("button")].map((x) => x.textContent).join(" | "));
    b.click();
  };
  const draw = async () => {
    const { envPanel } = await import("../src/envsets");
    env = await api.envState!();
    const el = envPanel(api, auth, seal, env, null, () => void refreshed++);
    body().append(el);
    return el;
  };
  const cardOf = (panel: HTMLElement, id: string) => panel.querySelector<HTMLElement>(`[data-proposal="${id}"]`)!;
  const text = (el: Element, sel: string) => el.querySelector(sel)!.textContent!;

  beforeAll(async () => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
    await completeLogin(api, auth, await prepareLogin(api));
    seal = await api.sealStatus!();
  });
  afterAll(async () => {
    await win.happyDOM.abort();
    win.close();
    m.stop();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("the dev fixture shows one card, with every part of the wording", async () => {
    const panel = await draw();
    const cards = panel.querySelectorAll<HTMLElement>("[data-proposal]");
    expect(cards.length).toBe(1);
    const card = cards[0]!, p = env.proposals![0]!;
    expect(text(card, "h3")).toBe(`${STAGING} · build-1 · Ref ${p.ref}`);
    expect(text(card, ".env-proposal-who")).toBe(`Store values build-1 (agent), from 192.0.2.14, wants to store values in ${STAGING} (Client A / PaaS / Staging env).`);
    expect(card.querySelector(".env-proposal-creates")).toBeNull(); // the set exists
    const op = card.querySelector(".env-mode")!;
    expect(op.textContent).toBe(`Import: REPLACES the whole set. Afterwards ${STAGING} holds exactly the 4 keys build-1 sent; 1 key in it now is removed.`);
    expect(op.classList.contains("warn")).toBe(true);
    const facts = [...card.querySelectorAll(".env-proposal-changes dt")].map((dt) => [dt.textContent, dt.nextElementSibling!.textContent]);
    expect(facts.slice(0, 6)).toEqual([
      ["Added", "SENTRY_DSN"],
      ["Replaced", "APP_SECRET, DATABASE_URL, SMTP_PASSWORD"],
      ["Removed", "TLS_KEY"],
      ["Revision", "7 → 8"],
      ["Commitment", p.commitment],
      ["Ref", p.ref],
    ]);
    expect(facts[6]![0]).toBe("Expires in");
    const left = card.querySelector<HTMLElement>("time.countdown")!;
    expect(left.dataset["until"]).toBe(String(p.expires_at)); // ticks with the page's other countdowns
    expect(left.textContent).toMatch(/^9:\d\d$/);
    expect(text(card, ".env-proposal-values")).toBe(`The values were chosen by build-1: you see their names here, never the values. Once committed they are what every later request for ${STAGING} receives.`);
    expect(text(card, ".env-proposal-compare")).toBe(`Compare the commitment and Ref ${p.ref} with what the CLI printed on build-1.`);
    expect(text(card, ".env-proposal-reason")).toBe("Requester explanation (unverified): rotate the staging credentials after the provider's key roll");
    expect(card.querySelector(".env-proposal-reason")!.classList.contains("agent")).toBe(true); // the untrusted fence
    expect([...card.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["Commit", "Discard"]);
    // Decided alone: nothing to select it by, no duration, no "don't ask again".
    expect(card.querySelectorAll("input, select").length).toBe(0);
    expect(card.textContent).not.toContain("Don't ask again");
    expect(card.textContent).not.toContain("mock-rotated"); // names only, never a value
    panel.remove();
    vault.cancelProposal(p.id);
  });

  test("a new service and set are announced; put and unset say which key", async () => {
    const created = vault.addProposal("client-a/billing/live", "put", { STRIPE_KEY: "mock" }, { create: true, title: "Live env" });
    const unset = vault.addProposal(STAGING, "unset", { TLS_KEY: "" });
    const panel = await draw();
    const c = cardOf(panel, created);
    expect(text(c, ".env-proposal-who")).toContain("wants to store values in client-a/billing/live (Client A / billing / Live env).");
    expect(text(c, ".env-proposal-creates")).toBe("Committing creates the service billing and creates the set live: neither exists yet.");
    expect(c.querySelector(".env-proposal-creates")!.classList.contains("warn")).toBe(true);
    expect(text(c, ".env-mode")).toBe("Put: sets one key, STRIPE_KEY. The other keys stay as they are.");
    expect(c.querySelector(".env-mode")!.classList.contains("warn")).toBe(false);
    expect(text(c, ".env-proposal-changes")).toContain("AddedSTRIPE_KEY");
    expect(text(c, ".env-proposal-changes")).toContain("Revision0 → 1");
    const u = cardOf(panel, unset);
    expect(text(u, ".env-mode")).toBe("Unset: removes one key, TLS_KEY. The other keys stay as they are.");
    expect(text(u, ".env-proposal-changes")).toContain("RemovedTLS_KEY");
    panel.remove();
    vault.cancelProposal(created);
    vault.cancelProposal(unset);
  });

  test("a hostile reason and key name are text, with invisible characters spelled out", async () => {
    const id = vault.addProposal(STAGING, "put", { [HOSTILE_KEY]: "v" }, { reason: HOSTILE_REASON });
    const panel = await draw();
    const card = cardOf(panel, id);
    expect(card.querySelectorAll("img, script, b, [onerror], [onmouseover]").length).toBe(0);
    expect(panel.querySelectorAll("img, script, b").length).toBe(0);
    const reason = text(card, ".env-proposal-reason");
    expect(reason).toContain('<img src=x onerror="alert(1)">');
    expect(reason).toContain("<script>alert(2)</script>");
    expect(reason).toContain("⟨U+202E⟩gnp.exe"); // a direction override cannot reorder the card
    expect(reason).not.toContain("‮");
    expect(text(card, ".env-proposal-changes .added")).toBe(HOSTILE_KEY);
    expect(text(card, ".env-mode")).toBe(`Put: sets one key, ${HOSTILE_KEY}. The other keys stay as they are.`);
    // The review before the tap shows it as text too.
    click(card, "Commit");
    await until(() => !!card.querySelector("[role=status] pre"));
    expect(card.querySelectorAll("img, script, b").length).toBe(0);
    expect(text(card, "[role=status] pre")).toContain("⟨U+202E⟩gnp.exe");
    click(card, "Cancel");
    expect(card.querySelector("[role=status]")!.children.length).toBe(0);
    panel.remove();
    vault.cancelProposal(id);
  });

  test("Commit: the broker's text is checked, then one tap writes the revision", async () => {
    const before = vault.sets.find((s) => s.set_slug === "staging")!.revision;
    const id = vault.addProposal(STAGING, "put", { SENTRY_DSN: "https://mock@sentry.example.com/3" }, { reason: "add error reporting" });
    const panel = await draw();
    const card = cardOf(panel, id);
    const taps = auth.gets.length;
    click(card, "Commit");
    await until(() => !!card.querySelector("[role=status] button.confirm"));
    expect(auth.gets.length).toBe(taps); // nothing is signed until the owner confirms
    const signed = text(card, "[role=status] pre");
    expect(signed).toContain(`Commit · Client A / PaaS / Staging env · Ref ${id.slice(-6)}`);
    expect(signed).toContain("Requester explanation (unverified): add error reporting");
    expect(signed).toContain('"reason": ""');
    click(card, "Commit with passkey");
    await until(() => refreshed === 1);
    expect(auth.gets.length).toBe(taps + 1);
    expect(text(card, "[role=status]")).toBe("Committed.");
    expect(vault.sets.find((s) => s.set_slug === "staging")).toMatchObject({ revision: before + 1 });
    expect(vault.sets.find((s) => s.set_slug === "staging")!.names).toContain("SENTRY_DSN");
    expect(vault.proposals.find((x) => x.id === id)).toMatchObject({ status: "committed", result_revision: before + 1 });
    panel.remove();
    expect((await draw()).querySelector("[data-proposal]")).toBeNull();
  });

  test("Discard is a tap of its own; a proposal that went stale says so on the card", async () => {
    const id = vault.addProposal(STAGING, "import", { ONLY: "1" });
    const stale = vault.addProposal(STAGING, "put", { LATE: "1" });
    const panel = await draw();
    const set = vault.sets.find((s) => s.set_slug === "staging")!, before = structuredClone(set);
    const taps = auth.gets.length, seen = refreshed;
    click(cardOf(panel, id), "Discard");
    await until(() => !!cardOf(panel, id).querySelector("[role=status] button.confirm"));
    expect(text(cardOf(panel, id), "[role=status] pre")).toContain("Nothing is stored; build-1 is told the proposal was discarded.");
    click(cardOf(panel, id), "Discard with passkey");
    await until(() => refreshed === seen + 1);
    expect(auth.gets.length).toBe(taps + 1);
    expect(set).toEqual(before);
    expect(vault.proposals.find((x) => x.id === id)!.status).toBe("discarded");
    // The set moves on under the other card: Commit explains, and no tap is asked for.
    set.revision++;
    click(cardOf(panel, stale), "Commit");
    await until(() => !!cardOf(panel, stale).querySelector("[role=status] .error"));
    expect(text(cardOf(panel, stale), "[role=status] .error")).toContain("the set changed since this was proposed");
    expect(auth.gets.length).toBe(taps + 1);
    set.revision--;
    panel.remove();
  });
});
