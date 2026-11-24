// The Help page's "Install the aqmas CLI" card: one block per platform that checks the
// download against the hash the broker supplied, and what is shown when it supplied none.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { cliHashes, helpPage, installCommand, PLATFORMS, type HelpConfig } from "../src/help";

const win = new Window({ url: "http://localhost/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "HTMLElement", "Node"];

const base = "https://github.com/example/agent-quartermaster/releases/download/v1.2.3";
const sums = { "aqmas-darwin-arm64": "d".repeat(64), "aqmas-linux-amd64": "a".repeat(64), "aqmas-linux-arm64": "b".repeat(64) };
const cfg = (over: Partial<HelpConfig> = {}): HelpConfig => ({
  agent_api_url: "https://agent.example.com:8443",
  cli_download_base_url: base,
  cli_download_source: "github",
  release_version: "1.2.3",
  cli_sha256: sums,
  ca_pin: "sha256:" + "0".repeat(64),
  owner_max_seconds: 86400,
  ...over,
});
const cardOf = (page: HTMLElement, title: string) => [...page.querySelectorAll("section.card")].find((s) => s.querySelector("h2")!.textContent === title)!;
const block = (page: HTMLElement, asset: string) => page.querySelector(`[data-platform="${asset}"] pre`)!.textContent!;

describe("Help: install the aqmas CLI", () => {
  beforeAll(() => {
    for (const k of GLOBALS) {
      saved[k] = G[k];
      G[k] = k === "window" ? win : (win as unknown as Record<string, unknown>)[k];
    }
  });
  afterAll(async () => {
    await win.happyDOM.abort();
    win.close();
    for (const k of GLOBALS) G[k] = saved[k];
  });

  test("every platform gets one block checked against the broker's hash", () => {
    const page = helpPage(cfg());
    const card = cardOf(page, "Install the aqmas CLI");
    expect([...card.querySelectorAll("[data-platform]")].map((e) => e.getAttribute("data-platform"))).toEqual(["aqmas-linux-arm64", "aqmas-linux-amd64", "aqmas-darwin-arm64"]);
    expect([...card.querySelectorAll("h3")].map((e) => e.textContent)).toEqual(["Linux arm64", "Linux x86-64", "macOS (Apple Silicon)", "Upgrade"]);
    for (const p of PLATFORMS) {
      const text = block(page, p.asset);
      const sum = p.asset === "aqmas-darwin-arm64" ? "shasum -a 256" : "sha256sum";
      expect(text.split("\n")).toEqual([
        "(set -e",
        `d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"`,
        `curl -fLsS --proto '=https' --proto-redir '=https' -o ${p.asset} -- '${base}/${p.asset}'`,
        `echo '${sums[p.asset]}  ${p.asset}' | ${sum} -c -`,
        'mkdir -p "$HOME/.local/bin"',
        `install -m 755 ${p.asset} "$HOME/.local/bin/aqmas"`,
        '"$HOME/.local/bin/aqmas" version)',
      ]);
      expect(text).not.toContain("SHA256SUMS");
      expect(card.textContent).toContain(p.uname);
    }
    expect(card.querySelector(".install-check")!.getAttribute("data-check")).toBe("broker");
    expect(card.textContent).toContain("aqmas 1.2.3 from GitHub");
    expect(card.textContent).toContain("uname -sm");
    expect(card.textContent).toContain("~/.zshrc");
    expect(card.textContent).toContain("~/.bashrc");
    expect(card.textContent).toContain("sudo aqmas upgrade");
    // Every command on the page keeps its copy button.
    expect(page.querySelectorAll("pre").length).toBe(page.querySelectorAll(".command button").length);
    // Enrolment follows the install and says what trips people up.
    const cards = [...page.querySelectorAll("section.card h2")].map((e) => e.textContent);
    expect(cards.indexOf("Enroll a machine")).toBe(cards.indexOf("Install the aqmas CLI") + 1);
    const enroll = cardOf(page, "Enroll a machine");
    expect(enroll.querySelector("pre")!.textContent).toBe(`aqmas enroll --name '<name>' --server 'https://agent.example.com:8443' --ca-pin 'sha256:${"0".repeat(64)}'`);
    for (const s of ["not the address of this web page", "--force", "admitted to an organisation"]) expect(enroll.textContent).toContain(s);
  });

  test("an operator's address is used with the broker's hashes", () => {
    const page = helpPage(cfg({ cli_download_base_url: "https://downloads.example.com/aqmas/", cli_download_source: "config" }));
    expect(block(page, "aqmas-linux-amd64")).toContain(`-- 'https://downloads.example.com/aqmas/aqmas-linux-amd64'\necho '${"a".repeat(64)}  aqmas-linux-amd64' | sha256sum -c -`);
    expect(cardOf(page, "Install the aqmas CLI").textContent).toContain("from the address the operator configured");
  });

  test("without broker hashes the blocks check GitHub's SHA256SUMS and say so", () => {
    // A missing, partial or malformed set is no set: never a block with half a hash.
    for (const cli_sha256 of [undefined, { ...sums, "aqmas-linux-arm64": "" }, { ...sums, "aqmas-darwin-arm64": "x'; rm -rf ~ #" }]) {
      const c = cfg({ cli_sha256 });
      expect(cliHashes(c)).toBeUndefined();
      const page = helpPage(c);
      const card = cardOf(page, "Install the aqmas CLI");
      expect(card.querySelector(".install-check")!.getAttribute("data-check")).toBe("published");
      expect(card.textContent).toContain("a check against GitHub only");
      for (const p of PLATFORMS) {
        const text = block(page, p.asset);
        const sum = p.asset === "aqmas-darwin-arm64" ? "shasum -a 256" : "sha256sum";
        expect(text).toContain(`-o SHA256SUMS -- '${base}/SHA256SUMS'\ngrep '  ${p.asset}$' SHA256SUMS > expected\n${sum} -c expected\n`);
        expect(text).not.toContain("echo");
        expect(text).not.toContain("rm -rf ~");
      }
    }
    const own = cardOf(helpPage(cfg({ cli_sha256: undefined, cli_download_source: "config" })), "Install the aqmas CLI");
    expect(own.textContent).toContain("at the same address the operator configured");
    expect(own.textContent).not.toContain("GitHub only");
  });

  test("with no address known there are no download blocks", () => {
    const page = helpPage(cfg({ cli_download_base_url: "", cli_download_source: "", release_version: undefined, cli_sha256: undefined }));
    const card = cardOf(page, "Install the aqmas CLI");
    expect(card.querySelector("[data-platform]")).toBeNull();
    expect(card.textContent).toContain("from the operator’s build");
    expect(card.textContent).not.toContain("curl");
    expect(card.textContent).toContain("aqmas upgrade");
    expect(page.querySelectorAll("pre").length).toBe(page.querySelectorAll(".command button").length);
  });

  test("addresses are shell-quoted", () => {
    expect(installCommand("https://example.com/it's", "aqmas-linux-arm64", "b".repeat(64))).toContain(`-- 'https://example.com/it'\\''s/aqmas-linux-arm64'`);
  });
});
