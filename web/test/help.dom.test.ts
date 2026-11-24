// The Help page's "Install aqmas and enroll a machine" card: one command for every platform
// that checks the download against the hash the broker supplied (or, per build, the published
// checksum file when it supplied none), installs, and offers enrolment; plus manual blocks.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { cliHashes, helpPage, installCommand, PLATFORMS, setupCommand, sumsFile, type HelpConfig } from "../src/help";

const win = new Window({ url: "http://localhost/" });
const G = globalThis as Record<string, unknown>;
const saved: Record<string, unknown> = {};
const GLOBALS = ["window", "document", "HTMLElement", "Node"];

const base = "https://github.com/example/agent-quartermaster/releases/download/v1.2.3";
const sums = { "aqmas-darwin-arm64": "d".repeat(64), "aqmas-darwin-amd64": "c".repeat(64), "aqmas-linux-amd64": "a".repeat(64), "aqmas-linux-arm64": "b".repeat(64) };
const cfg = (over: Partial<HelpConfig> = {}): HelpConfig => ({
  agent_api_url: "https://agent.example.com:8443",
  cli_download_base_url: base,
  cli_download_source: "github",
  release_version: "1.2.3",
  cli_sha256: sums,
  cli_sha256_sources: 1,
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

  const T = "Install aqmas and enroll a machine";
  const setup = (page: HTMLElement) => page.querySelector("[data-setup] pre")!.textContent!;
  const pin = "sha256:" + "0".repeat(64);
  const caseLine = (text: string, asset: string) => text.split("\n").find((l) => l.includes(`a=${asset};`))!;

  test("one command picks the platform, checks, installs and offers enrolment", () => {
    const page = helpPage(cfg());
    const card = cardOf(page, T);
    const text = setup(page);
    // Every build is in the case, with the broker's hash written into the command.
    for (const p of PLATFORMS) expect(caseLine(text, p.asset)).toBe(`  ${p.cases.join("|")}) a=${p.asset}; h=${sums[p.asset]}; s= ;;`);
    expect(text).toContain('case "$os/$arch" in');
    expect(text).toContain("Linux/aarch64|Linux/arm64)");
    expect(text).toContain("Darwin/x86_64)");
    expect(text).toContain("sysctl -n hw.optional.arm64");
    expect(text).toMatch(/\*\) echo "aqmas: there is no build for \$os \$arch\. .*" >&2; exit 1 ;;/);
    // It says what it will do before doing it.
    expect(text.indexOf("printf 'This downloads")).toBeLessThan(text.indexOf("curl"));
    expect(text).toContain(`'aqmas 1.2.3' "$a" 'https://agent.example.com:8443'`);
    expect(text).toContain(`-o "$a" -- '${base}/'"$a"`);
    expect(text).toContain(`if [ -n "$h" ]; then printf '%s  %s\\n' "$h" "$a" > expected; else`);
    expect(text).toContain("check256 -c expected || {");
    expect(text).toContain('install -m 755 "$a" "$HOME/.local/bin/aqmas.new"\nmv -f "$HOME/.local/bin/aqmas.new" "$HOME/.local/bin/aqmas"');
    expect(text).toContain("comes first on PATH");
    // Install before enrolment; questions on the terminal, not the rest of the paste.
    expect(text.indexOf("aqmas.new")).toBeLessThan(text.indexOf("enroll --server"));
    expect(text).toContain("read -r ok </dev/tty");
    expect(text).toContain("read -r name </dev/tty");
    expect(text).toContain("if ! (: </dev/tty) 2>/dev/null; then");
    // The name asked for is always passed: aqmasd replaces by name, so it is never left to guess.
    expect(text).toContain(`"$HOME/.local/bin/aqmas" enroll --server 'https://agent.example.com:8443' --ca-pin '${pin}' --name "$name")`);
    // y, yes or Enter is yes; n or no is no; anything else asks again.
    expect(text).toContain(`case "$ok" in ""|[yY]|[yY][eE][sS]) break ;; [nN]|[nN][oO]) `);
    expect(text).toContain(`*) echo "Please answer y or n." ;; esac\ndone`);
    // localhost is no default; a card marked "replaces" is explained before the name is asked.
    expect(text).toContain('case "$n" in localhost|localhost-*) n= ;; esac');
    expect(text.indexOf("approving it revokes the access of that other machine")).toBeLessThan(text.indexOf("Host name"));
    // Pasted into interactive zsh: no comments, no bash-only syntax.
    for (const l of text.split("\n")) expect(l.trimStart().startsWith("#")).toBe(false);
    expect(text).not.toContain("[[");
    expect(text).not.toContain("read -p");
    expect(text.startsWith("(set -e\n")).toBe(true);
    expect(text.endsWith(")")).toBe(true);

    expect(card.querySelector(".install-check")!.getAttribute("data-check")).toBe("broker");
    expect(card.textContent).toContain("aqmas 1.2.3 from GitHub");
    // Where the hashes come from is said as it is: one source is GitHub's own word.
    expect(card.textContent).toContain("GitHub’s published checksums alone");
    expect(card.textContent).not.toContain("second, independent source");
    const two = cardOf(helpPage(cfg({ cli_sha256_sources: 2 })), T);
    expect(two.textContent).toContain("GitHub and a second, independent source published the same hashes");
    expect(two.textContent).not.toContain("checksums alone");
    expect(card.textContent).toContain("~/.zshrc");
    expect(card.textContent).toContain("~/.bashrc");
    expect(card.textContent).toContain("sudo aqmas upgrade");
    // Enrolment is in the same card, for a machine that already has aqmas too.
    expect([...page.querySelectorAll("section.card h2")].map((e) => e.textContent)).not.toContain("Enroll a machine");
    expect([...card.querySelectorAll(".command pre")].map((e) => e.textContent)).toContain(`aqmas enroll --server 'https://agent.example.com:8443' --ca-pin '${pin}'`);
    for (const s of ["enrolled under its hostname", "--name <name>", "not the address of this web page", "--force --name <its enrolled name>", "enrol this one under its own name with --force --name <name>", "admitted to an organisation", "Cross-check the CA pin"]) expect(card.textContent).toContain(s);
    // Every command on the page keeps its copy button.
    expect(page.querySelectorAll("pre").length).toBe(page.querySelectorAll(".command button").length);
  });

  test("manual steps keep one install block per platform", () => {
    const page = helpPage(cfg());
    const manual = cardOf(page, T).querySelector("details.manual-install")!;
    expect(manual.querySelector("summary")!.textContent).toContain("Manual steps");
    expect(manual.textContent).toContain("uname -sm");
    expect([...manual.querySelectorAll("[data-platform]")].map((e) => e.getAttribute("data-platform"))).toEqual(["aqmas-linux-arm64", "aqmas-linux-amd64", "aqmas-darwin-arm64", "aqmas-darwin-amd64"]);
    expect([...manual.querySelectorAll("h3")].map((e) => e.textContent)).toEqual(["Linux arm64", "Linux x86-64", "macOS (Apple Silicon)", "macOS (Intel)"]);
    for (const p of PLATFORMS) {
      const text = block(page, p.asset);
      const sum = p.asset.startsWith("aqmas-darwin-") ? "shasum -a 256" : "sha256sum";
      expect(text.split("\n")).toEqual([
        "(set -e",
        `d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; cd "$d"`,
        `curl -fLsS --proto '=https' --proto-redir '=https' -o ${p.asset} -- '${base}/${p.asset}'`,
        `echo '${sums[p.asset]}  ${p.asset}' | ${sum} -c -`,
        'mkdir -p "$HOME/.local/bin"',
        `install -m 755 ${p.asset} "$HOME/.local/bin/aqmas.new"`,
        'mv -f "$HOME/.local/bin/aqmas.new" "$HOME/.local/bin/aqmas"',
        '"$HOME/.local/bin/aqmas" version',
        "p=$(command -v aqmas || true)",
        'if [ -n "$p" ] && ! [ "$p" -ef "$HOME/.local/bin/aqmas" ]; then echo "Note: $p comes first on PATH and is what \\"aqmas\\" runs; remove it or put ~/.local/bin first."; fi)',
      ]);
      expect(text).not.toContain("SHA256SUMS");
      expect(manual.textContent).toContain(p.uname);
    }
  });

  test("an operator's address is used with the broker's hashes", () => {
    const page = helpPage(cfg({ cli_download_base_url: "https://downloads.example.com/aqmas/", cli_download_source: "config" }));
    expect(block(page, "aqmas-linux-amd64")).toContain(`-- 'https://downloads.example.com/aqmas/aqmas-linux-amd64'\necho '${"a".repeat(64)}  aqmas-linux-amd64' | sha256sum -c -`);
    expect(setup(page)).toContain(`-- 'https://downloads.example.com/aqmas/'"$a"`);
    expect(cardOf(page, T).textContent).toContain("from the address the operator configured");
  });

  test("a build the broker's record has no hash for is checked against its published file, and the page says so", () => {
    // A broker upgraded from 0.9.2 recorded three hashes: aqmas-darwin-amd64 came later.
    const { ["aqmas-darwin-amd64"]: _, ...three } = sums;
    for (const c of [cfg({ cli_sha256: three }), cfg({ cli_sha256: { ...sums, "aqmas-darwin-amd64": "x'; rm -rf ~ #" } })]) {
      const page = helpPage(c);
      const card = cardOf(page, T);
      const text = setup(page);
      expect(caseLine(text, "aqmas-darwin-amd64")).toBe("  Darwin/x86_64) a=aqmas-darwin-amd64; h=; s=SHA256SUMS.extra ;;");
      for (const a of ["aqmas-linux-arm64", "aqmas-linux-amd64", "aqmas-darwin-arm64"] as const) expect(caseLine(text, a)).toContain(`h=${sums[a]}; s= ;;`);
      expect(text).toContain(`-o sums -- '${base}/'"$s"; grep "  $a\\$" sums > expected; fi`);
      expect(text).not.toContain("rm -rf ~");
      expect(card.querySelector(".install-check")!.getAttribute("data-check")).toBe("mixed");
      expect(card.textContent).toContain("no hash for macOS (Intel)");
      expect(card.textContent).toContain("SHA256SUMS.extra file published beside it");
      expect(card.textContent).toContain("a check against GitHub only");
      expect(block(page, "aqmas-darwin-amd64")).toContain(`-o SHA256SUMS.extra -- '${base}/SHA256SUMS.extra'\ngrep '  aqmas-darwin-amd64$' SHA256SUMS.extra > expected\nshasum -a 256 -c expected\n`);
      expect(block(page, "aqmas-linux-arm64")).toContain(`echo '${sums["aqmas-linux-arm64"]}  aqmas-linux-arm64'`);
    }
  });

  test("without broker hashes the command checks GitHub's published sums and says so", () => {
    const variants: (Record<string, string> | undefined)[] = [undefined, {}, { "aqmas-linux-arm64": "", "aqmas-darwin-arm64": "x'; rm -rf ~ #" }];
    for (const cli_sha256 of variants) {
      const c = cfg({ cli_sha256 });
      expect(cliHashes(c)).toEqual({});
      const page = helpPage(c);
      const card = cardOf(page, T);
      expect(card.querySelector(".install-check")!.getAttribute("data-check")).toBe("published");
      expect(card.textContent).toContain("a check against GitHub only");
      const text = setup(page);
      for (const p of PLATFORMS) expect(caseLine(text, p.asset)).toBe(`  ${p.cases.join("|")}) a=${p.asset}; h=; s=${sumsFile(p.asset)} ;;`);
      expect(text).not.toContain("rm -rf ~");
      for (const p of PLATFORMS) {
        const b = block(page, p.asset);
        const sum = p.asset.startsWith("aqmas-darwin-") ? "shasum -a 256" : "sha256sum";
        const f = sumsFile(p.asset);
        expect(b).toContain(`-o ${f} -- '${base}/${f}'\ngrep '  ${p.asset}$' ${f} > expected\n${sum} -c expected\n`);
        expect(b).not.toContain("echo '");
      }
    }
    const own = cardOf(helpPage(cfg({ cli_sha256: undefined, cli_download_source: "config" })), T);
    expect(own.textContent).toContain("at the same address the operator configured");
    expect(own.textContent).not.toContain("GitHub only");
  });

  test("without an agent API address the command installs only and says why", () => {
    const page = helpPage(cfg({ agent_api_url: "" }));
    const text = setup(page);
    expect(text).not.toContain("enroll --server");
    expect(text).not.toContain("/dev/tty");
    expect(text).toContain("ask the operator to set agent_api_url");
    expect(text.endsWith(")")).toBe(true);
    expect(cardOf(page, T).textContent).toContain("It does not enroll");
    expect(cardOf(page, T).textContent).toContain("ask the operator to set agent_api_url");
  });

  test("with no address known there are no download commands", () => {
    const page = helpPage(cfg({ cli_download_base_url: "", cli_download_source: "", release_version: undefined, cli_sha256: undefined }));
    const card = cardOf(page, T);
    expect(card.querySelector("[data-platform]")).toBeNull();
    expect(card.querySelector("[data-setup]")).toBeNull();
    expect(card.textContent).toContain("from the operator’s build");
    expect(card.textContent).not.toContain("curl");
    expect(card.textContent).toContain("aqmas upgrade");
    expect([...card.querySelectorAll(".command pre")].map((e) => e.textContent)).toContain(`aqmas enroll --server 'https://agent.example.com:8443' --ca-pin '${pin}'`);
    expect(page.querySelectorAll("pre").length).toBe(page.querySelectorAll(".command button").length);
  });

  test("addresses are shell-quoted", () => {
    expect(installCommand("https://example.com/it's", "aqmas-linux-arm64", "b".repeat(64))).toContain(`-- 'https://example.com/it'\\''s/aqmas-linux-arm64'`);
    const t = setupCommand({ base: "https://example.com/it's", hashes: { "aqmas-linux-arm64": "b".repeat(64) }, version: "1.2.3'; x", server: "https://a.example.com/'$(id)", pin: "sha256:'x" });
    expect(t).toContain(`-o "$a" -- 'https://example.com/it'\\''s/'"$a"`);
    expect(t).toContain(`enroll --server 'https://a.example.com/'\\''$(id)' --ca-pin 'sha256:'\\''x' --name "$name")`);
    expect(t).toContain(`'aqmas 1.2.3'\\''; x' "$a"`);
  });
});
