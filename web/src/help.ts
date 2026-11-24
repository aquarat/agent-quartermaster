import { h, type Child } from "./dom";

export interface HelpConfig {
  agent_api_url: string;
  /** Configured address, else the public GitHub release of the running version; "" when unknown. */
  cli_download_base_url: string;
  /** Which of the two the address is: "config", "github" or "". */
  cli_download_source?: string;
  /** The release the broker runs; absent for a development build. */
  release_version?: string;
  /** SHA-256 per CLI asset from the broker's verified record of that release; absent without one. */
  cli_sha256?: Record<string, string>;
  /** How many published sources agreed on those hashes when the record was made (1 or 2). */
  cli_sha256_sources?: number;
  ca_pin: string;
  owner_max_seconds: number;
}

// Commands are copied as well as displayed: HTML escaping alone isn't shell quoting.
const quote = (s: string) => "'" + s.replaceAll("'", "'\\''") + "'";

function command(text: string) {
  const button = h("button", { type: "button", class: "btn" }, "Copy");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Select and copy the command";
    }
  });
  return h("div", { class: "command" }, h("pre", null, h("code", null, text)), button);
}

/** The CLI builds, in the words of the page and of `uname -sm` on such a machine. */
export const PLATFORMS = [
  { asset: "aqmas-linux-arm64", title: "Linux arm64", uname: "Linux aarch64" },
  { asset: "aqmas-linux-amd64", title: "Linux x86-64", uname: "Linux x86_64" },
  { asset: "aqmas-darwin-arm64", title: "macOS (Apple Silicon)", uname: "Darwin arm64" },
] as const;

const sha256 = /^[0-9a-f]{64}$/;

/** The broker's hashes, only when it gave a well-formed one for every CLI build. */
export function cliHashes(c: HelpConfig): Record<string, string> | undefined {
  const sums = c.cli_sha256;
  return sums && PLATFORMS.every((p) => sha256.test(sums[p.asset] ?? "")) ? sums : undefined;
}

/**
 * One paste for bash or zsh: download into a fresh temporary directory, verify, install as
 * ~/.local/bin/aqmas, print the version. The subshell keeps `set -e` and the directory change
 * out of the user's shell, and any failing step ends it before the install.
 * With `hash` the download is checked against that value, which the broker supplied. Without
 * it the only reference left is the SHA256SUMS published beside the download.
 * The file goes in beside the old one and is renamed over it, so a running or half-written
 * aqmas is never what the name points at. Last, a copy elsewhere that comes first on PATH
 * (an older system-wide install) is named, because it is what typing "aqmas" would still run.
 */
export function installCommand(base: string, asset: string, hash?: string) {
  const check = asset.startsWith("aqmas-darwin-") ? "shasum -a 256" : "sha256sum";
  const curl = "curl -fLsS --proto '=https' --proto-redir '=https'";
  const verify = hash
    ? [`echo ${quote(`${hash}  ${asset}`)} | ${check} -c -`]
    : [`${curl} -o SHA256SUMS -- ${quote(base + "/SHA256SUMS")}`, `grep ${quote(`  ${asset}$`)} SHA256SUMS > expected`, `${check} -c expected`];
  return [
    "(set -e",
    'd=$(mktemp -d); trap \'rm -rf "$d"\' EXIT; cd "$d"',
    `${curl} -o ${asset} -- ${quote(base + "/" + asset)}`,
    ...verify,
    'mkdir -p "$HOME/.local/bin"',
    `install -m 755 ${asset} "$HOME/.local/bin/aqmas.new"`,
    'mv -f "$HOME/.local/bin/aqmas.new" "$HOME/.local/bin/aqmas"',
    '"$HOME/.local/bin/aqmas" version',
    'p=$(command -v aqmas || true)',
    'if [ -n "$p" ] && ! [ "$p" -ef "$HOME/.local/bin/aqmas" ]; then echo "Note: $p comes first on PATH and is what \\"aqmas\\" runs; remove it or put ~/.local/bin first."; fi)',
  ].join("\n");
}

function installCard(c: HelpConfig, card: (title: string, ...children: Child[]) => HTMLElement) {
  const p = (...s: Child[]) => h("p", null, s);
  const code = (s: string) => h("code", null, s);
  const base = c.cli_download_base_url.replace(/\/+$/, "");
  const hashes = cliHashes(c);
  const version = c.release_version ? `aqmas ${c.release_version}` : "aqmas";
  const after = [
    p("If the shell then answers “command not found” for aqmas, ", code("~/.local/bin"), " is not on its PATH. Add it once and open a new terminal: zsh (the macOS default) reads ", code("~/.zshrc"), ", bash reads ", code("~/.bashrc"), "."),
    command(`echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc`),
    command(`echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`),
    h("h3", null, "Upgrade"),
    p("Installed in ", code("~/.local/bin"), ", aqmas upgrades itself later without sudo, from this broker and with the same checks. A system-wide install (for example /usr/local/bin) needs ", code("sudo aqmas upgrade"), " instead."),
    command("aqmas upgrade"),
  ];
  if (!base)
    return card(
      "Install the aqmas CLI",
      p("This broker knows no download address for its release. Copy the aqmas binary for this machine from the operator’s build, then install it where your user can replace it:"),
      command('mkdir -p "$HOME/.local/bin" && install -m 755 aqmas "$HOME/.local/bin/aqmas.new" && mv -f "$HOME/.local/bin/aqmas.new" "$HOME/.local/bin/aqmas" && "$HOME/.local/bin/aqmas" version'),
      after,
    );
  const from = c.cli_download_source === "github" ? "GitHub" : "the address the operator configured";
  return card(
    "Install the aqmas CLI",
    p("On the machine that needs aqmas, find out which build it takes, then paste the block under that heading into its terminal (bash or zsh)."),
    command("uname -sm"),
    h("dl", { class: "facts" }, ...PLATFORMS.map((pl) => [h("dt", null, pl.uname), h("dd", null, pl.title)])),
    hashes
      ? h(
          "p",
          { class: "install-check", "data-check": "broker" },
          `Each block downloads ${version} from ${from} into a temporary directory and checks it against the SHA-256 this broker recorded when it verified the release it runs. `,
          c.cli_sha256_sources === 2
            ? "GitHub and a second, independent source published the same hashes then. "
            : "That record was made from GitHub’s published checksums alone, so it is GitHub’s word as it stood then, not a second opinion. ",
          "The hash is in the command itself: a file that differs from the recorded release stops the block and nothing is installed. Otherwise it installs ",
          code("~/.local/bin/aqmas"),
          " and prints its version. If another aqmas comes first on PATH, the block says so.",
        )
      : h(
          "p",
          { class: "install-check", "data-check": "published" },
          c.cli_download_source === "github"
            ? `This broker holds no verified record of the release it runs (self-update is not set up yet, or its record is of another version), so each block checks ${version} against the SHA256SUMS file GitHub publishes beside it. That is a check against GitHub only: it catches a damaged download, not a replaced release. `
            : `This broker holds no verified record of the release it runs, so each block checks ${version} against the SHA256SUMS file at the same address the operator configured. That shows the download arrived whole and nothing more: compare the SHA-256 of the installed file with an independently trusted release digest before relying on it. `,
          "A failed check stops the block and installs nothing; otherwise it installs ",
          code("~/.local/bin/aqmas"),
          " and prints its version.",
        ),
    ...PLATFORMS.map((pl) => [h("h3", null, pl.title), h("div", { "data-platform": pl.asset }, command(installCommand(base, pl.asset, hashes?.[pl.asset])))]),
    after,
  );
}

export function helpPage(c: HelpConfig) {
  const card = (title: string, ...children: Child[]) => h("section", { class: "card" }, h("h2", null, title), children);
  const p = (s: string) => h("p", null, s);
  const base = c.cli_download_base_url.replace(/\/+$/, "");
  const opts =
    "-F none -o IdentitiesOnly=yes -o IdentityAgent=none -i KEY -o CertificateFile=CERT -o UserKnownHostsFile=KNOWN -o StrictHostKeyChecking=yes";
  return h(
    "div",
    { class: "help" },
    card(
      "Where things are",
      h(
        "dl",
        { class: "facts help-map" },
        ...[
          ["Approvals", "Everything waiting for you (access requests, signature requests, env releases, hosts asking to join), then who holds access now and your auto-approvals. The number on the tab counts what waits, on every page."],
          ["Vault", "Every credential the broker holds, as one searchable list: env sets, signing keys, the Cloudflare parent credential, the CAs and the access rules. Filter by type or organisation; open an item for its fields, who may ask for it and what happened to it. “Add item” creates a new one."],
          ["Hosts", "Enrolled hosts, the organisations each may ask for (Admit, Remove) and Revoke. A host that has joined but is admitted nowhere is marked “Not admitted” and can ask for nothing; “Let it join…” on Approvals offers the admission in the same go."],
          ["Activity", "The audit log, with filters."],
          ["Security", "Whether your passkeys can open your credentials (and Enable for the ones that cannot), passkeys, the buckets open right now with Reopen, Rekey and Close all, approval windows, and the recovery key."],
          ["Settings", "Setup and upgrades, and each organisation's policies."],
        ].map(([k, v]) => [h("dt", null, k), h("dd", null, v)]),
      ),
      p("The pill at the top right says how many buckets are decrypted right now; it opens a panel with what is open, what waits and Close all. Search (the magnifier, / or Ctrl+K) finds vault items by name, path or key name, hosts, passkeys, pages and actions."),
    ),
    card(
      "Add, change and look at a credential",
      p("Vault → Add item. Choose Env set (values a command gets as environment variables) or Signing key, then the organisation and service it belongs to and its name. A new organisation or service is created on the way: each is one passkey approval, and a new organisation also gets its own encryption key (three taps). The slug becomes part of the path hosts ask for and cannot be changed later."),
      p("Open an env set to add, replace or remove keys, or drop a .env file on it; “Review and save” shows exactly what changes before the tap. The form is write-only: stored values are never loaded into it. Reveal shows one value, or all of them, for 60 seconds after a passkey tap of its own, and each reveal is logged with the key names; Copy is next to a revealed value. An organisation can have Reveal turned off (the item's “More”)."),
      p("There is no rename, move or delete of a whole item yet: remove its keys instead (an empty set delivers nothing), and ask before reusing a slug."),
    ),
    installCard(c, card),
    card(
      "Enroll a machine",
      p("With aqmas installed (above), enroll the machine with this broker. Cross-check the CA pin once against an independently recorded copy. A faked help page could point a new host at another server."),
      c.agent_api_url
        ? command(`aqmas enroll --server ${quote(c.agent_api_url)} --ca-pin ${quote(c.ca_pin)}`)
        : p("Ask the operator to set agent_api_url to show the enrollment command."),
      p(
        "The machine is enrolled under its hostname (up to the first dot, lowercased); add --name <name> to choose another. --server is the agent API address shown here, not the address of this web page: the CLI cannot enroll through the web UI. If the machine already has an enrollment (for example a configuration copied from another machine, or an expired certificate), add --force to replace it.",
      ),
      p(
        "The command prints a Ref and waits. Under Approvals, match the Ref and client key to the terminal, confirm its connecting address and class, and check “replaces”: approving a replacement revokes the old identity.",
      ),
      p("An approved host can ask for nothing until it is admitted to an organisation. The approval card offers that in the same go (“Let it join…”); later it is Admit under Hosts."),
    ),
    card(
      "CLI quick reference",
      p("SSH selectors accept a target name, alias, or address. Specify host:port (or [IPv6]:port) when services share an address."),
      ...[
        ["SSH login", 'aqmas ssh alice@web-1 --why "inspect logs"'],
        ["Roaming terminal (needs mosh on both ends)", 'aqmas mosh alice@web-1 --why "console"'],
        ["Print certificate paths", 'aqmas cert alice@web-1 --why "copy files"'],
        ["Active grants", "aqmas list --json"],
        ["Local enrollment and cache", "aqmas status"],
        ["Generate SSH config", "aqmas ssh-config alice@web-1"],
        ["List Cloudflare scopes", "aqmas cf scopes"],
        ["Request a scope", 'aqmas cf request cf.read --why "inventory"'],
        ["Call the proxy", "aqmas cf api GET /zones"],
        ["Use curl through the proxy", "aqmas cf curl -- https://api.cloudflare.com/client/v4/zones"],
        ["Run a tool through the proxy", 'aqmas cf env --request cf.read --why "inspect account" -- wrangler whoami'],
        ["Request a child token (if enabled)", 'aqmas cf token cf.workers.deploy script=demo --why "publish demo" -- wrangler deploy'],
        ["List change snapshots", "aqmas cf snapshot list"],
        ["Inspect a snapshot", "aqmas cf snapshot get 'SNAPSHOT-ID'"],
        ["Print version", "aqmas version"],
      ].map(([label, cmd]) => [h("h3", null, label), command(cmd!)]),
    ),
    card(
      "Prefer aqmas sign over fetching a key",
      p(
        "Where a signing scheme exists, the key should not leave aqmas. Put it in a signing key set (Vault) and have the host ask for signatures: the CLI hashes the files locally, the approval card shows each file name, size and SHA-256, and aqmas returns the signatures. The private key is never delivered, revealed or exported.",
      ),
      command('aqmas sign personal/firmware/release-key --why "release 1.2.3" image.bin'),
      p("Writes image.bin.sig. Several files, stdin (-) and a bare digest work too; --ttl and --count ask for a time-boxed grant that later calls reuse without another tap."),
      command('aqmas sign personal/firmware/release-key --why "nightly builds" --ttl 30m --count 20 build/*.bin'),
      command('aqmas sign personal/firmware/release-key --why "release 1.2.3" --digest sha256:<hex>'),
      p("aqmas run remains for tools that can only read a secret from their environment, where no signing scheme fits. A value delivered that way has left aqmas for good: rotate it at its provider when in doubt."),
      command('aqmas run client-a/paas/staging --why "check migration" -- ./migrate status'),
    ),
    card(
      "Git, scp and rsync",
      p("Run cert first. Replace KEY, CERT, KNOWN, address and port below with the printed values. Use a pinned target for these recipes."),
      command('aqmas cert git@forgejo --why "fetch repository"'),
      command(`GIT_SSH_COMMAND='ssh ${opts} -p 2222' git ls-remote ssh://git@192.0.2.10:2222/demo/repo.git`),
      command('aqmas cert alice@web-1 --why "transfer report"'),
      command(`scp ${opts} -P 22 report.txt alice@192.0.2.10:`),
      command(`rsync -e 'ssh ${opts} -p 22' report.txt alice@192.0.2.10:`),
    ),
    card(
      "Opt-in ssh-config",
      command("aqmas ssh-config alice@web-1"),
      p(
        "Review the snippet and place it near the top of ~/.ssh/config. Use canonical target names. Match exec runs cert on each connection, may wait for approval, and uses a fixed reason. If it fails, SSH falls through to your other keys and config. Set the user explicitly; DNS/address and port come from your SSH config. Pin the target host key. Regenerate if the cache moves; concurrent renewal can race the current symlink.",
      ),
    ),
    card(
      "Longer sessions",
      p(
        `On your own device, add --owner-device at enrollment and confirm that class on the card. Its SSH certificate limit here is ${c.owner_max_seconds} seconds, subject to target caps. Owner-device sessions are never subject to future session cutting at grant expiry.`,
      ),
      command(`aqmas ssh alice@web-1 --fresh --ttl ${c.owner_max_seconds}s --why "owner maintenance"`),
    ),
    card(
      "Credential buckets",
      p(
        "Every secret aqmas keeps (the SSH user CA, the internal CA, each organisation's Cloudflare proxy token, each env set and each signer key) is in its own encrypted bucket. Writing a value needs nothing open: it is encrypted to the bucket's public key. Reading one needs the bucket open, and only an approval opens it.",
      ),
      p(
        "Buckets belong to a scope: the installation (the two CAs) or one organisation. Each scope has its own key, wrapped once for every passkey enabled for it and once for your offline recovery key. One passkey tap opens at most two scope keys, for the length of the tap: the broker unwraps exactly the buckets the card lists and wipes the scope key at once.",
      ),
      p(
        "Before you tap, the card says what the tap opens and for how long, for example “Opens SSH user CA: for this action only” or “Opens personal Cloudflare proxy token: while the grant lasts”. The passkey signs that list together with the decision; a page that changes it is refused. A bucket stays open only while something holds it: one operation (instant), a Cloudflare grant, an env release until collected (10 minutes at most), a signing grant, a standing rule, auto-approval, or an approval window. Security → Buckets shows every hold and the header says how many buckets are open, or “nothing open”.",
      ),
      p(
        "After a restart nothing is open, and nothing needs to be until it is used. Grants that need a bucket pause; agents wait with “closed: waiting for the owner to reopen it” and keep their deadline. Security → Buckets lists them with Reopen (one tap opens up to two scopes). A standing rule or auto-approval needs one tap per restart, then none until the rule ends.",
      ),
      p(
        "Close all (Security → Buckets, one tap) wipes every open bucket key and hold and ends every approval window, without a restart. Use it when you step away or suspect something.",
      ),
      p(
        "Enabling a passkey: Security opens with how many of your passkeys can open your credentials. “Enable the other N” walks through them one after the other; or use Enable on one passkey under Security → Passkeys. The passkey you are signed in with taps first (that tap opens the scope keys), then the new one taps once per two scopes. Test checks a passkey can open its scopes. A passkey without the PRF extension signs in, denies, revokes and approves while buckets are already open, but cannot open a closed one by itself; the card says which passkey can.",
      ),
      p(
        "Remember this browser (for a passkey without PRF, such as one kept in some password managers): Enable offers it when the passkey returns no PRF result. This browser then makes a key that cannot be exported and keeps it in its own storage; from then on that passkey opens your credentials from this browser, and does everything a PRF passkey does there (approve, reveal, windows, rekey, enable others). The trade-off: anyone who has this browser profile and that passkey can open your credentials, where normally the passkey alone holds the secret. And anyone who has this browser profile and a copy of the broker's database, or of a backup of it, can open them with no passkey and no tap. The broker by itself stores only ciphertext it cannot open. Each remembered browser is listed with its name and the start of its key's fingerprint; two browsers of one passkey cannot have the same name. Security → Passkeys marks such a passkey “Browser key” and lists its remembered browsers with a label, when each was added and last used, and Forget. If the browser's storage is cleared (a private window, cleared site data, storage eviction) the browser is simply no longer remembered: enable it again. A passkey that has PRF is never moved to this path.",
      ),
      p(
        "Recovery: if no passkey can open a scope any more, Security → Recovery key enrols a passkey from your offline recovery key, and the recovery drill proves the key works without writing anything. This pastes the recovery key into a web page, so prefer enabling from another passkey. If a passkey or a backup is lost or stolen, remove it and Rekey its scopes (Security → Buckets): removing a passkey does not revoke copies of its wraps in old backups.",
      ),
      p(
        "Honest limits: buckets protect snapshots (a stolen disk or backup, a memory dump, brief root). They do not protect against an attacker who stays on the machine with root: every bucket is exposed as it is used. A window keeps its bucket open for its whole length, and auto-approval keeps the Cloudflare proxy token open from the first approval after a restart until the next restart; what may be approved meanwhile is limited by policy, not by cryptography. A malicious approval page can still turn your tap into another action, as before, and learn the keys of the scopes that tap opens.",
      ),
    ),
    card(
      "Troubleshooting",
      p(
        "5 — Server unreachable or TLS failed: check the agent API URL, route and certificate validity. On a pin mismatch, stop and verify the CA independently; do not bypass the check. For an expired client certificate, verify the pin and re-enroll with --force; review the replacement card.",
      ),
      p(
        "3 — Denied or revoked: review the decision before requesting again. 4 — Expired: submit a new request. 130 — Cancelled. 2 — Usage. 1 — Other error. 0 — Success; SSH, mosh and wrapped commands return their own exit status.",
      ),
      p("If aqmasd is down, use your emergency access."),
    ),
    card(
      "Bastion access",
      p("The bastion that runs aqmas can itself be reached in three controlled ways, once you have run “Allow aqmas access to the bastion” under Settings → Bastion access. Your emergency key is never touched and stays the way in when aqmas is down."),
      h("h3", null, "Inspect (amber card)"),
      p("An account that can only run fixed log and status commands: no shell, no forwarding, no sudo. One tap, default 1 hour; the certificate is reused until it expires."),
      command("aqmas ssh bastion --why 'approvals page slow' -- logs aqmasd since=2h"),
      h("h3", null, "Root (red card)"),
      p("Your admin account, with sudo. Root on the bastion can read every bucket that is open while the session lasts, mint certificates for the whole fleet and replace aqmasd: approving it is approving everything until the session ends. It always needs its own tap, lasts at most 1 hour, is only offered to hosts on the list root keeps (“Who may ask for root”), and the card lists the buckets open right now with “Close all open buckets first” ticked. While a root certificate is valid a red banner shows on every page."),
      command("aqmas ssh bastion --level root --why 'replace the tunnel credentials'"),
      h("h3", null, "Routine tasks (normal card, pinned passkey)"),
      p("Nobody logs in: the root maintenance runner runs a fixed task. An agent can queue one; nothing runs until you approve it."),
      command("aqmas bastion task os-update --why 'monthly updates'"),
      command("aqmas bastion task journal-vacuum --keep-days 14 --why 'disk at 90%'"),
      command("aqmas bastion task reboot --why 'kernel update pending'"),
      p("Also: restart-cloudflared, restart-broker, disk-usage. “aqmas bastion” alone shows what this host may ask for. A reboot or broker restart comes back with nothing open."),
    ),
  );
}
