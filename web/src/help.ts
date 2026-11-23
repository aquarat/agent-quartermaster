import { h, type Child } from "./dom";

export interface HelpConfig {
  agent_api_url: string;
  cli_download_base_url: string;
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

function download(base: string, platform: string) {
  const file = `aqmas-${platform}`;
  const check = platform.startsWith("darwin") ? "shasum -a 256" : "sha256sum";
  return command(
    `curl -fLsS --proto '=https' -o ${file} -- ${quote(base + "/" + file)} &&\n` +
      `curl -fLsS --proto '=https' -o SHA256SUMS -- ${quote(base + "/SHA256SUMS")} &&\n` +
      `awk '$2 == "${file}"' SHA256SUMS | ${check} -c - &&\n${check} ${file}`,
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
      "Enroll a machine",
      base
        ? [
            p(
              "In an empty directory, choose the build for this machine. The same-origin checksum checks transfer integrity only. Compare the printed SHA-256 with an independently trusted release digest before installing the verified file as aqmas on PATH.",
            ),
            ...["linux-arm64", "linux-amd64", "darwin-arm64"].map((os) => [h("h3", null, os), download(base, os)]),
          ]
        : p("Copy the aqmas binary for this machine from the operator’s build."),
      p("Cross-check the CA pin once against an independently recorded copy. A faked help page could point a new host at another server."),
      c.agent_api_url
        ? command(`aqmas enroll --name '<name>' --server ${quote(c.agent_api_url)} --ca-pin ${quote(c.ca_pin)}`)
        : p("Ask the operator to set agent_api_url to show the enrollment command."),
      p(
        "Replace <name> with the new host name. Match the Ref and client key to the terminal, confirm its connecting address and class, and check “replaces”: approving a replacement revokes the old identity.",
      ),
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
        "Where a signing scheme exists, the key should not leave aqmas. Put it in a signing key set (Admin → Credential sets) and have the host ask for signatures: the CLI hashes the files locally, the approval card shows each file name, size and SHA-256, and aqmas returns the signatures. The private key is never delivered, revealed or exported.",
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
        "Before you tap, the card says what the tap opens and for how long, for example “Opens SSH user CA: for this action only” or “Opens personal Cloudflare proxy token: while the grant lasts”. The passkey signs that list together with the decision; a page that changes it is refused. A bucket stays open only while something holds it: one operation (instant), a Cloudflare grant, an env release until collected (10 minutes at most), a signing grant, a standing rule, auto-approval, or an approval window. Admin → Buckets shows every hold and the header says how many buckets are open, or “nothing open”.",
      ),
      p(
        "After a restart nothing is open, and nothing needs to be until it is used. Grants that need a bucket pause; agents wait with “closed: waiting for the owner to reopen it” and keep their deadline. Admin → Buckets lists them with Reopen (one tap opens up to two scopes). A standing rule or auto-approval needs one tap per restart, then none until the rule ends.",
      ),
      p(
        "Close all (Admin → Buckets, one tap) wipes every open bucket key and hold and ends every approval window, without a restart. Use it when you step away or suspect something.",
      ),
      p(
        "Enabling a passkey: in Admin → Passkeys, Enable on the new passkey. The passkey you are signed in with taps first (that tap opens the scope keys), then the new one taps once per two scopes. Test checks a passkey can open its scopes. A passkey without the PRF extension signs in, denies, revokes and approves while buckets are already open, but cannot open a closed one; the card says which passkey can.",
      ),
      p(
        "Recovery: if no passkey can open a scope any more, Admin → Recovery key enrols a passkey from your offline recovery key, and the recovery drill proves the key works without writing anything. This pastes the recovery key into a web page, so prefer enabling from another passkey. If a passkey or a backup is lost or stolen, remove it and Rekey its scopes (Admin → Buckets): removing a passkey does not revoke copies of its wraps in old backups.",
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
  );
}
