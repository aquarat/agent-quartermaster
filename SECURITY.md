# Security policy

agent-quartermaster is **alpha software** that has **not had an independent security
review**. It brokers credentials. Use it at your own risk; see the status section of the
[README](README.md).

## Reporting a vulnerability

Please report privately, not in a public issue or pull request:

- Use the repository's **Security** tab → **Report a vulnerability** on GitHub. Where that
  button is offered, it opens a private report (a draft security advisory) that only the
  maintainers and you can see.

There is no security email address. If the Security tab offers no way to report privately,
open a public issue that says only that you have a security report and how to reach you,
with no details.

A useful report says which version or commit is affected, what an attacker needs (an
enrolled host, a web session, network position, a compromised component), what they gain, and
how to reproduce it. A proof of concept against your own test installation is welcome; please
do not test against installations that are not yours.

## What to expect

This is maintained by one person in spare time. **There is no guaranteed response or fix
time**, no bug bounty and no backports: fixes land on `main` and in the next release. You
will be credited in the advisory unless you ask not to be.

## In scope

- The broker `aqmasd`: the agent API (mTLS), the approval page and its API, passkey
  (WebAuthn) ceremonies and signed approvals, grant and certificate issuance, the sealed
  store and its buckets, the Cloudflare proxy and token minting.
- The root maintenance runner and the self-update path: approval verification, the release
  sources and their comparison, the sandboxed rebuild and installer
  ([docs/UPDATES.md](docs/UPDATES.md), [docs/SETUP.md](docs/SETUP.md)).
- The `aqmas` CLI: enrollment, credential handling on the host, `aqmas upgrade`.
- The host-trust installer and the units and examples under `deploy/`.
- The release workflows under `.github/` and `.forgejo/`, and the reproducible build.

Examples of what matters: getting a credential, certificate, token or signature without the
owner's approval, or a broader one than was approved; making the approval page show something
other than what is signed; an enrolled host reaching another host's grants; bypassing the
release checks or the sandbox to install unapproved code; reading sealed material without a
passkey or the recovery key.

## Out of scope

- Limits the documentation already states (for example the trust limits in
  [docs/UPDATES.md](docs/UPDATES.md) and [docs/DESIGN.md](docs/DESIGN.md)): a compromised
  owner passkey, a compromised bastion root account or kernel, an owner who approves malicious
  source.
- Vulnerabilities in dependencies or third-party services without a way to exploit them
  through aqmas; report those upstream.
- Any particular installation, its hosts, domains or network. Only the code in this
  repository is in scope.
- Denial of service by a party that already holds an enrolled host certificate or an owner
  session, and findings that need physical access to the bastion.
