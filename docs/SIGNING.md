# Signing inside aqmas

A **signer** is a credential set that holds one private signing key in the
sealed store. Agents never receive the key. They send what they want signed;
the owner approves the exact artifacts; aqmasd signs and returns signatures.

**Prefer `aqmas sign` to fetching a key.** Where a scheme below fits, keep the
key in a signer: nothing an agent host can copy, every signature approved or
bounded and recorded by digest. `aqmas run` with a key in an env set remains
for tools that must hold the key themselves; a key delivered that way can be
copied and cannot be recalled. The wire contract is in
[API.md](API.md#vault-web-form-reveal-and-signer-sets).

## For an agent

```sh
aqmas signer client-a/releases/firmware-key          # scheme, public key (hex and PEM), how to verify
aqmas sign client-a/releases/firmware-key --why "release 1.4.2" firmware.bin
#   → firmware.bin.sig after the owner approves
aqmas sign client-a/releases/firmware-key --why "nightly builds" --ttl 30m --count 20 a.bin b.bin
aqmas sign client-a/releases/firmware-key c.bin      # within the grant: no new approval
aqmas sign client-a/releases/firmware-key --end      # give the grant back early
aqmas sign client-a/releases/manifest-key --why "manifest" --format hex - < manifest.bin
aqmas sign client-a/releases/firmware-key --why "CI digest" --digest sha256:9f86d0…0a08
```

* Files are hashed on the requesting host. Only names, sizes and digests go
  to aqmasd, except for a scheme that signs the artifact's own bytes
  (`ed25519`): then the artifact travels too, and it must be at most 4096 bytes.
* While waiting the CLI prints each SHA-256 and a Ref. Compare them with the card.
* Each file gets `FILE.sig` (raw signature bytes). `--out PATH` names the
  output for a single input; `--format raw|hex|base64`; stdin and `--digest`
  print hex to stdout. An existing output file is refused without `--force`.
* The CLI verifies every signature against the signer's public key before it
  writes anything.
* `--why` is required for a new request. `--ttl` (1 min to 24 h) with `--count`
  (default 20, at most 1000) asks for a time-boxed grant; later calls for the
  same key on the same host reuse it until it runs out, expires or is revoked.
* At most 16 artifacts a call (and 40 KiB of them for `ed25519`, which sends
  the artifacts), and 30 requests an hour from one host: use a grant for a run
  of signatures. `--digest` works for schemes that sign a SHA-256 digest.
* Exit codes are those of the other commands: 3 denied, 4 expired, 130 cancelled.

## For the owner

**Vault → Add item → Signing key.** Choose the organisation and service
(a new one is created on the way), a name and a scheme, then either

* **Generate in aqmas**: the key is made on the bastion and never exists
  anywhere else; or
* **Paste an existing private key** once: a hex seed or scalar, or an
  unencrypted PKCS#8, SEC1 or OpenSSH PEM. The page encrypts it to a one-time
  key of the broker before it leaves the browser.

The passkey prompt shows the public key that will be created; for a pasted
key, compare it with the public half you already have. Afterwards the page
shows the new key as a Vault item: the public key (hex, PEM) and its
fingerprint with copy buttons, the hosts that may ask for signatures, its
pending requests and live grants, and its recent history. Give
those to whoever verifies. There is no reveal and no export for a signer: to
move a key elsewhere, import the copy you kept, or make a new key.

**The approval card** shows organisation › service › key, the scheme and what
exactly it signs, the requesting host and address, and for each artifact its
name, size and full SHA-256. Names and the reason are the requester's words;
the digest is what gets signed. For a scheme that signs the artifact itself
the card also shows all of its bytes in hex, checked against the SHA-256.
For `ed25519ph` the SHA-512 is what gets signed and is shown first; the
SHA-256 is then only the requester's claim. The confirmation before the
passkey prompt restates the limits you chose, and the inputs are frozen while
it is open. Two kinds of approval:

| Grant | What one tap authorises |
|---|---|
| Single use (default) | Signatures over exactly the artifacts on the card, once, collected within ten minutes. |
| Time-boxed (`--ttl`) | Up to N signatures for M minutes over **anything that host submits**, not only what the card lists. You can lower N and M, or turn it into a single-use approval. Above the organisation's soft cap the card says so. 24 hours at most; never indefinite. |

A grant ends when it is used up, at its deadline, on **Revoke**, and when the
host's admission, the organisation's policy or the set changes. Signing needs
an unlocked broker; requests queue while it is locked. Every signature is in
the activity log with the key, scheme, digest, artifact name and size,
requesting host and address. Signing approvals are always an individual
passkey tap: they are not offered in batches or approval windows.

A time-boxed grant trusts the host for its duration: a compromised agent on
it can obtain signatures over artifacts of its choosing until the count or
time runs out, and each one is logged by digest. Use single-use approvals for
release keys that matter.

## Schemes

| Scheme | Signs | Signature | Check with |
|---|---|---|---|
| `ed25519` | The artifact's own bytes (pure Ed25519, RFC 8032). At most 4096 bytes. | 64 raw bytes | `openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in FILE -sigfile FILE.sig` |
| `ed25519-sha256` | The 32 raw bytes of the artifact's SHA-256, with pure Ed25519. | 64 raw bytes | `openssl dgst -sha256 -binary FILE > d; openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in d -sigfile FILE.sig` |
| `ed25519ph` | The artifact's SHA-512 as Ed25519ph (RFC 8032, empty context). | 64 raw bytes | an Ed25519ph verifier |
| `ecdsa-p256-sha256` | The artifact's SHA-256 with ECDSA on NIST P-256. | ASN.1 DER | `openssl dgst -sha256 -verify pub.pem -signature FILE.sig FILE` |

A key is created for one scheme and signs only under it. That is what keeps a
signature over a 32-byte message from being passed off as a signature over a
file with that digest: use separate keys for separate schemes.

**Signed manifests.** Firmware and update formats often sign a small fixed
header that contains the image's hash, length and version, with pure Ed25519.
That is the `ed25519` scheme: build the header, sign it
(`aqmas sign … --format hex - < header.bin`), and append the 64 bytes. The
card then shows the header's SHA-256 and its bytes in hex, where the image
hash can be read at its offset. A signing tool that reads a private key file
needs a mode that takes the signature from a command instead.

**Adding a scheme** is one entry in `internal/signer/signer.go` (key type,
what the broker needs, sign and verify functions), a known-answer test, and a
row here. The CLI, the card and the audit record follow the registry. Formats
that wrap a signature in a container (minisign, SSH signatures, secure-boot
signature blocks) are not built in yet.

## What this does and does not protect

* The private key is sealed at rest and opened only inside the signing
  request, under the lock gate. It is not in any response, log, audit row or
  backup in the clear. Root on an unlocked bastion can still use or read it.
* The owner approves digests. aqmas cannot tell whether the bytes behind a
  digest are the build you meant; compare the digest with your build output.
* An approval page served by a hostile origin can misdescribe a request. The
  CLI's Ref and digests, and the activity log, are the independent checks.
