import { decode, encode } from "./b64url";
import { prepareTap, type Tap, type TapExpectation } from "./buckets";
export interface Review {
  canonical: string;
  challenge_id: string;
  public_key: unknown;
  /** Format 2: the buckets this tap opens (docs/BUCKETS.md §4.2). */
  open?: { descriptor: string };
}
export function binary32(v: unknown) {
  return (
    typeof v === "string" &&
    v.length === 43 &&
    decode(v).byteLength === 32 &&
    encode(decode(v)) === v
  );
}
function checkCanonical(b: Review, expected: Record<string, unknown>) {
  const c = JSON.parse(b.canonical);
  if (
    !binary32(c.nonce) ||
    typeof c.issued_at !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c.issued_at)
  )
    throw Error("Invalid ceremony metadata");
  const m = { ...expected, issued_at: c.issued_at, nonce: c.nonce };
  if (
    JSON.stringify(m, Object.keys(m).sort())
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029") !== b.canonical
  )
    throw Error("Canonical differs from the reviewed action");
}
/** A v3 review whose tap may open buckets: checks the canonical against what the card shows,
 * then the options and (if present) the open descriptor bound into the challenge. Pass
 * `installation`/`epoch` so a descriptor from another broker start is refused. */
export async function checkTap(
  b: Review,
  expected: Record<string, unknown>,
  rp: string,
  want: TapExpectation = {},
): Promise<Tap> {
  checkCanonical(b, expected);
  return prepareTap(b, rp, {
    installation: typeof expected.installation === "string" ? expected.installation : undefined,
    epoch: typeof expected.epoch === "string" ? expected.epoch : undefined,
    ...want,
  });
}
/** A v3 review whose tap opens nothing: challenge = SHA-256(canonical), no extensions. */
export async function checkReview(
  b: Review,
  expected: Record<string, unknown>,
  rp: string,
  selected?: string,
) {
  checkCanonical(b, expected);
  return (await prepareTap(b, rp, { selected, allowOpen: false })).options;
}
