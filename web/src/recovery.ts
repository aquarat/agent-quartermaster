import { h, replace } from "./dom";
import {
  browserAuthenticator,
  decodeCreationOptions,
  encodeAttestation,
  encodeAssertion,
  type Authenticator,
} from "./webauthn";
import { encode } from "./b64url";
import { binary32, checkReview, checkTap, type Review } from "./review";
const effects =
  "Replace all owner login keys and wraps, and rekey every scope and bucket. End every session, pending request, grant, standing rule and host admission; require new host enrollment. Preserve audit and SSH serials. Issued certificates, copied values and upstream children are not recalled.";
type Call = (stage: string, token: string, body: unknown) => Promise<any>;
interface Step {
  detail: string;
  apply(auth: Authenticator): Promise<Step | void>;
}
const SCOPE = /^[^\s]{1,256}$/;
// Runs only against the isolated recovery socket mapped to the trusted RP. The broker opened
// every scope key from the recovery key before this page could start; the page never sees
// an age identity, a scope key or a KEK in the clear: each tap's KEKs travel HPKE-sealed.
// Steps: begin → create → (evaluate → finish)… → replace (docs/SEAL-OPERATIONS.md).
export async function recoverSteps(
  call: Call,
  ticket: string,
  name: string,
  pin: string,
  rp: string,
): Promise<Step> {
  if (!/^[0-9a-f]{64}$/.test(pin))
    throw Error("Enter the independent manifest pin");
  const b = await call("begin", ticket, { name });
  const options = decodeCreationOptions(b.public_key);
  if (
    options.rp.id !== rp ||
    !options.extensions?.prf ||
    !binary32(b.epoch) ||
    !binary32(b.installation) ||
    !binary32(b.registration_id) ||
    !Array.isArray(b.scopes) ||
    !b.scopes.length ||
    b.scopes.some((x: unknown) => typeof x !== "string" || !SCOPE.test(x))
  )
    throw Error("Invalid recovery registration");
  const scopes: string[] = b.scopes;
  const post = (step: string, body: unknown) => call(step, b.session, body);
  return {
    detail: `Create replacement ${name} for ${rp}. It will hold the keys of: ${scopes.join(", ")}.`,
    async apply(auth) {
      const cr = await auth.create(options),
        raw = encode(cr.rawId);
      const c = await post("create", { credential: encodeAttestation(cr) });
      if (c.credential_id !== raw || JSON.stringify(c.scopes) !== JSON.stringify(scopes))
        throw Error("Wrong replacement credential");
      // One tap per one or two scopes: first create their wraps, then test them.
      async function next(): Promise<Step> {
        const r: Review = await post("evaluate", {});
        const c = JSON.parse(r.canonical);
        const purpose = c.action;
        if ((purpose !== "enrol" && purpose !== "test") || !Array.isArray(c.scopes) || !c.scopes.length || c.scopes.length > 2 || c.scopes.some((x: unknown) => !scopes.includes(x as string)))
          throw Error("Invalid replacement step");
        const expected = {
          v: 3,
          object: "recovery-enrol",
          action: purpose,
          id: b.registration_id,
          installation: b.installation,
          epoch: b.epoch,
          credential_id: raw,
          nickname: name,
          scopes: c.scopes,
        };
        const tap = await checkTap(r, expected, rp, { object: "scope-enrol", purposes: [purpose], requireOpen: true, selected: raw });
        const d = tap.open!.descriptor;
        if (d.credential_id !== raw || JSON.stringify(d.scopes) !== JSON.stringify(c.scopes))
          throw Error("The tap is for another passkey or other scopes");
        return {
          detail: (purpose === "enrol" ? "Create" : "Test") + ` the replacement passkey's key for: ${c.scopes.join(", ")}\n` + r.canonical,
          async apply(auth) {
            const signed = await tap.sign(auth);
            if (!signed.open)
              throw Error("This passkey returned no PRF result, so it cannot hold the store's keys. Use a passkey that supports PRF.");
            const res = await post("finish", { assertion: signed.assertion, open: signed.open });
            if (res.next === "evaluate") return next();
            if (res.next !== "replace") throw Error("Unexpected recovery step");
            const f = JSON.parse(res.canonical);
            if (
              !/^[0-9a-f]{64}$/.test(f.backup_sha256) ||
              !/^(0|[1-9]\d{0,18})$/.test(f.serial_high_water) ||
              typeof f.retire_credentials !== "string" ||
              f.retire_credentials.split(",").some((id: string) => !/^[a-zA-Z0-9_-]{1,1364}$/.test(id))
            )
              throw Error("Invalid retiring credentials");
            const want = {
              v: 3,
              id: b.registration_id,
              installation: b.installation,
              epoch: b.epoch,
              object: "recovery",
              action: "replace",
              credential_id: raw,
              nickname: name,
              effects,
              manifest_sha256: pin,
              backup_sha256: f.backup_sha256,
              serial_high_water: f.serial_high_water,
              retire_credentials: f.retire_credentials,
              scopes,
            };
            const opts = await checkReview(res as Review, want, rp, raw);
            return {
              detail: effects + "\n" + res.canonical,
              async apply(auth) {
                await post("replace", { assertion: encodeAssertion(await auth.get(opts)) });
              },
            };
          },
        };
      }
      return next();
    },
  };
}
export function recoveryUI(root: HTMLElement) {
  const ticket = h("input", { type: "password" }),
    name = h("input", { placeholder: "New nickname" }),
    pin = h("input", { placeholder: "Owner manifest SHA-256" }),
    review = h("div", { role: "status" });
  const call: Call = async (stage, token, body) => {
    const res = await fetch("/recovery/" + stage, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {
        "Content-Type": "application/json",
        "X-Aqmas": "1",
        "X-Aqmas-Recovery": token,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok)
      throw Error(
        "Recovery step refused. Check ticket, expiry and operator status.",
      );
    return res.json();
  };
  function show(s: Step | void) {
    if (!s) {
      replace(root, "Replacement committed. Stop recovery and restart the broker: nothing is open until an approval needs it.");
      return;
    }
    const go = h(
      "button",
      { type: "button" },
      "Confirm with replacement passkey",
    );
    go.onclick = async () => {
      go.disabled = true;
      try {
        show(await s.apply(browserAuthenticator()));
      } catch (e) {
        replace(review, String((e as Error).message));
      }
    };
    replace(review, h("pre", null, s.detail), go);
  }
  const begin = h("button", { type: "button" }, "Start isolated replacement");
  begin.onclick = async () => {
    try {
      show(
        await recoverSteps(
          call,
          ticket.value,
          name.value,
          pin.value,
          location.hostname,
        ),
      );
      ticket.value = "";
    } catch (e) {
      replace(review, String((e as Error).message));
    }
  };
  replace(
    root,
    h("h2", null, "Offline recovery · replacement passkey"),
    h("label", null, "One-use operator ticket ", ticket),
    name,
    pin,
    begin,
    review,
  );
}
