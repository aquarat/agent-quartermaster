import { h, replace } from "./dom";
import {
  browserAuthenticator,
  decodeCreationOptions,
  encodeAttestation,
  encodeAssertion,
  type Authenticator,
} from "./webauthn";
import { encode } from "./b64url";
import { prepareSeal, type SealBegin, type Selection } from "./seal";
import { binary32, checkReview, type Review } from "./review";
const effects =
  "Replace all owner login keys and wraps. End every session, pending request, grant, standing rule and host admission; require new host enrollment. Preserve audit and SSH serials. Issued certificates, copied values and upstream children are not recalled.";
type Call = (stage: string, token: string, body: unknown) => Promise<any>;
interface Step {
  detail: string;
  apply(auth: Authenticator): Promise<Step | void>;
}
// Runs only against the isolated recovery socket mapped to the trusted RP.
// The UI never sees an age identity, recovery packet plaintext or MK.
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
    !binary32(b.registration_id)
  )
    throw Error("Invalid recovery registration");
  const post = (step: string, body: unknown) => call(step, b.session, body);
  return {
    detail: `Create replacement ${name} for ${rp}`,
    async apply(auth) {
      const cr = await auth.create(options),
        raw = encode(cr.rawId);
      const sel: Selection = await post("create", {
        credential: encodeAttestation(cr),
      });
      if (
        sel.credential_id !== raw ||
        sel.rp_id !== rp ||
        sel.action !== "wrap-enroll" ||
        sel.epoch !== b.epoch ||
        sel.installation !== b.installation ||
        sel.mk_version !== b.mk_version ||
        sel.registration_id !== b.registration_id + "-create"
      )
        throw Error("Wrong replacement credential");
      async function evaluate(step: "create" | "test"): Promise<Step> {
        const expected = {
            ...sel,
            registration_id: b.registration_id + "-" + step,
          },
          packet: SealBegin = await post("evaluate", {});
        const p = await prepareSeal(expected, packet, rp);
        return {
          detail: p.canonical,
          async apply(auth) {
            const result = await post("finish", await p.finish(auth));
            if (step === "create") return evaluate("test");
            const c = JSON.parse(result.canonical);
            if (
              !/^[0-9a-f]{64}$/.test(c.backup_sha256)||! /^(0|[1-9]\d{0,18})$/.test(c.serial_high_water)||typeof c.retire_credentials !== "string" ||
              c.retire_credentials
                .split(",")
                .some((id: string) => !/^[a-zA-Z0-9_-]{1,1364}$/.test(id))
            )
              throw Error("Invalid retiring credentials");
            const expected = {
              v: 3,
              id: b.registration_id,
              installation: b.installation,
              epoch: b.epoch,
              mk_version: b.mk_version,
              object: "recovery",
              action: "replace",
              credential_id: raw,
              nickname: name,
              effects,
              manifest_sha256: pin,
              backup_sha256:c.backup_sha256,serial_high_water:c.serial_high_water,
              retire_credentials: c.retire_credentials,
            };
            const opts = await checkReview(result as Review, expected, rp, raw);
            return {
              detail: effects + "\n" + result.canonical,
              async apply(auth) {
                await post("replace", {
                  assertion: encodeAssertion(await auth.get(opts)),
                });
              },
            };
          },
        };
      }
      return evaluate("create");
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
      replace(root, "Replacement committed. Stop recovery and restart locked.");
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
    h("h2", null, "Offline recovery · replacement login and unlock key"),
    h("label", null, "One-use operator ticket ", ticket),
    name,
    pin,
    begin,
    review,
  );
}
