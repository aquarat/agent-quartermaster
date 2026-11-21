import { type Api } from "./api";
import { type SealView } from "./sealPanel";
import { prepareSeal, type SealBegin, type Selection } from "./seal";
import {
  type Authenticator,
  decodeCreationOptions,
  encodeAssertion,
  encodeAttestation,
} from "./webauthn";
import { h, replace } from "./dom";
import { binary32, checkReview, type Review } from "./review";
import { encode } from "./b64url";
import { type PasskeyInfo } from "./types";
export type Intent = {
  action: "register" | "enable" | "disable";
  capability: "unlock" | "approve-only";
  nickname: string;
  credential_id: string;
};
type Next = {
  ok?: boolean;
  registration_id?: string;
  public_key?: unknown;
  selection?: Selection;
};
export async function startCapability(
  api: Api,
  v: SealView,
  i: Intent,
  rp: string,
) {
  const b = await api.sealPost!<Review>("passkeys/challenge", i);
  const c = JSON.parse(b.canonical);
  if (
    !binary32(c.id) ||
    !Number.isSafeInteger(c.mk_version) ||
    c.mk_version < 1
  )
    throw Error("Invalid capability registration");
  const opts = await checkReview(
    b,
    {
      ...i,
      id: c.id,
      v: 3,
      epoch: v.epoch,
      installation: v.installation,
      object: "passkey-capability",
      mk_version: c.mk_version,
    },
    rp,
  );
  return {
    canonical: b.canonical,
    async approve(auth: Authenticator) {
      const n = await api.sealPost!<Next>("passkeys/authorize", {
        challenge_id: b.challenge_id,
        assertion: encodeAssertion(await auth.get(opts)),
      });
      if (i.action === "disable") {
        if (!n.ok) throw Error("Downgrade failed");
        return;
      }
      if (n.registration_id !== c.id) throw Error("Wrong registration");
      let selected = i.credential_id;
      const evaluate = async (
        sel: Selection,
        step: "create" | "test",
        salt?: string,
      ) => {
        if (
          sel.registration_id !== c.id + "-" + step ||
          sel.action !== "wrap-enroll" ||
          sel.credential_id !== selected ||
          sel.epoch !== v.epoch ||
          sel.installation !== v.installation ||
          sel.mk_version !== c.mk_version ||
          sel.rp_id !== rp ||
          (salt && salt !== sel.prf_salt)
        )
          throw Error("Unexpected wrap binding");
        const b = await api.sealPost!<SealBegin>("passkeys/evaluate", {
          registration_id: c.id,
        });
        const p = await prepareSeal(sel, b, rp);
        return {
          canonical: p.canonical,
          async tap(auth: Authenticator) {
            const next = await api.sealPost!<Next>("passkeys/finish", {
              ...(await p.finish(auth)),
              registration_id: c.id,
            });
            if (step === "test") {
              if (!next.ok) throw Error("No tested wrap");
              return;
            }
            if (!next.selection) throw Error("Independent test required");
            return evaluate(next.selection, "test", sel.prf_salt);
          },
        };
      };
      if (i.action === "enable") {
        if (!n.selection) throw Error("No wrap selection");
        return evaluate(n.selection, "create");
      }
      const create = decodeCreationOptions(n.public_key);
      if (create.rp.id !== rp || !create.extensions?.prf)
        throw Error("Registration options mismatch");
      return {
        canonical: `Register ${i.nickname}: ${i.capability}`,
        async tap(auth: Authenticator) {
          const cr = await auth.create(create);
          selected = encode(cr.rawId);
          const next = await api.sealPost!<Next>("passkeys/create", {
            registration_id: c.id,
            credential: encodeAttestation(cr),
          });
          if (i.capability === "approve-only") {
            if (!next.ok) throw Error("Registration failed");
            return;
          }
          if (!next.selection) throw Error("Wrap test required");
          return evaluate(next.selection, "create");
        },
      };
    },
  };
}
interface Step {
  canonical: string;
  tap(auth: Authenticator): Promise<Step | void>;
}
export function capabilityForm(
  api: Api,
  auth: Authenticator,
  v: SealView,
  pks: PasskeyInfo[],
  refresh: () => void,
) {
  const box = h("div"),
    review = h("div", { role: "status" }),
    name = h("input", { placeholder: "New passkey nickname" });
  const btn = (label: string, fn: () => Promise<void>) =>
    h(
      "button",
      {
        class: "btn",
        type: "button",
        on: {
          click: async (ev) => {
            const el = ev.currentTarget as HTMLButtonElement;
            el.disabled = true;
            try {
              await fn();
            } catch (e) {
              replace(review, String((e as Error).message));
            } finally {
              el.disabled = false;
            }
          },
        },
      },
      label,
    );
  function show(p?: Step | void) {
    if (!p) {
      replace(review, "Applied.");
      refresh();
      return;
    }
    replace(
      review,
      h("pre", null, p.canonical),
      btn("Confirm with passkey", async () => show(await p.tap(auth))),
    );
  }
  const start = (i: Intent) => async () => {
    const p = await startCapability(api, v, i, location.hostname);
    show({ canonical: p.canonical, tap: () => p.approve(auth) });
  };
  box.append(name);
  for (const capability of ["unlock", "approve-only"] as const)
    box.append(
      btn(`Add ${capability} passkey…`, async () =>
        start({
          action: "register",
          capability,
          nickname: name.value.trim(),
          credential_id: "",
        })(),
      ),
    );
  for (const p of pks) {
    if (!p.raw_id) continue;
    box.append(
      btn(
        (p.unlock_tested_at ? "Disable unlock" : "Test for unlock") +
          `: ${p.nickname}…`,
        start({
          action: p.unlock_tested_at ? "disable" : "enable",
          capability: p.unlock_tested_at ? "approve-only" : "unlock",
          nickname: p.nickname,
          credential_id: p.raw_id,
        }),
      ),
    );
  }
  box.append(review);
  return box;
}
