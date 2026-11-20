import { h } from "./dom";
import type { ActionTarget } from "./flows";
import { visibleText } from "./format";

export interface HostInfo {
  id: string;
  name: string;
  address: string;
  class: "agent" | "owner-device";
  enrolled_at: string;
  not_before: string;
  not_after: string;
  last_request_at: string | null;
  revoked_at: string | null;
}

export function hostCard(host: HostInfo, revoke: (target: ActionTarget) => void) {
  const row = (key: string, value: string) => [h("dt", null, key), h("dd", null, h("bdi", null, visibleText(value)))];
  return h(
    "article",
    { class: "card" },
    h("h3", null, h("bdi", null, visibleText(host.name))),
    h(
      "dl",
      { class: "facts" },
      row("Class", host.class),
      row("Enrolled from", host.address),
      row("Enrollment", host.id),
      row("Enrolled at", host.enrolled_at),
      row("Certificate valid from", host.not_before),
      row("Certificate valid until", host.not_after),
      row("Last access request", host.last_request_at ?? "Never"),
      row("Revoked", host.revoked_at ?? "No"),
    ),
    !host.revoked_at &&
      h(
        "button",
        {
          class: "btn deny",
          type: "button",
          on: {
            click: () =>
              revoke({ object: "host", id: host.id, facts: { requesting_host: host.name, class: host.class, address: host.address } }),
          },
        },
        "Revoke host…",
      ),
  );
}
