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

export interface UpdateView {
  current: string; commit: string; status: string; error: string;
  /** github: the manifest every installation checks. second: the configured second source's
   * manifest, absent without one. sources: how many published manifests the record holds. */
  candidate: { version: string; commit: string; github: Record<string,string>|null; second?: Record<string,string>|null; sources?: number };
  /** The published sources compared, by name: "GitHub", "second source (HOST)". */
  sources?: string[] | null;
  stat: string; diff: string;
}
const assets = ['aqmasd-linux-arm64','aqmas-linux-arm64','aqmas-linux-amd64','aqmas-darwin-arm64'] as const;
export function updateCard(view: UpdateView,approve:(target:ActionTarget)=>void) {
  const c=view.candidate, g=c.github??{}, two=!!c.second, f=c.second??{};
  const count=two?2:1;
  const names=view.sources?.length===count?view.sources:(two?['GitHub','the second source']:['GitHub']);
  // The count shown comes from the manifests themselves: one source needs GitHub's complete
  // manifest, two need both and identical.
  const show=(s:string)=>s.split('\n').map(line=>visibleText(line)).join('\n');
  const match=assets.every(a=>/^[a-f0-9]{64}$/.test(g[a]??'')&&(!two||f[a]===g[a]));
  const compared=count===1
    ? 'Compared 1 published source: GitHub. This machine rebuilds the release from source and installs it only if its own build has these hashes.'
    : `Compared 2 published sources: ${names.join(' and ')}. They agree. This machine rebuilds the release from source and installs it only if its own build has the same hashes.`;
  // Shown inside the “Upgrade aqmas” card of Settings → Setup.
  return h('div',{class:'update'},h('p',null,`Running ${view.current} (${view.commit})`),
    view.status && h('p',null,show(view.status)),view.error && h('p',{role:'status'},show(view.error)),
    c.version ? [h('h3',null,`Available: ${c.version} (${c.commit})`),h('p',{'data-sources':String(count)},match?compared:'Release hashes disagree or are unavailable'),
      ...assets.map(a=>h('details',null,h('summary',null,a),h('pre',null,`GitHub: ${g[a]??'unavailable'}`+(two?`\nSecond: ${f[a]??'unavailable'}`:'')))),
      h('pre',null,show(view.stat)), ...view.diff.split(/^(?=diff --git )/m).filter(Boolean).map(p=>h('details',null,h('summary',null,show(p.split('\n')[0]!)),h('pre',null,show(p)))),
      match && !view.error && h('button',{type:'button',class:'btn approve',on:{click:()=>approve({object:'update',id:c.commit,facts:{
        from_version:view.current,from_commit:view.commit,to_version:c.version,to_commit:c.commit,daemon_sha256:g[assets[0]]!,linux_arm64_sha256:g[assets[1]]!,linux_amd64_sha256:g[assets[2]]!,darwin_arm64_sha256:g[assets[3]]!,
      }})}},'Approve update…')] : h('p',null,'No verified update available.'));
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
