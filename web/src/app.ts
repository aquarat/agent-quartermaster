// The approval UI. Rendering only; the security-relevant logic lives in flows.ts,
// canonical.ts and webauthn.ts.
//
// Untrusted text (reason, requester fields, and for safety every server string) is shown
// through text nodes only, with invisible/bidi characters made visible (visibleText).

import { ApiError, createApi, type Api } from "./api";
import { FILTERS, actor, classify, detailUntrusted, groupByDay, matches, objectRef, rowKey, type Filter } from "./audit";
import { shortId, type Part } from "./canonical";
import { $, h, own, replace, type Child } from "./dom";
import {
  FlowError,
  LOGIN_OPTIONS_MAX_AGE_MS,
  PASSKEY_TARGET,
  authorizeAddPasskey,
  completeAction,
  completeLogin,
  completeRegistration,
  explainError,
  nicknameProblem,
  nothingChanged,
  prepareAction,
  prepareLogin,
  prepareRegistrationWithCode,
  targetForGrant,
  targetForPasskey,
  targetForPending,
  targetForStanding,
  type ActionChoice,
  type ActionTarget,
  type PreparedAction,
  type PreparedLogin,
  type PreparedRegistration,
} from "./flows";
import {
  STANDING_PRESETS,
  absoluteTime,
  ago,
  countdown,
  dayLabel,
  duration,
  eventTime,
  hours,
  isPlainName,
  kindLabel,
  shortDate,
  ttlChoices,
  visibleText as vt,
} from "./format";
import { CF_RISKS, cfScope, paramPairs, parseScopeParams, riskLabel, sentenceCase, unusualParams, type CFScopeDesc } from "./cfscopes";
import { chevronIcon, cloudIcon, eventIcon, navIcon, passkeyIcon, syncIcon } from "./icons";
import type { AuditEntry, GrantSummary, PasskeyChange, PasskeyInfo, PendingCloudflare, PendingItem, RegisterResult, StandingApproval, UIState } from "./types";
import { hostCard, type HostInfo } from './admin';
import { SetupPage, setupSummary } from './setupPage';
import type { SetupView } from './setup';
import { helpPage, type HelpConfig } from './help';
import { admissionButton, policyForm, type Catalogue } from './catalogue';
import { bucketsPanel, sealBanner, serving, type SealView } from './sealPanel';
import { capabilityForm, createScope, testAfterRekey } from './capabilities';
import { recoveryPanel } from './recoveryPanel';
import { opensList } from './approvals';
import {TabWindow,multiPanel,windowAdmin} from './approvals';
import {envPanel,type EnvState} from './envsets';
import { signCards } from './vaultPage';
import { BastionPanel, bastionCard, bastionChoice, bastionSummary, decisionLines, queuedTaskCard, rootConfirmBlock, syncRootBanner } from './bastion';
import type { VaultState } from './vault';
import { VaultView, type VaultViewHost } from './vaultView';
import { buildItems } from './vaultItems';
import { PAGES, navBar, pageTitle, parseRoute, updateNav, type PageId } from './nav';
import { readiness, readinessHeadline, readinessPanel } from './readiness';
import { SearchBox } from './search';
import { Tray } from './tray';

const route = () => parseRoute(location.hash);
function nav(label:string,hash:string,title:string) { const a=h('a',{title,'aria-label':title},label); a.href=hash; return a; }
function scopeHeading(f?:Record<string,string|number>){return f?h('h3',null,...['org_title','service_title','set_title'].map((k,i)=>h('span',null,i?' › ':'',h('bdi',null,vt(String(f[k]??'?')))))):null;}
import { browserAuthenticator, type Authenticator } from "./webauthn";

const POLL_MS = 5000;
/** Login options are refreshed this often while the sign-in page is open, so a tap can call
 * navigator.credentials.get at once (Safari needs the call inside the tap, before any await). */
const LOGIN_REFRESH_MS = 45_000;
/** Lists don't re-render for this long after a touch, so cards don't move under a finger. */
const TOUCH_SETTLE_MS = 1500;

/** Short reference shown on cards; the CLI prints the same so the owner can match them. */
export function refCode(id: string): string {
  return id.slice(-6).toUpperCase();
}

export class App {
  readonly api: Api;
  readonly auth: Authenticator;
  private root: HTMLElement;
  private state: UIState | null = null;
  private lastOk = 0;
  private offline = false;
  private view: "loading" | "signin" | "main" = "loading";
  private pollTimer: number | undefined;
  private refreshing = false;
  private page: PageId = route().page;
  private seal?: SealView;
  private tab=new TabWindow();
  private envState?:EnvState;
  /** Credential sets (docs/API.md "Vault"): undefined when this server has none. */
  private vaultState?: VaultState;
  private vaultView?: VaultView;
  private vaultHost(): VaultViewHost {
    return {
      api: this.api,
      auth: this.auth,
      changed: () => this.changed(),
      propose: (t, c) => this.sheet.openCatalogue(t, c),
      createScope: (scope, review) => createScope(this.api, this.auth, this.seal!, this.state?.passkeys ?? [], scope, review, () => this.changed()),
      readinessNote: () => this.readinessNote(),
    };
  }
  private tray?: Tray;
  private search = new SearchBox(() => ({
    items: buildItems(this.vaultState, this.catalogue, this.seal),
    hosts: this.hosts,
    passkeys: this.state?.passkeys ?? [],
    pending: this.state?.pending ?? [],
    signing: (this.vaultState?.requests ?? []).filter((r) => r.status === "pending"),
    releases: (this.envState?.releases ?? []).filter((r) => r.status === "pending"),
    canAdd: !!this.vaultState,
    toEnable: readiness(this.seal)?.fixable.length ?? 0,
  }), () => void this.loadDirectory());
  /** Which page hosts and the catalogue were last loaded for ("" = never). */
  private directoryAt = 0;
  private hosts: HostInfo[]=[];
  /** Admin: a one-line summary of Settings → Setup (null = this server has none). */
  private setupView?: SetupView | null;
  /** The Setup page polls and redraws by itself while it is open. */
  private setupPage?: SetupPage;
  /** Settings → Bastion access: polls and redraws by itself while Admin is open. */
  private bastionPanel?: BastionPanel;
  private catalogue?: Catalogue|null;
  private migration?:{id:string;plan:string;recovery_sha256:string}|null;
  private help?: HelpConfig;
  private rendered = new Map<string, string>();
  private login: PreparedLogin | null = null;
  private loginTimer: number | undefined;
  private sheet: Sheet;
  private focusId: string | null = null;
  private pointerDown = false;
  private lastTouch = 0;
  /** Activity filter and which rows are expanded (kept across re-renders). */
  private filter: Filter = "all";
  private expanded = new Set<string>();
  private evSeq = 0;

  constructor(root: HTMLElement, api: Api = createApi(), auth: Authenticator = browserAuthenticator()) {
    this.root = root;
    this.api = api;
    this.auth = auth;
    this.sheet = new Sheet(this);
    this.focusId = route().focus ?? null;
  }

  start(): void {
    window.addEventListener('pagehide',()=>{this.tab.end();this.vaultView?.clearSecrets();});this.search.bindKeys();window.addEventListener('pageshow',ev=>{if(ev.persisted){this.tab.forget();location.reload()}});
    window.addEventListener('hashchange',()=>{
      this.sheet.close(true); this.focusId=route().focus ?? null;
      if(this.view!=='main') return;
      // Moving inside the Vault (another item, Add item) redraws at once from what is loaded.
      if(route().page===this.page&&this.page==='vault') this.renderSections();
      void this.refresh();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible") return;
      if (this.view === "main") void this.refresh();
      if (this.view === "signin") this.prefetchLogin();
    });
    const down = () => {
      this.pointerDown = true;
      this.lastTouch = Date.now();
    };
    const up = () => {
      this.pointerDown = false;
      this.lastTouch = Date.now();
    };
    this.root.addEventListener("pointerdown", down, { passive: true });
    this.root.addEventListener("touchstart", down, { passive: true });
    for (const ev of ["pointerup", "pointercancel", "touchend", "touchcancel"]) window.addEventListener(ev, up, { passive: true });
    window.setInterval(() => this.tick(), 1000);
    void this.refresh();
  }

  // ---- data ----

  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    const requested=route().page;
    try {
      const s = await this.api.state();
      this.seal=s.seal_enabled?await this.api.sealStatus!():undefined;
      this.envState=serving(this.seal)?await this.api.envState!():undefined;
      this.vaultState=serving(this.seal)&&s.catalogue_enabled&&this.api.vaultState?await this.api.vaultState().catch((e)=>{if(e instanceof ApiError&&e.status===404)return undefined;throw e;}):undefined;
      if(this.tab.id()&&!this.seal?.active_windows?.some(w=>w.id===this.tab.id()))this.tab.forget();
      this.migration=s.migration;
      if(requested==='hosts') this.hosts=await this.api.hosts();
      if(requested==='settings') this.setupView=this.api.setupGet?await this.api.setupGet<SetupView>('').catch(()=>null):null;
      if(requested==='vault'||requested==='hosts'||requested==='settings')this.catalogue=s.catalogue_enabled?await this.api.catalogue?.():null;
      if(requested==='help') this.help=await this.api.help();
      if(requested!==route().page) return;
      this.state = normalise(s);
      this.lastOk = Date.now();
      this.offline = false;
      if (this.view !== "main" || this.page!==requested) this.showMain();
      else this.renderSections();
    } catch (e) {
      if (e instanceof ApiError && e.code === "unauthenticated") {
        this.sheet.close(true);
        if (this.view !== "signin") this.showSignin();
      } else if (this.view === "main") {
        this.offline = true;
        this.updateStatus(e);
      } else {
        this.showFatal(e);
      }
    } finally {
      this.refreshing = false;
      if(requested!==route().page) void this.refresh();
    }
  }

  /** Hosts and the catalogue for the global search, whatever page is open (at most every 30 s). */
  private async loadDirectory(): Promise<void> {
    if (!this.state || Date.now() - this.directoryAt < 30_000) return;
    this.directoryAt = Date.now();
    try {
      const [hosts, cat] = await Promise.all([this.api.hosts(), this.state.catalogue_enabled ? this.api.catalogue?.() : null]);
      this.hosts = hosts;
      this.catalogue = cat;
      this.search.refresh();
    } catch {
      this.directoryAt = 0; // the search still has the vault items, passkeys and pages
    }
  }

  private schedulePoll(): void {
    if (this.pollTimer !== undefined) return;
    this.pollTimer = window.setInterval(() => {
      if (document.visibilityState === "visible" && this.view === "main") void this.refresh();
    }, POLL_MS);
  }

  /** Called by the sheet after an action was attempted. */
  changed(): void {
    void this.refresh();
  }

  /** Is this object still live on the server, as of the last poll? undefined = can't tell. */
  stillLive(t: ActionTarget): boolean | undefined {
    const s = this.state;
    if (!s) return undefined;
    switch (t.object) {
      case 'host':return this.hosts.some(h=>h.id===t.id && !h.revoked_at);
      case "request":
      case "enrollment":
        return (s.pending ?? []).some((p) => p.id === t.id);
      case "standing":
        return (s.standing ?? []).some((a) => a.id === t.id);
      case "grant":
        return s.grants === undefined ? undefined : (s.grants ?? []).some((g) => g.id === t.id && g.status === "approved");
      case "passkey":
        return t.id === "new" || s.passkeys === undefined ? undefined : (s.passkeys ?? []).some((p) => p.id === t.id);
      default:
        return undefined;
    }
  }

  // ---- views ----

  private showFatal(e: unknown): void {
    this.view = "loading";
    replace(
      this.root,
      h(
        "main",
        { class: "signin" },
        h("h1", { class: "brand" }, "aqmas"),
        h("p", { class: "error", role: "alert" }, vt(explainError(e))),
        h("button", { class: "btn primary big", type: "button", on: { click: () => void this.refresh() } }, "Try again"),
        route().page === "setup" ? h("p", { class: "muted", role: "status" }, "The broker may be restarting. This page keeps trying by itself.") : null,
      ),
    );
    // Setup tasks restart the broker: a reload in that window must not end on a dead page.
    if (route().page === "setup") window.setTimeout(() => { if (this.view === "loading") void this.refresh(); }, 2000);
  }

  private loginStatus: HTMLElement | null = null;
  private loginDetails: HTMLDetailsElement | null = null;
  private signBtn: HTMLButtonElement | null = null;

  /** Fetch login options ahead of the tap (and keep them fresh). */
  private prefetchLogin(): void {
    if (this.view !== "signin") return;
    prepareLogin(this.api).then(
      (p) => {
        this.login = p;
        if (this.signBtn) this.signBtn.disabled = false;
      },
      (e) => {
        this.login = null;
        if (!this.loginStatus) return;
        if (e instanceof ApiError && e.code === "conflict") {
          if (this.loginDetails) this.loginDetails.open = true;
          this.loginStatus.textContent = "No passkey is registered yet. Register this device with the enroll code.";
        } else {
          this.loginStatus.textContent = vt(explainError(e));
        }
      },
    );
  }

  isCurrentPasskey(id: string): boolean {
    return (this.state?.passkeys ?? []).some((p) => p.id === id && p.current);
  }

  /** The session ended because its passkey was removed: back to sign-in with a message. */
  signedOut(message: string): void {
    this.sheet.close(true);
    this.showSignin(message);
  }

  /** Header button: ends this session on the server (its windows close, held values drop) and
   * shows the sign-in page. A failure says so and leaves the session as it is. */
  private signOutButton(): HTMLButtonElement {
    const b = h("button", { class: "signout", type: "button", title: "Sign out of aqmas in this browser", "aria-label": "Sign out" }, navIcon("signout"), h("span", { class: "signout-label" }, "Sign out")) as HTMLButtonElement;
    b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        await this.api.logout();
      } catch (e) {
        if (!(e instanceof ApiError && e.code === "unauthenticated")) {
          b.disabled = false;
          const el = this.root.querySelector("#status");
          if (el) {
            el.textContent = `Could not sign out (${vt(explainError(e))}). You are still signed in.`;
            el.classList.add("bad");
            el.setAttribute("role", "alert");
          }
          return;
        }
      }
      this.sheet.close(true);
      this.vaultView?.clearSecrets();
      this.vaultView = undefined;
      this.tab.forget();
      this.showSignin(undefined, "Signed out. Your approval windows are closed.");
    });
    return b;
  }

  private showSignin(message?: string, note?: string): void {
    this.tab.end();
    this.setupPage?.stop();
    this.setupPage = undefined;
    this.bastionPanel?.stop();
    this.bastionPanel = undefined;
    this.view = "signin";
    this.state = null;
    this.login = null;
    this.rendered.clear();
    document.title = "aqmas";
    const status = h("p", { class: "error", role: "alert", "aria-live": "assertive" }, message ? vt(message) : "");
    const signBtn = h("button", { class: "btn primary big", type: "button" }, "Sign in with passkey");
    const regDetails = h("details", { class: "first-run" });
    const regBody = h("div", { class: "first-run-body" });
    this.loginStatus = status;
    this.loginDetails = regDetails;
    this.signBtn = signBtn;
    replace(
      this.root,
      h(
        "main",
        { class: "signin" },
        h("h1", { class: "brand" }, "aqmas"),
        h("p", { class: "lede" }, "Approve and refuse access requests from your fleet."),
        signBtn,
        note ? h("p", { class: "muted signin-note", role: "status" }, note) : null,
        status,
        regDetails,
      ),
    );
    regDetails.append(h("summary", null, "First time on this device?"), regBody);
    this.renderRegisterStart(regBody, status);

    this.prefetchLogin();
    if (this.loginTimer === undefined) {
      this.loginTimer = window.setInterval(() => {
        if (this.view === "signin" && document.visibilityState === "visible") this.prefetchLogin();
      }, LOGIN_REFRESH_MS);
    }

    signBtn.addEventListener("click", () => {
      status.textContent = "";
      const p = this.login;
      this.login = null;
      if (!p || Date.now() - p.fetchedAt > LOGIN_OPTIONS_MAX_AGE_MS) {
        // Never await a fetch inside the tap: get fresh options and ask for another tap.
        signBtn.disabled = true;
        status.textContent = "Getting ready… tap again in a moment.";
        this.prefetchLogin();
        return;
      }
      signBtn.disabled = true;
      // completeLogin calls navigator.credentials.get synchronously from here.
      completeLogin(this.api, this.auth, p)
        .then(() => this.refresh())
        .catch((e) => {
          status.textContent = vt(explainError(e));
          this.prefetchLogin();
        });
    });
  }

  private renderRegisterStart(body: HTMLElement, status: HTMLElement): void {
    const input = h("input", {
      id: "enroll-code",
      type: "text",
      autocomplete: "one-time-code",
      inputmode: "text",
      spellcheck: "false",
      enterkeyhint: "go",
    });
    const go = h("button", { class: "btn", type: "button" }, "Continue");
    replace(
      body,
      h("p", null, "Register this device's passkey with a one-time code. On the aqmasd host, as root or the aqmas user, run:"),
      h("pre", { class: "cmd" }, "aqmasd passkey-enroll-code"),
      h("label", { for: "enroll-code" }, "Enroll code"),
      input,
      go,
    );
    const submit = async () => {
      if (go.disabled) return;
      status.textContent = "";
      go.disabled = true;
      try {
        const reg = await prepareRegistrationWithCode(this.api, input.value);
        this.renderRegisterCreate(body, status, reg);
      } catch (e) {
        status.textContent = vt(explainError(e));
      } finally {
        go.disabled = false;
      }
    };
    go.addEventListener("click", () => void submit());
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
  }

  private renderRegisterCreate(body: HTMLElement, status: HTMLElement, reg: PreparedRegistration): void {
    const create = h("button", { class: "btn primary big", type: "button" }, "Create passkey");
    replace(body, h("p", null, "Code accepted. Create the passkey on this device (Face ID, fingerprint or security key)."), create);
    create.addEventListener("click", () => {
      status.textContent = "";
      create.disabled = true;
      completeRegistration(this.api, this.auth, reg).then(
        () => this.showSignin("Passkey registered. Sign in with it now."),
        (e) => {
          status.textContent = vt(explainError(e));
          this.renderRegisterStart(body, status);
        },
      );
    });
  }

  private showMain(): void {
    this.page=route().page;
    this.view = "main";
    this.rendered.clear();
    this.loginStatus = this.signBtn = this.loginDetails = null;
    this.setupPage?.stop();
    this.setupPage = undefined;
    this.bastionPanel?.stop();
    this.bastionPanel = undefined;
    const filters = h(
      "div",
      { class: "filters", role: "group", "aria-label": "Show activity" },
      FILTERS.map((f) =>
        h(
          "button",
          {
            class: "filter",
            type: "button",
            "data-filter": f.id,
            "aria-pressed": String(f.id === this.filter),
            on: { click: () => this.setFilter(f.id) },
          },
          f.label,
        ),
      ),
    );
    const def = PAGES[this.page];
    // The header is rebuilt with the page: a keyboard user who followed a tab stays on the tabs.
    const fromTab = !!(document.activeElement as HTMLElement | null)?.closest?.(".tabs");
    this.tray ??= new Tray(this.api, this.auth, () => this.changed());
    let main: HTMLElement;
    switch (this.page) {
      case "approvals":
        main = h(
          "main",
          { class: "sections" },
          h("div", { class: "col col-queue" }, section("signing", "Signatures to approve"), section("env", "Env releases and staged edits"), section("pending", "Waiting for you"), section("enroll", "Hosts asking to join")),
          h("div", { class: "col col-access" }, section("grants", "Active access", "tiles"), section("standing", "Auto-approvals", "tiles")),
        );
        break;
      case "activity":
        main = h("main", { class: "subpage wide" }, section("recent", "Activity", "", filters));
        break;
      case "setup":
        main = h("main",{class:'subpage'},h('p',{class:'crumb'},nav('‹ Settings','#/settings','Back to Settings')),h('h2',null,'Setup'),h('p',{class:'muted'},'Each step is one passkey approval. A small root program on this machine checks your signature itself and does the work.'),h('div',{id:'setup-root',class:'setup'}));
        break;
      default:
        main = h("main", { class: `subpage${this.page === "vault" ? " wide vault-page" : ""}` }, this.page === "vault" || this.page === "help" ? null : h("h2", { class: "page-title" }, def.title), def.sections.map(([id, title]) => section(id, title)));
    }
    replace(
      this.root,
      h("header", { class: "topbar" }, h("h1", { class: "brand" }, nav('aqmas','#/','Approvals')), navBar(), h("div", { class: "top-tools" }, this.search.button, this.tray.el, this.signOutButton(), h("p", { class: "status", id: "status" }))),
      main,
    );
    if(this.sealOnTop())this.root.insertBefore(section('seal','Broker keys'),this.root.querySelector('main'));
    if(this.page!=='vault')this.vaultView?.clearSecrets();
    if(this.page==='setup'){
      this.setupPage=new SetupPage($('#setup-root',this.root),this.api,this.auth,{
        openMigration:t=>this.sheet.openMigration(t),
        openUpdate:t=>this.sheet.openUpdate(t),
        signedOut:()=>this.signedOut('Your session ended. Sign in again to continue the setup.'),
        changed:()=>this.changed(),
      });
      this.setupPage.start();
    }
    if((this.page==='settings'||this.page==='setup')&&this.api.bastion&&this.api.setupGet){
      this.bastionPanel=new BastionPanel(this.api,this.auth,{
        openRevoke:t=>this.sheet.openRevoke(t),
        signedOut:()=>this.signedOut('Your session ended. Sign in again.'),
        changed:()=>this.changed(),
      },this.page==='setup'?'tasks':'overview');
      // Settings → Setup: the bastion's own tasks follow the Setup queue.
      if(this.page==='setup')this.root.querySelector('main')?.append(this.bastionPanel.el);
      this.bastionPanel.start();
    }
    this.renderSections();
    if (fromTab) this.root.querySelector<HTMLElement>('.tab[aria-current="page"]')?.focus();
    this.schedulePoll();
  }

  /** Until when a root certificate for the bastion is valid (0 = none). */
  rootUntil(): number {
    const at = Date.parse(this.state?.bastion_root_until ?? "");
    return Number.isFinite(at) && at > Date.now() ? at : 0;
  }

  private renderRootBanner(): void { syncRootBanner(this.root, this.rootUntil() ? this.state!.bastion_root_until : undefined); }

  /** The seal panel sits above every page, except that Setup shows the supervised import as
   * its own checklist. */
  private sealOnTop(): boolean {
    return !!this.seal && !(this.page === "setup" && this.seal.mode === "setup");
  }

  /** Requests of every kind that wait for a decision (the Approvals tab's badge, the title). */
  private waiting(): number {
    const s = this.state;
    return (s?.pending ?? []).length + (this.vaultState?.requests ?? []).filter((r) => r.status === "pending").length + (this.envState?.releases ?? []).filter((r) => r.status === "pending").length + (this.envState?.drafts ?? []).length;
  }

  /** One line for the tray and the Vault's empty pane when some passkey opens too little. */
  private readinessNote(): Child {
    const r = readiness(this.seal);
    if (!r || !r.fixable.length) return null;
    const a = h("a", null, r.fixable.length === 1 ? "Enable the other one" : `Enable the other ${r.fixable.length}`);
    a.href = "#/security";
    return h("span", { class: "readiness-note" }, readinessHeadline(r), " ", a, ".");
  }

  private renderSections(): void {
    const s = this.state;
    if (!s || this.view !== "main") return;
    const page = this.page, seal = this.seal, live = serving(seal);
    this.renderRootBanner();
    if(!this.sealOnTop()){this.root.querySelector('#sec-seal')?.remove();this.rendered.delete('seal');}
    else{if(!this.root.querySelector('#sec-seal'))this.root.insertBefore(section('seal','Broker keys'),this.root.querySelector('main'));const batch=serving(seal)&&page==='approvals'&&(s.pending??[]).length>0;this.section('seal',[seal!.mode,page,batch?s.pending:null,batch?seal!.epoch:null,this.tab.id()],()=>[sealBanner(seal!),batch&&multiPanel(this.api,this.auth,seal!,this.tab,(s.pending??[]).filter(p=>p.kind!=='bastion'&&p.kind!=='setup'),()=>this.changed())],!sealBanner(seal!)&&!batch);}
    const waiting = this.waiting();
    const ready = readiness(seal);
    this.tray?.update(seal, waiting, this.readinessNote());
    updateNav(this.root, page, { approvals: waiting }, ready?.fixable.length ? { security: `${ready.fixable.length} passkey${ready.fixable.length === 1 ? "" : "s"} cannot open your credentials yet` } : {});
    document.title = pageTitle(page, waiting);
    switch (page) {
      case "approvals":
        this.renderApprovals(s);
        return;
      case "activity": {
        const shown = this.shownIds();
        this.section("recent", [s.recent, this.filter, [...shown].sort()], () => this.activity(s.recent!, shown), false, false, 0);
        break;
      }
      case "vault": {
        const v = this.vaultState;
        this.section('vault',!!v,()=>v?[(this.vaultView??=new VaultView(this.vaultHost())).el]:[h('p',{class:'empty'},seal?.mode==='migration-required'?'Available after the move to per-credential buckets (Settings → Setup).':'The vault opens once organisations are active and the store is sealed (Settings → Setup).')]);
        if(v&&seal)this.vaultView!.update(v,seal,this.catalogue,route().item);
        break;
      }
      case "hosts":
        this.section('hosts',[this.hosts,this.catalogue,(s.pending??[]).filter(p=>p.kind==='enrollment').length],()=>this.hostsPage(s),false,false,this.hosts.length);
        break;
      case "security": {
        // A step waiting for its tap (the guided Enable, Create's or Rekey's follow-up test) keeps its panel until it is done.
        this.section('readiness',[seal?.passkeys,seal?.scopes,s.passkeys],()=>ready?[readinessPanel({api:this.api,auth:this.auth,passkeys:()=>this.state?.passkeys??[],refresh:()=>this.changed()},seal!,ready)]:[],!ready,!!this.root.querySelector('#sec-readiness .wizard'),0);
        this.section('passkeys',[s.owner,s.passkeys,seal?.passkeys,seal?.scopes,seal?.mode],()=>this.passkeys(s),false,!!this.root.querySelector('#sec-passkeys .capabilities button.confirm'),s.passkeys?.length??0);
        const stepping=!!this.root.querySelector('#sec-buckets .buckets-review button.confirm');
        this.section('buckets',[seal,s.passkeys,this.tab.id()],()=>live?[bucketsPanel(this.api,this.auth,seal!,s.passkeys??[],()=>this.changed(),this.tab,{createScope:(scope,review)=>createScope(this.api,this.auth,seal!,s.passkeys??[],scope,review,()=>this.changed()),testAfterRekey:(scope,review)=>testAfterRekey(this.api,this.auth,seal!,s.passkeys??[],scope,review,()=>this.changed())}),windowAdmin(this.api,this.auth,seal!,this.tab,s.passkeys??[],()=>this.changed())]:[h('p',{class:'empty'},seal?.mode==='migration-required'?'Available after the move to per-credential buckets (Settings → Setup).':'Available once the store is sealed (Settings → Setup).')],!seal,stepping,0);
        this.section('recovery',[seal?.mode,seal?.installation,seal?.epoch,seal?.scopes,s.passkeys],()=>live?[recoveryPanel(this.api,this.auth,seal!,s.passkeys??[],()=>this.changed())]:[],!live,false,0);
        break;
      }
      case "settings":
        // The reveal policy lines sign against the broker's current epoch.
        if (this.vaultState && seal) (this.vaultView ??= new VaultView(this.vaultHost())).forms.bind(this.vaultState, seal);
        this.section('setup',[this.setupView],()=>[h('article',{class:'card'},h('p',null,setupSummary(this.setupView)),h('p',{class:'muted'},'Switch to organisations, seal the store, enable self-update, maintenance passkeys and upgrades: each is one passkey approval.'),h('div',{class:'actions'},(()=>{const a=nav('Open Setup','#/setup','Setup');a.className='btn approve';return a;})()))],false,false,0);
        this.section('bastion',!!this.bastionPanel,()=>this.bastionPanel?[this.bastionPanel.el]:[h('p',{class:'empty'},'This server has no bastion access.')],false,false,0);
        this.section('orgs',[this.catalogue,this.vaultState?.organisations,seal?.epoch],()=>this.orgsPage(),false,!!this.root.querySelector('#sec-orgs .vault-confirm'),this.catalogue?.organisations.length??0);
        break;
      case "help":
        if(this.help) this.section('help',this.help,()=>[helpPage(this.help!)]);
        break;
      case "setup":
        break;
    }
    this.updateStatus();
  }

  /** Hosts: each enrolled host with the organisations it may ask for. */
  private hostsPage(s: UIState): Child[] {
    const cat = this.catalogue;
    const joining = (s.pending ?? []).filter((p) => p.kind === "enrollment").length;
    const out: Child[] = [];
    if (joining) {
      const a = nav(joining === 1 ? "1 host is asking to join" : `${joining} hosts are asking to join`, "#/", "Approvals");
      a.className = "btn approve";
      out.push(h("p", { class: "hosts-joining" }, a));
    }
    if (!this.hosts.length) out.push(h("p", { class: "empty" }, "No enrolled hosts. Help has the command that enrolls one."));
    for (const host of this.hosts) {
      const card = hostCard(host, (t) => this.sheet.openRevoke(t));
      if (cat && !host.revoked_at) {
        const rows = cat.organisations.map((o) => ({ o, x: o.hosts.find((x) => x.enrollment === host.id) })).filter((r) => r.x);
        card.insertBefore(
          h(
            "div",
            { class: "admissions" },
            h("h4", null, "May ask for credentials of"),
            rows.length
              ? h("ul", { class: "admission-list" }, rows.map(({ o, x }) => h("li", { class: x!.active ? "in" : "out" }, h("bdi", null, vt(o.title)), h("span", { class: "badge" }, x!.active ? "admitted" : "not admitted"), admissionButton(cat, o, x!, (t, c) => this.sheet.openCatalogue(t, c)))))
              : h("p", { class: "muted" }, "No organisation lists this host."),
          ),
          card.querySelector("dl.facts"),
        );
      }
      out.push(card);
    }
    return out;
  }

  /** Settings: each organisation's policies (items and admissions live on Vault and Hosts). */
  private orgsPage(): Child[] {
    const cat = this.catalogue;
    if (!cat) return ["Available after personal activation (Setup)."];
    const forms = this.vaultState && this.seal ? (this.vaultView ??= new VaultView(this.vaultHost())).forms : undefined;
    return [
      h("p", { class: "muted" }, "Create organisations, services and items from Vault → Add item; admit hosts under Hosts."),
      ...cat.organisations.map((o) => {
        const vo = this.vaultState?.organisations.find((x) => x.id === o.id);
        const sets = o.services.reduce((n, v) => n + v.sets.filter((x) => !x.archived).length, 0);
        return h(
          "article",
          { class: "card org-card" },
          h("h3", null, h("bdi", null, vt(o.title))),
          h("p", { class: "muted" }, h("span", { class: "mono" }, vt(o.slug)), ` · ${o.services.length} service${o.services.length === 1 ? "" : "s"} · ${sets} item${sets === 1 ? "" : "s"} · ${o.hosts.filter((x) => x.active).length} admitted host${o.hosts.filter((x) => x.active).length === 1 ? "" : "s"}`),
          forms && vo ? forms.policyLine(vo) : null,
          policyForm(cat, o, (t, c) => this.sheet.openCatalogue(t, c)),
        );
      }),
    ];
  }

  private renderApprovals(s: UIState): void {
    const requests = s.pending!.filter((p) => p.kind !== "enrollment");
    const enrolls = s.pending!.filter((p) => p.kind === "enrollment");
    // While a finger is on the screen, leave the lists alone (the next poll catches up).
    const touching = this.pointerDown || Date.now() - this.lastTouch < TOUCH_SETTLE_MS;

    this.section(
      "pending",
      requests,
      () =>
        requests.length
          ? requests.map((p) => this.requestCard(p))
          : [h("p", { class: "empty" }, "Nothing is waiting. New requests show up here within a few seconds.")],
      false,
      // A queued task being approved keeps its card until that is done.
      touching || !!this.root.querySelector("#sec-pending .queued-run.busy"),
    );
    {
      const v = this.vaultState, reqs = v?.requests ?? [];
      const busy = !!this.root.querySelector("#sec-signing .vault-confirm");
      this.section("signing", [reqs, this.seal?.epoch], () => (v && this.seal ? signCards(this.vaultHost(), this.seal, v) : []), reqs.length === 0, touching || busy, reqs.filter((r) => r.status === "pending").length);
    }
    {
      // Env releases hosts asked for and edits staged from the CLI: approve, deny, revoke, commit.
      const e = this.envState, n = (e?.releases.length ?? 0) + (e?.drafts.length ?? 0);
      this.section("env", [e, this.seal?.mode], () => (e && this.seal ? [envPanel(this.api, this.auth, this.seal, e, null, () => this.changed())] : []), n === 0, touching || !!this.root.querySelector("#sec-env [role=status] button"), n);
    }
    this.section("enroll", enrolls, () => enrolls.map((p) => this.enrollCard(p)), enrolls.length === 0, touching);
    this.section(
      "grants",
      s.grants,
      () => {
        if (s.grants === undefined) return [h("p", { class: "empty" }, "This server doesn't list active grants yet.")];
        const active = s.grants!.filter((g) => g.status === "approved");
        return active.length ? active.map((g) => this.grantRow(g)) : [h("p", { class: "empty" }, "No host holds access right now.")];
      },
      false,
      touching,
    );
    this.section(
      "standing",
      s.standing,
      () => (s.standing!.length ? s.standing!.map((a) => this.standingRow(a)) : [h("p", { class: "empty" }, "No auto-approvals are active.")]),
      false,
      touching,
    );
    this.updateStatus();
    this.tick();
    if (this.focusId) {
      const el = this.root.querySelector(`[data-id="${CSS.escape(this.focusId)}"]`);
      if (el) {
        el.classList.add("focus");
        el.scrollIntoView({ block: "center" });
      }
      this.focusId = null;
    }
  }

  /** Ids of every card on the page (activity rows link to these). */
  private shownIds(): Set<string> {
    const s = this.state;
    const out = new Set<string>();
    if (!s) return out;
    for (const p of s.pending ?? []) out.add(p.id);
    for (const a of s.standing ?? []) out.add(a.id);
    for (const g of s.grants ?? []) if (g.status === "approved") out.add(g.id);
    return out;
  }

  private setFilter(f: Filter): void {
    this.filter = f;
    for (const b of this.root.querySelectorAll<HTMLElement>(".filters .filter")) b.setAttribute("aria-pressed", String(b.dataset["filter"] === f));
    this.renderSections();
  }

  /** Scroll to a card and highlight it for a moment. */
  private jumpTo(id: string): void {
    const el = this.root.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`);
    if (!el) {
      // The cards live on Approvals: go there and focus it (the #r= address the CLI prints).
      if (this.page !== "approvals" && /^[A-Za-z0-9_-]{1,64}$/.test(id)) location.hash = `#r=${id}`;
      return;
    }
    for (const f of this.root.querySelectorAll(".focus")) f.classList.remove("focus");
    el.classList.add("focus");
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const btn = el.querySelector<HTMLElement>("button");
    btn?.focus({ preventScroll: true });
    window.setTimeout(() => el.classList.remove("focus"), 2500);
  }

  // ---- activity ----

  private activity(entries: AuditEntry[], shown: Set<string>): Child[] {
    if (!entries.length) return [h("p", { class: "empty" }, "No activity yet.")];
    const list = entries.filter((e) => matches(e, this.filter));
    if (!list.length) return [h("p", { class: "empty" }, "Nothing of this kind in the recent activity.")];
    const now = Date.now();
    return groupByDay(list).map((g) => {
      const label = dayLabel(g.at, now);
      return h(
        "section",
        { class: "ev-day", "aria-label": label },
        h("h3", { class: "ev-day-h" }, h("time", { datetime: g.key }, label)),
        h("ol", { class: "ev-list" }, g.entries.map((e) => this.eventRow(e, shown, now))),
      );
    });
  }

  private eventRow(e: AuditEntry, shown: Set<string>, now: number): HTMLElement {
    const info = classify(e);
    const who = actor(e.actor);
    const obj = objectRef(e.object);
    const key = rowKey(e);
    const open = this.expanded.has(key);
    const at = new Date(e.at).getTime();
    const moreId = `ev-${++this.evSeq}`;
    const linkable = obj.id !== "" && shown.has(obj.id);

    const untrusted = detailUntrusted(e);
    const more = h(
      "div",
      { class: "ev-more", id: moreId, hidden: !open },
      h(
        "dl",
        { class: "facts" },
        fact("When", absoluteTime(at)),
        fact("By", h("bdi", { class: "mono" }, vt(e.actor))),
        e.object ? fact("About", h("span", { class: "mono" }, vt(e.object))) : null,
      ),
      e.detail
        ? untrusted
          ? h(
              "div",
              { class: "agent ev-detail", role: "group", "aria-label": "Details, may include text a host sent (unverified)" },
              h("p", { class: "agent-label" }, "Details", h("span", { class: "muted" }, ", may include text a host sent (unverified)")),
              h("p", { class: "mono", dir: "ltr" }, vt(e.detail)),
            )
          : h("p", { class: "ev-detail-plain mono" }, vt(e.detail))
        : null,
      linkable ? h("button", { class: "btn small", type: "button", on: { click: () => this.jumpTo(obj.id) } }, `Show the ${vt(obj.short)} card`) : null,
    );
    const toggle = h(
      "button",
      { class: "ev-toggle", type: "button", "aria-expanded": String(open), "aria-controls": moreId },
      h("span", { class: "ev-glyph" }, eventIcon(info.kind), info.cloudflare ? cloudIcon() : null),
      h("span", { class: "ev-label" }, vt(info.label)),
      e.detail?.includes(' INDEFINITE ') && (e.action==='approve'||e.action==='standing_create') ? h('strong',null,'INDEFINITE') : null,
      h("span", { class: `actor actor-${who.kind}` }, who.kind === "host" ? [h("span", { class: "sr" }, "host "), h("bdi", null, vt(who.name))] : vt(who.name)),
      obj.short ? h("span", { class: "ev-obj" }, vt(obj.short)) : null,
      h("time", { class: "ev-time", datetime: e.at, title: absoluteTime(at), "data-ev-at": String(at) }, eventTime(at, now)),
      chevronIcon(),
    );
    toggle.addEventListener("click", () => {
      const nowOpen = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(nowOpen));
      more.hidden = !nowOpen;
      if (nowOpen) this.expanded.add(key);
      else this.expanded.delete(key);
    });
    return h(
      "li",
      { class: `ev ev-${info.kind}${info.cloudflare ? " ev-cf" : ""}` },
      h(
        "div",
        { class: "ev-line" },
        toggle,
        linkable
          ? h(
              "button",
              { class: "ev-jump", type: "button", "aria-label": `Show the ${vt(obj.short)} card`, on: { click: () => this.jumpTo(obj.id) } },
              "Show",
            )
          : null,
      ),
      more,
    );
  }

  // ---- passkeys ----

  private passkeys(s: UIState): Child[] {
    const list = s.passkeys;
    const add = h("button", { class: "btn", type: "button", on: { click: () => this.sheet.openAddPasskey() } }, "Add a passkey");
    const signedIn = h("p", { class: "muted" }, "Signed in as ", h("bdi", null, vt(s.owner.name)), ".");
    if (list === undefined || list === null) {
      // Older server: only the count.
      return [
        h("p", null, `Signed in as ${vt(s.owner.name)}. `, s.owner.passkeys === 1 ? "1 passkey is registered." : `${s.owner.passkeys} passkeys are registered.`),
        add,
      ];
    }
    const only = list.length <= 1;
    return [
      h("div", { class: "tiles" }, list.map((p) => this.passkeyTile(p, only))),
      only ? h("p", { class: "muted" }, "Add a second passkey (another password manager or a hardware key) so you can still get in if you lose this one.") : null,
      h("div", { class: "pk-foot" }, this.seal ? serving(this.seal) ? capabilityForm(this.api, this.auth, this.seal, list, () => this.changed()) : "Passkeys are managed here again after the move to per-credential buckets (Setup)." : add, signedIn),
    ];
  }

  /** "Opens N of M buckets" / "Opens nothing yet" from the seal status (format 2). */
  private bucketBadge(p: PasskeyInfo): HTMLElement | null {
    const k = serving(this.seal) ? this.seal!.passkeys?.find((x) => x.id === p.id) : undefined;
    if (!k) return null;
    if (!k.prf || k.opens === 0) return h("span", { class: "badge", title: "Not enabled for any scope yet: Passkeys → Enable" }, "Opens nothing yet");
    return h("span", { class: "badge", title: k.missing.length ? "Not enabled for " + k.missing.map((m) => this.seal!.scopes?.find((x) => x.scope === m)?.title ?? m).join(", ") : "Enabled for every scope" }, `Opens ${k.opens} of ${k.of} buckets`);
  }

  /** Raw credential IDs → nicknames (to say which passkey can open a bucket). */
  passkeyNames(raw: string[]): string[] {
    const list = this.state?.passkeys ?? [];
    return raw.map((r) => list.find((p) => p.raw_id === r)?.nickname).filter((n): n is string => !!n);
  }

  private passkeyTile(p: PasskeyInfo, only: boolean): HTMLElement {
    const synced = p.backup_eligible === true;
    const transports = (p.transports ?? []).map(transportLabel).filter((t) => t !== "");
    return h(
      "article",
      { class: `row pk${p.current ? " current" : ""}`, "data-id": p.id, "aria-label": `Passkey ${vt(p.nickname)}` },
      h(
        "div",
        { class: "pk-head" },
        h("span", { class: "pk-icon" }, passkeyIcon(p.icon)),
        h(
          "div",
          { class: "pk-names" },
          h("h3", { class: "pk-name" }, h("bdi", null, vt(p.nickname))),
          h("p", { class: "pk-auth" }, vt(p.authenticator || "Unknown authenticator")),
        ),
      ),
      h(
        "div",
        { class: "badges" },
        h(
          "span",
          {
            class: `badge ${synced ? "synced" : "bound"}`,
            title: synced ? "Synced: the password manager copies it to your other devices" : "Device-bound: it never leaves this authenticator",
          },
          syncIcon(synced),
          synced ? "Synced" : "Device-bound",
        ),
        p.current ? h("span", { class: "badge this", title: "You signed in with this passkey" }, "This device") : null,
        this.bucketBadge(p),
      ),
      h(
        "dl",
        { class: "facts" },
        fact("Added", h("time", { datetime: p.created_at, title: absoluteTime(p.created_at) }, shortDate(p.created_at))),
        fact("Last used", p.last_used_at ? since(p.last_used_at) : h("span", { class: "muted" }, "never")),
        transports.length ? fact("Connects by", transports.join(", ")) : null,
        // The same short id the rename/remove confirmation shows (from the signed text).
        fact("Id", h("span", { class: "mono" }, vt(shortId(p.id)))),
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", type: "button", on: { click: () => this.sheet.openRename(p) } }, "Rename…"),
        h(
          "button",
          {
            class: "btn deny",
            type: "button",
            disabled: only,
            title: only ? "Your only passkey can't be removed" : undefined,
            on: { click: () => this.sheet.openRemove(p) },
          },
          "Remove…",
        ),
      ),
      only ? h("p", { class: "muted small" }, "Your only passkey can't be removed. Add another first.") : null,
    );
  }

  /** Re-render a section only when its data changed (keeps scroll/focus stable while polling). */
  private section(name: string, data: unknown, build: () => Child[], hidden = false, defer = false, count?: number): void {
    const key = JSON.stringify(data) ?? "undefined";
    const sec = $(`#sec-${name}`, this.root);
    if (this.rendered.get(name) === key) return;
    if (defer && this.rendered.has(name)) return;
    sec.hidden = hidden;
    this.rendered.set(name, key);
    const list = $(".list", sec);
    replace(list, build());
    const countEl = sec.querySelector(".count");
    const n = count ?? (Array.isArray(data) ? data.length : 0);
    if (countEl) countEl.textContent = n > 0 ? String(n) : "";
  }

  private updateStatus(err?: unknown): void {
    const el = this.root.querySelector("#status");
    if (!el) return;
    if (this.offline) {
      el.textContent = `Can't reach aqmas${err ? ` (${vt(explainError(err))})` : ""}. Retrying.`;
      el.classList.add("bad");
      el.setAttribute("role", "alert");
    } else {
      el.textContent = this.lastOk ? `Updated ${ago(this.lastOk)}` : "";
      el.classList.remove("bad");
      el.removeAttribute("role");
    }
  }

  private tick(): void {
    const now = Date.now();
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-until]")) updateCountdown(t, now);
    for (const t of document.querySelectorAll<HTMLElement>("dialog [data-until]")) updateCountdown(t, now);
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-since]")) t.textContent = ago(Number(t.dataset["since"]), now);
    for (const t of this.root.querySelectorAll<HTMLElement>("[data-ev-at]")) t.textContent = eventTime(Number(t.dataset["evAt"]), now);
    if (this.view === "main" && !this.offline) this.updateStatus();
    if (this.view === "main" && this.rendered.size > 0 && !this.pointerDown && now - this.lastTouch >= TOUCH_SETTLE_MS) {
      // Catch up on a render that was deferred during a touch.
      this.renderSectionsIfDeferred();
    }
    this.sheet.tick(now);
  }

  private renderSectionsIfDeferred(): void {
    if(this.page!=='approvals') return;
    const s = this.state;
    if (!s) return;
    const req = s.pending!.filter((p) => p.kind !== "enrollment");
    const enr = s.pending!.filter((p) => p.kind === "enrollment");
    const stale =
      this.rendered.get("pending") !== JSON.stringify(req) ||
      this.rendered.get("enroll") !== JSON.stringify(enr) ||
      this.rendered.get("standing") !== JSON.stringify(s.standing) ||
      this.rendered.get("grants") !== (JSON.stringify(s.grants) ?? "undefined");
    if (stale) this.renderSections();
  }

  // ---- cards ----

  private requestCard(p: PendingItem): HTMLElement {
    if (p.kind === "cloudflare") return this.cfRequestCard(p);
    if (p.kind === "bastion") return bastionCard(p, { approve: (x) => this.sheet.openApprove(x), deny: (x) => this.sheet.openDeny(x), agentSays, until, since, ref: refCode });
    if (p.kind === "setup") return queuedTaskCard(this.api, this.auth, p, { agentSays, until, ref: refCode, changed: () => this.changed() });
    const ssh = p.ssh;
    const high = p.risk === "high";
    const odd = !isPlainName(p.requesting_host) || (ssh && (!isPlainName(ssh.login_user) || !isPlainName(ssh.target_host)));
    return h(
      "article",
      { class: `card request${high ? " high" : ""}`, "data-id": p.id, "aria-label": `${kindLabel(p.kind)} request from ${vt(p.requesting_host)}` },
      scopeHeading(p.scoped_facts),
      h(
        "div",
        { class: "card-top" },
        h("span", { class: "kind" }, vt(kindLabel(p.kind))),
        high ? h("span", { class: "risk" }, "High risk") : null,
        h("span", { class: "expires" }, "Expires in ", until(p.expires_at)),
      ),
      ssh ? targetLine(ssh.login_user, ssh.target_host) : h("h3", { class: "target" }, vt(p.kind)),
      ssh ? h('p',null,'Certificate principal: ',h('bdi',null,vt(ssh.principal))) : null,
      ssh ? h('p',null,'Address: ',h('bdi',null,vt(ssh.target_address)),` · port ${ssh.target_port}`,ssh.requested_target && ssh.requested_target!==ssh.target_host ? [' · requested as ',h('bdi',null,vt(ssh.requested_target))] : null) : null,
      odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
      h(
        "dl",
        { class: "facts" },
        fact("From", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
        fact("Asks for", duration(p.ttl_requested), p.ttl_max > 0 ? h("span", { class: "muted" }, ` (up to ${duration(p.ttl_max)} allowed)`) : null),
        ssh ? fact("Key", h("span", { class: "mono" }, vt(ssh.key_fingerprint))) : null,
        p.similar_recent > 0 ? fact("Similar", p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`) : null,
        fact("Asked", since(p.created_at)),
        fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
      ),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Deny…"),
        h("button", { class: "btn approve", type: "button", on: { click: () => this.sheet.openApprove(p) } }, "Approve…"),
      ),
    );
  }

  /** A Cloudflare request: scope in this page's own words, each parameter, mode, TTL, risk. */
  private cfRequestCard(p: PendingItem): HTMLElement {
    const cf = p.cloudflare;
    const v = cfView(cf?.scope, cf?.scope_params, cf?.mode);
    const risk = v.scope?.risk ?? cfRisk(cf?.risk);
    const admin = cf?.scope === "cf.admin";
    const token = cf?.mode === "token";
    const odd = !isPlainName(p.requesting_host) || v.unusual.length > 0;
    return h(
      "article",
      {
        class: `card request cloudflare${risk === "high" || risk === "admin" ? " high" : ""}${admin ? " cf-admin" : ""}`,
        "data-id": p.id,
        "aria-label": `${admin ? "Break-glass " : ""}Cloudflare request from ${vt(p.requesting_host)}`,
      },
      scopeHeading(p.scoped_facts),
      h(
        "div",
        { class: "card-top" },
        h("span", { class: "kind" }, "Cloudflare"),
        riskBadge(risk),
        h("span", { class: "expires" }, "Expires in ", until(p.expires_at)),
      ),
      admin ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS: full Cloudflare access for 1 hour, everything except the deny-list. Approve only if you asked for it yourself.") : null,
      v.heading,
      v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
      odd ? h("p", { class: "warn" }, "A name here contains unusual characters. Check it letter by letter.") : null,
      h(
        "dl",
        { class: "facts" },
        fact("Scope", h("span", { class: "mono" }, vt(cf?.scope ?? "?"))),
        v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
        fact("Mode", token ? ["Real API token, usable only from ", h("span", { class: "mono" }, vt(cf?.ip_condition || "?"))] : "Through the aqmas proxy (no secret leaves aqmas)"),
        fact("From", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
        fact("Asks for", duration(p.ttl_requested), p.ttl_max > 0 ? h("span", { class: "muted" }, ` (up to ${duration(p.ttl_max)} allowed)`) : null),
        p.similar_recent > 0 ? fact("Similar", p.similar_recent === 1 ? "1 similar request recently" : `${p.similar_recent} similar requests recently`) : null,
        fact("Asked", since(p.created_at)),
        fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
      ),
      token ? tokenBox(cf!, v.scope) : null,
      scopeDetails(v.scope, cf),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Deny…"),
        h(
          "button",
          { class: "btn approve", type: "button", disabled: !!v.problem, title: v.problem ? "This page can't describe this scope, so it won't sign an approval" : undefined, on: { click: () => this.sheet.openApprove(p) } },
          admin ? "Approve break-glass…" : "Approve…",
        ),
      ),
    );
  }

  private enrollCard(p: PendingItem): HTMLElement {
    const e = p.enrollment;
    return h(
      "article",
      { class: "card enroll", "data-id": p.id, "aria-label": `${vt(p.requesting_host)} asks to join` },
      h("div", { class: "card-top" }, h("span", { class: "kind" }, "New host"), e?.replaces_existing ? h("span", { class: "risk" }, "Replaces an existing host") : null, h("span", { class: "expires" }, "Expires in ", until(p.expires_at))),
      h("h3", { class: "target" }, h("bdi", { class: "host" }, vt(p.requesting_host))),
      !isPlainName(p.requesting_host) ? h("p", { class: "warn" }, "This host name contains unusual characters. Check it letter by letter.") : null,
      e?.replaces_existing ? h("p", { class: "warn" }, "A host with this name is already enrolled. Approving revokes its certificate.") : null,
      enrollFacts(p),
      agentSays(p),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openDeny(p) } }, "Refuse…"),
        h("button", { class: "btn approve", type: "button", on: { click: () => this.sheet.openApprove(p) } }, "Let it join…"),
      ),
    );
  }

  private standingRow(a: StandingApproval): HTMLElement {
    if (a.kind === "cloudflare") {
      const v = cfView(a.scope, a.scope_params, a.mode, true);
      return h(
        "article",
        { class: "row cloudflare", "data-id": a.id },
        scopeHeading(a.scoped_facts),a.indefinite?h('strong',null,'INDEFINITE standing approval — until revoked'):null,
        v.heading,
        v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
        h(
          "dl",
          { class: "facts" },
          fact("Scope", h("span", { class: "mono" }, vt(a.scope ?? "?"))),
          v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
          fact("Mode", vt(modeWords(a.mode))),
          fact("For host", h("bdi", { class: "host-name" }, vt(a.requesting_host))),
          fact("Each grant", `up to ${duration(a.max_ttl_seconds)}`),
          a.indefinite?fact('Ends','On revocation'):fact("Ends in", until(a.expires_at)),
          fact("Used", a.uses === 1 ? "once" : `${a.uses} times`),
        ),
        h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForStanding(a)) } }, "Revoke…")),
      );
    }
    return h(
      "article",
      { class: "row", "data-id": a.id },
      targetLine(a.login_user, a.target_host, true),
      h(
        "dl",
        { class: "facts" },
        fact("For host", h("bdi", { class: "host-name" }, vt(a.requesting_host))),
        fact("Each grant", `up to ${duration(a.max_ttl_seconds)}`),
        fact("Ends in", until(a.expires_at)),
        fact("Used", a.uses === 1 ? "once" : `${a.uses} times`),
      ),
      h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForStanding(a)) } }, "Revoke…")),
    );
  }

  private grantRow(g: GrantSummary): HTMLElement {
    if (g.kind === "cloudflare") {
      const v = cfView(g.scope, g.scope_params, g.mode, true);
      const admin = g.scope === "cf.admin";
      return h(
        "article",
        { class: `row cloudflare${admin ? " cf-admin" : ""}`, "data-id": g.id },
        scopeHeading(g.scoped_facts),g.indefinite?h('strong',null,'INDEFINITE access — until revoked'):null,
        admin ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS access is active.") : null,
        v.heading,
        v.problem ? h("p", { class: "warn" }, vt(v.problem)) : null,
        h(
          "dl",
          { class: "facts" },
          g.requesting_host ? fact("Held by", h("bdi", { class: "host-name" }, vt(g.requesting_host))) : null,
          fact("Kind", "Cloudflare ", h("span", { class: "mono" }, vt(g.scope ?? "?"))),
          v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))),
          fact("Mode", vt(modeWords(g.mode))),
          g.indefinite?fact('Ends','On revocation'):fact("Ends in", until(g.not_after)),
        ),
        h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForGrant(g)) } }, "Revoke…")),
      );
    }
    return h(
      "article",
      { class: "row", "data-id": g.id },
      targetLine(g.login_user ?? "?", g.target_host ?? "?", true),
      h(
        "dl",
        { class: "facts" },
        g.requesting_host ? fact("Held by", h("bdi", { class: "host-name" }, vt(g.requesting_host))) : null,
        fact("Kind", vt(kindLabel(g.kind))),
        fact("Ends in", until(g.not_after)),
      ),
      h("div", { class: "actions" }, h("button", { class: "btn deny", type: "button", on: { click: () => this.sheet.openRevoke(targetForGrant(g)) } }, "Revoke…")),
    );
  }
}

// ---- helpers ----

function normalise(s: UIState): UIState {
  const pending = [...(s.pending ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at));
  return { ...s, pending, standing: s.standing ?? [], recent: s.recent ?? [], grants: s.grants === undefined ? undefined : (s.grants ?? []) };
}

function section(name: string, title: string, listClass = "", extra?: Child): HTMLElement {
  return h(
    "section",
    { id: `sec-${name}`, class: "section", "aria-labelledby": `sec-${name}-h` },
    h("div", { class: "section-head" }, h("h2", { id: `sec-${name}-h` }, title, " ", h("span", { class: "count" })), extra),
    h("div", { class: listClass ? `list ${listClass}` : "list" }),
  );
}

const TRANSPORTS: Record<string, string> = {
  usb: "USB",
  nfc: "NFC",
  ble: "Bluetooth",
  internal: "built in",
  hybrid: "phone (QR code)",
  "smart-card": "smart card",
};

function transportLabel(t: string): string {
  return own(TRANSPORTS, t) ?? vt(t);
}

function fact(label: string, ...value: Child[]): Child[] {
  return [h("dt", null, label), h("dd", null, ...value)];
}

function targetLine(user: string, host: string, small = false): HTMLElement {
  return h(
    "h3",
    { class: small ? "target small" : "target" },
    h("bdi", { class: "user" }, vt(user)),
    h("span", { class: "at" }, "@"),
    h("bdi", { class: "host" }, vt(host)),
  );
}

interface CFView {
  scope: CFScopeDesc | undefined;
  pairs: Array<[string, string]>;
  unusual: string[];
  heading: HTMLElement;
  /** Why this page won't sign an approval for it (unknown scope, bad parameters). */
  problem?: string;
}

/** A Cloudflare scope + canonical parameters as a heading in this page's own words. */
function cfView(scopeName: string | undefined, scopeParams: string | undefined, mode: string | undefined, small = false): CFView {
  const scope = cfScope(scopeName);
  let params: Record<string, string> = {};
  let problem: string | undefined;
  try {
    params = parseScopeParams(scopeParams ?? "");
  } catch (e) {
    problem = `${(e as Error).message}: this page won't sign it.`;
  }
  if (!scope) problem = `This page has no description of the Cloudflare scope "${scopeName ?? ""}", so it won't sign it.`;
  const cls = small ? "target cf small" : "target cf";
  const heading = scope
    ? h("h3", { class: cls }, renderParts(sentenceCase(scope.phrase(params))), mode === "token" ? h("span", { class: "muted mode-tag" }, " (API token)") : null)
    : h("h3", { class: cls }, "Unknown Cloudflare scope ", h("bdi", { class: "val" }, vt(scopeName ?? "?")));
  return { scope, pairs: paramPairs(scope, params), unusual: scope ? unusualParams(scope, params) : [], heading, problem };
}

function cfRisk(r: string | undefined): string {
  return r && (CF_RISKS as readonly string[]).includes(r) ? r : "high";
}

function riskBadge(risk: string): HTMLElement {
  return h("span", { class: `badge risk-${cfRisk(risk)}` }, riskLabel(cfRisk(risk)));
}

function modeWords(mode: string | undefined): string {
  if (mode === "token") return "Real API token";
  if (mode === "proxy") return "Through the aqmas proxy";
  return mode ?? "?";
}

/** Token mode: what the minted token can do (server's words) and this page's own warning. */
function tokenBox(cf: PendingCloudflare, scope: CFScopeDesc | undefined): HTMLElement {
  const own = scope?.tokenNote?.(cf.params ?? {});
  return h(
    "div",
    { class: "token-box", role: "group", "aria-label": "API token details" },
    h("p", { class: "token-label" }, "A real API token leaves aqmas"),
    h("p", null, "Guard rails and snapshots don't apply to it. It expires with the grant and is deleted at Cloudflare on revoke."),
    own ? h("p", { class: "warn" }, own) : null,
    cf.permissions?.length ? [h("p", { class: "muted" }, "Token permissions (from aqmas):"), h("ul", { class: "perms" }, cf.permissions.map((x) => h("li", null, vt(x))))] : null,
    cf.notes?.length ? h("ul", { class: "notes" }, cf.notes.map((x) => h("li", null, vt(x)))) : null,
  );
}

/** What the scope allows and doesn't (this page's words), plus the server's own description. */
function scopeDetails(scope: CFScopeDesc | undefined, cf: PendingCloudflare | undefined): HTMLElement | null {
  if (!scope && !cf?.description) return null;
  return h(
    "details",
    { class: "scope-details" },
    h("summary", null, "What this allows"),
    scope ? [h("p", { class: "muted" }, "Can:"), h("ul", null, scope.can.map((x) => h("li", null, x))), h("p", { class: "muted" }, "Cannot:"), h("ul", null, scope.cannot.map((x) => h("li", null, x)))] : null,
    cf?.title || cf?.description ? h("p", { class: "server-says" }, h("span", { class: "muted" }, "aqmas catalogue: "), vt(cf.title), cf.title && cf.description ? ". " : "", vt(cf.description)) : null,
  );
}

function enrollFacts(p: PendingItem): HTMLElement {
  const e = p.enrollment;
  return h(
    "dl",
    { class: "facts" },
    fact('Enrollment class',h('strong',{class:e?.class==='owner-device'?'warn':''},vt(e?.class))),
    e?.class==='owner-device' ? fact('Owner policy',`SSH certificates up to ${duration(e.max_ssh_seconds)}; standing approvals up to ${hours(e.max_standing_hours)}.`) : null,
    e?.replaces_existing ? fact('Replaces enrollment',h('bdi',null,vt(e.replaces_id))) : null,
    fact("Connecting from", h("span", { class: "addr" }, vt(p.requesting_address))),
    e?.csr_fingerprint ? fact("Client key", h("span", { class: "mono" }, vt(e.csr_fingerprint))) : null,
    e?.ssh_host_key_fingerprints?.length ? fact("SSH host keys (self-reported)", e.ssh_host_key_fingerprints.map((f) => h("span", { class: "mono block" }, vt(f)))) : null,
    fact("Asked", since(p.created_at)),
    fact("Ref", h("span", { class: "mono" }, vt(refCode(p.id)))),
  );
}

function until(iso: string | number): HTMLElement {
  const ms = typeof iso === "number" ? iso : new Date(iso).getTime();
  const t = h("time", { class: "countdown", "data-until": String(ms), datetime: Number.isFinite(ms) ? new Date(ms).toISOString() : "" });
  updateCountdown(t, Date.now());
  return t;
}

function since(iso: string): HTMLElement {
  const ms = new Date(iso).getTime();
  const t = h("time", { "data-since": String(ms), datetime: iso });
  t.textContent = ago(ms);
  return t;
}

function updateCountdown(t: HTMLElement, now: number): void {
  const ms = Number(t.dataset["until"]);
  const left = ms - now;
  t.textContent = countdown(ms, now);
  t.classList.toggle("soon", left > 0 && left < 60_000);
  t.classList.toggle("over", left <= 0);
}

/** Render description parts: canonical values isolated in <bdi>, our words as plain text. */
function renderParts(parts: Part[]): Child[] {
  return parts.map((p) => (typeof p === "string" ? p : h("bdi", { class: "val" }, vt(p.value))));
}

/** The untrusted, agent-written part of a request, visibly fenced off. */
function agentSays(p: PendingItem): HTMLElement {
  const r = p.requester ?? { tool: "", user: "" };
  const meta: Child[] = [];
  const add = (label: string, v: unknown) => {
    if (v === undefined || v === null || v === "" || v === 0) return;
    meta.push(h("dt", null, label), h("dd", { dir: "ltr" }, vt(v)));
  };
  add("Tool", r.tool);
  add("User", r.user);
  add("Directory", r.cwd);
  add("Session", r.session_id);
  add("PID", r.pid);
  return h(
    "div",
    { class: "agent", role: "group", "aria-label": "Agent says (unverified, written by the requester)" },
    h("p", { class: "agent-label" }, "Agent says", h("span", { class: "muted" }, ", unverified")),
    p.reason ? h("p", { class: "reason", dir: "auto" }, vt(p.reason)) : h("p", { class: "reason muted" }, "(no reason given)"),
    meta.length ? h("dl", { class: "agent-meta" }, meta) : null,
  );
}

function isNegative(action: string): boolean {
  return action === "deny" || action === "revoke" || action === "remove";
}

function passkeySummary(p: PasskeyInfo): HTMLElement {
  return h(
    "div",
    { class: "summary pk-head" },
    h("span", { class: "pk-icon" }, passkeyIcon(p.icon)),
    h("div", { class: "pk-names" }, h("p", { class: "pk-name" }, h("bdi", null, vt(p.nickname))), h("p", { class: "pk-auth" }, vt(p.authenticator))),
  );
}

/** A labelled nickname input with a hint and an error line. */
function nicknameField(id: string, value: string, placeholder: string) {
  const input = h("input", {
    id,
    type: "text",
    class: "text",
    value,
    autocomplete: "off",
    spellcheck: "false",
    maxlength: "64",
    enterkeyhint: "go",
    placeholder: placeholder || undefined,
    "data-autofocus": "",
    "aria-describedby": `${id}-hint ${id}-err`,
  });
  const error = h("p", { class: "error", id: `${id}-err`, role: "alert" });
  input.addEventListener("input", () => (error.textContent = ""));
  const field = (label: string, hint: string) =>
    h("div", { class: "field" }, h("label", { for: id }, label), input, h("p", { class: "hint muted", id: `${id}-hint` }, hint));
  return { input, error, field };
}

// ---- the decision sheet ----

type Step = "choose" | "working" | "confirm" | "signing" | "create" | "done" | "error";

class Sheet {
  private dlg: HTMLDialogElement;
  private body: HTMLElement;
  private step: Step | null = null;
  private target: ActionTarget | null = null;
  private prepared: PreparedAction | null = null;
  /** Nickname chosen for a passkey being added ("" = let the server name it). */
  private goneNote: HTMLElement | null = null;
  private retry: (() => void) | null = null;
  /** Bumped whenever a flow starts or the sheet closes; async results for an older flow are
   * dropped so they can never draw over (or act in) a different flow. */
  private seq = 0;

  constructor(private app: App) {
    this.body = h("div", { class: "sheet-body" });
    this.dlg = h("dialog", { class: "sheet", "aria-labelledby": "sheet-title" }, this.body) as HTMLDialogElement;
    this.dlg.addEventListener("cancel", (e) => {
      // Escape / Android back: not while a signed action is in flight.
      if (this.busy()) e.preventDefault();
    });
    this.dlg.addEventListener("close", () => {
      this.seq++;
      this.step = null;
      this.prepared = null;
      this.target = null;
      this.retry = null;
    });
    document.body.appendChild(this.dlg);
  }

  private busy(): boolean {
    return this.step === "signing";
  }

  close(force = false): void {
    if (!this.dlg.open) return;
    if (this.busy() && !force) return;
    this.dlg.close();
  }

  /** Start a new flow: returns its sequence number. */
  private begin(target: ActionTarget): number {
    this.seq++;
    this.target = target;
    this.prepared = null;
    this.retry = null;
    if (!this.dlg.open) {
      this.render();
      this.dlg.showModal();
    }
    return this.seq;
  }

  private current(seq: number): boolean {
    return seq === this.seq && this.dlg.open;
  }

  private render(...content: Child[]): void {
    this.goneNote = h("p", { class: "warn", role: "status", hidden: true }, "This is no longer waiting: it was decided elsewhere, withdrawn, revoked or expired.");
    replace(this.body, this.goneNote, ...content);
    const first = this.body.querySelector<HTMLElement>("[data-autofocus]") ?? this.body.querySelector<HTMLElement>("button");
    first?.focus();
    this.tick(Date.now());
  }

  tick(now: number): void {
    if (!this.dlg.open || !this.target) return;
    const gone = this.step !== "done" && this.step !== "signing" && this.app.stillLive(this.target) === false;
    if (this.goneNote) this.goneNote.hidden = !gone;
    if (this.step === "confirm" && this.prepared) {
      const btn = this.body.querySelector<HTMLButtonElement>("button.confirm");
      const expired = now > this.prepared.validUntil;
      if (btn) btn.disabled = expired || gone;
      if (expired) {
        const note = this.body.querySelector(".validity");
        if (note) note.textContent = "This confirmation has expired. Start again to get a fresh one.";
      }
    }
  }

  /** Which passkeys can open what this tap needs (§4.4: a passkey without PRF cannot). */
  private whoCanOpen(raw: string[]): HTMLElement {
    const names = this.app.passkeyNames(raw);
    if (!raw.length) return h("p", { class: "warn" }, "No passkey can open these buckets: this works only while they are already open.");
    return h("p", { class: "muted" }, names.length ? `A passkey that can open them: ${names.map((n) => vt(n)).join(", ")}. Another passkey only approves if they are already open.` : "Only some of your passkeys can open them.");
  }

  private cancelButton(): HTMLButtonElement {
    return h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Cancel");
  }

  private summary(p: PendingItem): HTMLElement {
    if (p.kind === "enrollment") {
      return h(
        "div",
        { class: "summary" },
        h("p", { class: "target" }, h("bdi", { class: "host" }, vt(p.requesting_host))),
        p.enrollment?.replaces_existing ? h("p", { class: "warn" }, "A host with this name is already enrolled. Approving revokes its certificate.") : null,
        enrollFacts(p),
      );
    }
    if (p.kind === "bastion") return bastionSummary(p);
    if (p.kind === "cloudflare") {
      const cf = p.cloudflare;
      const v = cfView(cf?.scope, cf?.scope_params, cf?.mode);
      return h(
        "div",
        { class: "summary" },
        cf?.scope === "cf.admin" ? h("p", { class: "breakglass", role: "note" }, "BREAK-GLASS: full Cloudflare access, everything except the deny-list.") : null,
        v.heading,
        h("dl", { class: "facts" }, v.pairs.map(([label, val]) => fact(label, h("bdi", { class: "param" }, vt(val)))), fact("Mode", vt(modeWords(cf?.mode)))),
        h("p", null, "Cloudflare requested by ", h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
      );
    }
    return h(
      "div",
      { class: "summary" },
      targetLine(p.ssh?.login_user ?? "?", p.ssh?.target_host ?? "?"),
      h("p", null, `${kindLabel(p.kind)} requested by `, h("bdi", { class: "host-name" }, vt(p.requesting_host)), " ", h("span", { class: "addr" }, vt(p.requesting_address))),
    );
  }

  openApprove(p: PendingItem): void {
    const target = targetForPending(p);
    const seq = this.begin(target);
    const again = () => this.openApprove(p);
    this.step = "choose";
    if (p.kind === "enrollment") {
      const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
      go.addEventListener("click", () => void this.prepare(seq, target, { action: "approve" }, again));
      this.render(
        h("h2", { id: "sheet-title" }, "Let this host join?"),
        this.summary(p),
        h("p", null, "It gets a client certificate and can ask for access. Configured automatic scopes and matching standing approvals may grant access without another prompt."),
        h("div", { class: "actions" }, this.cancelButton(), go),
      );
      return;
    }
    if (p.kind === "bastion") {
      this.chooseBastion(seq, p, again);
      return;
    }
    const cf = p.kind === "cloudflare" ? p.cloudflare : undefined;
    const cfDesc = cf ? cfScope(cf.scope) : undefined;
    // Never offer more than the card's ttl_max, nor (Cloudflare) the scope's built-in maximum.
    const maxTTL = cfDesc && !p.scoped_facts ? Math.min(p.ttl_max > 0 ? p.ttl_max : cfDesc.maxTTL, cfDesc.maxTTL) : p.ttl_max;
    const { options, def } = ttlChoices(p.ttl_requested, maxTTL);
    const ttlSet = h(
      "fieldset",
      { class: "chips" },
      h("legend", null, "How long"),
      options.map((t) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "ttl", value: String(t), checked: t === def }), h("span", null, duration(t), t === p.ttl_requested ? h("small", null, " requested") : null)),
      ),
    );
    // SSH: aqmasd refuses standing approvals for high-risk requests (high_risk target, root,
    // > 4 h). Cloudflare: only when the server allows it for this scope AND this page's own
    // table does, and only in proxy mode (never cf.admin, never a token).
    const offerStanding = (p.scoped_facts?Boolean(p.scoped_facts.offers_standing):true) && (cf ? cf.standing_allowed === true && cf.mode === "proxy" && cfDesc?.standing === true : p.risk !== "high");
    const standLegend: Child[] = cf
      ? ["Also auto-approve the same Cloudflare request (", h("bdi", null, vt(p.requesting_host)), ", ", h("bdi", null, vt(cf.scope)), cf.scope_params ? [" ", h("bdi", null, vt(cf.scope_params))] : null, ")"]
      : ["Also auto-approve the same request (", h("bdi", null, vt(p.requesting_host)), " to ", h("bdi", null, vt(p.ssh?.login_user ?? "?")), "@", h("bdi", null, vt(p.ssh?.target_host ?? "?")), ")"];
    const standSet = !offerStanding ? null : h(
      "fieldset",
      { class: "chips" },
      h("legend", null, standLegend),
      [...new Set([...STANDING_PRESETS,p.max_standing_hours ?? 8])].filter(n=>n<=(p.max_standing_hours ?? 8)).map((n) =>
        h("label", { class: "chip" }, h("input", { type: "radio", name: "standing", value: String(n), checked: n === 0 }), h("span", null, n === 0 ? "No" : `for ${hours(n)}`)),
      ),
    );
    if(p.scoped_facts?.offers_indefinite)ttlSet.append(h('label',null,h('input',{type:'radio',name:'ttl',value:'-1'}),' Indefinite — until revoked'));
    const standard=Number(p.scoped_facts?.standing_default??0);if(standard>0&&standard<=(p.max_standing_hours??0)*3600)standSet?.append(h('label',null,h('input',{type:'radio',name:'standing',value:'default'}),` Policy default: ${duration(standard)}`));
    if(p.scoped_facts?.offers_standing_indefinite)standSet?.append(h('label',null,h('input',{type:'radio',name:'standing',value:'-1'}),' Indefinite standing — until revoked'));
    const go = h("button", { class: "btn approve", type: "button", "data-autofocus": "" }, "Continue");
    go.addEventListener("click", () => {
      const ttl = Number(ttlSet.querySelector<HTMLInputElement>("input:checked")?.value ?? def);
      const selected=standSet?.querySelector<HTMLInputElement>("input:checked")?.value;
      const standing=selected==='default'?0:Number(selected??0);
      void this.prepare(seq, target, { action: "approve", ttl_seconds: Math.max(0,ttl), standing_hours: Math.max(0,standing),standing_seconds:selected==='default'?standard:0,indefinite:ttl===-1,standing_indefinite:standing===-1 }, again);
    });
    this.render(h("h2", { id: "sheet-title" }, cf?.scope === "cf.admin" ? "Approve break-glass access" : "Approve access"), this.summary(p), ttlSet, standSet, h("div", { class: "actions" }, this.cancelButton(), go));
  }

  /** A bastion session (bastion.ts): the card is read again before the challenge, so the
   * open-bucket list checked against the signed text is the current one. */
  private chooseBastion(seq: number, p: PendingItem, again: () => void): void {
    const form = bastionChoice(p, () => {
      const { ttl, close } = form.read();
      this.working("Preparing confirmation");
      this.app.api.request(p.id).then(
        (fresh) => {
          if (!this.current(seq)) return;
          const target = targetForPending({ ...fresh, kind: "bastion" });
          const choice: ActionChoice = { action: "approve", ttl_seconds: ttl };
          if (target.facts.level === "root" && target.facts.sealed) choice.closeBuckets = close;
          void this.prepare(seq, target, choice, again);
        },
        (e) => {
          if (!this.current(seq)) return;
          this.retry = again;
          this.showError(e);
        },
      );
    });
    this.render(form.title, form.body, h("div", { class: "actions" }, this.cancelButton(), form.go));
  }

  openDeny(p: PendingItem): void {
    const target = targetForPending(p);
    void this.prepare(this.begin(target), target, { action: "deny" });
  }

  openRevoke(target: ActionTarget): void {
    void this.prepare(this.begin(target), target, { action: "revoke" });
  }

  openUpdate(target: ActionTarget): void {
    void this.prepare(this.begin(target),target,{action:'approve'});
  }
  openMigration(target:ActionTarget):void{void this.prepare(this.begin(target),target,{action:'activate'});}
  openCatalogue(target:ActionTarget,choice:ActionChoice):void{void this.prepare(this.begin(target),target,choice);}

  openAddPasskey(): void {
    const target: ActionTarget = { ...PASSKEY_TARGET };
    const seq = this.begin(target);
    this.step = "choose";
    const { input, error, field } = nicknameField("pk-new-name", "", "e.g. YubiKey on keyring");
    const go = h("button", { class: "btn approve", type: "button" }, "Continue");
    const submit = () => {
      const name = input.value.trim();
      const problem = name ? nicknameProblem(name) : null;
      if (problem) {
        error.textContent = problem;
        input.focus();
        return;
      }
      void this.prepare(seq, target, { action: "add", nickname: name }, () => this.openAddPasskey());
    };
    go.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Add a passkey"),
      h("p", null, "First confirm with a passkey you already have. Then create the new one, on this device or another (the browser offers a QR code or a security key)."),
      field("Name (optional)", "Leave it empty to name it after its password manager or key, like “Bitwarden”."),
      error,
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
  }

  openRename(p: PasskeyInfo): void {
    const target = targetForPasskey(p);
    const seq = this.begin(target);
    this.step = "choose";
    const { input, error, field } = nicknameField("pk-rename", p.nickname, "");
    const go = h("button", { class: "btn approve", type: "button" }, "Continue");
    const submit = () => {
      const name = input.value.trim();
      const problem = nicknameProblem(name) ?? (name === p.nickname ? "That is already its name." : null);
      if (problem) {
        error.textContent = problem;
        input.focus();
        return;
      }
      void this.prepare(seq, target, { action: "rename", nickname: name }, () => this.openRename(p));
    };
    go.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Rename passkey"),
      passkeySummary(p),
      field("New name", "Names are unique. Pick one that tells you where the passkey lives."),
      error,
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
    input.select();
  }

  openRemove(p: PasskeyInfo): void {
    const target = targetForPasskey(p);
    const seq = this.begin(target);
    if (!p.current) {
      void this.prepare(seq, target, { action: "remove" }, () => this.openRemove(p));
      return;
    }
    this.step = "choose";
    const go = h("button", { class: "btn deny", type: "button" }, "Continue");
    go.addEventListener("click", () => void this.prepare(seq, target, { action: "remove" }, () => this.openRemove(p)));
    this.render(
      h("h2", { id: "sheet-title" }, "Remove the passkey you signed in with?"),
      passkeySummary(p),
      h("p", { class: "warn" }, "You signed in with this passkey. Removing it signs you out here; sign in again with another passkey."),
      h("div", { class: "actions" }, this.cancelButton(), go),
    );
  }

  private working(text: string): void {
    this.step = "working";
    this.render(h("h2", { id: "sheet-title" }, text), h("p", { class: "spinner", role: "status" }, "Working…"), h("div", { class: "actions" }, this.cancelButton()));
  }

  private async prepare(seq: number, target: ActionTarget, choice: ActionChoice, retry?: () => void): Promise<void> {
    if (!this.current(seq)) return;
    this.retry = retry ?? (() => void this.prepare(this.begin(target), target, choice));
    this.working("Preparing confirmation");
    try {
      const p = await prepareAction(this.app.api, target, choice);
      if (!this.current(seq)) return;
      this.prepared = p;
      this.showConfirm(seq, p);
    } catch (e) {
      if (!this.current(seq)) return;
      this.showError(e);
    }
  }

  private showConfirm(seq: number, p: PreparedAction): void {
    this.step = "confirm";
    const d = p.description;
    const negative = isNegative(p.choice.action);
    const removingCurrent = p.canonical.object === "passkey" && p.canonical.action === "remove" && this.app.isCurrentPasskey(p.target.id);
    // Root on the bastion: the red block, drawn from the signed text only.
    const rootFacts = d.bastion && d.bastion.level === "root" && d.bastion.action === "approve" ? d.bastion : undefined;
    const confirm = h("button", { class: `btn confirm big ${negative ? "deny" : "approve"}${rootFacts ? " root" : ""}`, type: "button", "data-autofocus": "" }, rootFacts ? "Approve root session with passkey" : "Confirm with passkey");
    confirm.addEventListener("click", () => this.confirm(seq, p, confirm));
    const loud = d.breakGlass && !negative;
    // The close choice is part of what is signed: changing it asks for a fresh challenge.
    const rootBlock = rootFacts ? rootConfirmBlock(rootFacts, (close) => { const retry = this.retry ?? undefined; void this.prepare(this.begin(p.target), p.target, { ...p.choice, closeBuckets: close }, retry); }) : null;
    const warnings = rootFacts ? d.warnings.filter((w) => w.includes("unusual characters")) : d.warnings;
    const rootActive = !!p.open && this.app.rootUntil() > 0;
    this.render(
      h("h2", { id: "sheet-title" }, rootFacts ? "Root on the bastion: check, then confirm" : loud ? "Break-glass: check, then confirm" : "Check, then confirm"),
      rootBlock,
      d.risk ? h("p", { class: "card-top" }, h("span", { class: "kind" }, "Cloudflare"), riskBadge(d.risk)) : null,
      h("p", { class: `headline ${negative ? "neg" : "pos"}${loud || rootFacts ? " loud" : ""}` }, renderParts(d.headlineParts)),
      d.details?.length ? h("ul", { class: "cf-details" }, d.details.map((line) => h("li", null, renderParts(line)))) : null,
      d.standingParts ? h("p", { class: "warn" }, renderParts(d.standingParts)) : null,
      warnings.map((w, i) => h("p", { class: loud && i === 0 ? "breakglass" : "warn" }, vt(w))),
      rootActive ? h("p", { class: "breakglass", role: "note" }, "A root certificate for the bastion is valid right now: what this approval opens is readable by that session.") : null,
      p.canonical.plan ? h('dl',{class:'facts'},d.fields.map(([k,v])=>fact(vt(k),h('bdi',null,vt(v))))) : null,
      removingCurrent ? h("p", { class: "warn" }, "This is the passkey you signed in with: you will be signed out here.") : null,
      p.open ? opensList(p.open.lines) : null,
      p.open ? this.whoCanOpen(p.open.canOpen) : null,
      h(
        "details",
        { class: "signed" },
        h("summary", null, "Exactly what your passkey signs"),
        h("dl", { class: "facts" }, d.fields.map(([k, v]) => fact(k, h("span", { class: "mono" }, vt(v))))),
      ),
      h("p", { class: "validity muted" }, "Valid for ", until(p.validUntil)),
      h("div", { class: "actions" }, this.cancelButton(), confirm),
    );
  }

  /** Runs inside the tap: the passkey prompt starts before any other await. */
  private confirm(seq: number, p: PreparedAction, btn: HTMLButtonElement): void {
    if (!this.current(seq) || this.step !== "confirm" || Date.now() > p.validUntil) return;
    btn.disabled = true;
    const isAdd = p.target.object === "passkey" && p.canonical.action === "add";
    // Both start with auth.get(...) synchronously, i.e. still inside the user gesture.
    const run = isAdd ? authorizeAddPasskey(this.app.api, this.app.auth, p) : completeAction(this.app.api, this.app.auth, p);
    // From here the signed action may reach the server: no Cancel, no Escape, until it settles.
    this.step = "signing";
    this.render(
      h("h2", { id: "sheet-title" }, "Waiting for your passkey"),
      h("p", { class: `headline ${isNegative(p.choice.action) ? "neg" : "pos"}` }, renderParts(p.description.headlineParts)),
      h("p", { class: "spinner", role: "status" }, "Confirm on your device. This closes by itself."),
    );
    run.then(
      (res) => {
        if (this.step === "signing") this.step = "done";
        const change = res as Partial<PasskeyChange> | null;
        if (p.target.object === "passkey" && change && change.signed_out === true) {
          // The removed passkey was this session's: the server ended the session.
          this.app.signedOut(`Removed the passkey “${vt(p.canonical.nickname ?? "")}”. You signed in with it, so sign in again with another passkey.`);
          return;
        }
        this.app.changed();
        if (!this.current(seq)) return;
        if (isAdd) this.showCreatePasskey(seq, res as PreparedRegistration);
        else this.showDone(p, res);
      },
      (e) => {
        this.app.changed();
        if (this.step === "signing") this.step = "error";
        if (!this.current(seq)) return;
        this.showError(e);
      },
    );
  }

  private showCreatePasskey(seq: number, reg: PreparedRegistration): void {
    this.step = "create";
    const create = h("button", { class: "btn approve big", type: "button", "data-autofocus": "" }, "Create the new passkey");
    create.addEventListener("click", () => {
      if (!this.current(seq)) return;
      create.disabled = true;
      // The nickname was signed with the add action; the server uses exactly that.
      completeRegistration(this.app.api, this.app.auth, reg).then(
        (res) => {
          this.app.changed();
          if (!this.current(seq)) return;
          this.step = "done";
          const pk = (res && typeof res === "object" ? (res as RegisterResult).passkey : undefined) ?? undefined;
          this.render(
            h("h2", { id: "sheet-title", class: "ok" }, "Passkey added"),
            pk && typeof pk.nickname === "string"
              ? h("p", null, "It's called ", h("bdi", { class: "val" }, vt(pk.nickname)), " (", vt(pk.authenticator || "Unknown authenticator"), "). You can rename it in the Passkeys list.")
              : null,
            h("p", null, "You can now sign in and approve with it."),
            h("div", { class: "actions" }, h("button", { class: "btn", type: "button", "data-autofocus": "", on: { click: () => this.close() } }, "Done")),
          );
        },
        (e) => {
          if (this.current(seq)) this.showError(e);
        },
      );
    });
    this.render(
      h("h2", { id: "sheet-title" }, "Create the new passkey"),
      h("p", null, "Approved. Now create the passkey, on this device or another one through the browser's options (QR code, security key)."),
      h("div", { class: "actions" }, this.cancelButton(), create),
    );
  }

  private showDone(p: PreparedAction, res: unknown): void {
    this.step = "done";
    const c = p.canonical;
    const r = (res && typeof res === "object" ? res : {}) as { status?: unknown; grant?: { not_after?: unknown } };
    const expected: Record<string, string> = { approve: "approved", deny: "denied" };
    const want = c.object === "request" || c.object === "enrollment" ? expected[c.action] : undefined;
    const status = typeof r.status === "string" ? r.status : undefined;
    const done = h("button", { class: "btn big", type: "button", "data-autofocus": "", on: { click: () => this.close() } }, "Done");

    if (want && status && status !== want) {
      this.render(
        h("h2", { id: "sheet-title", class: "neg" }, "Check this"),
        h("p", null, `aqmas accepted your passkey but reports the ${c.object} as "${vt(status)}", not "${want}".`),
        h("div", { class: "actions" }, done),
      );
      return;
    }
    const words: Record<string, string> = { approve: "Approved", deny: "Denied", revoke: "Revoked", rename: "Renamed", remove: "Removed" };
    const lines: Child[] = [];
    if (c.object === "grant" && c.kind === "cloudflare")
      lines.push(
        c.mode === "token"
          ? "Revoked, with any auto-approval that issued it or came with it. aqmas deletes the API token at Cloudflare now."
          : "Revoked, with any auto-approval that issued it or came with it. The aqmas proxy refuses it from the next call.",
      );
    else if (c.object === "grant" && c.kind === "bastion")
      lines.push("Marked revoked. A certificate that was not collected yet is no longer handed out; one that was already collected stays valid until it expires, and an open session stays open.");
    else if (c.object === "grant")
      lines.push("Marked revoked, with any auto-approval that issued it or came with it. aqmas on the host stops reusing it; the certificate itself stays valid until it expires (no revocation list yet).");
    else if (c.object === "request" && c.action === "approve" && c.kind === "cloudflare") {
      const notAfter = typeof r.grant?.not_after === "string" ? new Date(r.grant.not_after) : null;
      lines.push(
        h(
          "span",
          null,
          h("bdi", null, vt(c.requesting_host ?? "The host")),
          " has the Cloudflare grant ",
          h("span", { class: "mono" }, vt(c.scope ?? "?")),
          notAfter && Number.isFinite(notAfter.getTime()) ? ` until ${notAfter.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` : ` for ${duration(c.ttl_seconds ?? 0)}.`,
        ),
      );
      if (c.mode === "token") lines.push("The API token is handed to the host once, on its next poll.");
    }
    else if (c.object === "request" && c.action === "approve" && c.kind === "bastion") lines.push(...decisionLines(c, r as Record<string, unknown>));
    else if (c.object === "standing") lines.push("Matching requests need your approval again.");
    else if (c.object === "passkey" && c.action === "remove") lines.push("It can no longer sign in or approve anything here. Delete it from its password manager or key too if you no longer need it.");
    else if (c.object === "enrollment" && c.action === "approve") lines.push(h("span", null, h("bdi", null, vt(c.requesting_host ?? "The host")), " can now ask for access."));
    else if (c.object === "request" && c.action === "approve") {
      const notAfter = typeof r.grant?.not_after === "string" ? new Date(r.grant.not_after) : null;
      lines.push(
        h(
          "span",
          null,
          h("bdi", null, vt(c.requesting_host ?? "The host")),
          " can now use ",
          h("bdi", null, vt(c.login_user ?? "?")),
          "@",
          h("bdi", null, vt(c.target ?? "?")),
          notAfter && Number.isFinite(notAfter.getTime()) ? ` until ${notAfter.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.` : ` for ${duration(c.ttl_seconds ?? 0)}.`,
        ),
      );
    }
    this.render(
      h("h2", { id: "sheet-title", class: c.action === "approve" || c.action === "rename" ? "ok" : "neg" }, words[c.action] ?? "Done"),
      h("p", { class: "headline" }, renderParts(p.description.headlineParts)),
      lines.map((l) => (l instanceof HTMLElement && l.tagName === "P" ? l : h("p", null, l))),
      h("div", { class: "actions" }, done),
    );
  }

  private showError(e: unknown): void {
    this.step = "error";
    const msg = explainError(e);
    const again = this.retry;
    this.render(
      h("h2", { id: "sheet-title", class: "neg" }, e instanceof FlowError ? "Not signed" : "That didn't work"),
      h("p", { class: "error", role: "alert" }, vt(msg)),
      h(
        "p",
        { class: "muted" },
        nothingChanged(e) ? "Nothing was changed." : "It may or may not have gone through. Check the list, which updates by itself.",
      ),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", type: "button", on: { click: () => this.close() } }, "Close"),
        again ? h("button", { class: "btn approve", type: "button", on: { click: () => again() } }, "Start again") : null,
      ),
    );
  }
}
