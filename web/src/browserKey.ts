// Remembered browsers (docs/BUCKETS.md §13): the key a browser profile holds so that a
// passkey without PRF can open buckets from it. The private half is a non-extractable
// WebCrypto key kept in IndexedDB as a CryptoKey: it is never exported and never sent; only
// the public half goes to the broker. With it the page opens the sealed KEKs the broker
// releases inside a valid tap.
//
// Losing the key is harmless: a private window, cleared site data or the browser's storage
// eviction make this browser "no longer remembered" and it is enabled again. Nothing here
// throws for a missing or unreadable key: callers get `undefined` and say so in plain words.

import { encode } from "./b64url";
import { suite } from "./seal";

type Bytes = Uint8Array<ArrayBuffer>;

export class BrowserKeyError extends Error {
  override name = "BrowserKeyError";
}

export const NOT_REMEMBERED =
  "This browser is no longer remembered for this passkey: its key is missing (a private window, cleared site data, or the browser evicted this site's storage). Enable it again: Security → Passkeys → Remember this browser.";
export const NO_STORAGE =
  "This browser cannot keep a key for this site (a private window, or site storage is blocked), so it cannot be remembered. Use a normal window, or a passkey with PRF.";
export const TRADE_OFF =
  "Anyone who has this browser profile and this passkey can open your credentials. Normally the passkey alone holds the secret; here part of it lives in this browser's storage, so malware or a copy of this profile, together with the passkey, is enough.";

export interface LocalBrowserKey {
  pair: CryptoKeyPair;
  /** The public half: an uncompressed P-256 point (65 bytes). */
  publicKey: Bytes;
  /** The public half in base64url: what the broker and the signed actions name. */
  public: string;
  /** Fingerprint: hex of the first 16 bytes of SHA-256(public half). */
  id: string;
}

/** Where the key pair lives. IndexedDB in a browser; memory in tests and the mock. */
export interface BrowserKeyStore {
  load(): Promise<CryptoKeyPair | undefined>;
  save(pair: CryptoKeyPair): Promise<void>;
  clear(): Promise<void>;
}

const DB = "aqmas-browser-key", STORE = "keys", SLOT = "browser";

function request<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB request failed"));
  });
}
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (!idb) return reject(new Error("IndexedDB is not available"));
    const r = idb.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB could not be opened"));
    r.onblocked = () => reject(new Error("IndexedDB is blocked"));
  });
}
async function withStore<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDB();
  try {
    const tx = db.transaction(STORE, mode);
    const done = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    });
    const out = await request(fn(tx.objectStore(STORE)));
    await done;
    return out;
  } finally {
    db.close();
  }
}

/** The CryptoKeyPair is stored by structured clone: the private key stays non-extractable. */
export function idbStore(): BrowserKeyStore {
  return {
    async load() {
      const v = (await withStore("readonly", (s) => s.get(SLOT))) as unknown;
      const p = v as Partial<CryptoKeyPair> | undefined;
      return p && p.privateKey && p.publicKey ? (p as CryptoKeyPair) : undefined;
    },
    async save(pair) {
      await withStore("readwrite", (s) => s.put(pair, SLOT));
    },
    async clear() {
      await withStore("readwrite", (s) => s.delete(SLOT));
    },
  };
}

export function memoryStore(): BrowserKeyStore & { pair?: CryptoKeyPair } {
  const m: BrowserKeyStore & { pair?: CryptoKeyPair } = {
    async load() {
      return m.pair;
    },
    async save(pair) {
      m.pair = pair;
    },
    async clear() {
      delete m.pair;
    },
  };
  return m;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** hex(SHA-256(public half)[:16]), as the broker's seal.BrowserKeyID. */
export async function browserKeyId(publicKey: Uint8Array): Promise<string> {
  const copy = new Uint8Array(publicKey.length);
  copy.set(publicKey);
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", copy)).subarray(0, 16));
}

async function describe(pair: CryptoKeyPair): Promise<LocalBrowserKey> {
  if (pair.privateKey.extractable) throw new BrowserKeyError("The stored browser key is extractable; it is not used.");
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  if (publicKey.length !== 65 || publicKey[0] !== 4) throw new BrowserKeyError("Invalid browser key");
  return { pair, publicKey, public: encode(publicKey), id: await browserKeyId(publicKey) };
}

export interface Ensured {
  key: LocalBrowserKey;
  /** true: a key was made now. false: this profile already had one. */
  created: boolean;
  /** navigator.storage.persist(): true (kept), false (the browser may evict it), undefined
   * (it does not say). A refusal is not an error: an evicted key means "enable again". */
  persisted: boolean | undefined;
}

export class BrowserKeys {
  constructor(
    private store: BrowserKeyStore = idbStore(),
    private persist: () => Promise<boolean | undefined> = async () => {
      try {
        const s = (globalThis as { navigator?: { storage?: { persist?: () => Promise<boolean> } } }).navigator?.storage;
        return s?.persist ? await s.persist() : undefined;
      } catch {
        return undefined;
      }
    },
  ) {}

  /** This profile's key, or undefined when it has none or storage cannot be read. Never throws. */
  async current(): Promise<LocalBrowserKey | undefined> {
    try {
      const pair = await this.store.load();
      return pair ? await describe(pair) : undefined;
    } catch {
      return undefined;
    }
  }

  /** This profile's key, made now if there is none. Throws BrowserKeyError (plain words) when
   * the browser cannot keep one. */
  async ensure(): Promise<Ensured> {
    const have = await this.current();
    if (have) return { key: have, created: false, persisted: await this.persist() };
    let key: LocalBrowserKey;
    try {
      // Non-extractable: the private scalar cannot be exported by any script, including ours.
      const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
      key = await describe(pair);
      await this.store.save(pair);
    } catch (e) {
      if (e instanceof BrowserKeyError) throw e;
      throw new BrowserKeyError(NO_STORAGE);
    }
    // Read it back: some private modes accept the write and keep nothing.
    const back = await this.current();
    if (!back || back.public !== key.public) throw new BrowserKeyError(NO_STORAGE);
    return { key: back, created: true, persisted: await this.persist() };
  }

  /** Delete this profile's key (Forget, when no other passkey uses it). Never throws. */
  async forget(): Promise<void> {
    try {
      await this.store.clear();
    } catch {
      /* a key that cannot be deleted cannot be read either */
    }
  }

  /** Open one sealed KEK (HPKE base mode to this key, empty AAD): enc(65) ‖ ct(48). */
  async openKEK(key: LocalBrowserKey, info: Uint8Array, sealed: Uint8Array): Promise<Bytes> {
    if (sealed.length !== 65 + 32 + 16) throw new BrowserKeyError("Invalid sealed key");
    const own = (b: Uint8Array) => {
      const out = new Uint8Array(b.length);
      out.set(b);
      return out.buffer;
    };
    try {
      const ctx = await suite.createRecipientContext({ recipientKey: key.pair, enc: own(sealed.subarray(0, 65)), info: own(info) });
      const kek = new Uint8Array(await ctx.open(own(sealed.subarray(65))));
      if (kek.length !== 32) throw new Error("length");
      return kek;
    } catch {
      throw new BrowserKeyError("This browser's key did not open what the broker holds for it. Forget this browser and remember it again: Security → Passkeys.");
    }
  }
}

/** "Firefox on Linux": a default label from the user agent, editable before it is signed. */
export function defaultLabel(ua: string = (globalThis as { navigator?: { userAgent?: string } }).navigator?.userAgent ?? ""): string {
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /iPhone|iPad|iPod/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

/** As the broker's normalizeBrowserLabel: single spaces, 1 to 64 printable characters. */
export function normalizeLabel(s: string): string {
  const out = s.split(/\s+/).filter(Boolean).join(" ");
  if (!out || [...out].length > 64 || /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u.test(out)) throw new BrowserKeyError("A browser label has 1 to 64 printable characters.");
  return out;
}
