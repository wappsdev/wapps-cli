// Trust (roster) manifest doğrulama + kayıt/grant çözümleme (SPEC §4).
//
// internal/trust (chain.go, policy.go, manifest.go) + internal/registry'nin
// verify-only TS portu. DO'nun yazar-allowlist + grant + gerekli-recipient-set
// hesabı BURADAN gelir; otoritatif kaynak imzalı trust manifest'idir (D1 mirror
// G7'ye ertelendi).
//
// KRİTİK: trust manifest'te prev_trust_sha256 ve pin, İMZALANAN (payload)
// baytlarının hash'idir (trustObjectHash = sha256(obj.bytes)) — data manifest'in
// SARMALAYICI-hash'inden FARKLI (§4.2.2 vs §5.4.2).

import {
  SignedObject,
  VerifierKey,
  ALG_ED25519,
  ALG_ECDSA_P256_SHA256,
  assertCanonicalIntegerJSON,
  b64ToBytes,
  fingerprint,
  fingerprintRecipient,
  isRFC3339,
  newVerifierKey,
  sha256Hex,
  verifySignatureEnvelope,
} from "./crypto/verify.js";

export const SCHEMA_TRUST = "wapps-trust/v1";
// Epoch-reset kaydı şeması (§4.8) — trust manifest şemasından AYRIDIR.
export const SCHEMA_TRUST_RESET = "wapps-trust-reset/v1";

// change_class kapalı kümesi (§4.2.2).
export const CHANGE_ROSTER = "roster";
export const CHANGE_REGISTRY = "registry";
export const CHANGE_GRANT = "grant";
export const CHANGE_POLICY = "policy";
export const CHANGE_EPOCH_RESET = "epoch_reset";

const STATUS_ACTIVE = "active";
const STATUS_REVOKED = "revoked";
const SIGN_CLASS_ADMIN = "admin";
const SIGN_CLASS_DAILY = "daily";
const ENC_CLASS_DEVICE = "device";
const ENC_CLASS_BACKUP = "backup";
const TYPE_HUMAN = "human";
const TYPE_MACHINE = "machine";
const TYPE_ESCROW = "escrow";
export const KEY_WILDCARD = "*";

export class TrustError extends Error {
  constructor(public code: string, msg?: string) {
    super(msg ?? code);
    this.name = "TrustError";
  }
}

// --- Tipler (registry + trust; byte-exact JSON şekilleri) ------------------

export interface Quorum {
  m: number;
  n: number;
}
export interface RootKey {
  key_id: string;
  alg: string;
  pubkeyB64: string; // base64(ham 32B ed25519)
  media: string;
  holder: string;
  status: string;
}
export interface EncKey {
  key_id: string;
  class: string; // device | backup
  pubkey: string; // age1... (bech32 recipient)
  media: string;
  added_at: number;
  status: string;
}
export interface SigningKeyEntry {
  key_id: string;
  class: string; // root | admin | daily | automation
  alg: string;
  pubkey: string; // base64(ham pubkey)
  media: string;
  status: string;
}
export interface Identity {
  id: string;
  type: string;
  enc_keys: EncKey[];
  signing_keys: SigningKeyEntry[];
  status: string;
}
export interface Grant {
  principal: string;
  project: string;
  verbs: string[]; // §6.3 authz: read | write | rotate
  keys: string[]; // allowlist; ["*"] = tümü
}
export interface WriterAllow {
  principal: string;
  project: string;
  keys: string[];
}

/** PriorChain, bir epoch-reset kaydının zincirlediği önceki head (§4.8). */
export interface PriorChain {
  last_admin_epoch: number;
  last_trust_sha256: string;
}

/**
 * EpochResetRecord, güven zincirinin TEK yaptırımlı süreksizliğinin (§4.8)
 * payload'ıdır. Go internal/trust EpochReset ile byte-parite (schema, reset_id,
 * reason, prior_chain{last_admin_epoch,last_trust_sha256}, snapshot_ref).
 */
export interface EpochResetRecord {
  schema: string;
  reset_id: string;
  reason: string;
  prior_chain: PriorChain;
  snapshot_ref: string;
}

export interface TrustManifest {
  schema: string;
  admin_epoch: number;
  prev_trust_sha256: string;
  created_at: string;
  change_class: string;
  bootstrap_solo: boolean;
  quorum: Quorum;
  roots: RootKey[];
  admins: string[];
  identities: Identity[];
  grants: Grant[];
  writer_allowlists: WriterAllow[];
  worker_receipt_pubkey: unknown; // deep-equal için ham korunur (şekli parse'ta doğrulanır)
  worker_mint_pubkeys: unknown;
  epoch_reset: EpochResetRecord | null; // §4.8; reset dışı epoch'larda null
}

export interface Pin {
  admin_epoch: number;
  sha256: string;
}

export interface VerifiedEpoch {
  manifest: TrustManifest;
  bytesSHA256: string;
  view: SignerView;
}

/** trustObjectHash, İMZALANAN payload baytlarının çıplak-hex SHA-256'sı (§4.2.2). */
export function trustObjectHash(payloadBytes: Uint8Array): string {
  return sha256Hex(payloadBytes);
}

// --- Strict parse ----------------------------------------------------------

function exactKeys(o: Record<string, unknown>, allowed: readonly string[], ctx: string): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: unknown field ${k}`);
}
function str(v: unknown, ctx: string): string {
  if (typeof v !== "string") throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not a string`);
  return v;
}
function uint(v: unknown, ctx: string): number {
  // isSafeInteger: tam sayı VE ≤2^53-1 (Go uint64 >2^53'ü tam taşır; JS yuvarlar).
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not a uint`);
  return v;
}
function bool(v: unknown, ctx: string): boolean {
  if (typeof v !== "boolean") throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not a bool`);
  return v;
}
function strArr(v: unknown, ctx: string): string[] {
  if (!Array.isArray(v)) throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not an array`);
  return v.map((x, i) => str(x, `${ctx}[${i}]`));
}
function obj(v: unknown, ctx: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not an object`);
  return v as Record<string, unknown>;
}

const ROOT_KEYS = ["key_id", "alg", "pubkey", "media", "holder", "status"] as const;
const ENC_KEYS = ["key_id", "class", "pubkey", "media", "added_at", "status"] as const;
const SIGN_KEYS = ["key_id", "class", "alg", "pubkey", "media", "status"] as const;
const ID_KEYS = ["id", "type", "enc_keys", "signing_keys", "status", "enrolled_at", "vouched_by", "rotate_by"] as const;
const GRANT_KEYS = ["principal", "project", "verbs", "keys"] as const;
const WALLOW_KEYS = ["principal", "project", "keys"] as const;
const QUORUM_KEYS = ["m", "n"] as const;
const TRUST_KEYS = [
  "schema", "admin_epoch", "prev_trust_sha256", "created_at", "change_class", "bootstrap_solo",
  "quorum", "roots", "admins", "identities", "grants", "writer_allowlists",
  "worker_receipt_pubkey", "worker_mint_pubkeys", "epoch_reset",
] as const;
const RECEIPT_KEYS = ["kid", "alg", "jwk"] as const;
const EPOCH_RESET_KEYS = ["schema", "reset_id", "reason", "prior_chain", "snapshot_ref"] as const;
const PRIOR_CHAIN_KEYS = ["last_admin_epoch", "last_trust_sha256"] as const;

/**
 * validateReceiptKey, Go ReceiptKey ({kid,alg,jwk}) şeklini yaptırır: yalnızca
 * bu üç anahtar, kid/alg string (varsa), jwk opak passthrough (Go json.RawMessage
 * — yorumlanmaz). Bilinmeyen anahtar → red (Go DisallowUnknownFields paritesi).
 */
function validateReceiptKey(v: unknown, ctx: string): void {
  const o = obj(v, ctx);
  exactKeys(o, RECEIPT_KEYS, ctx);
  if (o.kid !== undefined) str(o.kid, `${ctx}.kid`);
  if (o.alg !== undefined) str(o.alg, `${ctx}.alg`);
  // jwk: opak (herhangi bir JSON) — doğrulanmaz, yalnızca varlığı serbest.
}

/** validateReceiptField, worker_receipt_pubkey (tek ReceiptKey | null | absent). */
function validateReceiptField(v: unknown, ctx: string): void {
  if (v === undefined || v === null) return; // Go null → zero value; kabul
  validateReceiptKey(v, ctx);
}

/** validateMintField, worker_mint_pubkeys ([]ReceiptKey | null | absent). */
function validateMintField(v: unknown, ctx: string): void {
  if (v === undefined || v === null) return;
  if (!Array.isArray(v)) throw new TrustError("TRUST_CHAIN_BROKEN", `${ctx}: not an array`);
  v.forEach((e, i) => validateReceiptKey(e, `${ctx}[${i}]`));
}

/**
 * parseEpochReset, epoch_reset kaydını STRICT ayrıştırır (Go EpochReset paritesi,
 * §4.8). Reset dışı epoch'larda alan omitempty → undefined/null → null döner.
 * Go, kayıt varsa tüm alanları (kesirsiz de olsa) emit eder; bilinmeyen anahtar
 * ve yanlış tip reddedilir. Boş reset_id/reason'ı verifyResetInternal reddeder.
 */
function parseEpochReset(v: unknown): EpochResetRecord | null {
  if (v === undefined || v === null) return null;
  const o = obj(v, "epoch_reset");
  exactKeys(o, EPOCH_RESET_KEYS, "epoch_reset");
  const pc = obj(o.prior_chain, "epoch_reset.prior_chain");
  exactKeys(pc, PRIOR_CHAIN_KEYS, "epoch_reset.prior_chain");
  return {
    schema: str(o.schema, "epoch_reset.schema"),
    reset_id: str(o.reset_id, "epoch_reset.reset_id"),
    reason: str(o.reason, "epoch_reset.reason"),
    prior_chain: {
      last_admin_epoch: uint(pc.last_admin_epoch, "epoch_reset.prior_chain.last_admin_epoch"),
      last_trust_sha256: str(pc.last_trust_sha256, "epoch_reset.prior_chain.last_trust_sha256"),
    },
    snapshot_ref: str(o.snapshot_ref, "epoch_reset.snapshot_ref"),
  };
}

/** parseTrustBody, ham payload baytlarını STRICT ayrıştırır (§3.6.3 sonrası). */
export function parseTrustBody(body: Uint8Array): TrustManifest {
  const text = new TextDecoder().decode(body);
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new TrustError("TRUST_CHAIN_BROKEN", "body not valid JSON");
  }
  // Sayı literalleri: `1e3`/`1.0`/>2^53 reddi (Go integer-decode paritesi).
  try {
    assertCanonicalIntegerJSON(text);
  } catch (e) {
    throw new TrustError("TRUST_CHAIN_BROKEN", (e as Error).message);
  }
  const o = obj(doc, "trust");
  exactKeys(o, TRUST_KEYS, "trust");
  const schema = str(o.schema, "schema");
  if (schema !== SCHEMA_TRUST) throw new TrustError("UNSUPPORTED_SCHEMA", schema);
  // KATİ RFC3339 (Go time.Time) — Date.parse GEVŞEK'tir, imzalı alanda ayrışır.
  if (!isRFC3339(str(o.created_at, "created_at"))) throw new TrustError("TRUST_CHAIN_BROKEN", "created_at not RFC3339");
  // worker_receipt_pubkey / worker_mint_pubkeys: {kid,alg,jwk} şekli yaptırılır.
  validateReceiptField(o.worker_receipt_pubkey, "worker_receipt_pubkey");
  validateMintField(o.worker_mint_pubkeys, "worker_mint_pubkeys");

  const q = obj(o.quorum, "quorum");
  exactKeys(q, QUORUM_KEYS, "quorum");

  const roots: RootKey[] = (Array.isArray(o.roots) ? o.roots : []).map((r, i) => {
    const ro = obj(r, `roots[${i}]`);
    exactKeys(ro, ROOT_KEYS, `roots[${i}]`);
    return {
      key_id: str(ro.key_id, "root.key_id"),
      alg: str(ro.alg, "root.alg"),
      pubkeyB64: str(ro.pubkey, "root.pubkey"),
      media: str(ro.media, "root.media"),
      holder: str(ro.holder, "root.holder"),
      status: str(ro.status, "root.status"),
    };
  });

  const identities: Identity[] = (Array.isArray(o.identities) ? o.identities : []).map((idv, i) => {
    const io = obj(idv, `identities[${i}]`);
    exactKeys(io, ID_KEYS, `identities[${i}]`);
    const enc: EncKey[] = (Array.isArray(io.enc_keys) ? io.enc_keys : []).map((ek, j) => {
      const eo = obj(ek, `enc_keys[${j}]`);
      exactKeys(eo, ENC_KEYS, `enc_keys[${j}]`);
      return {
        key_id: str(eo.key_id, "enc.key_id"), class: str(eo.class, "enc.class"), pubkey: str(eo.pubkey, "enc.pubkey"),
        media: str(eo.media, "enc.media"), added_at: uint(eo.added_at, "enc.added_at"), status: str(eo.status, "enc.status"),
      };
    });
    const sig: SigningKeyEntry[] = (Array.isArray(io.signing_keys) ? io.signing_keys : []).map((sk, j) => {
      const so = obj(sk, `signing_keys[${j}]`);
      exactKeys(so, SIGN_KEYS, `signing_keys[${j}]`);
      return {
        key_id: str(so.key_id, "sk.key_id"), class: str(so.class, "sk.class"), alg: str(so.alg, "sk.alg"),
        pubkey: str(so.pubkey, "sk.pubkey"), media: str(so.media, "sk.media"), status: str(so.status, "sk.status"),
      };
    });
    return { id: str(io.id, "id.id"), type: str(io.type, "id.type"), enc_keys: enc, signing_keys: sig, status: str(io.status, "id.status") };
  });

  const grants: Grant[] = (Array.isArray(o.grants) ? o.grants : []).map((g, i) => {
    const go = obj(g, `grants[${i}]`);
    exactKeys(go, GRANT_KEYS, `grants[${i}]`);
    return { principal: str(go.principal, "g.principal"), project: str(go.project, "g.project"), verbs: strArr(go.verbs, "g.verbs"), keys: strArr(go.keys, "g.keys") };
  });

  const writerAllow: WriterAllow[] = (Array.isArray(o.writer_allowlists) ? o.writer_allowlists : []).map((w, i) => {
    const wo = obj(w, `writer_allowlists[${i}]`);
    exactKeys(wo, WALLOW_KEYS, `writer_allowlists[${i}]`);
    return { principal: str(wo.principal, "w.principal"), project: str(wo.project, "w.project"), keys: strArr(wo.keys, "w.keys") };
  });

  return {
    schema,
    admin_epoch: uint(o.admin_epoch, "admin_epoch"),
    prev_trust_sha256: str(o.prev_trust_sha256, "prev_trust_sha256"),
    created_at: str(o.created_at, "created_at"),
    change_class: str(o.change_class, "change_class"),
    bootstrap_solo: bool(o.bootstrap_solo, "bootstrap_solo"),
    quorum: { m: uint(q.m, "quorum.m"), n: uint(q.n, "quorum.n") },
    roots,
    admins: o.admins == null ? [] : strArr(o.admins, "admins"),
    identities,
    grants,
    writer_allowlists: writerAllow,
    worker_receipt_pubkey: o.worker_receipt_pubkey ?? null,
    worker_mint_pubkeys: o.worker_mint_pubkeys ?? null,
    epoch_reset: parseEpochReset(o.epoch_reset),
  };
}

// --- İmzalayan görünümü (buildSignerView) ----------------------------------

interface AdminKeyInfo {
  vk: VerifierKey;
  humanID: string;
}
export interface SignerView {
  rootKeys: Map<string, VerifierKey>;
  adminKeys: Map<string, AdminKeyInfo>;
  m: number;
  n: number;
  bootstrapSolo: boolean;
  nAdminHumans: number;
}

function buildSignerView(m: TrustManifest): SignerView {
  const view: SignerView = { rootKeys: new Map(), adminKeys: new Map(), m: m.quorum.m, n: m.quorum.n, bootstrapSolo: m.bootstrap_solo, nAdminHumans: 0 };
  for (const r of m.roots) {
    if (r.status !== STATUS_ACTIVE) continue;
    if (r.alg !== ALG_ED25519) throw new TrustError("TRUST_CHAIN_BROKEN", `root ${r.key_id} must be ed25519`);
    const vk = newVerifierKey(r.alg, b64ToBytes(r.pubkeyB64));
    if (r.key_id !== "" && r.key_id !== vk.keyID) throw new TrustError("TRUST_CHAIN_BROKEN", "root key_id mismatch");
    view.rootKeys.set(vk.keyID, vk);
  }
  const adminSet = new Set(m.admins);
  const humans = new Set<string>();
  for (const id of m.identities) {
    if (!adminSet.has(id.id) || id.status !== STATUS_ACTIVE) continue;
    for (const sk of id.signing_keys) {
      if (sk.class !== SIGN_CLASS_ADMIN || sk.status !== STATUS_ACTIVE) continue;
      if (sk.alg !== ALG_ECDSA_P256_SHA256) continue; // admin presence anahtarları P-256
      const vk = newVerifierKey(sk.alg, b64ToBytes(sk.pubkey));
      if (sk.key_id !== "" && sk.key_id !== vk.keyID) throw new TrustError("TRUST_CHAIN_BROKEN", "admin key_id mismatch");
      view.adminKeys.set(vk.keyID, { vk, humanID: id.id });
      humans.add(id.id);
    }
  }
  view.nAdminHumans = humans.size;
  return view;
}

// --- Politika (RequiredSigners) --------------------------------------------

type SignerClass = "root" | "admin";
interface Requirement {
  cls: SignerClass;
  threshold: number;
  distinctHuman: boolean;
}
export type ProjectClass = "prod" | "lab" | "";
export type ProjectClassifier = (project: string) => ProjectClass;

function requiredSigners(changeClass: string, proj: ProjectClass, parentM: number, nAdminHumans: number): Requirement {
  switch (changeClass) {
    case CHANGE_ROSTER:
    case CHANGE_EPOCH_RESET:
      return { cls: "root", threshold: parentM, distinctHuman: false };
    case CHANGE_GRANT:
      if (proj === "prod") {
        const thr = nAdminHumans >= 2 ? 2 : 1;
        return { cls: "admin", threshold: thr, distinctHuman: thr >= 2 };
      }
      if (proj === "lab") return { cls: "admin", threshold: 1, distinctHuman: false };
      throw new TrustError("TRUST_CHAIN_BROKEN", "grant epoch needs prod/lab project class");
    case CHANGE_REGISTRY:
    case CHANGE_POLICY:
      return { cls: "admin", threshold: 1, distinctHuman: false };
    default:
      throw new TrustError("UNKNOWN_CHANGE_CLASS", changeClass);
  }
}

function verifyQuorum(childBytes: Uint8Array, sigs: SignedObject["sigs"], req: Requirement, parent: SignerView): void {
  const seen = new Set<string>();
  const humans = new Set<string>();
  let count = 0;
  for (const s of sigs) {
    let vk: VerifierKey | undefined;
    let human = "";
    if (req.cls === "root") {
      vk = parent.rootKeys.get(s.key_id);
    } else {
      const info = parent.adminKeys.get(s.key_id);
      if (info) {
        vk = info.vk;
        human = info.humanID;
      }
    }
    if (!vk) continue; // yabancı/yanlış-sınıf anahtar sayılmaz
    if (seen.has(s.key_id)) continue;
    if (!verifySignatureEnvelope(childBytes, s, vk)) continue; // geçersiz imza sayılmaz
    seen.add(s.key_id);
    count++;
    if (human) humans.add(human);
  }
  const got = req.distinctHuman ? humans.size : count;
  if (got < req.threshold) throw new TrustError("TRUST_QUORUM_UNMET", `have ${got}, need ${req.threshold} ${req.cls}`);
}

function maxHolderShare(roots: RootKey[]): number {
  const byHolder = new Map<string, number>();
  let max = 0;
  for (const r of roots) {
    if (r.status !== STATUS_ACTIVE) continue;
    const c = (byHolder.get(r.holder) ?? 0) + 1;
    byHolder.set(r.holder, c);
    if (c > max) max = c;
  }
  return max;
}

function validateRosterInvariants(m: TrustManifest): void {
  if (m.quorum.m < 2) throw new TrustError("TRUST_CHAIN_BROKEN", `quorum.m ${m.quorum.m} must be >= 2`);
  let active = 0;
  for (const r of m.roots) {
    if (r.status !== STATUS_ACTIVE) continue;
    active++;
    if (r.alg !== ALG_ED25519) throw new TrustError("TRUST_CHAIN_BROKEN", `root ${r.key_id} must be ed25519`);
    const pub = b64ToBytes(r.pubkeyB64);
    if (pub.length !== 32) throw new TrustError("TRUST_CHAIN_BROKEN", `root ${r.key_id} pubkey must be 32 bytes`);
    if (r.key_id !== "" && r.key_id !== fingerprint(pub)) throw new TrustError("TRUST_CHAIN_BROKEN", "root key_id mismatch");
  }
  if (active !== m.quorum.n) throw new TrustError("TRUST_CHAIN_BROKEN", `active roots ${active} != quorum.n ${m.quorum.n}`);
  if (m.quorum.m > m.quorum.n) throw new TrustError("TRUST_CHAIN_BROKEN", `quorum.m > quorum.n`);
  const wantSolo = maxHolderShare(m.roots) >= m.quorum.m;
  if (m.bootstrap_solo !== wantSolo) throw new TrustError("TRUST_CHAIN_BROKEN", `bootstrap_solo=${m.bootstrap_solo} but invariant requires ${wantSolo}`);
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function compareUnchanged(parent: TrustManifest, cur: TrustManifest): void {
  if (!deepEqual(parent.roots, cur.roots)) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies roots");
  if (!deepEqual(parent.quorum, cur.quorum)) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies quorum");
  if (!deepEqual(parent.admins, cur.admins)) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies admins");
  if (parent.bootstrap_solo !== cur.bootstrap_solo) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies bootstrap_solo");
  if (!deepEqual(parent.worker_receipt_pubkey, cur.worker_receipt_pubkey)) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies worker_receipt_pubkey");
  if (!deepEqual(parent.worker_mint_pubkeys, cur.worker_mint_pubkeys)) throw new TrustError("TRUST_CHAIN_BROKEN", "non-roster epoch modifies worker_mint_pubkeys");
}

function grantTargetClass(parent: TrustManifest, cur: TrustManifest, classifier: ProjectClassifier | null): ProjectClass {
  if (!classifier) return "prod";
  let sawProd = false;
  let sawLab = false;
  for (const g of cur.grants) {
    const changed = !parent.grants.some((pg) => deepEqual(pg, g));
    if (!changed) continue;
    const c = classifier(g.project);
    if (c === "prod") sawProd = true;
    else if (c === "lab") sawLab = true;
  }
  if (sawProd) return "prod";
  if (sawLab) return "lab";
  return "prod";
}

/**
 * verifyResetInternal, epoch-reset doğrulamasının ortak çekirdeğidir (SPEC §4.8);
 * Go internal/trust/reset.go verifyResetInternal ile TAM parite. Hem zincir-içi
 * (verifyNext) hem tek-başına (verifyEpochReset) yollarından çağrılır. İmza:
 * reset ÖNCESİ epoch'un ≥M KÖK-class Ed25519 anahtarı. Downgrade guard: istemcinin
 * pin'i reset'in prior sınırından YENİYSE reddedilir → reset bir rollback'i aklayamaz.
 */
function verifyResetInternal(
  o: SignedObject,
  cand: TrustManifest,
  hash: string,
  priorView: SignerView,
  priorSHA: string,
  priorAdminEpoch: number,
  pinnedLast: Pin,
  witnessBound: number,
  priorHeadAvailable: boolean,
): VerifiedEpoch {
  const er = cand.epoch_reset;
  if (!er) throw new TrustError("TRUST_CHAIN_BROKEN", "epoch_reset record required");
  if (er.schema !== SCHEMA_TRUST_RESET) throw new TrustError("TRUST_CHAIN_BROKEN", `reset schema ${er.schema}`);
  if (er.reset_id === "" || er.reason === "") throw new TrustError("TRUST_CHAIN_BROKEN", "reset missing reset_id/reason");

  // prior_chain, verilen prior roster ile tutarlı olmalı.
  if (er.prior_chain.last_admin_epoch !== priorAdminEpoch) {
    throw new TrustError("TRUST_CHAIN_BROKEN", `prior_chain.last_admin_epoch ${er.prior_chain.last_admin_epoch} != prior ${priorAdminEpoch}`);
  }

  // prev-link (§4.8): prior head mevcutsa prior_chain.last_trust_sha256 ve
  // prev_trust_sha256 eşleşir; kayıpsa (escrow-restore) prev BOŞ olmalıdır.
  if (priorHeadAvailable) {
    if (cand.prev_trust_sha256 !== priorSHA) throw new TrustError("TRUST_CHAIN_BROKEN", "prev_trust_sha256 does not link to prior head");
    if (er.prior_chain.last_trust_sha256 !== priorSHA) throw new TrustError("TRUST_CHAIN_BROKEN", "prior_chain.last_trust_sha256 mismatch");
  } else {
    if (cand.prev_trust_sha256 !== "") throw new TrustError("TRUST_CHAIN_BROKEN", "lost-head reset must carry empty prev_trust_sha256");
  }

  // Monotonluk: reset epoch'u prior head'ten VE tanık sınırından KATİ büyük olmalı.
  if (cand.admin_epoch <= er.prior_chain.last_admin_epoch) {
    throw new TrustError("TRUST_CHAIN_BROKEN", `reset admin_epoch ${cand.admin_epoch} must exceed prior ${er.prior_chain.last_admin_epoch}`);
  }
  if (cand.admin_epoch <= witnessBound) {
    throw new TrustError("TRUST_CHAIN_BROKEN", `reset admin_epoch ${cand.admin_epoch} must exceed witness bound ${witnessBound}`);
  }

  // Downgrade: reset bir rollback'i aklayamaz — pin, reset'in prior sınırından YENİYSE red.
  if (pinnedLast.admin_epoch > er.prior_chain.last_admin_epoch) {
    throw new TrustError("TRUST_DOWNGRADE", `pinned epoch ${pinnedLast.admin_epoch} newer than reset prior ${er.prior_chain.last_admin_epoch}`);
  }

  // İmza: reset ÖNCESİ epoch'un ≥M KÖK-class anahtarı (parent'ın görünümüne karşı).
  verifyQuorum(o.bytes, o.sigs, { cls: "root", threshold: priorView.m, distinctHuman: false }, priorView);

  // Reset epoch'u geçerli bir roster taşır.
  validateRosterInvariants(cand);
  const view = buildSignerView(cand);
  return { manifest: cand, bytesSHA256: hash, view };
}

/**
 * verifyEpochReset, bir epoch-reset kaydını TEK BAŞINA doğrular (SPEC §4.8) —
 * felaket kurtarma yolu. Go VerifyEpochReset paritesi. prior = reset öncesi son
 * (doğrulanmış) roster; priorHeadAvailable=false ise escrow-restore (prev boş).
 */
export function verifyEpochReset(
  o: SignedObject,
  prior: TrustManifest,
  priorSHA: string,
  pinnedLast: Pin,
  witnessBound: number,
  priorHeadAvailable: boolean,
): VerifiedEpoch {
  const priorView = buildSignerView(prior);
  const hash = trustObjectHash(o.bytes);
  const cand = parseTrustBody(o.bytes);
  if (cand.change_class !== CHANGE_EPOCH_RESET) throw new TrustError("TRUST_CHAIN_BROKEN", `change_class ${cand.change_class} is not epoch_reset`);
  return verifyResetInternal(o, cand, hash, priorView, priorSHA, prior.admin_epoch, pinnedLast, witnessBound, priorHeadAvailable);
}

/**
 * verifyGenesis, genesis güven epoch'unu (§4.4/§4.5 istisnası) doğrular: önce
 * payload hash pinlenmiş genesis hash'iyle eşleşmeli (parse ÖNCESİ), sonra
 * roster olduğu + prev boş + ≥M kendi kök imzası doğrulanır.
 */
export function verifyGenesis(pinnedGenesis: Pin, o: SignedObject): VerifiedEpoch {
  if (pinnedGenesis.sha256 === "") throw new TrustError("TRUST_PIN_MISSING", "no genesis pin");
  const hash = trustObjectHash(o.bytes);
  if (hash !== pinnedGenesis.sha256) throw new TrustError("TRUST_CHAIN_BROKEN", "genesis hash does not match pin");
  const cand = parseTrustBody(o.bytes);
  if (cand.admin_epoch !== pinnedGenesis.admin_epoch) throw new TrustError("TRUST_CHAIN_BROKEN", "genesis admin_epoch mismatch");
  if (cand.prev_trust_sha256 !== "") throw new TrustError("TRUST_CHAIN_BROKEN", "genesis prev must be empty");
  if (cand.change_class !== CHANGE_ROSTER) throw new TrustError("TRUST_CHAIN_BROKEN", "genesis must be roster");
  validateRosterInvariants(cand);
  const view = buildSignerView(cand);
  verifyQuorum(o.bytes, o.sigs, { cls: "root", threshold: cand.quorum.m, distinctHuman: false }, view);
  return { manifest: cand, bytesSHA256: hash, view };
}

/**
 * verifyNext, doğrulanmış parent'ın halefi (E+1) olan obj'yi doğrular (§4.5).
 * pinnedLast + witnessBound, zincir-içi bir epoch_reset'te §4.8 downgrade/rollback
 * ve tanık monotonluk yaptırımlarını beslemek için verifyResetInternal'a AYNEN
 * aktarılır (grant/roster/registry yollarında yok sayılır). Aksi halde reset yolu
 * bu korumaları SIFIRLAR → geçmiş bir epoch'un ≥M kök imzasıyla rollback aklanabilir.
 */
export function verifyNext(parent: VerifiedEpoch, o: SignedObject, classifier: ProjectClassifier | null, pinnedLast: Pin, witnessBound: number): VerifiedEpoch {
  const hash = trustObjectHash(o.bytes);
  const cand = parseTrustBody(o.bytes);
  // Epoch-reset (§4.8) ayrı yolla (gevşetilmiş epoch kuralı) doğrulanır; istemcinin
  // GERÇEK pin'i ve tanık sınırı aktarılır → downgrade/rollback koruması burada da yaptırılır.
  if (cand.change_class === CHANGE_EPOCH_RESET) {
    return verifyResetInternal(o, cand, hash, parent.view, parent.bytesSHA256, parent.manifest.admin_epoch, pinnedLast, witnessBound, true);
  }
  if (cand.prev_trust_sha256 !== parent.bytesSHA256) throw new TrustError("TRUST_CHAIN_BROKEN", "prev_trust_sha256 does not link to parent");
  if (cand.admin_epoch !== parent.manifest.admin_epoch + 1) throw new TrustError("TRUST_CHAIN_BROKEN", "admin_epoch not +1");
  let projClass: ProjectClass = "";
  if (cand.change_class === CHANGE_GRANT) projClass = grantTargetClass(parent.manifest, cand, classifier);
  const req = requiredSigners(cand.change_class, projClass, parent.view.m, parent.view.nAdminHumans);
  verifyQuorum(o.bytes, o.sigs, req, parent.view);
  validateRosterInvariants(cand);
  if (cand.change_class !== CHANGE_ROSTER) compareUnchanged(parent.manifest, cand);
  const view = buildSignerView(cand);
  return { manifest: cand, bytesSHA256: hash, view };
}

/**
 * verifyRosterChain, pinlenmiş genesis'ten yukarı zinciri yürütür ve head'i
 * döner (§4.4/§4.5). chain[0] genesis olmalı; downgrade (head < pinnedLast)
 * hard-fail. classifier grant katmanı için (nil = strict prod).
 */
export function verifyRosterChain(pinnedGenesis: Pin, pinnedLast: Pin, chain: SignedObject[], classifier: ProjectClassifier | null = null): VerifiedEpoch {
  if (chain.length === 0) throw new TrustError("TRUST_CHAIN_BROKEN", "empty chain");
  let head = verifyGenesis(pinnedGenesis, chain[0]);
  checkPinPassthrough(head, pinnedLast);
  // witnessBound = istemcinin last_verified epoch'u: zincir-içi bir reset bundan
  // KATİ büyük olmalı (§4.8 tanık monotonluğu). pinnedLast ile birlikte verifyNext'e
  // aktarılır; grant/roster/registry yollarında yok sayılır.
  const witnessBound = pinnedLast.admin_epoch;
  for (let i = 1; i < chain.length; i++) {
    head = verifyNext(head, chain[i], classifier, pinnedLast, witnessBound);
    checkPinPassthrough(head, pinnedLast);
  }
  if (head.manifest.admin_epoch < pinnedLast.admin_epoch) throw new TrustError("TRUST_DOWNGRADE", `head ${head.manifest.admin_epoch} below last-verified ${pinnedLast.admin_epoch}`);
  return head;
}

function checkPinPassthrough(ep: VerifiedEpoch, pinnedLast: Pin): void {
  if (pinnedLast.sha256 === "") return;
  if (ep.manifest.admin_epoch === pinnedLast.admin_epoch && ep.bytesSHA256 !== pinnedLast.sha256) {
    throw new TrustError("TRUST_DOWNGRADE", `epoch ${pinnedLast.admin_epoch} forks from last-verified pin`);
  }
}

// --- Grant / kayıt çözümleme (registry.go portu) ---------------------------

function keyMatches(allow: string[], key: string): boolean {
  return allow.some((a) => a === KEY_WILDCARD || a === key);
}

export function identityByID(m: TrustManifest, id: string): Identity | undefined {
  return m.identities.find((i) => i.id === id);
}

/** grantsFor, bir prensibin bir projedeki grant'ları. */
export function grantsFor(m: TrustManifest, principal: string, project: string): Grant[] {
  return m.grants.filter((g) => g.principal === principal && g.project === project);
}

/** verbKeyAllowed, prensibin projede bir anahtar üzerinde verb yetkisi var mı (§6.3). */
export function verbKeyAllowed(m: TrustManifest, principal: string, project: string, verb: string, key: string): boolean {
  return grantsFor(m, principal, project).some((g) => g.verbs.includes(verb) && keyMatches(g.keys, key));
}

/** hasVerbGrant, prensibin projede HERHANGİ bir anahtar üzerinde verb grant'ı var mı (read-path proje-seviyesi kontrol, §6.3). */
export function hasVerbGrant(m: TrustManifest, principal: string, project: string, verb: string): boolean {
  return grantsFor(m, principal, project).some((g) => g.verbs.includes(verb));
}

/** writerKeyAllowed, otomasyon kimliği projede bir anahtarı yazabilir mi (writer_allowlists). */
export function writerKeyAllowed(m: TrustManifest, principal: string, project: string, key: string): boolean {
  return m.writer_allowlists.some((w) => w.principal === principal && w.project === project && keyMatches(w.keys, key));
}

/** activeEscrowRecipients, aktif escrow kimliklerinin aktif enc-key parmak izleri (§6.2 step 9). */
export function activeEscrowRecipients(m: TrustManifest): Set<string> {
  const out = new Set<string>();
  for (const id of m.identities) {
    if (id.type !== TYPE_ESCROW || id.status === STATUS_REVOKED) continue;
    for (const ek of id.enc_keys) {
      if (ek.status === STATUS_ACTIVE) out.add(ek.key_id !== "" ? ek.key_id : fingerprintRecipient(ek.pubkey));
    }
  }
  return out;
}

/**
 * requiredRecipients, §6.2 step 9'un gerekli recipient kümesini hesaplar:
 * { read grant'lı her insan prensibinin device+backup enc anahtarları }
 *   ∪ { read grant'lı her makine prensibinin device enc anahtarı }
 *   ∪ { escrow recipient(ler) }.
 * Yalnızca aktif (non-revoked) kimlikler/anahtarlar sayılır.
 */
export function requiredRecipients(m: TrustManifest, project: string, keyName: string): Set<string> {
  const req = new Set<string>();
  for (const id of m.identities) {
    if (id.status === STATUS_REVOKED) continue;
    if (id.type !== TYPE_HUMAN && id.type !== TYPE_MACHINE) continue;
    if (!verbKeyAllowed(m, id.id, project, "read", keyName)) continue;
    for (const ek of id.enc_keys) {
      if (ek.status !== STATUS_ACTIVE) continue;
      if (id.type === TYPE_HUMAN && ek.class !== ENC_CLASS_DEVICE && ek.class !== ENC_CLASS_BACKUP) continue;
      if (id.type === TYPE_MACHINE && ek.class !== ENC_CLASS_DEVICE) continue;
      req.add(ek.key_id !== "" ? ek.key_id : fingerprintRecipient(ek.pubkey));
    }
  }
  for (const e of activeEscrowRecipients(m)) req.add(e);
  return req;
}

/**
 * findWriterSigningIdentity, verilen imzalama key_id'sinin sahibi kimliği ve
 * sınıfını çözer (§6.2 step 4-5). daily/admin (insan) veya automation (makine)
 * aktif imzalama anahtarı olmalı; revoked → yok. Bulamazsa undefined.
 */
export function findWriterSigningIdentity(m: TrustManifest, keyID: string): { identity: Identity; cls: string } | undefined {
  for (const id of m.identities) {
    if (id.status === STATUS_REVOKED) continue;
    for (const sk of id.signing_keys) {
      if (sk.status !== STATUS_ACTIVE) continue;
      if (sk.key_id === keyID) return { identity: id, cls: sk.class };
    }
  }
  return undefined;
}

export { SIGN_CLASS_ADMIN, SIGN_CLASS_DAILY, TYPE_HUMAN, TYPE_MACHINE, TYPE_ESCROW, STATUS_ACTIVE, ENC_CLASS_DEVICE, ENC_CLASS_BACKUP };
