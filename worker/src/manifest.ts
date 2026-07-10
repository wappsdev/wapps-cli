// Data manifest doğrulama + epoch zinciri + semantik diff (SPEC §5.4/§5.5/§6.2).
//
// KATİ KURAL (§3.6.3/§5.4.1): imza, depolanan TAM baytların SHA-256'sı üzerine.
// Doğrulayıcı ham baytları hash'ler ve imzayı body'yi PARSE ETMEDEN doğrular.
// Yeniden-serileştirme YOK. Body ancak imza geçtikten SONRA (strict) parse edilir.
//
// prevManifestSha256 / CurrentPointer.manifestSha256 = depolanan İMZALI
// SARMALAYICI baytlarının hex SHA-256'sıdır (body değil, TAM obje) — trust
// manifest'in payload-hash'inden FARKLI (§5.4.2 vs §4.2.2; trust.ts'e bakın).

import {
  SignedObject,
  VerifierKey,
  sha256Hex,
  verifySignatureEnvelope,
} from "./crypto/verify.js";

export const SCHEMA_DATA_MANIFEST = "wapps-secrets/data-manifest/v1";
export const SCHEMA_CURRENT_POINTER = "wapps-secrets/current/v1";

// Manifest-seviyesi hata kodları (§5.7 / §6 error contract).
export type ManifestError =
  | "BAD_SIGNATURE_COUNT"
  | "WRITER_UNKNOWN"
  | "SIG_INVALID"
  | "UNSUPPORTED_SCHEMA"
  | "MANIFEST_MALFORMED";

export class ManifestVerifyError extends Error {
  constructor(public code: ManifestError, msg?: string) {
    super(msg ?? code);
    this.name = "ManifestVerifyError";
  }
}

export interface DEKWrap {
  recipient: string; // şifreleme-pubkey parmak izi (§3.7)
  wrapB64: string; // DEK'in X25519 seal'i (Worker YORUMLAMAZ; sadece taşır)
}

export interface KeyEntry {
  keyName: string;
  keyVersion: number;
  blobHash: string; // çıplak-hex SHA-256 (§5.3)
  wraps: DEKWrap[];
  rotation?: unknown; // §8.6.2 opsiyonel passthrough; Worker ASLA yorumlamaz
  hasRotation: boolean;
}

export interface DataManifest {
  schema: string;
  project: string;
  epoch: number;
  prevManifestSha256: string;
  trustEpoch: number;
  createdAt: string;
  entries: KeyEntry[];
}

export interface CurrentPointer {
  schema: string;
  project: string;
  epoch: number;
  manifestSha256: string;
}

/** manifestObjectHash, depolanan imzalı-sarmalayıcı baytlarının çıplak-hex SHA-256'sı (§5.4.2/§5.5). */
export function manifestObjectHash(storedWrapperBytes: Uint8Array): string {
  return sha256Hex(storedWrapperBytes);
}

// --- Strict body parse (Go dec.DisallowUnknownFields eşdeğeri) --------------

function requireExactKeys(obj: Record<string, unknown>, allowed: readonly string[], ctx: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `${ctx}: unknown field ${k}`);
  }
}

function asUint(v: unknown, ctx: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw new ManifestVerifyError("MANIFEST_MALFORMED", `${ctx}: not a uint`);
  return v;
}
function asString(v: unknown, ctx: string): string {
  if (typeof v !== "string") throw new ManifestVerifyError("MANIFEST_MALFORMED", `${ctx}: not a string`);
  return v;
}

const WRAP_KEYS = ["recipient", "wrap"] as const;
const ENTRY_KEYS = ["keyName", "keyVersion", "blobHash", "wraps", "rotation"] as const;
const MANIFEST_KEYS = ["schema", "project", "epoch", "prevManifestSha256", "trustEpoch", "createdAt", "entries"] as const;

/**
 * parseManifestBody, ham body baytlarını DataManifest'e STRICT ayrıştırır
 * (bilinmeyen alan → red, tip kontrolü). YALNIZCA imza doğrulandıktan SONRA
 * çağrılmalıdır (§3.6.3). Şema yanlışsa UNSUPPORTED_SCHEMA.
 */
export function parseManifestBody(body: Uint8Array): DataManifest {
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new ManifestVerifyError("MANIFEST_MALFORMED", "body not valid JSON");
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new ManifestVerifyError("MANIFEST_MALFORMED", "body not an object");
  const o = doc as Record<string, unknown>;
  requireExactKeys(o, MANIFEST_KEYS, "manifest");

  const schema = asString(o.schema, "schema");
  if (schema !== SCHEMA_DATA_MANIFEST) throw new ManifestVerifyError("UNSUPPORTED_SCHEMA", schema);

  const createdAt = asString(o.createdAt, "createdAt");
  if (Number.isNaN(Date.parse(createdAt))) throw new ManifestVerifyError("MANIFEST_MALFORMED", "createdAt not RFC3339");

  if (!Array.isArray(o.entries)) throw new ManifestVerifyError("MANIFEST_MALFORMED", "entries not an array");
  const entries: KeyEntry[] = o.entries.map((raw, i) => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}] not an object`);
    const e = raw as Record<string, unknown>;
    requireExactKeys(e, ENTRY_KEYS, `entry[${i}]`);
    if (!Array.isArray(e.wraps)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}].wraps not an array`);
    const wraps: DEKWrap[] = e.wraps.map((wr, j) => {
      if (typeof wr !== "object" || wr === null || Array.isArray(wr)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `wrap[${j}] not an object`);
      const w = wr as Record<string, unknown>;
      requireExactKeys(w, WRAP_KEYS, `entry[${i}].wrap[${j}]`);
      return { recipient: asString(w.recipient, "recipient"), wrapB64: asString(w.wrap, "wrap") };
    });
    const hasRotation = Object.prototype.hasOwnProperty.call(e, "rotation") && e.rotation !== null;
    return {
      keyName: asString(e.keyName, `entry[${i}].keyName`),
      keyVersion: asUint(e.keyVersion, `entry[${i}].keyVersion`),
      blobHash: asString(e.blobHash, `entry[${i}].blobHash`),
      wraps,
      rotation: e.rotation,
      hasRotation,
    };
  });

  return {
    schema,
    project: asString(o.project, "project"),
    epoch: asUint(o.epoch, "epoch"),
    prevManifestSha256: asString(o.prevManifestSha256, "prevManifestSha256"),
    trustEpoch: asUint(o.trustEpoch, "trustEpoch"),
    createdAt,
    entries,
  };
}

/**
 * verifyDataManifest, imzalı bir data manifest sarmalayıcısını doğrular ve
 * body'yi ayrıştırır. SIRA KATİDİR (§3.6.3):
 *   1. Tam olarak 1 imza (yoksa BAD_SIGNATURE_COUNT).
 *   2. key_id ring'de çözülmeli (yoksa WRITER_UNKNOWN).
 *   3. SHA-256(bytes) üzerinde imza — body PARSE EDİLMEDEN (yoksa SIG_INVALID).
 *   4. Ancak O ZAMAN body strict parse edilir.
 */
export function verifyDataManifest(obj: SignedObject, ring: Map<string, VerifierKey>): DataManifest {
  if (obj.sigs.length !== 1) throw new ManifestVerifyError("BAD_SIGNATURE_COUNT", `sigs=${obj.sigs.length}`);
  const sig = obj.sigs[0];
  const vk = ring.get(sig.key_id);
  if (!vk) throw new ManifestVerifyError("WRITER_UNKNOWN", sig.key_id);
  if (!verifySignatureEnvelope(obj.bytes, sig, vk)) throw new ManifestVerifyError("SIG_INVALID");
  return parseManifestBody(obj.bytes);
}

/** parseCurrentPointer, current pointer baytlarını (şema doğrulamalı) çözer. */
export function parseCurrentPointer(raw: Uint8Array): CurrentPointer {
  const doc = JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  const schema = asString(doc.schema, "current.schema");
  if (schema !== SCHEMA_CURRENT_POINTER) throw new ManifestVerifyError("UNSUPPORTED_SCHEMA", schema);
  return {
    schema,
    project: asString(doc.project, "current.project"),
    epoch: asUint(doc.epoch, "current.epoch"),
    manifestSha256: asString(doc.manifestSha256, "current.manifestSha256"),
  };
}

// --- Semantik diff (§6.2 step 8-10 için saf, test edilebilir çekirdek) -------

export interface EntryDiff {
  added: KeyEntry[];
  removed: KeyEntry[];
  changed: { old: KeyEntry; cur: KeyEntry }[];
}

/** recipientSet, bir girdinin wrap-set'inin recipient parmak izleri kümesi. */
export function recipientSet(e: KeyEntry): Set<string> {
  return new Set(e.wraps.map((w) => w.recipient));
}

function entriesEqual(a: KeyEntry, b: KeyEntry): boolean {
  if (a.keyVersion !== b.keyVersion || a.blobHash !== b.blobHash) return false;
  // Wrap-set: recipient kümesi + wrap baytları (byte-identical carry-forward, §5.6).
  if (a.wraps.length !== b.wraps.length) return false;
  const bw = new Map(b.wraps.map((w) => [w.recipient, w.wrapB64]));
  for (const w of a.wraps) {
    if (bw.get(w.recipient) !== w.wrapB64) return false;
  }
  // rotation passthrough baytları (JSON-eşdeğer) değişmemeli.
  if (JSON.stringify(a.rotation ?? null) !== JSON.stringify(b.rotation ?? null)) return false;
  return true;
}

/**
 * diffEntries, eski→yeni manifest girdileri arasındaki semantik diff'i hesaplar
 * (§6.2 step 8): eklenen / kaldırılan / değişen anahtarlar. "changed" bir girdinin
 * HERHANGİ bir alanının (keyVersion/blobHash/wrap-set/rotation) farkı demektir.
 */
export function diffEntries(oldEntries: KeyEntry[], newEntries: KeyEntry[]): EntryDiff {
  const oldMap = new Map(oldEntries.map((e) => [e.keyName, e]));
  const newMap = new Map(newEntries.map((e) => [e.keyName, e]));
  const added: KeyEntry[] = [];
  const removed: KeyEntry[] = [];
  const changed: { old: KeyEntry; cur: KeyEntry }[] = [];
  for (const [name, cur] of newMap) {
    const prev = oldMap.get(name);
    if (!prev) added.push(cur);
    else if (!entriesEqual(prev, cur)) changed.push({ old: prev, cur });
  }
  for (const [name, prev] of oldMap) {
    if (!newMap.has(name)) removed.push(prev);
  }
  return { added, removed, changed };
}
