// Data manifest v2 (SPEC §2.6) — İMZASIZ, Worker-yazarlı düz JSON. ZK tasarımın
// imza sarmalayıcısı/semantik-diff makinesi SİLİNDİ (§0.2): Worker tek R2
// yazarıdır; out-of-band mutasyona karşı bütünlük, epoch hash zinciri + CLI epoch
// pin'i + B2 replikasıyla tamper-EVIDENT'tır (tamper-proof değil; kabul, §2.6).
//
// Kurallar: proje+epoch başına TAM anahtar kümesi (delta değil); entries keyName'e
// göre ARTAN sıralı + benzersiz (KEYNAME_RE); silme = yokluk; her girdi tam olarak
// BİR wrap taşır (recipient kapalı kümesi = worker-kek:v1, §2.4); rotation metadata
// opak taşınır. prevManifestSha256 = önceki manifest OBJE baytlarının hex SHA-256'sı.

import { sha256Hex, utf8, b64ToBytes } from "./crypto/encoding.js";
import { DekWrap, WRAP_RECIPIENT, WRAP_TOTAL_LEN } from "./crypto/kek.js";
import { validKeyName } from "./storage.js";

export const SCHEMA_DATA_MANIFEST = "wapps-secrets/data-manifest/v2";
export const SCHEMA_CURRENT_POINTER = "wapps-secrets/current/v1";
export const MANIFEST_CAP = 1_048_576; // 1 MB (§2.6 MANIFEST_TOO_LARGE)

export type ManifestError =
  | "UNSUPPORTED_SCHEMA"
  | "MANIFEST_MALFORMED"
  | "ALG_UNSUPPORTED";

export class ManifestVerifyError extends Error {
  constructor(public code: ManifestError, msg?: string) {
    super(msg ?? code);
    this.name = "ManifestVerifyError";
  }
}

export interface ManifestEntry {
  keyName: string;
  keyVersion: number;
  blobHash: string; // çıplak-hex SHA-256 içerik adresi
  wrap: DekWrap; // tam olarak BİR wrap (§2.4)
  rotation?: unknown; // opak taşınır (ZK §8.6.2 şekli); Worker yorumlamaz
}

export interface DataManifest {
  schema: string;
  project: string;
  epoch: number;
  prevManifestSha256: string; // "" iff epoch==1
  policyVersion: number;
  writer: string; // bilgilendirici (audit çapraz-referansı); AUTHZ GİRDİSİ DEĞİL (§2.6)
  createdAt: string; // RFC3339
  entries: ManifestEntry[];
}

export interface CurrentPointer {
  schema: string;
  project: string;
  epoch: number;
  manifestSha256: string;
}

/** manifestObjectHash, depolanan manifest baytlarının çıplak-hex SHA-256'sı (§2.6 zincir). */
export function manifestObjectHash(storedBytes: Uint8Array): string {
  return sha256Hex(storedBytes);
}

function asUint(v: unknown, ctx: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new ManifestVerifyError("MANIFEST_MALFORMED", `${ctx}: not a uint`);
  return v;
}
function asString(v: unknown, ctx: string): string {
  if (typeof v !== "string") throw new ManifestVerifyError("MANIFEST_MALFORMED", `${ctx}: not a string`);
  return v;
}

/**
 * parseManifest, depolanan v2 manifest baytlarını doğrulayarak çözer. Worker tek
 * yazar olsa da parse fail-closed'dur: şema uyuşmazlığı, tekrarlanan/sırasız
 * keyName, kapalı-küme dışı wrap recipient'i (ALG_UNSUPPORTED, §2.4) reddedilir.
 */
export function parseManifest(bytes: Uint8Array): DataManifest {
  if (bytes.length > MANIFEST_CAP) throw new ManifestVerifyError("MANIFEST_MALFORMED", "manifest exceeds 1 MB");
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ManifestVerifyError("MANIFEST_MALFORMED", "manifest not valid JSON");
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new ManifestVerifyError("MANIFEST_MALFORMED", "manifest not an object");
  const o = doc as Record<string, unknown>;
  const schema = asString(o.schema, "schema");
  if (schema !== SCHEMA_DATA_MANIFEST) throw new ManifestVerifyError("UNSUPPORTED_SCHEMA", schema);
  if (!Array.isArray(o.entries)) throw new ManifestVerifyError("MANIFEST_MALFORMED", "entries not an array");

  let prevName = "";
  const seenLower = new Set<string>();
  const entries: ManifestEntry[] = o.entries.map((raw, i) => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}] not an object`);
    const e = raw as Record<string, unknown>;
    const keyName = asString(e.keyName, `entry[${i}].keyName`);
    if (!validKeyName(keyName)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}]: invalid keyName`);
    // Artan sıra + benzersizlik (§2.6): önceki addan kesin büyük olmalı.
    if (keyName <= prevName) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}]: entries not strictly sorted by keyName`);
    // Case-insensitive KİMLİK (§4.1): authz FOO ≡ foo sayar; bir manifest İKİSİNİ birden
    // taşıyamaz (restore/craft edilmiş manifest'e karşı fail-closed — writer-DO ikinci hat).
    const lower = keyName.toLowerCase();
    if (seenLower.has(lower)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}]: case-colliding keyName`);
    seenLower.add(lower);
    prevName = keyName;
    const w = e.wrap;
    if (typeof w !== "object" || w === null || Array.isArray(w)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}].wrap not an object`);
    const wo = w as Record<string, unknown>;
    const recipient = asString(wo.recipient, `entry[${i}].wrap.recipient`);
    // Kapalı küme (§2.4): v2 manifest'te worker-kek:v1 dışındaki her recipient reddedilir.
    if (recipient !== WRAP_RECIPIENT) throw new ManifestVerifyError("ALG_UNSUPPORTED", `entry[${i}].wrap.recipient: ${recipient}`);
    const kid = asString(wo.kid, `entry[${i}].wrap.kid`);
    if (!/^[0-9a-f]{16}$/.test(kid)) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}].wrap.kid not 16-hex`);
    const wrapB64 = asString(wo.wrap, `entry[${i}].wrap.wrap`);
    let wrapBytes: Uint8Array;
    try {
      wrapBytes = b64ToBytes(wrapB64);
    } catch {
      throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}].wrap.wrap not canonical base64`);
    }
    if (wrapBytes.length !== WRAP_TOTAL_LEN) throw new ManifestVerifyError("MANIFEST_MALFORMED", `entry[${i}].wrap.wrap not 76 bytes`);
    return {
      keyName,
      keyVersion: asUint(e.keyVersion, `entry[${i}].keyVersion`),
      blobHash: asString(e.blobHash, `entry[${i}].blobHash`),
      wrap: { recipient, kid, wrap: wrapB64 },
      rotation: e.rotation,
    };
  });

  return {
    schema,
    project: asString(o.project, "project"),
    epoch: asUint(o.epoch, "epoch"),
    prevManifestSha256: asString(o.prevManifestSha256, "prevManifestSha256"),
    policyVersion: asUint(o.policyVersion, "policyVersion"),
    writer: asString(o.writer, "writer"),
    createdAt: asString(o.createdAt, "createdAt"),
    entries,
  };
}

/**
 * serializeManifest, bir DataManifest'i depolanacak baytlara çevirir. entries
 * keyName'e göre SIRALANIR (§2.6); rotation undefined ise alan atlanır.
 */
export function serializeManifest(m: DataManifest): Uint8Array {
  const entries = [...m.entries].sort((a, b) => (a.keyName < b.keyName ? -1 : a.keyName > b.keyName ? 1 : 0));
  const doc = {
    schema: SCHEMA_DATA_MANIFEST,
    project: m.project,
    epoch: m.epoch,
    prevManifestSha256: m.prevManifestSha256,
    policyVersion: m.policyVersion,
    writer: m.writer,
    createdAt: m.createdAt,
    entries: entries.map((e) => ({
      keyName: e.keyName,
      keyVersion: e.keyVersion,
      blobHash: e.blobHash,
      wrap: e.wrap,
      ...(e.rotation !== undefined ? { rotation: e.rotation } : {}),
    })),
  };
  const bytes = utf8(JSON.stringify(doc));
  if (bytes.length > MANIFEST_CAP) throw new ManifestVerifyError("MANIFEST_MALFORMED", "manifest exceeds 1 MB");
  return bytes;
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
