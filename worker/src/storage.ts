// R2 obje namespace'i + read-path yardımcıları (SPEC §2.6/§4.1). Okuma yolu
// DO-free'dir; manifest/blob/pointer doğrudan Worker'dan R2'ye. v2 delta: trust/*
// anahtarları SİLİNDİ (§0.2); policy/* anahtarları EKLENDİ (§4.1).

// --- Anahtar düzeni ----------------------------------------------------------

export function keyBlob(project: string, sha256: string): string {
  return `secrets/${project}/blobs/${sha256}`;
}
export function keyManifest(project: string, epoch: number): string {
  return `secrets/${project}/manifests/${epoch}.json`;
}
export function keyCurrent(project: string): string {
  return `secrets/${project}/current`;
}
export function keyPointerEvent(project: string, epoch: number): string {
  // Escrow tarafı append-only pointer-event akışı (§8.3).
  return `pointer-events/${project}/${epoch}.json`;
}
export function keyPolicyCurrent(): string {
  return `policy/current`;
}
export function keyPolicyVersion(n: number): string {
  return `policy/versions/${n}.json`;
}

// --- Proje / anahtar-adı doğrulama -------------------------------------------

const PROJECT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
// POSIX ortam-değişkeni adı: ilk karakter harf/altçizgi, sonrası alfanümerik/altçizgi
// (karışık harf). Yalnız-BÜYÜK değil — gerçek infra sırları karışık harf kullanır
// (tofu `TF_VAR_<lower>` sözleşmesi, `vaulter_pg_<role>_password` çıktıları). Anahtar
// adı R2 path'ine GİRMEZ (blob'lar sha256 content-addressed; manifest adı DATA tutar),
// dolayısıyla karışık harf path-güvenliğini bozmaz.
const KEYNAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
// JS prototype-özel adları reddet: response haritaları plain object (values[k]=…);
// `__proto__` bir data anahtarı DEĞİL, prototype setter'ını tetikler → yazılan sır
// read yanıtından SESSİZCE düşer (+ prototype-pollution). Gerçek hiçbir sır bu adları
// kullanmaz → reddetmek bedava + güvenli.
const PROTO_SPECIAL = new Set(["__proto__", "constructor", "prototype"]);
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export function validProject(p: string): boolean {
  return PROJECT_RE.test(p);
}
export function validKeyName(k: string): boolean {
  return KEYNAME_RE.test(k) && !PROTO_SPECIAL.has(k);
}
export function validSha256Hex(h: string): boolean {
  return SHA256_HEX_RE.test(h);
}

// --- Bounded-concurrency havuzu (R2 fan-out) ---------------------------------

/** BLOB_POOL, bulk read/write'ta AYNI ANDA açık R2 op üst sınırı. Sıralı (wall-time
 *  aşımı) ile sınırsız Promise.all (bellek + eşzamanlı-subrequest patlaması) arasında. */
export const BLOB_POOL = 24;
/** MAX_BULK_KEYS, tek bir bulk read/import isteğindeki anahtar üst sınırı (DoS bandı;
 *  manifest boyutu zaten MANIFEST_TOO_LARGE ile sınırlı, bu ek/açık bir korkuluk). */
export const MAX_BULK_KEYS = 1000;

/** mapPool, öğeleri EN FAZLA `limit` eşzamanlı işler (sınırsız Promise.all yerine).
 *  Sonuçlar giriş sırasında döner; bir fn reddederse başlamış işler iptal EDİLMEZ
 *  (çağıran atomikliği başka katmanda sağlar). */
export async function mapPool<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(Math.max(1, limit), items.length) }, () => worker()));
  return results;
}

// --- R2 read yardımcıları ----------------------------------------------------

export interface FetchedObject {
  bytes: Uint8Array;
  etag: string;
}

/** getObject, bir R2 objesini ham baytlar + ETag olarak getirir; yoksa null. */
export async function getObject(bucket: R2Bucket, key: string): Promise<FetchedObject | null> {
  const o = await bucket.get(key);
  if (!o) return null;
  const buf = await o.arrayBuffer();
  return { bytes: new Uint8Array(buf), etag: o.etag };
}

/** headEtag, bir objenin ETag'ini döner (yoksa null) — CAS için. */
export async function headEtag(bucket: R2Bucket, key: string): Promise<string | null> {
  const h = await bucket.head(key);
  return h ? h.etag : null;
}

/** deriveProjects, R2'deki `secrets/<project>/` öneklerinden proje adlarını çıkarır. */
export async function deriveProjects(bucket: R2Bucket): Promise<string[]> {
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const l = await bucket.list({ prefix: "secrets/", delimiter: "/", cursor });
    for (const p of l.delimitedPrefixes ?? []) {
      const m = p.match(/^secrets\/([^/]+)\/$/);
      if (m) seen.add(m[1]);
    }
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  return [...seen];
}
