// R2 obje namespace'i + read-path yardımcıları (SPEC §2.6/§4.1). Okuma yolu
// DO-free'dir; manifest/blob/pointer doğrudan Worker'dan R2'ye. v2 delta: trust/*
// anahtarları SİLİNDİ (§0.2); policy/* anahtarları EKLENDİ (§4.1).

// --- Key layout ----------------------------------------------------------------
//
// A store name is a project (`vaulter`) or a shared id (`apple/asc`). Every R2 key
// below goes through storeSegment, the ONE place that maps a name to its prefix:
// a shared id becomes `<ns>~<name>` (`~` is in neither grammar), a project name is
// unchanged. deriveProjects is the one place that maps a prefix back.

/** storeSegment encodes a store name as one R2 path segment. It throws on a name
 * that could alias another prefix: a `/` that is not a valid shared id, or any `~`. */
function storeSegment(name: string): string {
  if (name.includes("/")) {
    if (!validSharedId(name)) throw new Error("invalid store name: malformed shared id");
    return name.replace("/", "~");
  }
  if (name.includes("~")) throw new Error("invalid store name: `~` is reserved for shared ids");
  return name;
}

/** decodeStoreSegment maps an R2 path segment back to its store name; null for a
 * `~` segment that is not a valid shared id (no route can create one). */
function decodeStoreSegment(seg: string): string | null {
  if (!seg.includes("~")) return seg;
  const id = seg.split("~").join("/");
  return validSharedId(id) ? id : null;
}

export function keyBlob(project: string, sha256: string): string {
  return `secrets/${storeSegment(project)}/blobs/${sha256}`;
}
export function keyManifest(project: string, epoch: number): string {
  return `secrets/${storeSegment(project)}/manifests/${epoch}.json`;
}
export function keyCurrent(project: string): string {
  return `secrets/${storeSegment(project)}/current`;
}
export function keyPointerEvent(project: string, epoch: number): string {
  // Append-only pointer-event stream on the escrow side (§8.3).
  return `pointer-events/${storeSegment(project)}/${epoch}.json`;
}
export function keyPolicyCurrent(): string {
  return `policy/current`;
}
export function keyPolicyVersion(n: number): string {
  return `policy/versions/${n}.json`;
}

// --- Proje / anahtar-adı doğrulama -------------------------------------------

const PROJECT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
// Shared id: `<namespace>/<name>`, exactly one `/`. The namespace is the issuer of
// the credential (`apple`), never a consumer.
const SHARED_ID_RE = /^[a-z0-9][a-z0-9-]{0,30}\/[a-z0-9][a-z0-9-]{0,30}$/;
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
export function validSharedId(id: string): boolean {
  return SHARED_ID_RE.test(id);
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
/** RESPONSE_MAX, tek bir bulk read yanıtının serileştirilmiş üst sınırı — Worker isolate
 *  belleğini (128 MB) korur (chunked-stream ciphertext'i zaten bantlar; bu, biriken
 *  plaintext yanıtını bantlar). İstemci transport limiti (16<<20) ile HİZALIDIR: kabul
 *  edilen her yanıt istemcice okunabilir. Bunu aşan PATOLOJİK-büyük bir read-all 413
 *  RESPONSE_TOO_LARGE alır (gerçek sır projeleri « bu sınır; OOM yerine temiz hata). */
export const RESPONSE_MAX = 16 * 1024 * 1024;

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

/** R2 batch-delete üst sınırı (tek `bucket.delete(keys[])` çağrısı). */
const DELETE_BATCH = 1000;
/** Silme turu üst sınırı (~1M obje) — ilerlemeyen döngüye karşı emniyet. */
const DELETE_MAX_ROUNDS = 1000;

/**
 * deleteProjectObjects, bir projenin TÜM veri objelerini siler (`secrets/<p>/`:
 * blob'lar + manifest'ler + current pointer) ve silinen obje sayısını döner.
 *
 * `pointer-events/<p>/` KASITLI OLARAK BIRAKILIR: o akış append-only escrow/DR
 * kaydıdır (§8.3) — audit defteri gibi, projenin var olduğunun kanıtı. Silinmesi
 * "hiç olmamış gibi" bir geçmiş üretirdi; bu sistemin tamper-evident sözleşmesine
 * aykırı. GC (gc.ts) yetim pointer-event'leri kendi politikasıyla ele alır.
 *
 * Epoch sıfırlaması BEDAVA gelir: writer DO epoch'u DO storage'ında DEĞİL, R2
 * `current` pointer'ında tutar — pointer gidince aynı adla yeniden yazılan proje
 * temiz bir şekilde epoch 1'den başlar.
 */
export async function deleteProjectObjects(bucket: R2Bucket, project: string): Promise<number> {
  // The trailing `/` keeps `apple` from matching `apple~asc` or `apple-asc`.
  const prefix = `secrets/${storeSegment(project)}/`;
  let deleted = 0;
  // Cursor KULLANILMAZ: sildikçe listeyi baştan tazeliyoruz — bir cursor,
  // altından objeler silinince zaten geçersizleşir. Her tur bir sayfa (≤1000)
  // götürür; boş sayfa gelince iş bitmiştir.
  for (let round = 0; round < DELETE_MAX_ROUNDS; round++) {
    const l = await bucket.list({ prefix });
    if (l.objects.length === 0) return deleted;
    const keys = l.objects.map((o) => o.key);
    for (let i = 0; i < keys.length; i += DELETE_BATCH) {
      await bucket.delete(keys.slice(i, i + DELETE_BATCH));
    }
    deleted += keys.length;
  }
  // Bir tur boş sayfa döndürmediyse silme ilerlemiyor demektir (R2 sessiz hata
  // veya eşzamanlı yazım seli): sonsuz döngü yerine gürültülü hata.
  throw new Error(`deleteProjectObjects(${project}): not converging after ${DELETE_MAX_ROUNDS} rounds`);
}

/** deriveProjects returns every store name with data in R2 (`secrets/<segment>/`):
 * project names and decoded shared ids. GC, rewrap, rotate-plan and the project
 * list iterate it, so shared secrets are covered with no second code path. */
export async function deriveProjects(bucket: R2Bucket): Promise<string[]> {
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const l = await bucket.list({ prefix: "secrets/", delimiter: "/", cursor });
    for (const p of l.delimitedPrefixes ?? []) {
      const m = p.match(/^secrets\/([^/]+)\/$/);
      const name = m ? decodeStoreSegment(m[1]) : null;
      if (name !== null) seen.add(name);
    }
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  return [...seen];
}
