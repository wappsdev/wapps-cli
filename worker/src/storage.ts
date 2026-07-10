// R2 obje namespace'i + read-path yardımcıları (SPEC §5.2/§5.5). Okuma yolu
// DO-free'dir (§5.5 rule 5): manifest/blob/pointer doğrudan Worker'dan R2'ye.

// --- Anahtar düzeni (§5.2) -------------------------------------------------

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
  // Escrow tarafı append-only pointer-event akışı (§9.2.3 / F2).
  return `pointer-events/${project}/${epoch}.json`;
}
export function keyTrustManifest(epoch: number): string {
  return `trust/manifests/${epoch}.json`;
}
export function keyTrustCurrent(): string {
  return `trust/current`;
}

// --- Proje / anahtar-adı doğrulama (§5.2 rule 1, §5.4.3 rule 1) -------------

const PROJECT_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const KEYNAME_RE = /^[A-Z][A-Z0-9_]{0,127}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export function validProject(p: string): boolean {
  return PROJECT_RE.test(p);
}
export function validKeyName(k: string): boolean {
  return KEYNAME_RE.test(k);
}
export function validSha256Hex(h: string): boolean {
  return SHA256_HEX_RE.test(h);
}

// --- R2 read yardımcıları --------------------------------------------------

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
