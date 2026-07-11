// Escrow write-through to a NON-Cloudflare, object-locked B2 bucket (SPEC §6.8 /
// §9.2). Her ACCEPTED immutable obje (content-addressed blob + data manifest +
// append-only pointer event + audit segment) B2'ye S3 API üzerinden, append-only
// bir application key ile PUSH edilir. Anahtar YAZAR ama SİLEMEZ/ÜZERİNE YAZAMAZ:
// tam ele geçirilmiş bir Worker çöp EKLEYEBİLİR ama object-lock'lı geçmişi YOK
// EDEMEZ (§9.2.2). Doğrulama VM verifier'ındadır (§9.3).
//
// FAIL-SOFT (§6.2(d) / §9.2.4): B2 push HATASI kalıcı commit'i ASLA düşürmez —
// availability of B2 is NOT on the write path. Push, commit sonrası DO storage'a
// "pending-escrow" olarak kuyruklanır ve DO alarm'ıyla drene edilir (mevcut
// pending-pointer-event desenini yeniden kullanır); 3 denemeden sonra hâlâ
// başarısızsa alert A4 (§6.10) tetiklenir.
//
// F2 (§9.2.3): MUTABLE `current` pointer B2'ye ASLA yazılmaz (object-lock altında
// mutable key yeniden yazılamaz) — yalnızca immutable pointer EVENT'leri.

import { utf8, b64ToBytes, sha256, bytesToHex } from "./crypto/verify.js";

// --- B2 / S3 config -------------------------------------------------------

/** EscrowConfig, B2 S3-uyumlu escrow hedefinin Worker-secret yapılandırmasıdır. */
export interface EscrowConfig {
  endpoint: string; // ör. "s3.us-west-004.backblazeb2.com" (NON-Cloudflare)
  region: string; // ör. "us-west-004"
  bucket: string; // object-lock'lı escrow bucket (ör. "wapps-secrets-escrow")
  keyId: string; // append-only application key id (B2_KEY_ID)
  appKey: string; // append-only application key secret (B2_APP_KEY)
}

/** EscrowEnv, escrow config'in okunduğu env alt kümesidir (Worker secret'ları). */
export interface EscrowEnv {
  B2_ENDPOINT?: string;
  B2_REGION?: string;
  B2_BUCKET?: string;
  B2_KEY_ID?: string;
  B2_APP_KEY?: string;
}

/**
 * escrowConfig, env'den escrow config'i çözer. Herhangi bir alan eksikse null
 * döner (escrow YAPILANDIRILMAMIŞ → write-through devre dışı, fail-soft no-op).
 * Bu, B2 yapılandırılmadığı sürece mevcut testlerin escrow yoluna girmemesini sağlar.
 */
export function escrowConfig(env: EscrowEnv): EscrowConfig | null {
  const endpoint = (env.B2_ENDPOINT ?? "").trim();
  const region = (env.B2_REGION ?? "").trim();
  const bucket = (env.B2_BUCKET ?? "").trim();
  const keyId = (env.B2_KEY_ID ?? "").trim();
  const appKey = (env.B2_APP_KEY ?? "").trim();
  if (!endpoint || !region || !bucket || !keyId || !appKey) return null;
  return { endpoint, region, bucket, keyId, appKey };
}

// --- AWS SigV4 (S3 PUT) — küçük WebCrypto implementasyonu ------------------
//
// aws4fetch yerine bağımlılıksız minimal SigV4: Worker yalnızca PUT yapar
// (LIST/GET = VM verifier'ın işi, §9.3). Payload-hash imzalanır (x-amz-content-
// sha256 = hex(sha256(body))). Tek-chunk, streaming yok.

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key.buffer as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, data.buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

/** amzDates, ISO8601 basic (YYYYMMDDTHHMMSSZ) + datestamp (YYYYMMDD) döner. */
function amzDates(now: Date): { amzDate: string; dateStamp: string } {
  const iso = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // 20260709T120000Z
  return { amzDate: iso, dateStamp: iso.slice(0, 8) };
}

/** uriEncodePath, S3 canonical URI için her segmenti kodlar ('/' korunur). */
function uriEncodePath(path: string): string {
  return path
    .split("/")
    .map((seg) => encodeURIComponent(seg).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()))
    .join("/");
}

/**
 * putObject, tek bir immutable objeyi B2'ye SigV4-imzalı PUT ile yazar (path-style
 * https://<endpoint>/<bucket>/<key>). 2xx → başarı; aksi halde throw (fail-soft
 * çağıran kuyruğa alır). now enjekte edilebilir (test determinizmi).
 */
export async function putObject(
  cfg: EscrowConfig,
  key: string,
  body: Uint8Array,
  contentType: string,
  now: Date = new Date(),
): Promise<void> {
  const { amzDate, dateStamp } = amzDates(now);
  const host = cfg.endpoint;
  const canonicalUri = "/" + uriEncodePath(cfg.bucket + "/" + key);
  const payloadHash = bytesToHex(sha256(body));

  // Canonical headers (alfabetik, imzalananlar): host, x-amz-content-sha256, x-amz-date.
  const canonicalHeaders =
    `host:${host}\n` + `x-amz-content-sha256:${payloadHash}\n` + `x-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

  const canonicalRequest = ["PUT", canonicalUri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, bytesToHex(sha256(utf8(canonicalRequest)))].join("\n");

  // İmzalama anahtarı zinciri.
  const kDate = await hmac(utf8("AWS4" + cfg.appKey), utf8(dateStamp));
  const kRegion = await hmac(kDate, utf8(cfg.region));
  const kService = await hmac(kRegion, utf8("s3"));
  const kSigning = await hmac(kService, utf8("aws4_request"));
  const signature = bytesToHex(await hmac(kSigning, utf8(stringToSign)));

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${cfg.keyId}/${scope}, ` + `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const url = `https://${host}${canonicalUri}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: authorization,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": payloadHash,
      "content-type": contentType,
    },
    body: body.buffer as ArrayBuffer,
  });
  if (!res.ok) {
    throw new Error(`escrow putObject ${key}: HTTP ${res.status}`);
  }
}

/**
 * headObject, bir objenin escrow bucket'ında var olup olmadığını SigV4-imzalı
 * HEAD ile kontrol eder (§6.7 koşul c per-blob teyidi). Append-only B2 key silemez
 * ama OKUYABİLİR. 2xx → true, 404 → false, diğer hata → throw (çağıran güvenli
 * tarafta kalmalı: hata = "teyit edilemedi" = silme).
 */
export async function headObject(cfg: EscrowConfig, key: string, now: Date = new Date()): Promise<boolean> {
  const { amzDate, dateStamp } = amzDates(now);
  const host = cfg.endpoint;
  const canonicalUri = "/" + uriEncodePath(cfg.bucket + "/" + key);
  const emptyHash = bytesToHex(sha256(new Uint8Array(0)));
  const canonicalHeaders = `host:${host}\n` + `x-amz-content-sha256:${emptyHash}\n` + `x-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = ["HEAD", canonicalUri, "", canonicalHeaders, signedHeaders, emptyHash].join("\n");
  const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, bytesToHex(sha256(utf8(canonicalRequest)))].join("\n");
  const kDate = await hmac(utf8("AWS4" + cfg.appKey), utf8(dateStamp));
  const kRegion = await hmac(kDate, utf8(cfg.region));
  const kService = await hmac(kRegion, utf8("s3"));
  const kSigning = await hmac(kService, utf8("aws4_request"));
  const signature = bytesToHex(await hmac(kSigning, utf8(stringToSign)));
  const authorization = `AWS4-HMAC-SHA256 Credential=${cfg.keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const res = await fetch(`https://${host}${canonicalUri}`, {
    method: "HEAD",
    headers: { Authorization: authorization, "x-amz-date": amzDate, "x-amz-content-sha256": emptyHash },
  });
  if (res.ok) return true;
  if (res.status === 404) return false;
  throw new Error(`escrow headObject ${key}: HTTP ${res.status}`);
}

// --- Escrow obje anahtar düzeni (§9.2.3, R2 layout'u BİRE BİR mirror) -------

/** keyEscrowAuditSegment, tek bir audit satırının immutable escrow segment anahtarı. */
export function keyEscrowAuditSegment(seq: number): string {
  return `audit/segments/${seq}.json`;
}

// --- Pending-escrow kuyruğu (DO storage) + fail-soft drenajı ---------------

/** EscrowPushItem, B2'ye push edilecek tek bir immutable obje. */
export interface EscrowPushItem {
  b2Key: string; // B2'deki hedef anahtar (R2 ile birebir mirror)
  contentType: string;
  r2Key?: string; // set ise gövde SECRETS_BUCKET'tan (R2) okunur (immutable → güvenli)
  bodyB64?: string; // aksi halde satır-içi base64 gövde (ör. audit segment)
}

interface PendingEscrow {
  item: EscrowPushItem;
  attempts: number;
}

/** ESCROW alert callback'i (writer-do → deliverAlert, audit-do → düz Discord post). */
export type EscrowAlert = (rule: string, summary: string, detail?: Record<string, unknown>) => Promise<void>;

const PENDING_ESCROW_PREFIX = "pending-escrow-push:";
const ESCROW_RETRY_MS = 30_000;
const ESCROW_ALERT_AFTER = 3; // 3 denemeden sonra A4 (§6.8)

/**
 * enqueueEscrowPushes, verilen immutable objeleri DO storage'a "pending-escrow"
 * olarak kuyruklar ve bir drenaj alarm'ı zamanlar. Bu, commit'in KRİTİK
 * BÖLÜMÜNDE (blockConcurrencyWhile) çağrılır ama YALNIZCA yerel storage yazar —
 * B2 write path'te DEĞİLDİR (§9.2.4). Gerçek push alarm()'da olur.
 */
export async function enqueueEscrowPushes(storage: DurableObjectStorage, items: EscrowPushItem[]): Promise<void> {
  if (items.length === 0) return;
  for (const item of items) {
    const rec: PendingEscrow = { item, attempts: 0 };
    await storage.put(PENDING_ESCROW_PREFIX + item.b2Key, rec);
  }
  // Drenaj alarm'ı (pointer-event fail-soft deseniyle aynı gecikme). Anlık değil
  // ama RPO ≈ dakikalar (§9.2.4) içinde; gerçek push alarm()'da write-path DIŞINDA.
  await storage.setAlarm(Date.now() + ESCROW_RETRY_MS);
}

/**
 * drainEscrowPushes, bekleyen escrow push'larını B2'ye yazar (§6.8 retry).
 * Başarılı → marker silinir. Başarısız → attempts++, marker kalır; attempts
 * ESCROW_ALERT_AFTER'a ULAŞINCA alert A4 (bir kez). remaining>0 ise çağıran
 * yeniden alarm zamanlamalı. bucket, r2Key'li item'lar için gerekir (writer-do);
 * audit-do satır-içi bodyB64 kullanır (bucket gerekmez).
 *
 * @returns hâlâ bekleyen (drene edilemeyen) item sayısı.
 */
export async function drainEscrowPushes(
  storage: DurableObjectStorage,
  cfg: EscrowConfig | null,
  bucket: R2Bucket | null,
  alert: EscrowAlert,
): Promise<number> {
  const pending = await storage.list<PendingEscrow>({ prefix: PENDING_ESCROW_PREFIX });
  if (pending.size === 0) return 0;
  if (!cfg) {
    // Config kaybolmuş (deploy/rollback) → drene edemeyiz; bekletmeye devam.
    return pending.size;
  }
  let remaining = 0;
  for (const [storageKey, rec] of pending) {
    let body: Uint8Array | null = null;
    try {
      if (rec.item.r2Key) {
        if (!bucket) throw new Error("escrow drain: r2Key item but no bucket");
        const o = await bucket.get(rec.item.r2Key);
        if (!o) throw new Error(`escrow drain: source ${rec.item.r2Key} not in R2 yet`);
        body = new Uint8Array(await o.arrayBuffer());
      } else if (rec.item.bodyB64 !== undefined) {
        body = b64ToBytes(rec.item.bodyB64);
      } else {
        throw new Error("escrow drain: item has neither r2Key nor bodyB64");
      }
      await putObject(cfg, rec.item.b2Key, body, rec.item.contentType);
      await storage.delete(storageKey);
    } catch (err) {
      remaining++;
      const attempts = rec.attempts + 1;
      await storage.put(storageKey, { item: rec.item, attempts });
      if (attempts === ESCROW_ALERT_AFTER) {
        await alert("A4", `escrow push failing after ${attempts} attempts`, { key: rec.item.b2Key }).catch(() => {});
      }
      console.error(`escrow: push retry still failing (${storageKey}, attempt ${attempts})`, err);
    }
  }
  return remaining;
}

/** escrowRetryMs, drenaj alarm'ının yeniden zamanlama gecikmesi. */
export const escrowRetryMs = ESCROW_RETRY_MS;

/** pendingEscrowCount, test/gözlem için bekleyen escrow item sayısını döner. */
export async function pendingEscrowCount(storage: DurableObjectStorage): Promise<number> {
  const pending = await storage.list({ prefix: PENDING_ESCROW_PREFIX });
  return pending.size;
}
