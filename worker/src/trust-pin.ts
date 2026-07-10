// Worker-tarafı MONOTONİK last-verified trust pin aynası (SPEC §4.4 + §4.8).
//
// §4.4: "The Worker maintains its own monotonic last-verified pin in Durable
// Object storage and enforces the identical rules on the write path." Burada
// bunu D1'de TEK satırlık (`trust_pin`) bir aynayla gerçekliyoruz — Go istemcinin
// roots.json `last_verified` yüksek-su-işareti ile parite (pinnedLast).
//
// KRİTİK: pin ASLA AZALMAZ (monotonluk). loadTrustHead, getirilen zinciri
// pinlenmiş genesis'e (parse öncesi hash) VE bu kalıcı last-verified'a karşı
// doğrular; kalıcı head'in ALTINA bir rollback TRUST_DOWNGRADE ile reddedilir
// (§4.5 downgrade, §4.8 reset-rollback-aklama koruması). Fail-closed.

import { ensureSchema } from "./schema.js";
import { Pin } from "./trust.js";

interface PinRow {
  admin_epoch: number;
  trust_sha256: string;
}

/**
 * loadLastVerifiedPin, D1'deki tek-satırlık last-verified pin'i okur. Satır yoksa
 * veya (savunma amaçlı) kayıtlı epoch genesis'in ALTINDAysa, genesis taban-değeri
 * döner — genesis her zaman doğrulanmış zemin katıdır. Böylece downgrade yüksek-su
 * işareti hiçbir zaman genesis'in altına düşmez.
 */
export async function loadLastVerifiedPin(db: D1Database, genesis: Pin): Promise<Pin> {
  await ensureSchema(db);
  const row = await db.prepare("SELECT admin_epoch, trust_sha256 FROM trust_pin WHERE id = 1").first<PinRow>();
  if (!row || !Number.isInteger(row.admin_epoch) || row.admin_epoch < genesis.admin_epoch || typeof row.trust_sha256 !== "string") {
    return genesis;
  }
  return { admin_epoch: row.admin_epoch, sha256: row.trust_sha256 };
}

/**
 * persistLastVerifiedPin, doğrulanmış head'i last-verified pin olarak KALICILAŞTIRIR.
 * Monotonluk SQL seviyesinde atomik yaptırılır: `ON CONFLICT ... WHERE excluded >
 * mevcut` → yalnızca admin_epoch KATİ artışında yazar; eşit veya düşük epoch ASLA
 * mevcut satırı ezmez (eşit-epoch fork sha'sı da korunur → checkPinPassthrough). Bu,
 * eşzamanlı istekler arasında read-modify-write yarışına da bağışıktır.
 */
export async function persistLastVerifiedPin(db: D1Database, pin: Pin): Promise<void> {
  await ensureSchema(db);
  await db
    .prepare(
      `INSERT INTO trust_pin (id, admin_epoch, trust_sha256) VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET admin_epoch = excluded.admin_epoch, trust_sha256 = excluded.trust_sha256
       WHERE excluded.admin_epoch > trust_pin.admin_epoch`,
    )
    .bind(pin.admin_epoch, pin.sha256)
    .run();
}
