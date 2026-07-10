// Trust head yükleme (R2'den zincir yürüyüşü + M-of-N doğrulama) — DO commit ve
// Worker blob-PUT grant kontrolü ortak kullanır. Otoritatif kaynak imzalı trust
// manifest'idir (§4). Getirilen zincir HEM pinlenmiş genesis'e (parse öncesi hash)
// HEM de D1'deki MONOTONİK last-verified pin'e (§4.4 yüksek-su-işareti) karşı
// doğrulanır → kalıcı head'in altına rollback TRUST_DOWNGRADE ile reddedilir.

import { parseSignedObject, newVerifierKey, b64ToBytes, VerifierKey } from "./crypto/verify.js";
import { keyTrustCurrent, keyTrustManifest, getObject } from "./storage.js";
import { TrustManifest, VerifiedEpoch, verifyRosterChain, Pin, TrustError } from "./trust.js";
import { loadLastVerifiedPin, persistLastVerifiedPin } from "./trust-pin.js";

/**
 * loadTrustHead, trust/current'ı okur, genesis→head zincirini R2'den yürütür ve
 * M-of-N doğrulanmış head'i döner (§4.5). genesisSha256 pinlenmiş genesis payload
 * hash'idir (Worker config GENESIS_TRUST_SHA256). Doğrulanamazsa TrustError
 * (çağıran 503 SERVICE_MISCONFIGURED'e eşler — §6.2 step 3).
 *
 * db verilirse (AUDIT_DB): getirilen zincir, D1'deki kalıcı last-verified pin'e
 * karşı da yaptırılır (downgrade tavanı, §4.4). Doğrulama başarılı olduktan sonra
 * head MONOTONİK olarak kalıcılaştırılır (yalnızca ileri; asla azalmaz). db yoksa
 * geriye dönük davranış korunur (yalnızca genesis'e karşı doğrulama).
 */
export async function loadTrustHead(bucket: R2Bucket, genesisSha256: string, db?: D1Database): Promise<VerifiedEpoch> {
  if (!genesisSha256) throw new TrustError("SERVICE_MISCONFIGURED", "no genesis pin configured");
  const cur = await getObject(bucket, keyTrustCurrent());
  if (!cur) throw new TrustError("SERVICE_MISCONFIGURED", "trust/current missing");
  let adminEpoch: number;
  let trustSha: string | undefined;
  try {
    const doc = JSON.parse(new TextDecoder().decode(cur.bytes)) as { admin_epoch?: unknown; trustSha256?: unknown };
    if (typeof doc.admin_epoch !== "number" || !Number.isInteger(doc.admin_epoch) || doc.admin_epoch < 1) {
      throw new Error("bad admin_epoch");
    }
    adminEpoch = doc.admin_epoch;
    if (typeof doc.trustSha256 === "string") trustSha = doc.trustSha256;
  } catch {
    throw new TrustError("SERVICE_MISCONFIGURED", "trust/current malformed");
  }

  const chain = [];
  for (let e = 1; e <= adminEpoch; e++) {
    const o = await getObject(bucket, keyTrustManifest(e));
    if (!o) throw new TrustError("SERVICE_MISCONFIGURED", `trust manifest ${e} missing (chain gap)`);
    chain.push(parseSignedObject(JSON.parse(new TextDecoder().decode(o.bytes))));
  }

  const pinnedGenesis: Pin = { admin_epoch: 1, sha256: genesisSha256 };
  // pinnedLast = kalıcı MONOTONİK last-verified pin (§4.4). D1 yoksa (veya kayıt
  // yoksa) genesis taban-değeri → yalnızca genesis'e karşı doğrulama (geriye dönük).
  // GENESIS'İ İKİ pin OLARAK kullanma artçısı burada kapanır: last-verified ARTIK
  // gerçek yüksek-su-işaretidir, genesis DEĞİL.
  const pinnedLast: Pin = db ? await loadLastVerifiedPin(db, pinnedGenesis) : pinnedGenesis;
  const head = verifyRosterChain(pinnedGenesis, pinnedLast, chain, null);

  // trust/current, doğrulanmış head'i işaret etmeli (locator tutarlılığı).
  if (trustSha !== undefined && trustSha !== head.bytesSHA256) {
    throw new TrustError("SERVICE_MISCONFIGURED", "trust/current points to a different epoch than the verified head");
  }

  // Doğrulanmış head'i MONOTONİK olarak kalıcılaştır (yalnızca ileri epoch'ta yazar;
  // eşit/düşük ASLA ezmez — SQL guard). Böylece bir sonraki yükleme daha yüksek
  // tavanla gelir ve altına rollback reddedilir.
  if (db && head.manifest.admin_epoch > pinnedLast.admin_epoch) {
    await persistLastVerifiedPin(db, { admin_epoch: head.manifest.admin_epoch, sha256: head.bytesSHA256 });
  }
  return head;
}

/**
 * dataWriterKeyring, doğrulanmış trust head'inden data-manifest yazar-doğrulama
 * keyring'ini kurar: her AKTİF kimliğin her AKTİF imzalama anahtarı → VerifierKey
 * (key_id → vk). verifyDataManifest bunu kullanır (§5.4.1/§6.2).
 */
export function dataWriterKeyring(m: TrustManifest): Map<string, VerifierKey> {
  const ring = new Map<string, VerifierKey>();
  for (const id of m.identities) {
    if (id.status === "revoked") continue;
    for (const sk of id.signing_keys) {
      if (sk.status !== "active") continue;
      try {
        const vk = newVerifierKey(sk.alg, b64ToBytes(sk.pubkey));
        ring.set(vk.keyID, vk);
      } catch {
        // Kapalı-küme dışı / bozuk anahtar → keyring'e alınmaz (fail-closed).
      }
    }
  }
  return ring;
}
