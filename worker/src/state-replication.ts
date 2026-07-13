// tofu state → B2 replikasyonu (arch §5.2 — "ucuz aynı-hesap sigortası").
// SAF runner: scheduling BURADA YOK — çağıran (scheduled() nightly branch /
// P2.4 SchedulerDO) tetikler. Mevcut escrow SigV4 makinesi yeniden kullanılır
// (escrowConfig/putObject/headObject).
//
// DÜRÜST KAPSAM (§5.2): bu replikasyon YALNIZCA same-account state loss /
// corruption'a karşı korur; F5'te (full CF-account-loss) eski state zaten işe
// yaramaz — resource ID'leri yeni hesapta anlamsız. RPO ≤24h kabul edilmiştir:
// cron write path'in DIŞINDADIR, DO/pending-queue YOK.
//
// GÜVENLİK NOTU: state client-side pbkdf2-AES-GCM ciphertext'idir — Worker'ın
// STATE_BUCKET'ı okuyabilmesi blast radius'u yalnızca marjinal büyütür (§5.2
// kabulü). R2 binding'leri read-write olduğundan append-only B2 kopyaları
// corruption backstop'udur: B2 object-lock altında sabit bir anahtar ASLA
// yeniden yazılamaz → anahtarlar content-addressed'tır.

import { utf8, sha256Hex } from "./crypto/encoding.js";
import { escrowConfig, putObject, headObject, EscrowEnv } from "./escrow.js";

/** StateReplicationEnv, runner'ın ihtiyaç duyduğu env alt kümesi (B2 + binding). */
export interface StateReplicationEnv extends EscrowEnv {
  STATE_BUCKET?: R2Bucket; // wapps-tofu-state (yalnızca PROD wrangler.jsonc, P2.2)
}

/** StateReplicationAlert, hata bildirimi callback'i (çağıran A4'e bağlar). */
export type StateReplicationAlert = (summary: string, detail?: Record<string, unknown>) => void;

/**
 * keyStateSnapshot, content-addressed B2 snapshot anahtarı: aynı içerik → aynı
 * anahtar → object-lock'la çakışma imkânsız; içerik değişince yeni anahtar.
 */
export function keyStateSnapshot(r2Key: string, sha256HexStr: string): string {
  return `tofu-state/${r2Key}/${sha256HexStr}`;
}

/** keyStateSnapshotEvent, immutable snapshot event'inin B2 anahtarı (ts-addressed). */
export function keyStateSnapshotEvent(r2Key: string, isoTs: string): string {
  return `tofu-state-events/${r2Key}/${isoTs}.json`;
}

/**
 * runStateReplication, STATE_BUCKET'taki her `*.tfstate` objesini append-only
 * B2'ye content-addressed kopyalar + immutable `wapps.state-snapshot.v1`
 * event'i yazar. İdempotent: snapshot zaten B2'deyse (headObject 2xx) atlanır.
 * B2 config'i VEYA binding eksikse SESSİZ no-op (staging-safe; prod'da B2_*
 * bugün boş placeholder → dormant merge). Obje-başına hata → alert (çağıran
 * A4'e bağlar) + kalan objelerle devam; asla throw etmez.
 */
export async function runStateReplication(
  env: StateReplicationEnv,
  alert: StateReplicationAlert,
  now: Date = new Date(),
): Promise<void> {
  const cfg = escrowConfig(env);
  const bucket = env.STATE_BUCKET;
  if (!cfg || !bucket) return; // yapılandırılmamış → sessiz no-op (fail-soft)

  // 1) Tüm *.tfstate anahtarlarını topla (cursor'lı sayfalama — gc.ts deseni).
  const stateKeys: string[] = [];
  try {
    let cursor: string | undefined;
    do {
      const l = await bucket.list({ cursor });
      for (const o of l.objects) {
        if (o.key.endsWith(".tfstate")) stateKeys.push(o.key);
      }
      cursor = l.truncated ? l.cursor : undefined;
    } while (cursor);
  } catch (e) {
    alert("state replication: STATE_BUCKET list failed", { error: String(e) });
    return;
  }

  // 2) Her state için: sha256 → content-addressed anahtar → HEAD-skip → PUT.
  for (const r2Key of stateKeys) {
    try {
      const obj = await bucket.get(r2Key);
      if (!obj) continue; // list ile get arasında kaybolmuş → atla
      const body = new Uint8Array(await obj.arrayBuffer());
      const sha = sha256Hex(body);
      const snapKey = keyStateSnapshot(r2Key, sha);

      // İçerik değişmemişse snapshot B2'de zaten var → idempotent skip.
      if (await headObject(cfg, snapKey, now)) continue;

      await putObject(cfg, snapKey, body, "application/octet-stream", now);

      // Immutable event: hangi state, hangi hash, ne zaman (append-only iz).
      const ts = now.toISOString();
      const event = utf8(
        JSON.stringify({ schema: "wapps.state-snapshot.v1", r2_key: r2Key, sha256: sha, size: body.length, ts }),
      );
      await putObject(cfg, keyStateSnapshotEvent(r2Key, ts), event, "application/json", now);
    } catch (e) {
      // Fail-soft: tek objenin hatası diğerlerini durdurmaz; çağıran A4 fire eder.
      alert(`state replication: push failed for ${r2Key}`, { key: r2Key, error: String(e) });
    }
  }
}
