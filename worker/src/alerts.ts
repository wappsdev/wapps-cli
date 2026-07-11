// Alert kuralları (SPEC §0.1 mutabık envanter) — hepsi Discord webhook'una
// (DISCORD_WEBHOOK_URL). Alert teslimatı başarısızlığı ALTTAKİ operasyonu ASLA
// bloklamaz/düşürmez (alert = tespit, enforcement değil); başarısız post bir kez
// retry edilir ve audit'e `alert.failed` yazılır. Kuralları tetikleyen yerler
// index/writer/gc/identity. Bu liste EKSİKSİZDİR; başka kural yaşamaz (§0.1).

import { AuditRow } from "./audit.js";

export const ALERT = {
  A1: "A1", // denial spike (GRANT_DENIED/deny-row burst — policy-deny modelinin birincil erken uyarısı)
  A2: "A2", // value-read burst (value.read/value.read.bulk satır patlaması / principal)
  A3: "A3", // service-token rotasyon hatırlatması (90 gün; doctor + CF expires_at)
  A4: "A4", // escrow/replika backlog (§8.3)
  A7: "A7", // Worker versiyon değişimi (deploy-time; C1)
  A8: "A8", // misconfig / audit-down / GC anomalisi (fail-closed yol sinyali)
  A9: "A9", // policy değişimi (§4.1 — her policy PUT)
  A10: "A10", // identity-endpoint şekil kayması (§3.2 adım 2 / §3.4)
} as const;
export type AlertRule = (typeof ALERT)[keyof typeof ALERT];

export interface AlertEnv {
  DISCORD_WEBHOOK_URL?: string;
  AUDIT_LOG: DurableObjectNamespace;
}

/**
 * fireAlert, bir alert'i Discord'a POST eder (best-effort). ASLA throw etmez ve
 * çağıranı bloklamaz — waitUntil ile arka planda gönderilir. Başarısız post bir kez
 * retry edilir; hâlâ başarısızsa audit'e `alert.failed` yazılır (§6.10).
 */
export function fireAlert(ctx: ExecutionContext, env: AlertEnv, rule: AlertRule, summary: string, detail?: Record<string, unknown>): void {
  ctx.waitUntil(deliverAlert(env, rule, summary, detail));
}

/** deliverAlert, senkron await'lenebilir teslimat (test + waitUntil ortak yolu). */
export async function deliverAlert(env: AlertEnv, rule: AlertRule, summary: string, detail?: Record<string, unknown>): Promise<void> {
  const url = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  if (!url) return; // webhook yoksa sessiz no-op (alert enforcement değildir)
  const content = `[secrets-gate ${rule}] ${summary}`;
  const body = JSON.stringify({ content, embeds: detail ? [{ description: "```" + JSON.stringify(detail).slice(0, 1500) + "```" }] : undefined });
  let ok = await post(url, body);
  if (!ok) ok = await post(url, body); // bir kez retry
  if (!ok) {
    // Teslimat kalıcı başarısız → audit'e alert.failed (best-effort, read-path async değil
    // ama alert yolu; sync değil — çağıranı bloklamamak için batch API).
    const row: AuditRow = { principal: "worker", principal_type: "worker", verb: "alert.failed", decision: "allow", intent: `${rule}:${summary}`.slice(0, 200) };
    try {
      await env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName("__audit__")).fetch("https://audit/append-batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ rows: [row] }),
      });
    } catch {
      // audit da erişilemezse yapacak bir şey yok (alert = tespit).
    }
  }
}

async function post(url: string, body: string): Promise<boolean> {
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    return res.ok;
  } catch {
    return false;
  }
}
