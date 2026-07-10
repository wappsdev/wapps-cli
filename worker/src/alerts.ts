// Alert kuralları (SPEC §6.10) — hepsi Discord webhook'una (DISCORD_WEBHOOK_URL).
// v1 için 8 normatif kural. Alert teslimatı başarısızlığı ALTTAKİ operasyonu ASLA
// bloklamaz/düşürmez (alert = tespit, enforcement değil); başarısız post bir kez
// retry edilir ve audit'e `alert.failed` yazılır (§6.10). Bu dosyada Discord POST
// mekaniği + kural sabitleri var; kuralları tetikleyen yerler index/writer/admin.

import { AuditRow } from "./audit.js";

// 8 normatif kural (§6.10).
export const ALERT = {
  A1: "A1", // denial spike (≥10 deny / principal / 5dk)
  A2: "A2", // full-manifest blob-fetch burst (≥50 distinct blobs / 10dk)
  A3: "A3", // machine rotate_by (14 gün içinde / geçmiş)
  A4: "A4", // escrow push failure (G10 stub)
  A5: "A5", // witness stale / verification failure (G10 stub; Worker'ın kendi fetch'i)
  A6: "A6", // GC failure/skip (G10 stub)
  A7: "A7", // Worker version change (deploy-time)
  A8: "A8", // integrity/config anomaly (audit-DO down, misconfig, chain discontinuity, ingest backlog)
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
