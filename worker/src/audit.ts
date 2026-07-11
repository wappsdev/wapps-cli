// Audit ledger çağıran-tarafı yardımcıları (SPEC §6.5). TÜM append'ler TEK global
// AuditLogDO'dan (idFromName="__audit__") geçer — o D1 `audit` tablosunun tek
// yazarıdır. Write-path/control-plane append'leri SENKRON'dur (attempt→outcome
// sırası, §6.2); read-path append'leri ASENKRON best-effort'tur (waitUntil,
// sınırlı-kayıp caveat R18). Bu dosya yalnızca DO'ya RPC yapar; zincir mantığı DO'da.

import { doStubFetch } from "./do-util.js";

export const AUDIT_DO_NAME = "__audit__";
export const GENESIS_HASH = "0".repeat(64);

export type Decision = "allow" | "deny";
export type PrincipalType = "human" | "machine" | "worker";

/** AuditRow, bir audit satırının çağıran-tarafı şekli (seq/prev/hash DO'da atanır). */
export interface AuditRow {
  ts?: string; // RFC3339; verilmezse DO now() atar
  principal: string;
  principal_type: PrincipalType;
  project?: string | null;
  key?: string | null;
  verb: string;
  decision: Decision;
  intent?: string | null;
  ip?: string | null;
  cf_ray?: string | null;
  token_jti?: string | null;
}

export interface AppendResult {
  seq: number;
  hash: string;
  deduped?: boolean;
}

function makeAuditStub(ns: DurableObjectNamespace): () => DurableObjectStub {
  return () => ns.get(ns.idFromName(AUDIT_DO_NAME));
}

/**
 * auditAppendSync, TEK satırı SENKRON append eder (write-path/control-plane).
 * DO erişilemezse THROW eder → çağıran commit'i 503 AUDIT_UNAVAILABLE ile fail-close
 * eder (§6.2 step 12). idempotencyKey verilirse (örn. commit outcome `project:epoch`)
 * DO tekrar-insert etmez; recovery marker (§6.2 case c) budur.
 */
export async function auditAppendSync(ns: DurableObjectNamespace, row: AuditRow, idempotencyKey?: string): Promise<AppendResult> {
  const res = await doStubFetch(makeAuditStub(ns), "https://audit/append", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ row, idempotencyKey }),
  });
  if (!res.ok) throw new Error(`audit append failed: ${res.status}`);
  return (await res.json()) as AppendResult;
}

/**
 * auditAppendBatch, birden çok satırı tek exclusive turda append eder (read-path
 * batch flush). batchCounter ingest-liveness için (A8 backlog/silence, §6.5).
 */
export async function auditAppendBatch(ns: DurableObjectNamespace, rows: AuditRow[], batchCounter?: number): Promise<void> {
  if (rows.length === 0) return;
  const res = await doStubFetch(makeAuditStub(ns), "https://audit/append-batch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rows, batchCounter }),
  });
  if (!res.ok) throw new Error(`audit append-batch failed: ${res.status}`);
}

/**
 * auditReadAsync, read-path bir satırını ASENKRON best-effort append eder
 * (waitUntil; isolate flush öncesi ölürse satır kaybolur — R18 caveat, §6.5).
 * ASLA istek yanıtını bloklamaz; hata yutulur.
 */
export function auditReadAsync(ctx: ExecutionContext, ns: DurableObjectNamespace, row: AuditRow): void {
  ctx.waitUntil(auditAppendBatch(ns, [row]).catch(() => {}));
}

/** ipOf/rayOf, isteğin CF meta header'larını çıkarır (audit ip/cf_ray). */
export function ipOf(request: Request): string | null {
  return request.headers.get("cf-connecting-ip");
}
export function rayOf(request: Request): string | null {
  return request.headers.get("cf-ray");
}
