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

/** AUDIT_FIELD_MAX caps every text field of an audit row (UTF-16 code units). The
 * audit DO refuses a longer field with 400 before any write; edge handlers check
 * caller-supplied text (X-Wapps-Intent, rotate-plan identity) against it first. */
export const AUDIT_FIELD_MAX = 512;

/** AuditAppendError is a refused or failed append. 400 (ROW_INVALID) and 409
 * (IDEMPOTENCY_MISMATCH) = the DO refused it on purpose: a retry with the same input
 * cannot succeed. */
export class AuditAppendError extends Error {
  constructor(
    route: string,
    readonly status: number,
  ) {
    super(`audit ${route} failed: ${status}`);
  }
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
  if (!res.ok) throw new AuditAppendError("append", res.status);
  return (await res.json()) as AppendResult;
}

/**
 * auditAppendBatch appends many rows in ONE exclusive turn: the per-key rows of a
 * bulk op get one chain append, one ack, one DO round trip (§6.4). With an
 * idempotencyKey (e.g. the commit outcome `project:epoch:manifestSha`) the DO dedups
 * the whole batch for good (a crash-recovery retry does not double the rows). A
 * requestId dedups only for a short time: it covers the worker→DO retries of one
 * call. batchCounter is for ingest liveness (A8 backlog/silence). Throws
 * AuditAppendError.
 */
export async function auditAppendBatch(
  ns: DurableObjectNamespace,
  rows: AuditRow[],
  opts?: { batchCounter?: number; idempotencyKey?: string; requestId?: string },
): Promise<void> {
  if (rows.length === 0) return;
  const res = await doStubFetch(makeAuditStub(ns), "https://audit/append-batch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rows, batchCounter: opts?.batchCounter, idempotencyKey: opts?.idempotencyKey, requestId: opts?.requestId }),
  });
  if (!res.ok) throw new AuditAppendError("append-batch", res.status);
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
