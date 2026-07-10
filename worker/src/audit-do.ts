// Global audit-zinciri serileştiricisi (SPEC §6.5, F3). TEK instance
// (idFromName="__audit__") D1 `audit` tablosunun TEK yazarıdır: zincir head'ini
// (seq, hash) DO storage'da tutar, seq atar, hash hesaplar ve satırları tek tek
// insert eder. Zincir ÇATALLANMAZ çünkü tam olarak bir yazarı vardır.
//
// Chain rule (pinned): hash = hex(SHA-256(prev_hash_utf8 || 0x0A || row_json)),
// row_json = 12 alanın [seq,ts,principal,principal_type,project,key,verb,decision,
// intent,ip,cf_ray,token_jti] boşluksuz JSON dizisi (null = eksik).

import { sha256Hex, utf8 } from "./crypto/verify.js";
import { ensureSchema } from "./schema.js";
import { AuditRow, GENESIS_HASH } from "./audit.js";

interface DOEnv {
  AUDIT_DB: D1Database;
}

interface ChainHead {
  seq: number;
  hash: string;
}

const HEAD_KEY = "head";
const IDEM_PREFIX = "idem:";
const INGEST_TS_KEY = "ingest:lastTs";
const INGEST_COUNTER_KEY = "ingest:lastCounter";

export class AuditLogDO {
  private db: D1Database;
  // Basit async-mutex: append'ler kesinlikle serileşir (head fork'u imkânsız).
  private lock: Promise<unknown> = Promise.resolve();

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.db = env.AUDIT_DB;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/append" && request.method === "POST") {
        const { row, idempotencyKey } = (await request.json()) as { row: AuditRow; idempotencyKey?: string };
        const res = await this.runExclusive(() => this.appendOne(row, idempotencyKey));
        return json(res);
      }
      if (url.pathname === "/append-batch" && request.method === "POST") {
        const { rows, batchCounter } = (await request.json()) as { rows: AuditRow[]; batchCounter?: number };
        const res = await this.runExclusive(() => this.appendBatch(rows, batchCounter));
        return json(res);
      }
      if (url.pathname === "/head" && request.method === "GET") {
        return json(await this.head());
      }
      if (url.pathname === "/ingest-status" && request.method === "GET") {
        const lastTs = (await this.ctx.storage.get<string>(INGEST_TS_KEY)) ?? null;
        const lastCounter = (await this.ctx.storage.get<number>(INGEST_COUNTER_KEY)) ?? null;
        return json({ lastTs, lastCounter, ...(await this.head()) });
      }
      return json({ error: "NOT_FOUND" }, 404);
    } catch (e) {
      // Audit DO içi hata → 503; write-path bunu AUDIT_UNAVAILABLE'a çevirir.
      return json({ error: "AUDIT_DO_ERROR", message: String(e) }, 503);
    }
  }

  private async head(): Promise<ChainHead> {
    return (await this.ctx.storage.get<ChainHead>(HEAD_KEY)) ?? { seq: 0, hash: GENESIS_HASH };
  }

  /** appendOne, tek satırı zincire ekler; idempotencyKey varsa tekrar-insert etmez. */
  private async appendOne(row: AuditRow, idempotencyKey?: string): Promise<{ seq: number; hash: string; deduped?: boolean }> {
    await ensureSchema(this.db);
    if (idempotencyKey) {
      const existing = await this.ctx.storage.get<ChainHead>(IDEM_PREFIX + idempotencyKey);
      if (existing) return { seq: existing.seq, hash: existing.hash, deduped: true };
    }
    const head = await this.head();
    const inserted = await this.insertRow(head, row);
    await this.ctx.storage.put(HEAD_KEY, { seq: inserted.seq, hash: inserted.hash });
    if (idempotencyKey) await this.ctx.storage.put(IDEM_PREFIX + idempotencyKey, { seq: inserted.seq, hash: inserted.hash });
    return inserted;
  }

  private async appendBatch(rows: AuditRow[], batchCounter?: number): Promise<{ appended: number; seq: number; hash: string }> {
    await ensureSchema(this.db);
    let head = await this.head();
    for (const row of rows) {
      head = await this.insertRow(head, row);
    }
    await this.ctx.storage.put(HEAD_KEY, head);
    // Ingest-liveness (A8 backlog/silence, §6.5): son batch zamanı + sayaç.
    await this.ctx.storage.put(INGEST_TS_KEY, new Date().toISOString());
    if (typeof batchCounter === "number") await this.ctx.storage.put(INGEST_COUNTER_KEY, batchCounter);
    return { appended: rows.length, seq: head.seq, hash: head.hash };
  }

  /** insertRow, tek satırı hesaplar + D1'e yazar ve yeni head'i döner (storage GÜNCELLEMEZ). */
  private async insertRow(head: ChainHead, row: AuditRow): Promise<ChainHead> {
    const seq = head.seq + 1;
    const ts = row.ts ?? new Date().toISOString();
    // Sıra KATİ (§6.5 chain rule): 12 alan, null = eksik.
    const values: (string | number | null)[] = [
      seq,
      ts,
      row.principal,
      row.principal_type,
      row.project ?? null,
      row.key ?? null,
      row.verb,
      row.decision,
      row.intent ?? null,
      row.ip ?? null,
      row.cf_ray ?? null,
      row.token_jti ?? null,
    ];
    const rowJson = JSON.stringify(values); // boşluksuz (JSON.stringify default)
    const hash = sha256Hex(utf8(head.hash + "\n" + rowJson));
    await this.db
      .prepare(
        `INSERT INTO audit (seq, ts, principal, principal_type, project, key, verb, decision, intent, ip, cf_ray, token_jti, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(...values, head.hash, hash)
      .run();
    return { seq, hash };
  }

  /** runExclusive, append'leri sıkı serileştirir — head okuma-yazma yarışını önler. */
  private async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.lock;
    let release!: () => void;
    this.lock = new Promise<void>((r) => (release = r));
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
