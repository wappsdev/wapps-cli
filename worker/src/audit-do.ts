// Global audit-zinciri serileştiricisi (SPEC §6.5, F3). TEK instance
// (idFromName="__audit__") D1 `audit` tablosunun TEK yazarıdır: zincir head'ini
// (seq, hash) DO storage'da tutar, seq atar, hash hesaplar ve satırları tek tek
// insert eder. Zincir ÇATALLANMAZ çünkü tam olarak bir yazarı vardır.
//
// Chain rule (pinned): hash = hex(SHA-256(prev_hash_utf8 || 0x0A || row_json)),
// row_json = 12 alanın [seq,ts,principal,principal_type,project,key,verb,decision,
// intent,ip,cf_ray,token_jti] boşluksuz JSON dizisi (null = eksik).

import { sha256Hex, utf8, bytesToB64 } from "./crypto/verify.js";
import { ensureSchema } from "./schema.js";
import { AuditRow, GENESIS_HASH } from "./audit.js";
import {
  EscrowConfig,
  EscrowEnv,
  escrowConfig,
  enqueueEscrowPushes,
  drainEscrowPushes,
  keyEscrowAuditSegment,
  escrowRetryMs,
  EscrowAlert,
} from "./escrow.js";

interface DOEnv extends EscrowEnv {
  AUDIT_DB: D1Database;
  // §6.8: audit segment'leri de B2'ye write-through edilir (fail-soft).
  DISCORD_WEBHOOK_URL?: string;
}

interface ChainHead {
  seq: number;
  hash: string;
}

/** insertedRow, insertRow'un ürettiği zincir+escrow-segment materyalidir. */
interface insertedRow {
  seq: number;
  hash: string;
  prevHash: string;
  rowJson: string;
}

const HEAD_KEY = "head";
const IDEM_PREFIX = "idem:";
const INGEST_TS_KEY = "ingest:lastTs";
const INGEST_COUNTER_KEY = "ingest:lastCounter";

export class AuditLogDO {
  private db: D1Database;
  // Basit async-mutex: append'ler kesinlikle serileşir (head fork'u imkânsız).
  private lock: Promise<unknown> = Promise.resolve();
  // §6.8 escrow write-through: audit segment'leri B2'ye push edilir (fail-soft).
  private escrow: EscrowConfig | null;
  private discordUrl: string;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.db = env.AUDIT_DB;
    this.escrow = escrowConfig(env);
    this.discordUrl = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  }

  /** escrowAlert, audit-do escrow push başarısızlığında A4'ü doğrudan Discord'a
   * gönderir (audit DO kendisi olduğu için alert.failed audit fallback'i yoktur). */
  private escrowAlert: EscrowAlert = async (rule, summary, detail) => {
    const url = this.discordUrl;
    if (!url) return;
    const content = `[secrets-gate ${rule}] ${summary}`;
    const body = JSON.stringify({ content, embeds: detail ? [{ description: "```" + JSON.stringify(detail).slice(0, 1500) + "```" }] : undefined });
    try {
      await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    } catch {
      /* alert = tespit; teslimat hatası operasyonu bloklamaz */
    }
  };

  /** enqueueAuditSegment, tek bir audit satırını immutable escrow segment'i olarak
   * kuyruklar (§6.8). Segment = zincir doğrulaması için gereken TAM materyal:
   * {seq, prev_hash, row_json, hash}. B2 yapılandırılmamışsa no-op. */
  private async enqueueAuditSegment(r: insertedRow): Promise<void> {
    if (!this.escrow) return;
    const segmentBody = JSON.stringify({ schema: "wapps.audit-segment.v1", seq: r.seq, prev_hash: r.prevHash, row_json: r.rowJson, hash: r.hash });
    await enqueueEscrowPushes(this.ctx.storage, [
      { b2Key: keyEscrowAuditSegment(r.seq), bodyB64: bytesToB64(utf8(segmentBody)), contentType: "application/json" },
    ]).catch((err) => console.error(`audit-do: escrow enqueue failed (seq ${r.seq})`, err));
  }

  /** alarm, bekleyen audit-segment escrow push'larını drene eder (§6.8 fail-soft). */
  async alarm(): Promise<void> {
    const remaining = await drainEscrowPushes(this.ctx.storage, this.escrow, null, this.escrowAlert);
    if (remaining > 0) await this.ctx.storage.setAlarm(Date.now() + escrowRetryMs);
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
    await this.enqueueAuditSegment(inserted); // §6.8 escrow write-through (fail-soft)
    return { seq: inserted.seq, hash: inserted.hash };
  }

  private async appendBatch(rows: AuditRow[], batchCounter?: number): Promise<{ appended: number; seq: number; hash: string }> {
    await ensureSchema(this.db);
    let head = await this.head();
    const inserted: insertedRow[] = [];
    for (const row of rows) {
      const ins = await this.insertRow(head, row);
      head = { seq: ins.seq, hash: ins.hash };
      inserted.push(ins);
    }
    await this.ctx.storage.put(HEAD_KEY, head);
    for (const ins of inserted) await this.enqueueAuditSegment(ins); // §6.8 (fail-soft)
    // Ingest-liveness (A8 backlog/silence, §6.5): son batch zamanı + sayaç.
    await this.ctx.storage.put(INGEST_TS_KEY, new Date().toISOString());
    if (typeof batchCounter === "number") await this.ctx.storage.put(INGEST_COUNTER_KEY, batchCounter);
    return { appended: rows.length, seq: head.seq, hash: head.hash };
  }

  /** insertRow, tek satırı hesaplar + D1'e yazar ve yeni head'i + escrow-segment
   * materyalini (prev_hash + row_json) döner (storage GÜNCELLEMEZ). */
  private async insertRow(head: ChainHead, row: AuditRow): Promise<insertedRow> {
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
    return { seq, hash, prevHash: head.hash, rowJson };
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
