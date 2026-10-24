// Global audit-chain serializer (SPEC §6.5, F3). ONE instance
// (idFromName="__audit__") is the ONLY writer of the D1 `audit` table: it keeps the
// chain head (seq, hash) in DO storage, assigns seq and computes hashes. The chain
// does NOT fork because it has exactly one writer.
//
// Chain rule (pinned): hash = hex(SHA-256(prev_hash_utf8 || 0x0A || row_json)),
// row_json = the 12 fields [seq,ts,principal,principal_type,project,key,verb,decision,
// intent,ip,cf_ray,token_jti] as a JSON array without spaces (null = absent).
//
// Crash safety (incident 2026-10-24: a canceled append left rows in D1 beyond the
// head, and every later append hit a seq conflict). The chain hash has NO key, so
// anyone who can write D1 and knows the head can build rows that verify. The DO
// therefore never adopts rows only because they chain. One append is:
//   1. put an INTENT in DO storage: the seq range and the hash of every row;
//   2. write all rows to D1 in ONE batch (a D1 batch is one transaction);
//   3. ONE DO storage transaction: new head + idempotency receipt + escrow outbox,
//      and delete the intent.
// Before every append the DO resolves a pending intent: D1 holds exactly the
// intent's rows → adopt; D1 holds none of them → drop the intent; anything else →
// fail closed. Then D1's last row must be the head (same seq, same hash). Rows that
// no intent covers (the legacy suffix of the incident, or a forgery) stay
// fail-closed (503 + alert A8) until a human admin pins them with reconcile.

import { sha256Hex, utf8, bytesToB64 } from "./crypto/encoding.js";
import { ensureSchema } from "./schema.js";
import { AuditRow, GENESIS_HASH } from "./audit.js";
import { ALERT } from "./alerts.js";
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
  // §6.8: audit segments are also written through to B2 (fail-soft).
  DISCORD_WEBHOOK_URL?: string;
}

interface ChainHead {
  seq: number;
  hash: string;
}

/** ChainLink is one row under the chain rule: its D1 values and its escrow segment material. */
interface ChainLink {
  seq: number;
  prevHash: string;
  rowJson: string;
  hash: string;
  values: (string | number | null)[];
}

/** Intent is the DO's durable record of an append, written BEFORE its D1 write. */
interface Intent {
  idempotencyKey: string | null;
  inputDigest: string;
  firstSeq: number;
  lastSeq: number;
  rowHashes: string[]; // one per row, in seq order; the last one is the new head hash
}

/** Receipt is stored with the head, per idempotency key. inputDigest is absent in
 * receipts written before 2026-10-25; those still dedup, without the payload check. */
interface Receipt {
  seq: number;
  hash: string;
  inputDigest?: string;
}

/** StoredRow is the shape of a D1 `audit` row as the DO reads it back. */
type StoredRow = AuditRow & { seq: number; ts: string; prev_hash: string; hash: string };

/** AuditRefused is a deliberate refusal (409), not an outage (503). */
class AuditRefused extends Error {
  constructor(
    readonly code: "IDEMPOTENCY_MISMATCH" | "RECONCILE_REFUSED",
    message: string,
  ) {
    super(message);
  }
}

const HEAD_KEY = "head";
const INTENT_KEY = "intent";
const RECEIPT_PREFIX = "idem:";
const INGEST_TS_KEY = "ingest:lastTs";
const INGEST_COUNTER_KEY = "ingest:lastCounter";
// reconcile reads the legacy suffix in pages of this many rows; memory stays bounded.
const RECONCILE_PAGE = 100;

const ROW_COLUMNS = "seq, ts, principal, principal_type, project, key, verb, decision, intent, ip, cf_ray, token_jti, prev_hash, hash";
const INSERT_ROW_SQL = `INSERT INTO audit (${ROW_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
const TAIL_SQL = `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`;
const ROWS_AFTER_SQL = `SELECT ${ROW_COLUMNS} FROM audit WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?`;

/**
 * chainLink applies the pinned chain rule. It is the ONLY place that builds
 * row_json: appends, intent recovery and reconcile all call it, so they cannot diverge.
 */
function chainLink(seq: number, prevHash: string, row: AuditRow & { ts: string }): ChainLink {
  // The order is FIXED (§6.5 chain rule): 12 fields, null = absent.
  const values: (string | number | null)[] = [
    seq,
    row.ts,
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
  const rowJson = JSON.stringify(values); // no spaces (JSON.stringify default)
  return { seq, prevHash, rowJson, hash: sha256Hex(utf8(prevHash + "\n" + rowJson)), values };
}

/** linkMatches: a stored row is exactly the link the chain rule gives for it. */
function linkMatches(r: StoredRow, link: ChainLink): boolean {
  return r.seq === link.seq && r.prev_hash === link.prevHash && r.hash === link.hash;
}

export class AuditLogDO {
  private db: D1Database;
  // Simple async mutex: appends are strictly serialized (no head fork is possible).
  private lock: Promise<unknown> = Promise.resolve();
  // §6.8 escrow write-through: audit segments are pushed to B2 (fail-soft).
  private escrow: EscrowConfig | null;
  private discordUrl: string;

  constructor(private ctx: DurableObjectState, env: DOEnv) {
    this.db = env.AUDIT_DB;
    this.escrow = escrowConfig(env);
    this.discordUrl = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  }

  /** discordAlert posts an alert straight to Discord. The audit DO has no
   * `alert.failed` audit fallback, because it is the audit writer itself. */
  private discordAlert: EscrowAlert = async (rule, summary, detail) => {
    const url = this.discordUrl;
    if (!url) return;
    const content = `[secrets-gate ${rule}] ${summary}`;
    const body = JSON.stringify({ content, embeds: detail ? [{ description: "```" + JSON.stringify(detail).slice(0, 1500) + "```" }] : undefined });
    try {
      await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    } catch {
      /* an alert is detection; a delivery error does not block the operation */
    }
  };

  /** alarm drains the pending audit-segment escrow pushes (§6.8 fail-soft). */
  async alarm(): Promise<void> {
    const remaining = await drainEscrowPushes(this.ctx.storage, this.escrow, null, this.discordAlert);
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
        const { rows, batchCounter, idempotencyKey } = (await request.json()) as { rows: AuditRow[]; batchCounter?: number; idempotencyKey?: string };
        const res = await this.runExclusive(() => this.appendBatch(rows, batchCounter, idempotencyKey));
        return json(res);
      }
      if (url.pathname === "/reconcile" && request.method === "POST") {
        const { seq, hash, row } = (await request.json()) as { seq: number; hash: string; row: AuditRow };
        const res = await this.runExclusive(() => this.reconcile({ seq, hash }, row));
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
      if (e instanceof AuditRefused) return json({ error: e.code, message: e.message }, 409);
      // Any other error inside the audit DO → 503; the write path turns it into AUDIT_UNAVAILABLE.
      return json({ error: "AUDIT_DO_ERROR", message: String(e) }, 503);
    }
  }

  private async head(): Promise<ChainHead> {
    return (await this.ctx.storage.get<ChainHead>(HEAD_KEY)) ?? { seq: 0, hash: GENESIS_HASH };
  }

  /** appendOne appends one row; with an idempotencyKey a repeat does not insert again. */
  private async appendOne(row: AuditRow, idempotencyKey?: string): Promise<{ seq: number; hash: string; deduped?: boolean }> {
    const r = await this.append([row], idempotencyKey, {});
    return r.deduped ? { seq: r.head.seq, hash: r.head.hash, deduped: true } : { seq: r.head.seq, hash: r.head.hash };
  }

  /** appendBatch appends many rows in one exclusive turn. Batch idempotency (§6.4 bulk
   * outcome recovery): a repeated key dedups the WHOLE batch (no doubled per-key rows). */
  private async appendBatch(rows: AuditRow[], batchCounter?: number, idempotencyKey?: string): Promise<{ appended: number; seq: number; hash: string; deduped?: boolean }> {
    // Ingest liveness (A8 backlog/silence, §6.5): last batch time + counter.
    const ingest: Record<string, unknown> = { [INGEST_TS_KEY]: new Date().toISOString() };
    if (typeof batchCounter === "number") ingest[INGEST_COUNTER_KEY] = batchCounter;
    const r = await this.append(rows, idempotencyKey, ingest);
    if (r.deduped) return { appended: 0, seq: r.head.seq, hash: r.head.hash, deduped: true };
    return { appended: rows.length, seq: r.head.seq, hash: r.head.hash };
  }

  /** append runs one append (intent → D1 batch → head commit) after recover(). */
  private async append(rows: AuditRow[], idempotencyKey: string | undefined, extra: Record<string, unknown>): Promise<{ head: ChainHead; deduped: boolean }> {
    await ensureSchema(this.db);
    const base = await this.recover();
    const inputDigest = sha256Hex(utf8(JSON.stringify(rows)));
    if (idempotencyKey) {
      const receipt = await this.ctx.storage.get<Receipt>(RECEIPT_PREFIX + idempotencyKey);
      if (receipt) {
        if (receipt.inputDigest !== undefined && receipt.inputDigest !== inputDigest) {
          throw new AuditRefused("IDEMPOTENCY_MISMATCH", "idempotency key reused with a different input");
        }
        return { head: { seq: receipt.seq, hash: receipt.hash }, deduped: true };
      }
    }
    const links: ChainLink[] = [];
    let head = base;
    for (const row of rows) {
      const link = chainLink(head.seq + 1, head.hash, { ...row, ts: row.ts ?? new Date().toISOString() });
      links.push(link);
      head = { seq: link.seq, hash: link.hash };
    }
    const key = idempotencyKey ?? null;
    if (links.length > 0) {
      const intent: Intent = { idempotencyKey: key, inputDigest, firstSeq: base.seq + 1, lastSeq: head.seq, rowHashes: links.map((l) => l.hash) };
      await this.ctx.storage.put(INTENT_KEY, intent);
      // A D1 batch is ONE transaction: if any statement fails, nothing is written.
      // On any error the intent stays; the next recover() decides from D1.
      await this.db.batch(links.map((l) => this.db.prepare(INSERT_ROW_SQL).bind(...l.values, l.prevHash, l.hash)));
    }
    await this.commitHead(head, links, key, inputDigest, extra);
    return { head, deduped: false };
  }

  /**
   * commitHead moves the head, stores the receipt, queues the rows' escrow segments
   * and deletes the intent, in ONE DO storage transaction: a crash cannot keep one
   * of them and lose another.
   */
  private async commitHead(head: ChainHead, links: ChainLink[], idempotencyKey: string | null, inputDigest: string, extra: Record<string, unknown>): Promise<void> {
    await this.ctx.storage.transaction(async (txn) => {
      const entries: Record<string, unknown> = { [HEAD_KEY]: head, ...extra };
      if (idempotencyKey) entries[RECEIPT_PREFIX + idempotencyKey] = { seq: head.seq, hash: head.hash, inputDigest } satisfies Receipt;
      await txn.put(entries);
      await txn.delete(INTENT_KEY);
      if (!this.escrow || links.length === 0) return;
      // §6.8 escrow outbox. A segment holds the FULL material that chain verification
      // needs: {seq, prev_hash, row_json, hash}. The B2 push itself is fail-soft (alarm).
      const items = links.map((l) => ({
        b2Key: keyEscrowAuditSegment(l.seq),
        bodyB64: bytesToB64(utf8(JSON.stringify({ schema: "wapps.audit-segment.v1", seq: l.seq, prev_hash: l.prevHash, row_json: l.rowJson, hash: l.hash }))),
        contentType: "application/json",
      }));
      await enqueueEscrowPushes(txn, items);
    });
  }

  /** recover resolves a pending intent, then requires D1's last row to be the head. */
  private async recover(): Promise<ChainHead> {
    let head = await this.head();
    const intent = await this.ctx.storage.get<Intent>(INTENT_KEY);
    if (intent) head = await this.resolveIntent(head, intent);
    const tail = await this.db.prepare(TAIL_SQL).first<ChainHead>();
    const tailSeq = tail?.seq ?? 0;
    if (tailSeq > head.seq) return this.chainBroken("D1 has rows beyond the DO head that no intent covers (reconcile needed)", { headSeq: head.seq, tailSeq });
    if (tailSeq < head.seq) return this.chainBroken("D1 tail is behind the DO head", { headSeq: head.seq, tailSeq });
    if (tail && tail.hash !== head.hash) return this.chainBroken("D1 row at the head seq has a different hash", { headSeq: head.seq });
    return head;
  }

  /**
   * resolveIntent finishes an append that stopped between its D1 write and its head
   * commit. D1 holds exactly the intent's rows → adopt them; none → drop the intent
   * (the D1 transaction did not commit); anything else → fail closed.
   */
  private async resolveIntent(head: ChainHead, intent: Intent): Promise<ChainHead> {
    const n = intent.rowHashes.length;
    if (intent.firstSeq !== head.seq + 1 || intent.lastSeq !== head.seq + n) {
      return this.chainBroken("pending intent does not start at the DO head", { headSeq: head.seq, firstSeq: intent.firstSeq });
    }
    // n + 1 rows: one row more than the intent covers reveals extra rows beyond it.
    const page = await this.db.prepare(ROWS_AFTER_SQL).bind(head.seq, intent.lastSeq + 1, n + 1).all<StoredRow>();
    const rows = page.results ?? [];
    if (rows.length === 0) {
      await this.ctx.storage.delete(INTENT_KEY);
      return head;
    }
    if (rows.length !== n) return this.chainBroken("D1 holds a different number of rows than the pending intent", { headSeq: head.seq, intentRows: n, d1Rows: rows.length });
    const links: ChainLink[] = [];
    let cur = head;
    for (let i = 0; i < n; i++) {
      const link = chainLink(cur.seq + 1, cur.hash, rows[i]);
      if (!linkMatches(rows[i], link) || link.hash !== intent.rowHashes[i]) {
        return this.chainBroken("D1 row differs from the pending intent", { headSeq: head.seq, seq: rows[i].seq });
      }
      links.push(link);
      cur = { seq: link.seq, hash: link.hash };
    }
    await this.commitHead(cur, links, intent.idempotencyKey, intent.inputDigest, {});
    console.warn(`audit-do: recovered pending append ${head.seq + 1}..${cur.seq} from its intent`);
    return cur;
  }

  /**
   * reconcile adopts a legacy D1 suffix that no intent covers (rows the pre-intent
   * code left behind). A human admin pins the expected last row {seq, hash}, read
   * from D1 and checked independently. The DO adopts it ONLY when it is D1's last
   * row and the chain from the DO head to it recomputes exactly. Its own audit row
   * (audit.reconcile, old and new head) is the first row after the adopted suffix.
   */
  private async reconcile(target: ChainHead, row: AuditRow): Promise<{ from: ChainHead; to: ChainHead; row: ChainHead }> {
    await ensureSchema(this.db);
    let from = await this.head();
    const intent = await this.ctx.storage.get<Intent>(INTENT_KEY);
    if (intent) from = await this.resolveIntent(from, intent);
    const tail = await this.db.prepare(TAIL_SQL).first<ChainHead>();
    if (!tail || tail.seq !== target.seq || tail.hash !== target.hash) {
      throw new AuditRefused("RECONCILE_REFUSED", "the pinned {seq, hash} is not D1's last row");
    }
    if (target.seq <= from.seq) throw new AuditRefused("RECONCILE_REFUSED", "D1 has no rows beyond the DO head");
    // Verify the WHOLE suffix first, so a bad row anywhere means nothing is adopted;
    // then walk it again and adopt page by page (each page re-verified).
    await this.walkSuffix(from, target, null);
    await this.walkSuffix(from, target, (h, links) => this.commitHead(h, links, null, "", {}));
    console.warn(`audit-do: reconciled legacy suffix ${from.seq + 1}..${target.seq}`);
    const rec = await this.append([{ ...row, intent: `reconcile ${from.seq}:${from.hash} -> ${target.seq}:${target.hash}` }], undefined, {});
    return { from, to: target, row: rec.head };
  }

  /** walkSuffix verifies D1 rows from.seq+1..target.seq in pages; onPage adopts a verified page. */
  private async walkSuffix(from: ChainHead, target: ChainHead, onPage: ((h: ChainHead, links: ChainLink[]) => Promise<void>) | null): Promise<void> {
    let cur = from;
    while (cur.seq < target.seq) {
      const page = await this.db.prepare(ROWS_AFTER_SQL).bind(cur.seq, target.seq, RECONCILE_PAGE).all<StoredRow>();
      const rows = page.results ?? [];
      if (rows.length === 0) throw new AuditRefused("RECONCILE_REFUSED", `D1 has no row after seq ${cur.seq}`);
      const links: ChainLink[] = [];
      for (const r of rows) {
        const link = chainLink(cur.seq + 1, cur.hash, r);
        if (!linkMatches(r, link)) throw new AuditRefused("RECONCILE_REFUSED", `D1 row ${r.seq} does not link to seq ${cur.seq} under the chain rule`);
        links.push(link);
        cur = { seq: link.seq, hash: link.hash };
      }
      if (onPage) await onPage(cur, links);
    }
    if (cur.hash !== target.hash) throw new AuditRefused("RECONCILE_REFUSED", "the recomputed chain does not end at the pinned hash");
  }

  /** chainBroken fires alert A8 (fail-closed path signal, §0.1) and throws → 503. */
  private async chainBroken(reason: string, detail: Record<string, unknown>): Promise<never> {
    console.error(`audit-do: audit chain broken: ${reason}`, detail);
    await this.discordAlert(ALERT.A8, `audit chain broken: ${reason}; appends refused`, detail);
    throw new Error(`AUDIT_CHAIN_BROKEN: ${reason}`);
  }

  /** runExclusive strictly serializes appends; it prevents a head read/write race. */
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
