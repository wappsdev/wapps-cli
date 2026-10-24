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
// therefore adopts D1 rows only against a commitment it holds itself. One append is:
//   1. put an INTENT in DO storage: seq range + the hash of its LAST row. Because each
//      hash covers the previous one, that hash commits to every row of the range, so
//      the intent has a fixed size whatever the batch size;
//   2. write all rows to D1 in ONE batch (a D1 batch is one transaction);
//   3. ONE DO storage transaction: new head + receipt + escrow outbox, delete intent.
// recover() runs before every append. D1 rows beyond the head are adopted only when
// they are exactly the range of the current intent or of a recently abandoned one
// (a batch that landed after its intent was given up). An intent with none of its
// rows in D1 is abandoned, not forgotten. Anything else fails closed (503 + A8).
// Then D1's last row must be the head (same seq, same hash).
//
// A suffix that no intent covers (the incident's rows, written by the pre-intent
// code) is adopted only through reconcile: a root admin pins {seq, hash}; the DO
// verifies the chain from its head to the pin in ONE read and adopts exactly the
// links it verified. The adoption and a durable reconcile record commit together;
// recover() writes the record's audit.reconcile row before any other append.

import { sha256Hex, utf8, bytesToB64 } from "./crypto/encoding.js";
import { ensureSchema } from "./schema.js";
import { AUDIT_FIELD_MAX, AuditRow, GENESIS_HASH } from "./audit.js";
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

/** Ticket names the caller of an append for dedup: a durable idempotencyKey (writer
 * outcomes, kept forever) or a short-lived requestId (one plaintext read attempt). */
interface Ticket {
  idempotencyKey: string | null;
  requestId: string | null;
  inputDigest: string;
}

/** Intent is the DO's durable commitment to an append, written BEFORE its D1 write. */
interface Intent extends Ticket {
  firstSeq: number;
  lastSeq: number;
  lastHash: string;
}

/** Receipt is stored with the head, per idempotency key. inputDigest is absent in
 * receipts written before 2026-10-25; those still dedup, without the payload check. */
interface Receipt {
  seq: number;
  hash: string;
  inputDigest?: string;
}

/** RecentRequest is a requestId receipt in the bounded ring. */
interface RecentRequest extends Receipt {
  id: string;
}

/** ReconcileRecord is a reconcile whose adoption is committed but whose own audit
 * row may not be written yet. recover() finishes it before any other append. */
interface ReconcileRecord {
  from: ChainHead;
  to: ChainHead;
  key: string; // idempotency key of the audit.reconcile row
  row: AuditRow & { ts: string };
}

interface ReconcileResult {
  from: ChainHead;
  to: ChainHead;
  row: ChainHead;
}

/** StoredRow is the shape of a D1 `audit` row as the DO reads it back. */
type StoredRow = AuditRow & { seq: number; ts: string; prev_hash: string; hash: string };

/** AuditRefused is a deliberate refusal (400/409), not an outage (503). */
class AuditRefused extends Error {
  readonly status: number;
  constructor(
    readonly code: "ROW_INVALID" | "IDEMPOTENCY_MISMATCH" | "RECONCILE_REFUSED",
    message: string,
  ) {
    super(message);
    this.status = code === "ROW_INVALID" ? 400 : 409;
  }
}

// The text fields of AuditRow. Each must be a string (or absent/null for the optional
// ones) of at most AUDIT_FIELD_MAX code units.
const ROW_TEXT_FIELDS = ["ts", "principal", "principal_type", "project", "key", "verb", "decision", "intent", "ip", "cf_ray", "token_jti"] as const;
// A segment of a row at the field cap stays far below this (12 fields x 512 units x
// 6 bytes of JSON escaping, escaped again inside the segment, then base64 ≈ 99 KB).
// The check runs before the intent and the D1 write, so a head commit can never
// fail on size after D1 has committed.
const SEGMENT_MAX_B64 = 128 * 1024;

/** validateRows refuses (400) a row with a non-string or oversized text field. It
 * never truncates: an audit row says exactly what happened, or it is not written. */
function validateRows(rows: unknown): asserts rows is AuditRow[] {
  if (!Array.isArray(rows)) throw new AuditRefused("ROW_INVALID", "rows must be an array");
  rows.forEach((r, i) => {
    if (typeof r !== "object" || r === null) throw new AuditRefused("ROW_INVALID", `row ${i} is not an object`);
    for (const f of ROW_TEXT_FIELDS) {
      const v = (r as Record<string, unknown>)[f];
      if (v === undefined || v === null) continue;
      if (typeof v !== "string") throw new AuditRefused("ROW_INVALID", `row ${i}: field ${f} is not a string`);
      if (v.length > AUDIT_FIELD_MAX) throw new AuditRefused("ROW_INVALID", `row ${i}: field ${f} exceeds ${AUDIT_FIELD_MAX} characters`);
    }
  });
}

/** segmentItem is the escrow outbox item of one link (§6.8): the FULL material chain
 * verification needs, {seq, prev_hash, row_json, hash}. */
function segmentItem(l: ChainLink): { b2Key: string; bodyB64: string; contentType: string } {
  return {
    b2Key: keyEscrowAuditSegment(l.seq),
    bodyB64: bytesToB64(utf8(JSON.stringify({ schema: "wapps.audit-segment.v1", seq: l.seq, prev_hash: l.prevHash, row_json: l.rowJson, hash: l.hash }))),
    contentType: "application/json",
  };
}

const HEAD_KEY = "head";
const INTENT_KEY = "intent";
const ABANDONED_KEY = "abandoned-intents";
const ABANDONED_MAX = 4;
const RECEIPT_PREFIX = "idem:";
const RECENT_KEY = "recent-requests";
// A requestId only has to survive the worker→DO retries of one call (milliseconds).
// If it is evicted anyway, the cost is one duplicate audit row, never a lost one.
const RECENT_MAX = 64;
const RECONCILE_KEY = "reconcile:pending";
const RECONCILE_DONE_PREFIX = "reconcile:done:";
// reconcile holds the verified links in memory and adopts them in one transaction.
const RECONCILE_MAX_ROWS = 1000;
const INGEST_TS_KEY = "ingest:lastTs";
const INGEST_COUNTER_KEY = "ingest:lastCounter";
const READ_PAGE = 100;

const ROW_COLUMNS = "seq, ts, principal, principal_type, project, key, verb, decision, intent, ip, cf_ray, token_jti, prev_hash, hash";
const INSERT_ROW_SQL = `INSERT INTO audit (${ROW_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
const TAIL_SQL = `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`;
const ROWS_AFTER_SQL = `SELECT ${ROW_COLUMNS} FROM audit WHERE seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?`;

/**
 * chainLink applies the pinned chain rule. It is the ONLY place that builds
 * row_json: appends, recovery and reconcile all call it, so they cannot diverge.
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

function sameHead(a: ChainHead, b: ChainHead): boolean {
  return a.seq === b.seq && a.hash === b.hash;
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
        const b = (await request.json()) as { row: AuditRow; idempotencyKey?: string; requestId?: string };
        const res = await this.runExclusive(() => this.appendOne(b.row, b));
        return json(res);
      }
      if (url.pathname === "/append-batch" && request.method === "POST") {
        const b = (await request.json()) as { rows: AuditRow[]; batchCounter?: number; idempotencyKey?: string; requestId?: string };
        const res = await this.runExclusive(() => this.appendBatch(b.rows, b.batchCounter, b));
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
      if (e instanceof AuditRefused) return json({ error: e.code, message: e.message }, e.status);
      // Any other error inside the audit DO → 503; the write path turns it into AUDIT_UNAVAILABLE.
      return json({ error: "AUDIT_DO_ERROR", message: String(e) }, 503);
    }
  }

  private async head(): Promise<ChainHead> {
    return (await this.ctx.storage.get<ChainHead>(HEAD_KEY)) ?? { seq: 0, hash: GENESIS_HASH };
  }

  private async tail(): Promise<ChainHead | null> {
    return this.db.prepare(TAIL_SQL).first<ChainHead>();
  }

  /** appendOne appends one row; with an idempotencyKey/requestId a repeat does not insert again. */
  private async appendOne(row: AuditRow, ids: { idempotencyKey?: string; requestId?: string }): Promise<{ seq: number; hash: string; deduped?: boolean }> {
    await ensureSchema(this.db);
    const r = await this.appendAt(await this.recover(), [row], ids, {});
    return r.deduped ? { seq: r.head.seq, hash: r.head.hash, deduped: true } : { seq: r.head.seq, hash: r.head.hash };
  }

  /** appendBatch appends many rows in one exclusive turn. Batch idempotency (§6.4 bulk
   * outcome recovery): a repeated key dedups the WHOLE batch (no doubled per-key rows). */
  private async appendBatch(rows: AuditRow[], batchCounter: number | undefined, ids: { idempotencyKey?: string; requestId?: string }): Promise<{ appended: number; seq: number; hash: string; deduped?: boolean }> {
    await ensureSchema(this.db);
    // Ingest liveness (A8 backlog/silence, §6.5): last batch time + counter.
    const ingest: Record<string, unknown> = { [INGEST_TS_KEY]: new Date().toISOString() };
    if (typeof batchCounter === "number") ingest[INGEST_COUNTER_KEY] = batchCounter;
    const r = await this.appendAt(await this.recover(), rows, ids, ingest);
    if (r.deduped) return { appended: 0, seq: r.head.seq, hash: r.head.hash, deduped: true };
    return { appended: rows.length, seq: r.head.seq, hash: r.head.hash };
  }

  /** appendAt runs one append after `base` (which recover() returned): dedup, intent,
   * one D1 batch, one head commit. */
  private async appendAt(
    base: ChainHead,
    rows: AuditRow[],
    ids: { idempotencyKey?: string; requestId?: string },
    extra: Record<string, unknown>,
  ): Promise<{ head: ChainHead; deduped: boolean }> {
    validateRows(rows);
    const ticket: Ticket = { idempotencyKey: ids.idempotencyKey ?? null, requestId: ids.requestId ?? null, inputDigest: sha256Hex(utf8(JSON.stringify(rows))) };
    const receipt = await this.findReceipt(ticket);
    if (receipt) {
      if (receipt.inputDigest !== undefined && receipt.inputDigest !== ticket.inputDigest) {
        throw new AuditRefused("IDEMPOTENCY_MISMATCH", "idempotency key reused with a different input");
      }
      return { head: { seq: receipt.seq, hash: receipt.hash }, deduped: true };
    }
    const links: ChainLink[] = [];
    let head = base;
    for (const row of rows) {
      const link = chainLink(head.seq + 1, head.hash, { ...row, ts: row.ts ?? new Date().toISOString() });
      links.push(link);
      head = { seq: link.seq, hash: link.hash };
    }
    for (const l of links) {
      if (segmentItem(l).bodyB64.length > SEGMENT_MAX_B64) throw new AuditRefused("ROW_INVALID", `row ${l.seq}: escrow segment exceeds ${SEGMENT_MAX_B64} bytes`);
    }
    if (links.length > 0) {
      const intent: Intent = { ...ticket, firstSeq: base.seq + 1, lastSeq: head.seq, lastHash: head.hash };
      await this.ctx.storage.put(INTENT_KEY, intent);
      // A D1 batch is ONE transaction: if any statement fails, nothing is written.
      // On any error the intent stays; the next recover() decides from D1.
      await this.db.batch(links.map((l) => this.db.prepare(INSERT_ROW_SQL).bind(...l.values, l.prevHash, l.hash)));
    }
    await this.commitHead(head, links, ticket, extra);
    return { head, deduped: false };
  }

  private async findReceipt(t: Ticket): Promise<Receipt | null> {
    if (t.idempotencyKey) return (await this.ctx.storage.get<Receipt>(RECEIPT_PREFIX + t.idempotencyKey)) ?? null;
    if (t.requestId) {
      const recent = (await this.ctx.storage.get<RecentRequest[]>(RECENT_KEY)) ?? [];
      return recent.find((r) => r.id === t.requestId) ?? null;
    }
    return null;
  }

  /**
   * commitHead moves the head, stores the ticket's receipt, queues the rows' escrow
   * segments, writes `extra` and deletes the intent, in ONE DO storage transaction:
   * a crash cannot keep one of them and lose another.
   */
  private async commitHead(head: ChainHead, links: ChainLink[], ticket: Ticket | null, extra: Record<string, unknown>): Promise<void> {
    await this.ctx.storage.transaction(async (txn) => {
      const entries: Record<string, unknown> = { [HEAD_KEY]: head, ...extra };
      const receipt: Receipt = { seq: head.seq, hash: head.hash, inputDigest: ticket?.inputDigest };
      if (ticket?.idempotencyKey) entries[RECEIPT_PREFIX + ticket.idempotencyKey] = receipt;
      if (ticket?.requestId) {
        const recent = (await txn.get<RecentRequest[]>(RECENT_KEY)) ?? [];
        entries[RECENT_KEY] = [...recent, { ...receipt, id: ticket.requestId }].slice(-RECENT_MAX);
      }
      await txn.put(entries);
      await txn.delete(INTENT_KEY);
      if (!this.escrow || links.length === 0) return;
      // §6.8 escrow outbox, committed with the head. The B2 push itself is fail-soft (alarm).
      await enqueueEscrowPushes(txn, links.map(segmentItem));
    });
  }

  /**
   * recover brings the DO to a state where an append may follow, or throws (503 + A8):
   * adopt or abandon the pending intent, require D1's last row to be the head, and
   * finish a pending reconcile.
   */
  private async recover(): Promise<ChainHead> {
    let head = await this.head();
    const intent = (await this.ctx.storage.get<Intent>(INTENT_KEY)) ?? null;
    const abandoned = (await this.ctx.storage.get<Intent[]>(ABANDONED_KEY)) ?? [];
    const tail = await this.tail();
    const tailSeq = tail?.seq ?? 0;
    if (tailSeq > head.seq) {
      // Rows beyond the head: adopt them only as the exact range of an intent we hold.
      const adopted = await this.adoptHeldIntent(head, (c) => c.lastSeq === tailSeq);
      if (!adopted) return this.chainBroken("D1 has rows beyond the DO head that no intent covers (reconcile needed)", { headSeq: head.seq, tailSeq });
      head = adopted;
    } else if (intent) {
      // D1 holds none of the intent's rows: its batch did not commit, or not yet.
      // Keep it as abandoned, so a batch that lands late is still adopted.
      await this.ctx.storage.transaction(async (txn) => {
        await txn.put(ABANDONED_KEY, [...abandoned, intent].slice(-ABANDONED_MAX));
        await txn.delete(INTENT_KEY);
      });
    }
    if (tailSeq < head.seq) return this.chainBroken("D1 tail is behind the DO head", { headSeq: head.seq, tailSeq });
    if (tail && tail.hash !== head.hash) return this.chainBroken("D1 row at the head seq has a different hash", { headSeq: head.seq });
    const rec = await this.ctx.storage.get<ReconcileRecord>(RECONCILE_KEY);
    if (rec) head = await this.finishReconcile(head, rec);
    return head;
  }

  /** heldIntentsAt returns the intents we hold (current + abandoned) that start right
   * after head. Older ones can never commit: their first seq is taken. */
  private async heldIntentsAt(head: ChainHead): Promise<{ all: Intent[]; abandoned: Intent[]; atHead: Intent[] }> {
    const intent = (await this.ctx.storage.get<Intent>(INTENT_KEY)) ?? null;
    const abandoned = (await this.ctx.storage.get<Intent[]>(ABANDONED_KEY)) ?? [];
    const all = [...(intent ? [intent] : []), ...abandoned];
    return { all, abandoned, atHead: all.filter((c) => c.firstSeq === head.seq + 1) };
  }

  /**
   * adoptHeldIntent adopts the D1 rows of a held intent that starts right after head
   * and passes `fits`, if D1 holds exactly its rows. It commits with the intent's OWN
   * ticket, so the caller's receipt survives. Returns the new head, or null.
   */
  private async adoptHeldIntent(head: ChainHead, fits: (c: Intent) => boolean): Promise<ChainHead | null> {
    const { abandoned, atHead } = await this.heldIntentsAt(head);
    for (const c of atHead.filter(fits)) {
      const end = { seq: c.lastSeq, hash: c.lastHash };
      const links = await this.verifiedLinks(head, end);
      if (!links) continue;
      const rest = abandoned.filter((a) => a !== c);
      // commitHead also deletes the current intent: if it was not the adopted one, its
      // seq range is taken now, so its D1 batch can never commit.
      await this.commitHead(end, links, c, rest.length !== abandoned.length ? { [ABANDONED_KEY]: rest } : {});
      console.warn(`audit-do: adopted pending append ${c.firstSeq}..${c.lastSeq} from its intent`);
      return end;
    }
    return null;
  }

  /**
   * verifiedLinks reads D1 rows head.seq+1..end.seq (in pages) and returns their
   * links if each one is exactly what the chain rule gives and the chain ends at
   * end.hash; otherwise null. The caller commits THESE links, never a second read.
   */
  private async verifiedLinks(head: ChainHead, end: ChainHead): Promise<ChainLink[] | null> {
    const links: ChainLink[] = [];
    let cur = head;
    while (cur.seq < end.seq) {
      const page = await this.db.prepare(ROWS_AFTER_SQL).bind(cur.seq, end.seq, READ_PAGE).all<StoredRow>();
      const rows = page.results ?? [];
      if (rows.length === 0) return null;
      for (const r of rows) {
        const link = chainLink(cur.seq + 1, cur.hash, r);
        if (r.seq !== link.seq || r.prev_hash !== link.prevHash || r.hash !== link.hash) return null;
        links.push(link);
        cur = { seq: link.seq, hash: link.hash };
      }
    }
    return cur.hash === end.hash ? links : null;
  }

  /**
   * reconcile adopts a legacy D1 suffix that no intent covers (rows the pre-intent
   * code left behind). A root admin pins the expected last row {seq, hash}, read from
   * D1 and checked independently. The DO adopts it ONLY when it is D1's last row and
   * the chain from the DO head recomputes to it. Its own audit row (audit.reconcile,
   * old and new head) is the first row after the suffix. A retry of the same pin
   * returns the completed result.
   */
  private async reconcile(target: ChainHead, row: AuditRow): Promise<ReconcileResult> {
    await ensureSchema(this.db);
    const doneKey = `${RECONCILE_DONE_PREFIX}${target.seq}:${target.hash}`;
    const done = async () => (await this.ctx.storage.get<ReconcileResult>(doneKey)) ?? null;
    let result = await done();
    if (result) return result;
    if (await this.ctx.storage.get(RECONCILE_KEY)) {
      await this.recover(); // finishes the pending reconcile (this pin or an earlier one)
      result = await done();
      if (result) return result;
    }
    let from = await this.head();
    const tail = await this.tail();
    if (!tail || !sameHead(tail, target)) throw new AuditRefused("RECONCILE_REFUSED", "the pinned {seq, hash} is not D1's last row");
    if (target.seq <= from.seq) throw new AuditRefused("RECONCILE_REFUSED", "D1 has no rows beyond the DO head");
    // Rows that an intent we hold covers are that append's own rows: adopt them first,
    // with the intent's ticket, so its idempotency receipt is kept. Reconcile adopts
    // only rows that no intent covers; any other overlap with an intent is refused.
    for (let next = await this.adoptHeldIntent(from, (c) => c.lastSeq <= target.seq); next; next = await this.adoptHeldIntent(from, (c) => c.lastSeq <= target.seq)) {
      from = next;
    }
    if ((await this.heldIntentsAt(from)).atHead.length > 0) {
      throw new AuditRefused("RECONCILE_REFUSED", "the pinned suffix overlaps an append intent whose rows D1 does not hold exactly");
    }
    if (target.seq === from.seq) throw new AuditRefused("RECONCILE_REFUSED", "the rows beyond the DO head were an append's own rows and are recovered; nothing to reconcile");
    if (target.seq - from.seq > RECONCILE_MAX_ROWS) {
      throw new AuditRefused("RECONCILE_REFUSED", `the suffix has ${target.seq - from.seq} rows; one reconcile adopts at most ${RECONCILE_MAX_ROWS}`);
    }
    const links = await this.verifiedLinks(from, target);
    if (!links) throw new AuditRefused("RECONCILE_REFUSED", "the chain from the DO head does not recompute to the pinned row");
    const rec: ReconcileRecord = {
      from,
      to: target,
      key: `reconcile:${target.seq}:${target.hash}`,
      row: { ...row, ts: new Date().toISOString(), intent: `reconcile ${from.seq}:${from.hash} -> ${target.seq}:${target.hash}` },
    };
    // The adoption and the record commit in ONE transaction. No held intent starts
    // at `from` (checked above), so any intent still stored is stale: its first seq
    // is taken, and it can never commit.
    await this.commitHead(target, links, null, { [RECONCILE_KEY]: rec });
    console.warn(`audit-do: reconciled legacy suffix ${from.seq + 1}..${target.seq}`);
    await this.finishReconcile(target, rec);
    result = await done();
    if (!result) throw new Error("reconcile: completed record missing");
    return result;
  }

  /** finishReconcile writes the record's audit.reconcile row (once, by its key),
   * stores the result and clears the record. recover() calls it before any append. */
  private async finishReconcile(head: ChainHead, rec: ReconcileRecord): Promise<ChainHead> {
    let rowHead = await this.ctx.storage.get<Receipt>(RECEIPT_PREFIX + rec.key);
    if (!rowHead) {
      if (!sameHead(head, rec.to)) return this.chainBroken("pending reconcile does not match the DO head", { headSeq: head.seq, toSeq: rec.to.seq });
      head = (await this.appendAt(head, [rec.row], { idempotencyKey: rec.key }, {})).head;
      rowHead = head;
    }
    const result: ReconcileResult = { from: rec.from, to: rec.to, row: { seq: rowHead.seq, hash: rowHead.hash } };
    await this.ctx.storage.transaction(async (txn) => {
      await txn.put(`${RECONCILE_DONE_PREFIX}${rec.to.seq}:${rec.to.hash}`, result);
      await txn.delete(RECONCILE_KEY);
    });
    await this.discordAlert(ALERT.A8, `audit chain reconciled by ${rec.row.principal}: ${rec.from.seq} -> ${rec.to.seq}; appends resume`, { from: rec.from, to: rec.to, row: result.row });
    return head;
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
