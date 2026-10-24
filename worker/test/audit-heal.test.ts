// Audit chain crash-safety tests (incident 2026-10-24: a canceled append-batch left
// rows in D1 beyond the DO head, so every later append hit a seq conflict and the
// gate refused every read).
//
// The chain hash has NO key: anyone who can write D1 and knows the head can build
// rows that verify. So the DO never adopts rows just because they chain. It adopts
// only (a) rows that match its OWN durable intent (current or abandoned), written
// before the D1 write, or (b) a legacy suffix that a root admin pins with
// {seq, hash} via reconcile.

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env, runDurableObjectAlarm } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  AuditRowDb,
  runInDoRetry,
  discordCalls,
  ADMIN_EMAIL,
  AUD_WRITE,
} from "./helpers.js";
import { AUDIT_DO_NAME, AuditRow, GENESIS_HASH } from "../src/audit.js";
import { sha256Hex, utf8 } from "../src/crypto/encoding.js";
import { EscrowConfig } from "../src/escrow.js";

const TEST_ESCROW: EscrowConfig = {
  endpoint: "s3.test-region.backblazeb2.com",
  region: "test-region",
  bucket: "wapps-secrets-escrow",
  keyId: "0004b2keyid",
  appKey: "K004appkeysecret",
};

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});
afterEach(async () => {
  // A test may set escrow or a D1 hook on the shared DO instance; never let it leak.
  await runInDoRetry(auditStub(), (instance: unknown) => {
    (instance as { escrow: EscrowConfig | null }).escrow = null;
  });
  if (restoreDb) await restoreDb();
  restoreDb = null;
});

let restoreDb: (() => Promise<void>) | null = null;

/** hookDb replaces the audit DO's D1 binding with a wrapper built from the real one
 * (fault and race injection at the D1 boundary). afterEach restores it. */
async function hookDb(make: (real: D1Database) => Partial<D1Database>): Promise<void> {
  let saved: D1Database | undefined;
  await runInDoRetry(auditStub(), (instance: unknown) => {
    const i = instance as { db: D1Database };
    saved = i.db;
    const real = i.db;
    i.db = { prepare: (sql: string) => real.prepare(sql), batch: (s: D1PreparedStatement[]) => real.batch(s), ...make(real) } as D1Database;
  });
  restoreDb = async () => {
    await runInDoRetry(auditStub(), (instance: unknown) => {
      if (saved) (instance as { db: D1Database }).db = saved;
    });
  };
}

/** failNextBatch makes the DO's next D1 batch fail once: "drop" = it never runs
 * (rolled back); "commit" = it runs, then the call is canceled. */
async function failNextBatch(mode: "drop" | "commit"): Promise<void> {
  let armed = true;
  await hookDb((real) => ({
    batch: async (stmts: D1PreparedStatement[]) => {
      if (!armed) return real.batch(stmts);
      armed = false;
      if (mode === "commit") await real.batch(stmts);
      throw new Error("injected: D1 batch canceled");
    },
  }));
}

function auditStub(): DurableObjectStub {
  return env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME));
}

function row(key: string, extra: Partial<AuditRow> = {}): AuditRow {
  return { principal: "human:t@wapps.dev", principal_type: "human", project: "vaulter", key, verb: "value.read", decision: "allow", ...extra };
}

async function appendBatch(rows: AuditRow[], idempotencyKey?: string): Promise<Response> {
  return auditStub().fetch("https://audit/append-batch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rows, idempotencyKey }),
  });
}

async function appendOne(r: AuditRow, idempotencyKey?: string): Promise<Response> {
  return auditStub().fetch("https://audit/append", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ row: r, idempotencyKey }),
  });
}

async function doHead(): Promise<{ seq: number; hash: string }> {
  const res = await auditStub().fetch("https://audit/head");
  return (await res.json()) as { seq: number; hash: string };
}

/** rowJson, an independent copy of the pinned chain rule (12 fields, null = absent). */
function rowJson(seq: number, ts: string, r: AuditRow): string {
  return JSON.stringify([seq, ts, r.principal, r.principal_type, r.project ?? null, r.key ?? null, r.verb, r.decision, r.intent ?? null, r.ip ?? null, r.cf_ray ?? null, r.token_jti ?? null]);
}
function linkHash(prevHash: string, json: string): string {
  return sha256Hex(utf8(prevHash + "\n" + json));
}

const RAW_TS = "2026-10-24T19:32:56.862Z";

/** writeRawRow writes one row straight into D1 with a valid chain link: what the old
 * code left behind, and exactly what a forger with D1 write access can produce. */
async function writeRawRow(seq: number, prevHash: string, r: AuditRow, hashOverride?: string): Promise<string> {
  const hash = hashOverride ?? linkHash(prevHash, rowJson(seq, RAW_TS, r));
  await env.AUDIT_DB.prepare(
    `INSERT INTO audit (seq, ts, principal, principal_type, project, key, verb, decision, intent, ip, cf_ray, token_jti, prev_hash, hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(seq, RAW_TS, r.principal, r.principal_type, r.project ?? null, r.key ?? null, r.verb, r.decision, r.intent ?? null, r.ip ?? null, r.cf_ray ?? null, r.token_jti ?? null, prevHash, hash)
    .run();
  return hash;
}

/** expectContinuousChain checks seq 1..n with no gap and every link recomputed. */
function expectContinuousChain(rows: AuditRowDb[]): void {
  let prev = GENESIS_HASH;
  rows.forEach((r, i) => {
    const rr = r as unknown as AuditRow & { seq: number; ts: string };
    expect(r.seq).toBe(i + 1);
    expect(r.prev_hash).toBe(prev);
    expect(r.hash).toBe(linkHash(prev, rowJson(r.seq, r.ts, rr)));
    prev = r.hash;
  });
}

/** injectCommitFault makes the NEXT commit of the head fail once, after the D1 write
 * already happened: the 2026-10-24 cancellation, reproduced. */
async function injectCommitFault(): Promise<void> {
  await runInDoRetry(auditStub(), (instance: unknown) => {
    const storage = (instance as { ctx: DurableObjectState }).ctx.storage as unknown as Record<string, (...a: unknown[]) => unknown>;
    const put = storage.put.bind(storage);
    const transaction = storage.transaction.bind(storage);
    const restore = () => {
      storage.put = put;
      storage.transaction = transaction;
    };
    storage.put = (k: unknown, ...rest: unknown[]) => {
      if (k === "head" || (typeof k === "object" && k !== null && "head" in k)) {
        restore();
        throw new Error("injected: canceled after the D1 write");
      }
      return put(k, ...rest);
    };
    storage.transaction = () => {
      restore();
      throw new Error("injected: canceled after the D1 write");
    };
  });
}

function chainAlerts(): { body: string }[] {
  return discordCalls.filter((c) => c.body.includes("A8") && c.body.includes("audit chain"));
}

async function pendingSegments(): Promise<{ seq: number; prev_hash: string; hash: string }[]> {
  return runInDoRetry(auditStub(), async (_i: unknown, state: DurableObjectState) => {
    const m = await state.storage.list<{ item: { bodyB64: string } }>({ prefix: "pending-escrow-push:audit/segments/" });
    return [...m.values()].map((v) => JSON.parse(atob(v.item.bodyB64)) as { seq: number; prev_hash: string; hash: string }).sort((a, b) => a.seq - b.seq);
  });
}

async function setEscrow(): Promise<void> {
  await runInDoRetry(auditStub(), (instance: unknown) => {
    (instance as { escrow: EscrowConfig | null }).escrow = TEST_ESCROW;
  });
}

async function reconcile(body: unknown, jwtClaims: Record<string, unknown> = validClaimsWrite(ADMIN_EMAIL)): Promise<Response> {
  const jwt = await signer.makeJWT(jwtClaims);
  return callGate("/v1/admin/audit/reconcile", { method: "POST", headers: authHeader(jwt), body: JSON.stringify(body) });
}

async function readValue(key: string, envOverride: Record<string, unknown> = {}): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  return callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(jwt), body: JSON.stringify({ keys: [key] }) }, envOverride);
}

async function putValue(key: string, value: string): Promise<void> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  const w = await callGate(`/v1/projects/vaulter/keys/${key}`, { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value }) });
  expect(w.status).toBe(200);
  await settleAudit("vaulter", (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow"));
}

describe("legacy suffix: rows in D1 beyond the head with no intent (the live incident)", () => {
  it("INCIDENT REPLAY: reads stay 503 until a human admin reconciles the exact tail; then they resume", async () => {
    await putValue("DATABASE_URL", "v");
    const old = await doHead();
    const h1 = await writeRawRow(old.seq + 1, old.hash, row("DATABASE_URL"));
    const h2 = await writeRawRow(old.seq + 2, h1, row("DATABASE_URL"));

    // Fail-closed: no automatic adoption, alert A8.
    expect((await readValue("DATABASE_URL")).status).toBe(503);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
    expect(await doHead()).toEqual(old);

    // Wrong hash, and a correct hash for a row that is not D1's tail: both refused.
    const wrong = await reconcile({ seq: old.seq + 2, hash: "a".repeat(64) });
    expect(wrong.status).toBe(409);
    const notTail = await reconcile({ seq: old.seq + 1, hash: h1 });
    expect(notTail.status).toBe(409);
    expect(await doHead()).toEqual(old);

    const ok = await reconcile({ seq: old.seq + 2, hash: h2 });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { from: { seq: number; hash: string }; to: { seq: number; hash: string }; row: { seq: number } };
    expect(body.from).toEqual(old);
    expect(body.to).toEqual({ seq: old.seq + 2, hash: h2 });
    expect(body.row.seq).toBe(old.seq + 3);

    // The reconcile writes its own audit row, the first row after the adopted tail.
    const rows = await allAuditRows();
    const rec = rows[old.seq + 2];
    expect(rec.seq).toBe(old.seq + 3);
    expect(rec.verb).toBe("audit.reconcile");
    expect(rec.principal).toBe(`human:${ADMIN_EMAIL}`);
    expect(rec.intent).toContain(`${old.seq}:${old.hash}`);
    expect(rec.intent).toContain(`${old.seq + 2}:${h2}`);
    expectContinuousChain(rows);
    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.includes("audit chain reconciled"))).toBe(true);

    const rd = await readValue("DATABASE_URL");
    expect(rd.status).toBe(200);
    expect(((await rd.json()) as { values: Record<string, string> }).values.DATABASE_URL).toBe("v");
    expectContinuousChain(await allAuditRows());
  });

  it("RECONCILE ESCROW: the adopted legacy rows and the reconcile row are queued as audit segments", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    await setEscrow();
    const old = await doHead();
    const h2 = await writeRawRow(2, old.hash, row("K2"));
    const h3 = await writeRawRow(3, h2, row("K3"));
    expect((await reconcile({ seq: 3, hash: h3 })).status).toBe(200);

    const segs = await pendingSegments();
    expect(segs.map((s) => s.seq)).toEqual([2, 3, 4]);
    const rows = await allAuditRows();
    for (const s of segs) {
      expect(s.hash).toBe(rows[s.seq - 1].hash);
      expect(s.prev_hash).toBe(rows[s.seq - 1].prev_hash);
    }
  });

  it("RECONCILE AUTHZ: a non-admin human, an admin-granted service token and a group admin are refused, and each refusal is audited", async () => {
    // Healthy chain: the deny rows CAN be written, so their presence is a real check.
    await seedPolicy([...defaultRules(), { service: "svc-ops", projects: ["*"], keys: ["*"], verbs: ["*"] }]);
    groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    const pin = { seq: old.seq, hash: old.hash };

    const human = await reconcile(pin, validClaimsWrite("writer@wapps.dev"));
    expect(human.status).toBe(403);
    const svc = await reconcile(pin, serviceTokenClaims("svc-ops", { aud: [AUD_WRITE] }));
    expect(svc.status).toBe(403);
    expect(((await svc.json()) as { error: string }).error).toBe("HUMAN_REQUIRED");
    const groupAdmin = await reconcile(pin, validClaimsWrite("boss@wapps.dev"));
    expect(groupAdmin.status).toBe(403);
    expect(((await groupAdmin.json()) as { error: string }).error).toBe("ROOT_ADMIN_REQUIRED");

    const rows = await allAuditRows();
    const denies = rows.filter((r) => r.decision === "deny");
    expect(denies.some((r) => r.principal === "human:writer@wapps.dev")).toBe(true);
    expect(denies.some((r) => r.principal === "service:svc-ops" && r.verb === "audit.reconcile")).toBe(true);
    expect(denies.some((r) => r.principal === "human:boss@wapps.dev" && r.verb === "audit.reconcile")).toBe(true);
    expect(rows.filter((r) => r.verb === "audit.reconcile" && r.decision === "allow")).toEqual([]);
    expectContinuousChain(rows);
  });

  it("RECONCILE TOCTOU: D1 replaced with another valid continuation after verification never becomes the head or escrow", async () => {
    expect((await appendBatch([row("K0")])).status).toBe(200);
    await setEscrow();
    const original = new Map<number, string>();
    let prev = (await doHead()).hash;
    for (let seq = 2; seq <= 251; seq++) {
      prev = await writeRawRow(seq, prev, row(`K${seq}`));
      original.set(seq, prev);
    }
    const pin = { seq: 251, hash: prev };

    // After the third suffix page read (the end of a full verification pass), a D1
    // writer swaps rows 102..251 for a forged continuation that still chains from 101.
    const forged = new Set<string>();
    let pageReads = 0;
    await hookDb((real) => ({
      prepare: (sql: string) => {
        const stmt = real.prepare(sql);
        if (!/WHERE seq > \? AND seq <= \?/.test(sql)) return stmt;
        return {
          bind: (...args: unknown[]) => ({
            all: async () => {
              const res = await stmt.bind(...args).all();
              if (++pageReads === 3) {
                await real.prepare("DELETE FROM audit WHERE seq >= 102").run();
                let h = original.get(101)!;
                for (let seq = 102; seq <= 251; seq++) {
                  h = await writeRawRow(seq, h, row(`K${seq}`, { principal: "human:forger@wapps.dev" }));
                  forged.add(h);
                }
              }
              return res;
            },
          }),
        } as unknown as D1PreparedStatement;
      },
    }));

    await reconcile(pin);
    expect(forged.size).toBe(150);
    const head = await doHead();
    expect(forged.has(head.hash)).toBe(false);
    const segs = await pendingSegments();
    expect(segs.filter((s) => forged.has(s.hash))).toEqual([]);
    for (const s of segs) if (original.has(s.seq)) expect(s.hash).toBe(original.get(s.seq));
  });

  it("RECONCILE ROW DROPPED: if the audit.reconcile write rolls back, the next append writes it first", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    const h2 = await writeRawRow(2, old.hash, row("K2"));
    await failNextBatch("drop");
    expect((await reconcile({ seq: 2, hash: h2 })).status).toBe(503);

    const next = await appendBatch([row("K3")]);
    expect(next.status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.map((r) => r.verb)).toEqual(["value.read", "value.read", "audit.reconcile", "value.read"]);
    expect(rows[2].principal).toBe(`human:${ADMIN_EMAIL}`);
    expectContinuousChain(rows);

    // A retry of the same pin returns the completed result instead of 409.
    const retry = await reconcile({ seq: 2, hash: h2 });
    expect(retry.status).toBe(200);
    expect(((await retry.json()) as { row: { seq: number } }).row.seq).toBe(3);
    expect((await allAuditRows()).filter((r) => r.verb === "audit.reconcile").length).toBe(1);
  });

  it("RECONCILE ROW COMMITTED, CALL CANCELED: a retry of the same pin returns the result; the row is written once", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    const h2 = await writeRawRow(2, old.hash, row("K2"));
    await failNextBatch("commit");
    expect((await reconcile({ seq: 2, hash: h2 })).status).toBe(503);

    const retry = await reconcile({ seq: 2, hash: h2 });
    expect(retry.status).toBe(200);
    const body = (await retry.json()) as { from: { seq: number }; to: { seq: number }; row: { seq: number } };
    expect(body.from.seq).toBe(1);
    expect(body.to.seq).toBe(2);
    expect(body.row.seq).toBe(3);
    expect((await appendBatch([row("K4")])).status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.filter((r) => r.verb === "audit.reconcile").length).toBe(1);
    expectContinuousChain(rows);
  });

  it("RECONCILE BAD LINK: a pinned tail whose chain from the head does not recompute is refused", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    const h2 = await writeRawRow(2, "e".repeat(64), row("K2")); // does not link to the head
    const res = await reconcile({ seq: 2, hash: h2 });
    expect(res.status).toBe(409);
    expect(await doHead()).toEqual(old);
  });

  it("RECONCILE LARGE GAP: a tail longer than one read page is verified and adopted in pages", async () => {
    expect((await appendBatch([row("K0")])).status).toBe(200);
    let prev = (await doHead()).hash;
    for (let seq = 2; seq <= 251; seq++) prev = await writeRawRow(seq, prev, row(`K${seq}`));
    expect((await reconcile({ seq: 251, hash: prev })).status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.length).toBe(252);
    expectContinuousChain(rows);
  });

  it("RECONCILE LARGE GAP, BAD LATE ROW: one bad row in a later page means nothing is adopted", async () => {
    expect((await appendBatch([row("K0")])).status).toBe(200);
    const old = await doHead();
    let prev = old.hash;
    for (let seq = 2; seq <= 251; seq++) prev = await writeRawRow(seq, prev, row(`K${seq}`), seq === 240 ? "c".repeat(64) : undefined);
    expect((await reconcile({ seq: 251, hash: prev })).status).toBe(409);
    expect(await doHead()).toEqual(old);
  });

  it("FORGED SUFFIX: rows that chain perfectly but have no intent are never adopted by an append", async () => {
    expect((await appendBatch([row("K1"), row("K2")])).status).toBe(200);
    const old = await doHead();
    const h3 = await writeRawRow(3, old.hash, row("K3", { principal: "human:someone-else@wapps.dev" }));
    await writeRawRow(4, h3, row("K4"));

    expect((await appendBatch([row("K5")])).status).toBe(503);
    expect((await appendOne(row("K5"))).status).toBe(503);
    expect(await doHead()).toEqual(old);
    expect((await allAuditRows()).length).toBe(4);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
  });
});

describe("intent: the DO's own record of an append, written before the D1 write", () => {
  it("FULLY COMMITTED: a cancel after the D1 commit is recovered; the next append continues the chain", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    await setEscrow();
    await injectCommitFault();
    expect((await appendBatch([row("K2"), row("K3")])).status).toBe(503);

    const res = await appendBatch([row("K4")]);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { seq: number }).seq).toBe(4);
    const rows = await allAuditRows();
    expect(rows.map((r) => r.key)).toEqual(["K1", "K2", "K3", "K4"]);
    expectContinuousChain(rows);
    expect((await pendingSegments()).map((s) => s.seq)).toEqual([2, 3, 4]);
  });

  it("NOTHING COMMITTED: a failed D1 transaction leaves no partial rows; the intent is dropped and appends continue", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    // Row 2 violates the principal_type CHECK constraint, after row 1 of the batch is valid.
    const bad = row("K3", { principal_type: "robot" as AuditRow["principal_type"] });
    expect((await appendBatch([row("K2"), bad])).status).toBe(503);
    expect((await allAuditRows()).length).toBe(1);
    expect(await doHead()).toEqual(old);

    const ok = await appendBatch([row("K2")]);
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { seq: number }).seq).toBe(2);
    expectContinuousChain(await allAuditRows());
  });

  it("PARTIAL: D1 holds only part of the intent's rows → fail closed + A8", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    await injectCommitFault();
    expect((await appendBatch([row("K2"), row("K3")])).status).toBe(503);
    await env.AUDIT_DB.prepare("DELETE FROM audit WHERE seq = 3").run();

    expect((await appendBatch([row("K4")])).status).toBe(503);
    expect(await doHead()).toEqual(old);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
  });

  it("DIFFERENT ROWS: D1 holds rows for the intent's range that chain but differ from the intent → fail closed", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    await injectCommitFault();
    expect((await appendBatch([row("K2")])).status).toBe(503);
    // Replace the committed row with a forged one that still links to the head.
    await env.AUDIT_DB.prepare("DELETE FROM audit WHERE seq = 2").run();
    await writeRawRow(2, old.hash, row("K2", { principal: "human:forger@wapps.dev" }));

    expect((await appendBatch([row("K3")])).status).toBe(503);
    expect(await doHead()).toEqual(old);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
  });

  it("EXTRA ROWS: D1 holds the intent's rows plus more beyond them → fail closed", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    await injectCommitFault();
    expect((await appendBatch([row("K2")])).status).toBe(503);
    const h2 = (await allAuditRows())[1].hash;
    await writeRawRow(3, h2, row("K3"));

    expect((await appendBatch([row("K4")])).status).toBe(503);
    expect(await doHead()).toEqual(old);
  });

  it("LATE LANDING: a batch that commits after its intent was given up is still adopted by the next append", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    // Batch A is canceled before D1 ran it. The next append (B) finds no rows and
    // gives up A's intent; A's D1 batch then lands late, just before B's.
    let saved: D1PreparedStatement[] | null = null;
    let calls = 0;
    await hookDb((real) => ({
      batch: async (stmts: D1PreparedStatement[]) => {
        calls++;
        if (calls === 1) {
          saved = stmts;
          throw new Error("injected: canceled before D1 ran it");
        }
        if (calls === 2 && saved) await real.batch(saved);
        return real.batch(stmts);
      },
    }));
    expect((await appendBatch([row("A2"), row("A3")])).status).toBe(503);
    expect((await appendBatch([row("B2")])).status).toBe(503); // B collides with A's late rows

    const c = await appendBatch([row("C4")]);
    expect(c.status).toBe(200);
    expect(((await c.json()) as { seq: number }).seq).toBe(4);
    const rows = await allAuditRows();
    expect(rows.map((r) => r.key)).toEqual(["K1", "A2", "A3", "C4"]);
    expectContinuousChain(rows);
  });

  it("INTENT SIZE: the pending intent of a 2500-row batch stays far below the 128 KiB DO value limit, and recovers", async () => {
    const rows = Array.from({ length: 2500 }, (_, i) => row(`B${i}`));
    await injectCommitFault();
    expect((await appendBatch(rows)).status).toBe(503);
    const intent = await runInDoRetry(auditStub(), (_i: unknown, state: DurableObjectState) => state.storage.get("intent"));
    expect(intent).toBeTruthy();
    expect(JSON.stringify(intent).length).toBeLessThan(1024);

    const next = await appendBatch([row("after")]);
    expect(next.status).toBe(200);
    expect(((await next.json()) as { seq: number }).seq).toBe(2501);
  });
});

describe("boundary: D1's last row must be the head, on every append", () => {
  it("REPLACED TAIL: D1's last row at head.seq with a different hash fails closed", async () => {
    expect((await appendBatch([row("K1"), row("K2")])).status).toBe(200);
    const old = await doHead();
    await env.AUDIT_DB.prepare("UPDATE audit SET hash = ? WHERE seq = 2").bind("d".repeat(64)).run();

    expect((await appendBatch([row("K3")])).status).toBe(503);
    expect((await allAuditRows()).length).toBe(2);
    expect(await doHead()).toEqual(old);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
  });

  it("D1 BEHIND HEAD: MAX(seq) < head.seq fails closed; nothing is appended", async () => {
    expect((await appendBatch([row("K1"), row("K2"), row("K3")])).status).toBe(200);
    const old = await doHead();
    await env.AUDIT_DB.prepare("DELETE FROM audit WHERE seq = 3").run();

    expect((await appendBatch([row("K4")])).status).toBe(503);
    expect((await appendOne(row("K4"))).status).toBe(503);
    expect((await allAuditRows()).map((r) => r.seq)).toEqual([1, 2]);
    expect(await doHead()).toEqual(old);
    expect(chainAlerts().length).toBeGreaterThanOrEqual(1);
  });
});

describe("idempotency receipts", () => {
  it("BATCH RETRY, SAME INPUT: a retry after a cancel that followed the D1 commit is deduped, not doubled", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const batch = [row("K2", { verb: "key.set" }), row("K3", { verb: "key.set" })];
    await injectCommitFault();
    expect((await appendBatch(batch, "vaulter:7")).status).toBe(503);

    const retry = await appendBatch(batch, "vaulter:7");
    expect(retry.status).toBe(200);
    const body = (await retry.json()) as { seq: number; deduped?: boolean };
    expect(body.deduped).toBe(true);
    expect(body.seq).toBe(3);
    const rows = await allAuditRows();
    expect(rows.length).toBe(3);
    expectContinuousChain(rows);
  });

  it("SAME KEY, DIFFERENT INPUT: refused with 409; nothing is appended", async () => {
    expect((await appendBatch([row("K1", { verb: "key.set" })], "vaulter:8")).status).toBe(200);
    const res = await appendBatch([row("K9", { verb: "key.set" })], "vaulter:8");
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("IDEMPOTENCY_MISMATCH");
    expect((await allAuditRows()).length).toBe(1);
  });

  it("SINGLE RETRY: /append with a key is deduped after the same cancel", async () => {
    expect((await appendOne(row("K1"))).status).toBe(200);
    await injectCommitFault();
    expect((await appendOne(row("K2", { verb: "commit.attempt" }), "vaulter:9:attempt")).status).toBe(503);

    const retry = await appendOne(row("K2", { verb: "commit.attempt" }), "vaulter:9:attempt");
    expect(retry.status).toBe(200);
    expect(((await retry.json()) as { deduped?: boolean }).deduped).toBe(true);
    const rows = await allAuditRows();
    expect(rows.length).toBe(2);
    expectContinuousChain(rows);
  });

  it("RE-CREATED PROJECT: the first commit after a project delete is audited (its epoch restarts at 1)", async () => {
    await putValue("DATABASE_URL", "v1");
    const jwt = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const del = await callGate("/v1/admin/projects/vaulter", { method: "DELETE", headers: authHeader(jwt), body: JSON.stringify({ confirm: "vaulter" }) });
    expect(del.status).toBe(200);

    const w = await callGate("/v1/projects/vaulter/keys/OTHER_KEY", {
      method: "PUT",
      headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))),
      body: JSON.stringify({ value: "v2" }),
    });
    expect(w.status).toBe(200);
    expect(((await w.json()) as { epoch: number }).epoch).toBe(1);
    const rows = await settleAudit("vaulter", (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "OTHER_KEY"));
    expect(rows.some((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "OTHER_KEY")).toBe(true);
  });

  it("READ RPC RETRY: one plaintext read is audited once, even when the worker→DO call is retried", async () => {
    await putValue("DATABASE_URL", "v");
    const before = (await allAuditRows()).length;
    // The DO completes the append, then the stub reports a transient reset, so
    // doStubFetch retries the SAME request.
    let failed = false;
    const flaky = {
      idFromName: (n: string) => env.AUDIT_LOG.idFromName(n),
      get: (id: DurableObjectId) => {
        const real = env.AUDIT_LOG.get(id);
        return {
          fetch: async (input: string, init?: RequestInit) => {
            const res = await real.fetch(input, init);
            if (!failed && input.endsWith("/append-batch")) {
              failed = true;
              throw new Error("Durable Object reset because its code was updated.");
            }
            return res;
          },
        };
      },
    } as unknown as DurableObjectNamespace;

    const rd = await readValue("DATABASE_URL", { AUDIT_LOG: flaky });
    expect(rd.status).toBe(200);
    expect(failed).toBe(true);
    const reads = (await allAuditRows()).slice(before).filter((r) => r.verb === "value.read");
    expect(reads.length).toBe(1);
  });

  it("TWO READS: two separate plaintext reads produce two audit rows", async () => {
    await putValue("DATABASE_URL", "v");
    const before = (await allAuditRows()).length;
    expect((await readValue("DATABASE_URL")).status).toBe(200);
    expect((await readValue("DATABASE_URL")).status).toBe(200);
    const reads = (await allAuditRows()).slice(before).filter((r) => r.verb === "value.read");
    expect(reads.length).toBe(2);
  });

  it("READ RECEIPTS ARE BOUNDED: a read leaves no permanent receipt in DO storage", async () => {
    await putValue("DATABASE_URL", "v");
    for (let i = 0; i < 3; i++) expect((await readValue("DATABASE_URL")).status).toBe(200);
    const keys = await runInDoRetry(auditStub(), async (_i: unknown, state: DurableObjectState) => [...(await state.storage.list({ prefix: "idem:read:" })).keys()]);
    expect(keys).toEqual([]);
  });

  it("LEGACY RECEIPT: a receipt written before payload binding (no inputDigest) still dedups", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const head = await doHead();
    await runInDoRetry(auditStub(), (_i: unknown, state: DurableObjectState) => state.storage.put("idem:vaulter:3", { seq: head.seq, hash: head.hash }));
    const res = await appendBatch([row("K9", { verb: "key.set" })], "vaulter:3");
    expect(res.status).toBe(200);
    expect(((await res.json()) as { deduped?: boolean }).deduped).toBe(true);
    expect((await allAuditRows()).length).toBe(1);
  });
});

describe("reconcile of a long suffix", () => {
  /** writeRawSuffix writes rows from..to straight into D1 (in D1 batches), chained from prevHash. */
  async function writeRawSuffix(from: number, to: number, prevHash: string): Promise<string> {
    let prev = prevHash;
    const stmts: D1PreparedStatement[] = [];
    for (let seq = from; seq <= to; seq++) {
      const r = row(`L${seq}`);
      const hash = linkHash(prev, rowJson(seq, RAW_TS, r));
      stmts.push(
        env.AUDIT_DB.prepare(
          `INSERT INTO audit (seq, ts, principal, principal_type, project, key, verb, decision, intent, ip, cf_ray, token_jti, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(seq, RAW_TS, r.principal, r.principal_type, r.project ?? null, r.key ?? null, r.verb, r.decision, null, null, null, null, prev, hash),
      );
      prev = hash;
    }
    for (let i = 0; i < stmts.length; i += 200) await env.AUDIT_DB.batch(stmts.slice(i, i + 200));
    return prev;
  }

  it("OVER 1000 ROWS: one pin of the final tail adopts a 1200-row suffix in pages", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const last = await writeRawSuffix(2, 1201, (await doHead()).hash);
    const res = await reconcile({ seq: 1201, hash: last });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { row: { seq: number } }).row.seq).toBe(1202);
    const rows = await allAuditRows();
    expect(rows.length).toBe(1202);
    expectContinuousChain(rows);
  });

  it("INTERRUPTED ADOPTION: a page commit that fails mid-reconcile is resumed by the next append, which writes audit.reconcile first", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const last = await writeRawSuffix(2, 251, (await doHead()).hash);
    await injectCommitFault();
    expect((await reconcile({ seq: 251, hash: last })).status).toBe(503);

    const next = await appendBatch([row("after")]);
    expect(next.status).toBe(200);
    const rows = await allAuditRows();
    expect(rows[251].verb).toBe("audit.reconcile");
    expect(rows[252].key).toBe("after");
    expectContinuousChain(rows);
  });
});

describe("reconcile and held intents", () => {
  it("INTENT ROWS KEEP THEIR RECEIPT: reconcile adopts an intent's committed rows with its ticket; the retry dedups", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const outcome = [row("K2", { verb: "key.set" }), row("K3", { verb: "key.set" })];
    await injectCommitFault();
    expect((await appendBatch(outcome, "vaulter:5:sha")).status).toBe(503);
    const committed = await allAuditRows();
    const h4 = await writeRawRow(4, committed[2].hash, row("K4")); // a legacy row after the intent's rows

    expect((await reconcile({ seq: 4, hash: h4 })).status).toBe(200);
    const same = await appendBatch(outcome, "vaulter:5:sha");
    expect(same.status).toBe(200);
    expect(((await same.json()) as { deduped?: boolean }).deduped).toBe(true);
    const other = await appendBatch([row("K9", { verb: "key.set" })], "vaulter:5:sha");
    expect(other.status).toBe(409);
    expect(((await other.json()) as { error: string }).error).toBe("IDEMPOTENCY_MISMATCH");
    const rows = await allAuditRows();
    expect(rows.map((r) => r.key)).toEqual(["K1", "K2", "K3", "K4", null]);
    expect(rows[4].verb).toBe("audit.reconcile");
    expectContinuousChain(rows);
  });

  it("INTENT RANGE MISMATCH: a pinned suffix over an intent's range that D1 does not match is refused", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    await injectCommitFault();
    expect((await appendBatch([row("K2"), row("K3")], "vaulter:6:sha")).status).toBe(503);
    // Replace the intent's rows with a forged continuation that still links to the head.
    await env.AUDIT_DB.prepare("DELETE FROM audit WHERE seq >= 2").run();
    const f2 = await writeRawRow(2, old.hash, row("K2", { principal: "human:forger@wapps.dev" }));
    const f3 = await writeRawRow(3, f2, row("K3"));

    expect((await reconcile({ seq: 3, hash: f3 })).status).toBe(409);
    expect(await doHead()).toEqual(old);
  });
});

describe("row bounds: checked before the intent and the D1 write", () => {
  it("OVERSIZED FIELD: a row field over 512 chars is refused with 400 before D1 is touched; the chain stays healthy", async () => {
    expect((await appendBatch([row("K1")])).status).toBe(200);
    const old = await doHead();
    const res = await appendBatch([row("K2"), row("K3", { intent: "x".repeat(513) })]);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("ROW_INVALID");
    expect((await allAuditRows()).length).toBe(1);
    expect(await doHead()).toEqual(old);
    const intent = await runInDoRetry(auditStub(), (_i: unknown, state: DurableObjectState) => state.storage.get("intent"));
    expect(intent).toBeUndefined();

    expect((await appendOne(row("K2", { key: "k".repeat(513) }))).status).toBe(400);
    expect((await appendBatch([row("K2")])).status).toBe(200);
    expectContinuousChain(await allAuditRows());
  });

  it("NON-STRING FIELD: a row field that is not a string is refused with 400", async () => {
    const res = await appendBatch([{ ...row("K1"), intent: { nested: "x".repeat(10) } as unknown as string }]);
    expect(res.status).toBe(400);
    expect((await allAuditRows()).length).toBe(0);
  });

  it("WORST-CASE ROW: every free-text field at the cap with the worst JSON escaping still fits the segment bound", async () => {
    await setEscrow();
    const worst = String.fromCharCode(1).repeat(512); // each char escapes to \u0001, twice
    const r: AuditRow = { ...row(worst), principal: worst, project: worst, intent: worst, ip: worst, cf_ray: worst, token_jti: worst, ts: worst };
    expect((await appendBatch([r])).status).toBe(200);
    const bodies = await runInDoRetry(auditStub(), async (_i: unknown, state: DurableObjectState) => {
      const m = await state.storage.list<{ item: { bodyB64: string } }>({ prefix: "pending-escrow-push:audit/segments/" });
      return [...m.values()].map((v) => v.item.bodyB64.length);
    });
    expect(bodies.length).toBe(1);
    expect(bodies[0]).toBeLessThanOrEqual(128 * 1024);
  });

  it("EDGE: an X-Wapps-Intent header over 512 chars is refused with 400 before any commit", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/projects/vaulter/keys/DATABASE_URL", {
      method: "PUT",
      headers: authHeader(jwt, { "X-Wapps-Intent": "i".repeat(513) }),
      body: JSON.stringify({ value: "v" }),
    });
    expect(res.status).toBe(400);
    expect((await allAuditRows()).filter((r) => r.verb === "commit.attempt")).toEqual([]);
  });
});

describe("writer outcome retries", () => {
  function writerStub(): DurableObjectStub {
    return env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
  }
  afterEach(async () => {
    await runInDoRetry(writerStub(), (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
  });

  it("TERMINAL 409: an outcome retry refused with IDEMPOTENCY_MISMATCH is dropped and alerted, not retried forever", async () => {
    await putValue("DATABASE_URL", "v");
    expect((await appendBatch([row("OTHER", { verb: "key.set" })], "vaulter:77:abc")).status).toBe(200);
    await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => {
      await state.storage.put("pending-audit-outcome:vaulter:77:abc", { rows: [row("MINE", { verb: "key.set" })], idempotencyKey: "vaulter:77:abc" });
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(writerStub())).toBe(true);
    const left = await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => [...(await state.storage.list({ prefix: "pending-audit-outcome:" })).keys()]);
    expect(left).toEqual([]);
    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.includes("IDEMPOTENCY_MISMATCH"))).toBe(true);
  });

  it("LEGACY LONG INTENT: a pending outcome with a 600-char intent is appended once, clamped with a visible marker, and cleared", async () => {
    await putValue("DATABASE_URL", "v");
    const long = "s".repeat(600);
    await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => {
      await state.storage.put("pending-audit-outcome:vaulter:88", { rows: [row("LEGACY", { verb: "key.set", intent: long })], idempotencyKey: "vaulter:88" });
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(writerStub())).toBe(true);

    const rows = (await allAuditRows()).filter((r) => r.key === "LEGACY");
    expect(rows.length).toBe(1);
    expect(rows[0].intent!.length).toBeLessThanOrEqual(512);
    expect(rows[0].intent!.endsWith("…[truncated from 600]")).toBe(true);
    expect(long.startsWith(rows[0].intent!.slice(0, -"…[truncated from 600]".length))).toBe(true);
    const left = await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => [...(await state.storage.list({ prefix: "pending-audit-outcome:" })).keys()]);
    expect(left).toEqual([]);
  });

  it("PENDING KEY: a queued outcome is stored under project:epoch:manifestSha, so a re-created project cannot overwrite it", async () => {
    const realNs = env.AUDIT_LOG;
    const outcomeDown = {
      idFromName: (n: string) => realNs.idFromName(n),
      get: (id: DurableObjectId) => {
        const real = realNs.get(id);
        return {
          fetch: async (input: string, init?: RequestInit) => {
            if (input.endsWith("/append-batch")) throw new Error("audit down");
            return real.fetch(input, init);
          },
        };
      },
    } as unknown as DurableObjectNamespace;
    let saved: DurableObjectNamespace | undefined;
    await runInDoRetry(writerStub(), (instance: unknown) => {
      const w = instance as { auditLog: DurableObjectNamespace };
      saved = w.auditLog;
      w.auditLog = outcomeDown;
    });
    try {
      const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
      const w = await callGate("/v1/projects/vaulter/keys/DATABASE_URL", { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value: "v" }) });
      expect(w.status).toBe(200);
      const { manifestSha256 } = (await w.json()) as { manifestSha256: string };
      const keys = await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => [...(await state.storage.list({ prefix: "pending-audit-outcome:" })).keys()]);
      expect(keys).toEqual([`pending-audit-outcome:vaulter:1:${manifestSha256}`]);
    } finally {
      await runInDoRetry(writerStub(), (instance: unknown) => {
        if (saved) (instance as { auditLog: DurableObjectNamespace }).auditLog = saved;
      });
      await runInDoRetry(writerStub(), (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
    }
  });
});
