// D1 hash-zincirli audit testleri (SPEC §6.4): zincir kuralı + süreklilik,
// attempt→outcome sıralaması, deny satırları, yazma yolunda AUDIT_UNAVAILABLE
// fail-closed (hiçbir store durumu değişmez), metadata okumaları async.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
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
} from "./helpers.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { sha256Hex, utf8 } from "../src/crypto/encoding.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});

/** rowHash, DO ile AYNI formülle bir satırın hash'ini yeniden hesaplar (zincir kuralı). */
function rowHash(prevHash: string, r: AuditRowDb & { ip?: string | null; cf_ray?: string | null; token_jti?: string | null }): string {
  const rr = r as unknown as Record<string, unknown>;
  const values = [r.seq, r.ts, r.principal, r.principal_type, r.project, r.key, r.verb, r.decision, r.intent, rr.ip ?? null, rr.cf_ray ?? null, rr.token_jti ?? null];
  return sha256Hex(utf8(prevHash + "\n" + JSON.stringify(values)));
}

async function put(key: string, value: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  return callGate(`/v1/projects/vaulter/keys/${key}`, { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value }) });
}

describe("hash-chained audit (§6.4)", () => {
  it("CHAIN: every row hash = SHA256(prev_hash || 0x0A || row_json); consecutive rows link", async () => {
    expect((await put("DATABASE_URL", "v")).status).toBe(200);
    // Harness invalidation'ı outcome batch'ini pending kuyruğuna düşürebilir → settle.
    const rows = await settleAudit("vaulter", (r) => r.length >= 2);
    expect(rows.length).toBeGreaterThanOrEqual(2); // attempt + per-key outcome
    for (let i = 0; i < rows.length; i++) {
      expect(rows[i].hash).toBe(rowHash(rows[i].prev_hash, rows[i]));
      if (i > 0) expect(rows[i].prev_hash).toBe(rows[i - 1].hash);
    }
    expect(rows[0].prev_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("ORDERING: commit.attempt row precedes the per-key outcome row", async () => {
    await put("DATABASE_URL", "v");
    const rows = await settleAudit("vaulter", (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow"));
    const attempt = rows.find((r) => r.verb === "commit.attempt");
    const outcome = rows.find((r) => r.verb === "key.set" && r.decision === "allow");
    expect(attempt).toBeTruthy();
    expect(outcome).toBeTruthy();
    expect(attempt!.seq).toBeLessThan(outcome!.seq);
  });

  it("DENY: a rejected write appends a deny row (no allow outcome)", async () => {
    // Developer *_PROD_* yazamaz (policy deny-glob) → Worker-level deny satırı.
    const res = await put("DB_PROD_URL", "x");
    expect(res.status).toBe(403);
    const rows = await allAuditRows();
    const deny = rows.find((r) => r.verb === "key.set" && r.decision === "deny");
    expect(deny).toBeTruthy();
    expect(deny!.key).toBe("DB_PROD_URL");
    expect(rows.find((r) => r.verb === "key.set" && r.decision === "allow")).toBeUndefined();
    expect(deny!.hash).toBe(rowHash(deny!.prev_hash, deny!));
  });

  it("AUDIT_UNAVAILABLE: audit DO down at attempt → write fails closed (503), NOTHING written + A8", async () => {
    expect((await put("DATABASE_URL", "v1")).status).toBe(200); // epoch 1 → DO warm

    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
    const failing = {
      idFromName: () => ({}),
      get: () => ({ fetch: async () => { throw new Error("audit down"); } }),
    } as unknown as DurableObjectNamespace;
    let saved: DurableObjectNamespace | undefined;
    await runInDoRetry(stub, (instance: unknown) => {
      const h = instance as { auditLog: DurableObjectNamespace };
      saved = h.auditLog;
      h.auditLog = failing;
    });

    const res = await put("DATABASE_URL", "v2");
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("AUDIT_UNAVAILABLE");

    // Fail-closed: current epoch-1'de kaldı, manifests/2 YAZILMADI.
    const cur = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCurrent("vaulter")))!.text()) as { epoch: number };
    expect(cur.epoch).toBe(1);
    expect(await env.SECRETS_BUCKET.get(keyManifest("vaulter", 2))).toBeNull();
    // A8 alert'i ateşlendi (audit-down commit).
    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.toLowerCase().includes("audit"))).toBe(true);

    await runInDoRetry(stub, (instance: unknown) => {
      if (saved) (instance as { auditLog: DurableObjectNamespace }).auditLog = saved;
    });
  });

  it("METADATA ASYNC: an allowed keys-list read appends an async audit row", async () => {
    await put("DATABASE_URL", "v");
    const before = (await allAuditRows()).length;
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.length).toBeGreaterThan(before);
    expect(rows.some((r) => r.verb === "key.list" && r.decision === "allow" && r.project === "vaulter")).toBe(true);
  });

  it("304 poll is NOT audited (KEPT behavior)", async () => {
    await put("DATABASE_URL", "v");
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const first = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(jwt) });
    const etag = first.headers.get("ETag")!;
    const before = (await allAuditRows()).length;
    const poll = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(jwt, { "If-None-Match": etag }) });
    expect(poll.status).toBe(304);
    expect((await allAuditRows()).length).toBe(before);
  });
});
