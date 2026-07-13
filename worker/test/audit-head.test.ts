// GET /v1/audit/head testleri (P1.4): read-AUD zorunlu, {seq, hash} şekli,
// okumanın kendisinin audit'lenmesi (verb audit.head) ve DO-down fail-closed.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  discordCalls,
} from "./helpers.js";
import { GENESIS_HASH } from "../src/audit.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});

async function put(key: string, value: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  return callGate(`/v1/projects/vaulter/keys/${key}`, { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value }) });
}

describe("GET /v1/audit/head (P1.4)", () => {
  it("AUTH_REQUIRED: assertion olmadan 401", async () => {
    const res = await callGate("/v1/audit/head", { method: "GET" });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("AUTH_REQUIRED");
  });

  it("AUD_MISMATCH: write-AUD JWT read rotasında 403 (read-AUD zorunlu)", async () => {
    const jwt = await signer.makeJWT(validClaimsWrite("writer@wapps.dev"));
    const res = await callGate("/v1/audit/head", { headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("AUD_MISMATCH");
  });

  it("SHAPE: taze store'da genesis head'i döner ({seq:0, hash:GENESIS})", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/audit/head", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { seq: number; hash: string };
    expect(body.seq).toBe(0);
    expect(body.hash).toBe(GENESIS_HASH);
  });

  it("HEAD: yazımlar sonrası dönen head, çağrı ANINDAKİ son zincir satırıyla eşleşir", async () => {
    expect((await put("DATABASE_URL", "v")).status).toBe(200);
    // Outcome batch'i pending kuyruğuna düşmüş olabilir → önce settle.
    const before = await settleAudit("vaulter", (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow"));
    const last = before[before.length - 1];
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/audit/head", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { seq: number; hash: string };
    // Dönen head, audit.head satırının ÖNCESİNİ gösterir (metadata read async).
    expect(body.seq).toBe(last.seq);
    expect(body.hash).toBe(last.hash);
    expect(body.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("AUDITED: okumanın kendisi audit'lenir (verb audit.head, allow, project null)", async () => {
    const beforeLen = (await allAuditRows()).length;
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/audit/head", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.length).toBe(beforeLen + 1);
    const row = rows.find((r) => r.verb === "audit.head");
    expect(row).toBeTruthy();
    expect(row!.decision).toBe("allow");
    expect(row!.project).toBeNull();
    expect(row!.key).toBeNull();
    expect(row!.principal).toBe("human:writer@wapps.dev");
    expect(row!.principal_type).toBe("human");
  });

  it("DO DOWN: audit DO erişilemezse 503 AUDIT_UNAVAILABLE + A8 (fail-closed)", async () => {
    const failing = {
      idFromName: () => ({}),
      get: () => ({ fetch: async () => { throw new Error("audit down"); } }),
    } as unknown as DurableObjectNamespace;
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/audit/head", { headers: authHeader(jwt) }, { AUDIT_LOG: failing });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("AUDIT_UNAVAILABLE");
    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.includes("head"))).toBe(true);
  });
});
