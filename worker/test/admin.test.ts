// Admin API + pending-ops kuyruğu testleri (SPEC §6.9): write-AUD gating, admin
// üyeliği, CORS, pending-ops state machine (panel ÖNERİR — asla mutasyon).
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { seedTrust, ensureJwks, validClaims, validClaimsWrite, authHeader, callGate, resetWorld } from "./helpers.js";
import { keyTrustManifest } from "../src/storage.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

async function adminGate(t: Awaited<ReturnType<typeof seedTrust>>, email: string, path: string, init: RequestInit = {}): Promise<Response> {
  const jwt = await signer.makeJWT(validClaimsWrite(email));
  return callGate(path, { ...init, headers: { ...authHeader(jwt), ...(init.headers as Record<string, string>) } }, t.pin);
}

describe("admin API gating (§6.9)", () => {
  it("GATE: read-AUD JWT on an admin route → 403 AUD_MISMATCH (write-AUD required)", async () => {
    const t = await seedTrust();
    const readJwt = await signer.makeJWT(validClaims(t.adminEmail)); // read-AUD
    const res = await callGate("/v1/admin/audit", { headers: authHeader(readJwt) }, t.pin);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("AUD_MISMATCH");
  });

  it("GATE: write-AUD but NON-admin email → 403 GRANT_DENIED", async () => {
    const t = await seedTrust();
    const res = await adminGate(t, "writer@wapps.dev", "/v1/admin/audit");
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GRANT_DENIED");
  });

  it("GATE: write-AUD admin → 200 with strict CORS header", async () => {
    const t = await seedTrust();
    const res = await adminGate(t, t.adminEmail, "/v1/admin/audit");
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://admin.meapps.dev");
  });

  it("PREFLIGHT: OPTIONS returns CORS without auth", async () => {
    const t = await seedTrust();
    const res = await callGate("/v1/admin/pending-ops", { method: "OPTIONS" }, t.pin);
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://admin.meapps.dev");
  });
});

describe("pending-ops queue (§6.9 — propose only, never mutate)", () => {
  it("PROPOSE → LIST → GET → WITHDRAW → re-WITHDRAW conflict", async () => {
    const t = await seedTrust();
    // Propose.
    const proposeRes = await adminGate(t, t.adminEmail, "/v1/admin/pending-ops", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "grant", payload: { principal: "human:new@wapps.dev", project: "vaulter", verbs: ["read"], keys: ["X"] } }),
    });
    expect(proposeRes.status).toBe(201);
    const op = (await proposeRes.json()) as { id: string; status: string };
    expect(op.status).toBe("proposed");

    // List (proposed).
    const listRes = await adminGate(t, t.adminEmail, "/v1/admin/pending-ops?status=proposed");
    expect(listRes.status).toBe(200);
    const list = (await listRes.json()) as { ops: { id: string }[] };
    expect(list.ops.some((o) => o.id === op.id)).toBe(true);

    // Get.
    const getRes = await adminGate(t, t.adminEmail, `/v1/admin/pending-ops/${op.id}`);
    expect(getRes.status).toBe(200);

    // Withdraw (proposed → withdrawn).
    const wRes = await adminGate(t, t.adminEmail, `/v1/admin/pending-ops/${op.id}/withdraw`, { method: "POST" });
    expect(wRes.status).toBe(200);
    expect(((await wRes.json()) as { status: string }).status).toBe("withdrawn");

    // Re-withdraw → 409 PENDING_OP_INVALID_STATE (forward-only state machine).
    const w2Res = await adminGate(t, t.adminEmail, `/v1/admin/pending-ops/${op.id}/withdraw`, { method: "POST" });
    expect(w2Res.status).toBe(409);
    expect(((await w2Res.json()) as { error: string }).error).toBe("PENDING_OP_INVALID_STATE");
  });

  it("PROPOSE REJECT: non-admin cannot propose → 403", async () => {
    const t = await seedTrust();
    const res = await adminGate(t, "reader@wapps.dev", "/v1/admin/pending-ops", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "grant", payload: {} }),
    });
    expect(res.status).toBe(403);
  });

  it("GET missing op → 404 PENDING_OP_NOT_FOUND", async () => {
    const t = await seedTrust();
    const res = await adminGate(t, t.adminEmail, "/v1/admin/pending-ops/does-not-exist");
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe("PENDING_OP_NOT_FOUND");
  });
});

// P3-b (§6.9 audit cross-check): committed çözümü SPESİFİK committed_epoch'a bağlanır —
// resolving principal'ın "herhangi bir commit'i" DEĞİL, o epoch'u GERÇEKTEN yazdığı kanıtı gerekir.
describe("pending-ops resolve cross-check (P3-b, §6.9)", () => {
  // Ham audit satırı ekler (DO'yu atlar; resolveOp proof'u env.AUDIT_DB'yi doğrudan okur).
  async function insertCommitAudit(principal: string, intent: string): Promise<void> {
    await env.AUDIT_DB.prepare(
      "INSERT INTO audit (ts, principal, principal_type, verb, decision, intent, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
    )
      .bind(new Date().toISOString(), principal, "human", "trust.commit", "allow", intent, "00", `h-${intent}`)
      .run();
  }
  async function proposeOp(t: Awaited<ReturnType<typeof seedTrust>>): Promise<string> {
    const res = await adminGate(t, t.adminEmail, "/v1/admin/pending-ops", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "grant", payload: {} }),
    });
    return ((await res.json()) as { id: string }).id;
  }

  it("REJECT: admin with an UNRELATED prior commit resolves an epoch they did NOT write → 409", async () => {
    const t = await seedTrust();
    const id = await proposeOp(t); // şema kurar + op yaratır
    // Admin'in ALAKASIZ önceki commit'i (farklı epoch=3). Eski kod bunu eşleştirir → yanlış 200.
    await insertCommitAudit(t.adminId, "3");
    // committed_epoch=7 R2'de VAR → hata SPESİFİK-epoch audit cross-check'inden gelir (R2 yokluğundan değil).
    await env.SECRETS_BUCKET.put(keyTrustManifest(7), "dummy-manifest-7");
    const res = await adminGate(t, t.adminEmail, `/v1/admin/pending-ops/${id}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "committed", committed_epoch: 7 }),
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("PENDING_OP_INVALID_STATE");
  });

  it("ACCEPT: admin whose audit row references committed_epoch → 200 committed", async () => {
    const t = await seedTrust();
    const id = await proposeOp(t);
    await env.SECRETS_BUCKET.put(keyTrustManifest(9), "dummy-manifest-9");
    await insertCommitAudit(t.adminId, "9"); // epoch 9'a atıfta bulunan gerçek commit kanıtı
    const res = await adminGate(t, t.adminEmail, `/v1/admin/pending-ops/${id}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "committed", committed_epoch: 9 }),
    });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { status: string; committed_epoch: number };
    expect(j.status).toBe("committed");
    expect(j.committed_epoch).toBe(9);
  });
});
