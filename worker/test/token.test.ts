// Opsiyonel mint katmanı testleri (SPEC §5.3): scope ⊆ policy satırları, minted
// token'ın data-plane'de KESİŞTİRMESİ (asla genişletme), revoke (deny-list).

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  authHeader,
  callGate,
  seedPolicy,
  groupsByEmail,
  allAuditRows,
  ADMIN_EMAIL,
  AUD_WRITE,
} from "./helpers.js";
import { scopeAllowsKey } from "../src/mint.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy([
    { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "write"] },
    { service: "svc-ci", projects: ["vaulter"], keys: ["DEPLOY_TOKEN", "DB_URL"], verbs: ["read"] },
  ]);
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});

async function svcJwt(): Promise<string> {
  return signer.makeJWT(serviceTokenClaims("svc-ci"));
}
async function seedValues(): Promise<void> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  await callGate("/v1/projects/vaulter/import", {
    method: "POST",
    headers: authHeader(jwt),
    body: JSON.stringify({ values: { DEPLOY_TOKEN: "tok", DB_URL: "url" } }),
  });
}

describe("scopeAllowsKey — case-insensitive anahtar kimliği (§5.3, policy ile tutarlı)", () => {
  it("case-fold: DEPLOY_TOKEN scope'u deploy_token'ı da kapsar; '*' tümünü", () => {
    const scope = { project: "vaulter", keys: ["DEPLOY_TOKEN"], verbs: ["read"] } as never;
    expect(scopeAllowsKey(scope, "DEPLOY_TOKEN")).toBe(true);
    expect(scopeAllowsKey(scope, "deploy_token")).toBe(true);
    expect(scopeAllowsKey(scope, "Deploy_Token")).toBe(true);
    expect(scopeAllowsKey(scope, "OTHER_KEY")).toBe(false);
    expect(scopeAllowsKey({ project: "vaulter", keys: ["*"], verbs: ["read"] } as never, "anything")).toBe(true);
  });
});

describe("POST /v1/token (§5.3)", () => {
  it("mints within policy rows; token.mint audited synchronously; TTL clamped", async () => {
    const res = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] }, ttl_seconds: 6000 }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string; expires_in: number; sub: string; jti: string };
    expect(body.sub).toBe("service:svc-ci");
    expect(body.expires_in).toBeLessThanOrEqual(600); // TTL clamp
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "token.mint" && r.decision === "allow" && r.principal === "service:svc-ci")).toBe(true);
  });

  it("scope exceeding the policy rows → TOKEN_SCOPE_EXCEEDED", async () => {
    const res = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["write"], keys: ["DEPLOY_TOKEN"] } }),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_SCOPE_EXCEEDED");
  });

  it("humans cannot mint", async () => {
    const res = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] } }),
    });
    expect(res.status).toBe(403);
  });
});

describe("minted token on the data plane — INTERSECTS the policy row (§5.3)", () => {
  it("scoped key readable; policy-allowed-but-out-of-scope key DENIED", async () => {
    await seedValues();
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] } }),
    });
    const { token } = (await mint.json()) as { token: string };

    // Scope içi anahtar → 200.
    const ok = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }),
    });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { values: Record<string, string> }).values.DEPLOY_TOKEN).toBe("tok");

    // Policy satırı DB_URL'ye izin verir ama minted scope DEĞİL → deny (kesişim).
    const denied = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DB_URL"] }),
    });
    expect(denied.status).toBe(403);
  });

  it("service token WITHOUT a minted token still reads directly (v2 §5.1 delta)", async () => {
    await seedValues();
    const res = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ keys: ["DB_URL"] }),
    });
    expect(res.status).toBe(200);
  });

  it("rotate-scoped minted token executes data-plane WRITES (rotate⊃write §4.2) but not reads", async () => {
    await seedPolicy([
      { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "write"] },
      { service: "svc-ci", projects: ["vaulter"], keys: ["DEPLOY_TOKEN"], verbs: ["rotate"] },
    ]);
    await seedValues();
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["rotate"], keys: ["DEPLOY_TOKEN"] } }),
    });
    expect(mint.status).toBe(200);
    const { token } = (await mint.json()) as { token: string };

    // Rotasyonun değer yazımı normal write rotasından geçer → rotate scope kapsar.
    const put = await callGate("/v1/projects/vaulter/keys/DEPLOY_TOKEN", {
      method: "PUT",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ value: "rotated" }),
    });
    expect(put.status).toBe(200);

    // rotate, read'e GENİŞLEMEZ (yalnızca write'a).
    const read = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }),
    });
    expect(read.status).toBe(403);
  });

  it("revoked jti → TOKEN_REVOKED on next use (admin revoke via /v1/admin/token/revoke)", async () => {
    await seedValues();
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] } }),
    });
    const { token, jti } = (await mint.json()) as { token: string; jti: string };

    const rev = await callGate("/v1/admin/token/revoke", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL))),
      body: JSON.stringify({ jti }),
    });
    expect(rev.status).toBe(200);

    const res = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_REVOKED");
    // token.revoke audit satırı yazıldı.
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "token.revoke" && r.decision === "allow")).toBe(true);
  });
});

describe("minted token PRINCIPAL BINDING — cross-principal use rejected", () => {
  it("svc-ci'ye mint'lenmiş token'ı başka bir service principal sunarsa → TOKEN_PRINCIPAL_MISMATCH + deny audit", async () => {
    await seedValues();
    // svc-ci kendi policy satırı içinde mint'ler (meşru).
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] } }),
    });
    expect(mint.status).toBe(200);
    const { token } = (await mint.json()) as { token: string };

    // svc-other, KENDİ geçerli CF Access JWT'si + YAKALANMIŞ minted Bearer ile
    // gelir: policy svc-ci'nin sub'ı üzerinden DEĞERLENDİRİLMEMELİ → 403.
    const stolen = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(serviceTokenClaims("svc-other")), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }),
    });
    expect(stolen.status).toBe(403);
    expect(((await stolen.json()) as { error: string }).error).toBe("TOKEN_PRINCIPAL_MISMATCH");

    // Deny, DIŞ (gerçek) principal adına audit'lendi.
    const rows = await allAuditRows();
    expect(
      rows.some(
        (r) => r.verb === "token.use" && r.decision === "deny" && r.principal === "service:svc-other" && r.intent === "TOKEN_PRINCIPAL_MISMATCH",
      ),
    ).toBe(true);

    // Kontrast: aynı token'ı KENDİ ihraççısı (svc-ci) sunarsa çalışmaya devam eder.
    const legit = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await svcJwt(), { Authorization: `Bearer ${token}` }),
      body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }),
    });
    expect(legit.status).toBe(200);
  });
});

describe("minted token on ADMIN routes — rejected (§5.3 scope-escalation guard)", () => {
  it("minted token is DENIED admin even when the parent service row grants admin; bare service token passes", async () => {
    await seedPolicy([
      { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "write"] },
      { service: "svc-ci", projects: ["vaulter"], keys: ["DEPLOY_TOKEN"], verbs: ["*"] },
    ]);
    // read-AUD service JWT ile read-scoped mint (policy satırı kapsıyor → 200).
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await svcJwt()),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DEPLOY_TOKEN"] } }),
    });
    expect(mint.status).toBe(200);
    const { token } = (await mint.json()) as { token: string };

    // Edge write-app'e kabul edilmiş service JWT + minted Bearer: parent satır
    // admin/["*"] verse bile minted principal admin rotasında RED (scope kesişimi —
    // MINTABLE_VERBS admin içermez, scope asla genişlemez).
    const writeSvcJwt = await signer.makeJWT(serviceTokenClaims("svc-ci", { aud: [AUD_WRITE] }));
    const denied = await callGate("/v1/policy", { headers: authHeader(writeSvcJwt, { Authorization: `Bearer ${token}` }) });
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: string }).error).toBe("GRANT_DENIED");

    // Kontrast: minted token OLMADAN service principal admin satırıyla GEÇER (§5.1).
    const ok = await callGate("/v1/policy", { headers: authHeader(writeSvcJwt) });
    expect(ok.status).toBe(200);

    // Deny, minted_token intent'iyle audit'lendi.
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "policy.read" && r.decision === "deny" && r.intent === "minted_token")).toBe(true);
  });
});
