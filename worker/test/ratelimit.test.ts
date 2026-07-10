// Per-principal rate limiting testleri (SPEC §6.1): 60/dk sabit pencere → 429 +
// Retry-After.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, resetWorld } from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

describe("rate limiting (§6.1)", () => {
  it("60 requests pass, the 61st → 429 RATE_LIMITED + Retry-After", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    // İlk 60 istek geçer (aynı pencere, resetWorld sayaç sıfırladı).
    for (let i = 0; i < 60; i++) {
      const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
      expect(res.status).toBe(200);
    }
    // 61. istek → 429.
    const limited = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(limited.status).toBe(429);
    expect(((await limited.json()) as { error: string }).error).toBe("RATE_LIMITED");
    const retryAfter = limited.headers.get("retry-after");
    expect(retryAfter).toBeTruthy();
    expect(Number(retryAfter)).toBeGreaterThan(0);
  });

  it("distinct principals have independent counters", async () => {
    const t = await seedTrust();
    const jwtA = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const jwtB = await signer.makeJWT(validClaims("reader@wapps.dev"));
    for (let i = 0; i < 60; i++) await callGate("/v1/trust/current", { headers: authHeader(jwtA) }, t.pin);
    // A tükendi; B hâlâ geçmeli.
    const aLimited = await callGate("/v1/trust/current", { headers: authHeader(jwtA) }, t.pin);
    expect(aLimited.status).toBe(429);
    const bOk = await callGate("/v1/trust/current", { headers: authHeader(jwtB) }, t.pin);
    expect(bOk.status).toBe(200);
  });
});
