// Per-principal rate limiting testleri (SPEC §6.1): 60/dk sabit pencere → 429 +
// Retry-After. Determinizm için `now` ENJEKTE edilir (sabit pencere): gerçek
// wall-clock kullanmayız → 61 istek dakika-sınırını straddle edip 200-vs-429
// flakiness'i üretemez (G7 flake fix).
import { beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { resetWorld } from "./helpers.js";
import { checkRateLimit, RATE_LIMIT } from "../src/ratelimit.js";

beforeEach(resetWorld);

// Sabit pencere-içi bir an (pencere ortası): enjekte edilen `now` ile tüm istekler
// AYNI pencerede kalır → deterministik LIMIT×allowed sonra denied.
const FIXED_NOW = 1_800_000_030_000; // 60_000'in katı DEĞİL → retryAfter > 0

describe("rate limiting (§6.1)", () => {
  it(`first ${RATE_LIMIT} requests allowed, the next → denied + Retry-After (fixed clock)`, async () => {
    const id = "human:writer@wapps.dev";
    // İlk LIMIT istek geçer (aynı pencere, resetWorld sayaç sıfırladı).
    for (let i = 0; i < RATE_LIMIT; i++) {
      const d = await checkRateLimit(env, id, FIXED_NOW);
      expect(d.allowed).toBe(true);
    }
    // LIMIT+1. istek → red.
    const limited = await checkRateLimit(env, id, FIXED_NOW);
    expect(limited.allowed).toBe(false);
    expect(limited.retryAfter).toBeGreaterThan(0);
    // Tekrar denemek de reddedilir (sayaç artmaz, deterministik).
    const again = await checkRateLimit(env, id, FIXED_NOW);
    expect(again.allowed).toBe(false);
  });

  it("distinct principals have independent counters (fixed clock)", async () => {
    const a = "human:writer@wapps.dev";
    const b = "human:reader@wapps.dev";
    for (let i = 0; i < RATE_LIMIT; i++) await checkRateLimit(env, a, FIXED_NOW);
    // A tükendi; B hâlâ geçmeli.
    expect((await checkRateLimit(env, a, FIXED_NOW)).allowed).toBe(false);
    expect((await checkRateLimit(env, b, FIXED_NOW)).allowed).toBe(true);
  });
});
