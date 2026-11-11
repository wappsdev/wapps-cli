// Per-principal rate limiting tests (SPEC §6.1): 60 requests per 60 s per principal,
// enforced by the Workers Rate Limiting binding (RATE_LIMITER). The old KV counter
// wrote one key per request and KV allows ~1 write/s/key, so a burst from one
// principal threw "KV PUT failed: 429" and the request ended in HTTP 500.
//
// The tests drive the limiter with a FAKE binding that behaves like the real one
// (fixed limit per key, success=false past it), so the counts are deterministic and
// no wall clock is involved.
import { beforeAll, beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { createFakeRateLimiter, ensureJwks, resetWorld, validClaims, authHeader, callGate, seedPolicy, defaultRules, groupsByEmail, settleAudit } from "./helpers.js";
import { checkRateLimit, RATE_LIMIT, RATE_PERIOD_S } from "../src/ratelimit.js";

const fakeLimiter = createFakeRateLimiter;

/** throwingLimiter is a binding whose backend is down. */
function throwingLimiter(): RateLimit {
  return {
    async limit() {
      throw new Error("rate limiter backend unavailable");
    },
  };
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("checkRateLimit (§6.1)", () => {
  it(`first ${RATE_LIMIT} requests allowed, the next → denied + Retry-After = the period`, async () => {
    const env = { RATE_LIMITER: fakeLimiter() };
    const id = "human:writer@wapps.dev";
    for (let i = 0; i < RATE_LIMIT; i++) {
      expect((await checkRateLimit(env, id)).allowed).toBe(true);
    }
    const limited = await checkRateLimit(env, id);
    expect(limited.allowed).toBe(false);
    // The binding returns no reset time, so Retry-After is the whole period.
    expect(limited.retryAfter).toBe(RATE_PERIOD_S);
    expect(RATE_PERIOD_S).toBe(60);
    // Asking again stays refused.
    expect((await checkRateLimit(env, id)).allowed).toBe(false);
  });

  it("uses the principal id as the binding key; distinct principals have independent counters", async () => {
    const limiter = fakeLimiter();
    const env = { RATE_LIMITER: limiter };
    const a = "human:writer@wapps.dev";
    const b = "human:reader@wapps.dev";
    for (let i = 0; i < RATE_LIMIT; i++) await checkRateLimit(env, a);
    expect((await checkRateLimit(env, a)).allowed).toBe(false);
    expect((await checkRateLimit(env, b)).allowed).toBe(true);
    expect(new Set(limiter.calls)).toEqual(new Set([a, b]));
  });

  it("fails OPEN when the binding throws: the request is allowed and the failure is logged", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const d = await checkRateLimit({ RATE_LIMITER: throwingLimiter() }, "human:writer@wapps.dev");
    expect(d.allowed).toBe(true);
    expect(err).toHaveBeenCalledTimes(1);
    expect(String(err.mock.calls[0][0])).toContain("rate limiter");
  });
});

describe("rate limiting on the request path (§6.1)", () => {
  async function list(envOverride: Record<string, unknown>): Promise<Response> {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    return callGate("/v1/projects", { method: "GET", headers: authHeader(jwt) }, envOverride);
  }

  it("70 back-to-back requests from one principal → 60 allowed, 10 RATE_LIMITED, never a 500", async () => {
    const envOverride = { RATE_LIMITER: fakeLimiter() };
    const statuses: number[] = [];
    let last: Response | undefined;
    for (let i = 0; i < 70; i++) {
      last = await list(envOverride);
      statuses.push(last.status);
    }
    expect(statuses.filter((s) => s === 200)).toHaveLength(60);
    expect(statuses.filter((s) => s === 429)).toHaveLength(10);
    expect(statuses.filter((s) => s >= 500)).toHaveLength(0);

    // The refusal contract: 429 RATE_LIMITED + Retry-After, in the first 60 / last 10 order.
    expect(statuses.slice(0, 60).every((s) => s === 200)).toBe(true);
    expect(last!.status).toBe(429);
    expect(last!.headers.get("Retry-After")).toBe("60");
    const body = (await last!.json()) as { error: string; retry_after: number };
    expect(body.error).toBe("RATE_LIMITED");
    expect(body.retry_after).toBe(60);
  });

  it("a refused request writes a deny audit row (verb rate_limit)", async () => {
    const envOverride = { RATE_LIMITER: fakeLimiter(1) };
    expect((await list(envOverride)).status).toBe(200);
    expect((await list(envOverride)).status).toBe(429);
    const rows = await settleAudit("", (r) => r.some((x) => x.verb === "rate_limit"));
    const deny = rows.filter((x) => x.verb === "rate_limit");
    expect(deny).toHaveLength(1);
    expect(deny[0].decision).toBe("deny");
    expect(deny[0].principal).toBe("human:writer@wapps.dev");
  });

  it("a limiter outage does not take the gate down: the request still succeeds (fail open)", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await list({ RATE_LIMITER: throwingLimiter() });
    expect(res.status).toBe(200);
  });

  it("the deployed binding (wrangler.jsonc) is present and answers", async () => {
    const { env } = await import("cloudflare:test");
    const out = await env.RATE_LIMITER.limit({ key: "human:binding-smoke@wapps.dev" });
    expect(out.success).toBe(true);
  });
});
