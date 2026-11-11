// Per-principal rate limiting (SPEC §6.1). Every authenticated principal gets 60
// requests per 60 s. Past that the gate answers 429 RATE_LIMITED + Retry-After, and
// the refusal is audited as a denial (§6.5, 304 freshness polls excepted — the
// caller decides that).
//
// The counter is the Workers Rate Limiting binding (RATE_LIMITER, wrangler
// `ratelimits`). It replaced a KV counter that wrote one key per request: KV allows
// about one write per second per key, so a burst from one principal threw
// "KV PUT failed: 429" and the request ended in HTTP 500.
//
// The binding is approximate and local to the Cloudflare location serving the
// request (counts sync in the background). That is enough for §6.1: the limiter
// stops accidental loops and bursts, it is not an auth control. The limit and the
// period live in the binding config (wrangler.jsonc / wrangler.staging.jsonc);
// the constants below mirror them for the Retry-After value and the tests.

export const RATE_LIMIT = 60;
export const RATE_PERIOD_S = 60;

export interface RateEnv {
  RATE_LIMITER: RateLimit;
}

export interface RateDecision {
  allowed: boolean;
  retryAfter: number; // seconds (only meaningful when !allowed)
}

/**
 * checkRateLimit asks the binding whether the principal may proceed. The key is the
 * principal id. The binding returns no reset time, so Retry-After is the whole
 * period: a safe upper bound, never too early.
 *
 * FAIL OPEN: if the binding throws, the request is allowed and the error is logged.
 * The gate is the only way to read secrets, so an outage of an abuse limiter must
 * not become an outage of the gate. Authentication and authorization run on their
 * own and stay fail-closed; the limiter only bounds volume.
 */
export async function checkRateLimit(env: RateEnv, principalId: string): Promise<RateDecision> {
  try {
    const { success } = await env.RATE_LIMITER.limit({ key: principalId });
    return { allowed: success, retryAfter: RATE_PERIOD_S };
  } catch (e) {
    console.error("rate limiter unavailable, allowing request:", e instanceof Error ? e.message : String(e));
    return { allowed: true, retryAfter: RATE_PERIOD_S };
  }
}
