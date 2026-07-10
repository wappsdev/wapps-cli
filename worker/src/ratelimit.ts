// Per-principal rate limiting (SPEC §6.1). Her kimlik doğrulanmış principal 60
// istek/dk (sabit pencere) ile sınırlı. Aşım → 429 RATE_LIMITED + Retry-After
// (saniye). Sayaç KV'de (RATE binding). Rate-limit red'leri denial olarak audit'lenir
// (§6.5), 304 freshness poll'ları HARİÇ (çağıran tarafın kararı).

const LIMIT = 60;
const WINDOW_MS = 60_000;

export interface RateEnv {
  RATE: KVNamespace;
}

export interface RateDecision {
  allowed: boolean;
  retryAfter: number; // saniye (yalnızca !allowed)
  count: number;
}

/**
 * checkRateLimit, principal için sabit-pencere sayaç kontrolü yapar. Pencere
 * anahtarı = rl:<principal>:<windowStart>. Sınır aşılırsa allowed=false + Retry-After.
 * KV eventual-consistency: sayım yaklaşıktır (kabul edilen; §6.1 "KV or DO counter").
 */
export async function checkRateLimit(env: RateEnv, principalId: string): Promise<RateDecision> {
  const now = Date.now();
  const windowStart = Math.floor(now / WINDOW_MS) * WINDOW_MS;
  const key = `rl:${principalId}:${windowStart}`;
  const raw = await env.RATE.get(key);
  const count = raw ? parseInt(raw, 10) || 0 : 0;
  const retryAfter = Math.max(1, Math.ceil((windowStart + WINDOW_MS - now) / 1000));
  if (count >= LIMIT) {
    return { allowed: false, retryAfter, count };
  }
  // TTL 2 pencere → eski sayaçlar kendiliğinden düşer.
  await env.RATE.put(key, String(count + 1), { expirationTtl: 120 });
  return { allowed: true, retryAfter, count: count + 1 };
}

export const RATE_LIMIT = LIMIT;
