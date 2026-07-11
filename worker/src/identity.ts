// Kimlik/grup çözümü (SPEC §3.2–§3.4). Google Workspace grupları Access JWT'sinde
// YOKTUR; human principal'lar için Worker, doğrulanmış app token'ıyla get-identity'yi
// çağırır ve grup e-postalarını çıkarır:
//   GET https://{ACCESS_TEAM_DOMAIN}/cdn-cgi/access/get-identity
//   Cookie: CF_Authorization=<doğrulanmış Access JWT>
//
// KV cache (ident:<sha256(jwt)>, TTL 300 s) YALNIZCA gecikme optimizasyonudur —
// grup-tazeliği sınırı DEĞİLDİR (§3.4: deny sınırı = Access session revoke / session
// ömrü). Yeni login = yeni JWT = cache miss = taze çözüm. DOĞRUDAN üyelikler (nested
// grup açılımı YOK). get-identity hatası → fail-closed IDENTITY_UNAVAILABLE (503).
//
// FALLBACK topolojisi (§3.3, per-project Access app'leri): GroupResolver arayüzü
// dar tutulmuştur — day-1 smoke test FALLBACK'i seçerse get-identity çağrısı yerine
// aud→projects haritalı, get-identity'siz bir resolver takılır (Worker iss+aud-only
// kalır); route/policy katmanı değişmez.

import { sha256Hex, utf8 } from "./crypto/encoding.js";

/** IdentityError, get-identity erişilemez/şekil-dışı → 503 IDENTITY_UNAVAILABLE. */
export class IdentityError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "IdentityError";
  }
}

/**
 * GroupResolver, human principal'ın grup kümesini çözer. PRIMARY implementasyonu
 * get-identity + KV cache'tir; FALLBACK topolojisinde get-identity'siz bir
 * implementasyonla değiştirilir (§3.3). Service principal'lar bu arayüze HİÇ girmez.
 */
export interface GroupResolver {
  resolve(jwt: string, email: string): Promise<string[]>;
}

interface CachedIdentity {
  email: string;
  groups: string[];
  cachedAt: string;
}

const CACHE_TTL_S = 300; // ~5 dk (§3.2 adım 3) — SADECE gecikme optimizasyonu
const CACHE_PREFIX = "ident:";

/** ShapeDriftAlert, A10 (kimlik-endpoint şekil kayması) tetikleyicisi (§3.2 adım 2). */
export type ShapeDriftAlert = (summary: string, detail?: Record<string, unknown>) => void;

/**
 * extractGroups, get-identity dokümanından grup TANIMLAYICILARINI (Google grup
 * e-postaları) çıkarır. Toleranslı şekiller (§3.2 adım 2): `groups` düz string
 * dizisi VEYA {email|name|id} obje dizisi. Başka her şekil → şekil kayması (A10)
 * + fail-closed IdentityError. Alan hiç yoksa da şekil kayması sayılır: PRIMARY
 * topolojisi ancak gruplar bu şekilde görünüyorsa seçilir (§8.1 adım 8).
 */
export function extractGroups(doc: unknown): string[] {
  if (typeof doc !== "object" || doc === null) throw new IdentityError("identity document not an object");
  const groups = (doc as Record<string, unknown>).groups;
  if (!Array.isArray(groups)) throw new IdentityError("identity document has no groups array");
  const out: string[] = [];
  for (const g of groups) {
    if (typeof g === "string") {
      out.push(g);
      continue;
    }
    if (typeof g === "object" && g !== null && !Array.isArray(g)) {
      const o = g as Record<string, unknown>;
      const ident = o.email ?? o.name ?? o.id;
      if (typeof ident === "string" && ident !== "") {
        out.push(ident);
        continue;
      }
    }
    throw new IdentityError("unrecognized group entry shape");
  }
  return out;
}

/**
 * createGroupResolver, PRIMARY get-identity resolver'ını kurar (§3.2).
 * fetcher enjekte edilebilir (test); üretimde global fetch.
 */
export function createGroupResolver(
  teamDomain: string,
  cache: KVNamespace,
  onShapeDrift: ShapeDriftAlert,
  fetcher: typeof fetch = fetch,
): GroupResolver {
  const identityURL = `https://${teamDomain}/cdn-cgi/access/get-identity`;
  return {
    async resolve(jwt: string, email: string): Promise<string[]> {
      // 3. KV cache: anahtar jwt hash'i → yeni login (yeni JWT) daima yeniden çözer.
      const cacheKey = CACHE_PREFIX + sha256Hex(utf8(jwt));
      try {
        const hit = await cache.get(cacheKey);
        if (hit) {
          const parsed = JSON.parse(hit) as CachedIdentity;
          if (Array.isArray(parsed.groups)) return parsed.groups;
        }
      } catch {
        // Cache okunamadı → get-identity'ye düş (cache yalnızca optimizasyon).
      }

      // 1-2. get-identity + çıkarım. Hata (non-200, ağ, parse, şekil) → fail-closed.
      let res: Response;
      try {
        res = await fetcher(identityURL, { headers: { Cookie: `CF_Authorization=${jwt}` } });
      } catch {
        throw new IdentityError("get-identity unreachable");
      }
      if (!res.ok) throw new IdentityError(`get-identity status ${res.status}`);
      let doc: unknown;
      try {
        doc = await res.json();
      } catch {
        throw new IdentityError("get-identity response unparsable");
      }
      let groups: string[];
      try {
        groups = extractGroups(doc);
      } catch (e) {
        // Şekil kayması → A10 + fail-closed (§3.2 adım 2 / alert envanteri A10).
        onShapeDrift("get-identity shape drift: groups not extractable", { error: (e as Error).message });
        throw e;
      }

      const entry: CachedIdentity = { email, groups, cachedAt: new Date().toISOString() };
      try {
        await cache.put(cacheKey, JSON.stringify(entry), { expirationTtl: CACHE_TTL_S });
      } catch {
        // Cache yazılamadıysa da sonuç geçerli (yalnızca gecikme optimizasyonu).
      }
      return groups;
    },
  };
}
