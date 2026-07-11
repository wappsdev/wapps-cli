// Kimlik/grup çözümü testleri (SPEC §3.2/§3.4): get-identity çıkarımı (iki
// toleranslı şekil + şekil kayması A10), KV cache (jwt-hash anahtarlı, SADECE
// gecikme optimizasyonu), fail-closed IDENTITY_UNAVAILABLE.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { extractGroups, createGroupResolver, IdentityError } from "../src/identity.js";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  setIdentityMode,
  identityCalls,
  discordCalls,
  TEAM_DOMAIN,
} from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

describe("extractGroups (§3.2 adım 2 — fixture şekilleri)", () => {
  it("plain string array", () => {
    expect(extractGroups({ email: "a@b.c", groups: ["g1@x.co", "g2@x.co"] })).toEqual(["g1@x.co", "g2@x.co"]);
  });
  it("object array: email > name > id önceliği", () => {
    expect(
      extractGroups({ groups: [{ email: "g1@x.co", name: "G1" }, { name: "G2" }, { id: "0abc" }] }),
    ).toEqual(["g1@x.co", "G2", "0abc"]);
  });
  it("empty array geçerli (grupsuz kullanıcı edge'de zaten reddedilir)", () => {
    expect(extractGroups({ groups: [] })).toEqual([]);
  });
  it("şekil kayması → throw (alan yok / yanlış tip / tanımlayıcısız obje)", () => {
    expect(() => extractGroups({})).toThrowError(IdentityError);
    expect(() => extractGroups({ groups: "dev" })).toThrowError(IdentityError);
    expect(() => extractGroups({ groups: [42] })).toThrowError(IdentityError);
    expect(() => extractGroups({ groups: [{ slug: "x" }] })).toThrowError(IdentityError);
  });
});

describe("GroupResolver (get-identity + KV cache)", () => {
  it("resolves groups; ikinci çağrı KV cache'ten (get-identity'ye tek gidiş)", async () => {
    groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
    const alerts: string[] = [];
    const resolver = createGroupResolver(TEAM_DOMAIN, env.IDENTITY_CACHE, (s) => alerts.push(s));
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const before = identityCalls;
    expect(await resolver.resolve(jwt, "writer@wapps.dev")).toEqual(["developers@wapps.co"]);
    expect(identityCalls).toBe(before + 1);
    expect(await resolver.resolve(jwt, "writer@wapps.dev")).toEqual(["developers@wapps.co"]);
    expect(identityCalls).toBe(before + 1); // cache hit — ek fetch yok
    // FARKLI JWT (yeni login) → cache miss → taze çözüm (§3.2: hash anahtarı jwt).
    const jwt2 = await signer.makeJWT(validClaims("writer@wapps.dev"));
    await resolver.resolve(jwt2, "writer@wapps.dev");
    expect(identityCalls).toBe(before + 2);
    expect(alerts.length).toBe(0);
  });

  it("get-identity down → IdentityError (fail-closed; boş grupla ASLA ilerlenmez)", async () => {
    setIdentityMode("down");
    const resolver = createGroupResolver(TEAM_DOMAIN, env.IDENTITY_CACHE, () => {});
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    await expect(resolver.resolve(jwt, "writer@wapps.dev")).rejects.toThrowError(IdentityError);
  });

  it("şekil kayması → A10 callback + fail-closed", async () => {
    setIdentityMode("badshape");
    const alerts: string[] = [];
    const resolver = createGroupResolver(TEAM_DOMAIN, env.IDENTITY_CACHE, (s) => alerts.push(s));
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    await expect(resolver.resolve(jwt, "writer@wapps.dev")).rejects.toThrowError(IdentityError);
    expect(alerts.length).toBe(1);
  });
});

describe("Worker entegrasyonu (§3.2 adım 5)", () => {
  it("human isteğinde get-identity down → 503 IDENTITY_UNAVAILABLE + A10 fires on shape drift", async () => {
    await seedPolicy(defaultRules());
    setIdentityMode("down");
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("IDENTITY_UNAVAILABLE");
  });

  it("şekil kayması worker yolunda → 503 + Discord A10 alert'i", async () => {
    await seedPolicy(defaultRules());
    setIdentityMode("badshape");
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(503);
    expect(discordCalls.some((c) => c.body.includes("A10"))).toBe(true);
  });

  it("whoami çözülmüş grupları + efektif kuralları döner", async () => {
    await seedPolicy(defaultRules());
    groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { principal: string; groups: string[]; grants: unknown[]; is_root_admin: boolean };
    expect(body.principal).toBe("human:writer@wapps.dev");
    expect(body.groups).toEqual(["developers@wapps.co"]);
    expect(body.grants.length).toBe(1); // developers kuralı
    expect(body.is_root_admin).toBe(false);
  });
});
