// CF Access auth middleware testleri (SPEC §3.1 — KEPT davranışlar): accept +
// reject (bad aud/iss, missing assertion, forged email header, expired, bad alg),
// service-token şekli (v2: data-plane'e DOĞRUDAN kabul, §5.1).

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  serviceTokenClaims,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  ISSUER,
  AUD_READ,
} from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});

async function body(res: Response): Promise<{ error?: string }> {
  return (await res.json()) as { error?: string };
}

describe("auth middleware (§3.1)", () => {
  it("ACCEPT: valid human JWT → 200 on /v1/whoami", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
  });

  it("REJECT: missing Cf-Access-Jwt-Assertion → 401 AUTH_REQUIRED", async () => {
    const res = await callGate("/v1/whoami", { headers: {} });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_REQUIRED");
  });

  it("REJECT: wrong audience → 403 AUD_MISMATCH", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev", { aud: ["wrong-audience"] }));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect((await body(res)).error).toBe("AUD_MISMATCH");
  });

  it("REJECT: wrong issuer → 401 ISSUER_MISMATCH (issuer pinning)", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev", { iss: "https://evil-team.cloudflareaccess.com" }));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("ISSUER_MISMATCH");
  });

  it("REJECT: expired token (beyond leeway) → 401 AUTH_EXPIRED", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], email: "writer@wapps.dev", nbf: now - 4000, exp: now - 3600 });
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_EXPIRED");
  });

  it("REJECT: token with NO exp claim → 401 AUTH_INVALID (exp zorunlu)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], email: "writer@wapps.dev", nbf: now - 10 });
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_INVALID");
  });

  it("REJECT: unexpected alg (none) → 401 AUTH_INVALID", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"), { alg: "none" });
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_INVALID");
  });

  it("STRIP: forged Cf-Access-Authenticated-User-Email alone (no JWT) → 401 AUTH_REQUIRED", async () => {
    const res = await callGate("/v1/whoami", { headers: { "Cf-Access-Authenticated-User-Email": "attacker@evil.com" } });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_REQUIRED");
  });

  it("STRIP: forged email header is IGNORED — identity comes from the signed JWT", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt, { "Cf-Access-Authenticated-User-Email": "attacker@evil.com" }) });
    expect(res.status).toBe(200);
    const b = (await res.json()) as { principal: string };
    expect(b.principal).toBe("human:writer@wapps.dev"); // header DEĞİL, JWT kimliği
  });

  it("SERVICE: common_name JWT resolves to service:<cn> and skips group resolution (§3.2)", async () => {
    const jwt = await signer.makeJWT(serviceTokenClaims("svc-woodpecker"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const b = (await res.json()) as { principal: string; kind: string; groups: string[] };
    expect(b.principal).toBe("service:svc-woodpecker");
    expect(b.kind).toBe("service");
    expect(b.groups).toEqual([]);
  });

  it("REJECT: JWT with neither email nor common_name → 401 AUTH_INVALID", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], nbf: now - 10, exp: now + 3600 });
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_INVALID");
  });

  it("FAIL-CLOSED CONFIG: missing MASTER_KEK / ADMIN_EMAILS → 503 on every route (§3.1)", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    for (const override of [{ MASTER_KEK: "" }, { ADMIN_EMAILS: "" }, { ACCESS_TEAM_DOMAIN: "" }]) {
      const res = await callGate("/v1/whoami", { headers: authHeader(jwt) }, override);
      expect(res.status).toBe(503);
      expect((await body(res)).error).toBe("SERVICE_MISCONFIGURED");
    }
  });
});
