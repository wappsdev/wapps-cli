// Device-session guard (work item 1cb9a4c1). Cloudflare Access admits the owner's
// Cloudflare One client (WARP) device session and then injects Cf-Access-Jwt-Assertion
// for ANY program on that device. A human principal is admitted only when the caller
// also presents its own Access app token (cf-access-token header, or the CF_Authorization
// cookie) that verifies like the assertion and names the same subject.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  makeAccessSigner,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  assertionOnly,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  settleAudit,
  subOf,
  ISSUER,
  AUD_READ,
  ADMIN_EMAIL,
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

const WRITER = "writer@wapps.dev";

async function errorOf(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { error?: string }).error;
}

describe("device session alone does not admit a human (1cb9a4c1)", () => {
  it("assertion only → 401 DEVICE_SESSION_ONLY and a deny audit row", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");

    const rows = await settleAudit("", (r) => r.some((x) => x.decision === "deny"));
    const deny = rows.filter((x) => x.decision === "deny");
    expect(deny).toHaveLength(1);
    expect(deny[0].principal).toBe(`human:${WRITER}`);
    expect(deny[0].principal_type).toBe("human");
    expect(deny[0].verb).toBe("auth");
    expect(deny[0].intent).toBe("DEVICE_SESSION_ONLY");
  });

  it("assertion + matching cf-access-token header → admitted", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const presented = await signer.makeJWT(validClaims(WRITER, { iat: Math.floor(Date.now() / 1000) - 5 }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": presented }) });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { principal: string }).principal).toBe(`human:${WRITER}`);
  });

  it("assertion + matching CF_Authorization cookie → admitted", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { Cookie: `theme=dark; CF_Authorization=${jwt}; other=1` }) });
    expect(res.status).toBe(200);
  });

  it("presented token for another person → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const other = await signer.makeJWT(validClaims("other@wapps.dev"));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": other }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("presented token with the same email but another sub → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const other = await signer.makeJWT(validClaims(WRITER, { sub: subOf("other@wapps.dev") }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": other }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("presented token with the same sub but another email → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const other = await signer.makeJWT(validClaims("other@wapps.dev", { sub: subOf(WRITER) }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": other }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("assertion and presented token without a sub → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER, { sub: undefined }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": jwt }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("presented READ token on a write route → 401; the write token → admitted", async () => {
    const assertion = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const readToken = await signer.makeJWT(validClaims(ADMIN_EMAIL));
    const denied = await callGate("/v1/admin/policy", { headers: assertionOnly(assertion, { "cf-access-token": readToken }) });
    expect(denied.status).toBe(401);
    expect(await errorOf(denied)).toBe("DEVICE_SESSION_ONLY");

    const ok = await callGate("/v1/admin/policy", { headers: assertionOnly(assertion, { "cf-access-token": assertion }) });
    expect(ok.status).toBe(200);
  });

  it("expired presented token → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const now = Math.floor(Date.now() / 1000);
    const expired = await signer.makeJWT(validClaims(WRITER, { nbf: now - 4000, exp: now - 3600 }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": expired }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("garbage presented token (header or cookie) → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const cases: Record<string, string>[] = [{ "cf-access-token": "not-a-jwt" }, { Cookie: "CF_Authorization=a.b.c" }, { "cf-access-token": "" }];
    for (const extra of cases) {
      const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, extra) });
      expect(res.status).toBe(401);
      expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
    }
  });

  it("presented token signed by a key outside the Access JWKS → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const forger = await makeAccessSigner(); // same kid, another key
    const forged = await forger.makeJWT(validClaims(WRITER));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": forged }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("presented token from another issuer → 401", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const foreign = await signer.makeJWT(validClaims(WRITER, { iss: "https://evil-team.cloudflareaccess.com" }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": foreign }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("service token principal with no presented token → admitted as before", async () => {
    const jwt = await signer.makeJWT(serviceTokenClaims("svc-woodpecker"));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt) });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { principal: string }).principal).toBe("service:svc-woodpecker");
  });

  it("a presented service token does not stand in for a human's own token", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const svc = await signer.makeJWT(serviceTokenClaims("svc-woodpecker", { aud: [AUD_READ], iss: ISSUER }));
    const res = await callGate("/v1/whoami", { headers: assertionOnly(jwt, { "cf-access-token": svc }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });
});
