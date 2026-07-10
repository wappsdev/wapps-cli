// CF Access auth middleware testleri (SPEC §6.1): accept + reject (bad aud/iss,
// missing assertion, forged email header, expired, bad alg, service-token).
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, clearBucket, ISSUER, AUD_READ } from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;

beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(clearBucket);

async function body(res: Response): Promise<{ error?: string }> {
  return (await res.json()) as { error?: string };
}

describe("auth middleware", () => {
  it("ACCEPT: valid enrolled human JWT → 200", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
  });

  it("REJECT: missing Cf-Access-Jwt-Assertion → 401 AUTH_REQUIRED", async () => {
    const t = await seedTrust();
    const res = await callGate("/v1/trust/current", { headers: {} }, t.pin);
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_REQUIRED");
  });

  it("REJECT: wrong audience → 403 AUD_MISMATCH", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev", { aud: ["wrong-audience"] }));
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(403);
    expect((await body(res)).error).toBe("AUD_MISMATCH");
  });

  it("REJECT: wrong issuer → 401 ISSUER_MISMATCH (delta vs cfaccess.go)", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev", { iss: "https://evil-team.cloudflareaccess.com" }));
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("ISSUER_MISMATCH");
  });

  it("REJECT: expired token (beyond leeway) → 401 AUTH_EXPIRED", async () => {
    const t = await seedTrust();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], email: "writer@wapps.dev", nbf: now - 4000, exp: now - 3600 });
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_EXPIRED");
  });

  it("REJECT: token with NO exp claim → 401 AUTH_INVALID (exp zorunlu, §6.1 step 4)", async () => {
    const t = await seedTrust();
    const now = Math.floor(Date.now() / 1000);
    // exp KASITLI olarak yok → süresiz token; imza geçerli olsa da reddedilmeli.
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], email: "writer@wapps.dev", nbf: now - 10 });
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_INVALID");
  });

  it("REJECT: unexpected alg (none) → 401 AUTH_INVALID", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"), { alg: "none" });
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_INVALID");
  });

  it("STRIP: forged Cf-Access-Authenticated-User-Email alone (no JWT) → 401 AUTH_REQUIRED", async () => {
    const t = await seedTrust();
    const res = await callGate(
      "/v1/trust/current",
      { headers: { "Cf-Access-Authenticated-User-Email": "attacker@evil.com" } },
      t.pin,
    );
    expect(res.status).toBe(401);
    expect((await body(res)).error).toBe("AUTH_REQUIRED");
  });

  it("STRIP: forged email header is IGNORED — identity comes from the signed JWT", async () => {
    const t = await seedTrust();
    // JWT email = enrolled writer; forged header = unenrolled attacker.
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate(
      "/v1/trust/current",
      { headers: authHeader(jwt, { "Cf-Access-Authenticated-User-Email": "attacker@evil.com" }) },
      t.pin,
    );
    // 200 = principal resolved to the JWT's writer (enrolled), NOT the forged attacker (would 403).
    expect(res.status).toBe(200);
  });

  it("REJECT: service-token identity on a data route → 403 MACHINE_TOKEN_REQUIRED (minted token = G7)", async () => {
    const t = await seedTrust();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signer.makeJWT({ iss: ISSUER, aud: [AUD_READ], common_name: "tofu-sync-vaulter", nbf: now - 10, exp: now + 3600 });
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(403);
    expect((await body(res)).error).toBe("MACHINE_TOKEN_REQUIRED");
  });
});
