// OAuth-session guard (work item 1cb9a4c1, reworked for Access Managed OAuth).
// Cloudflare Access admits the owner's Cloudflare One client (WARP) device session and
// then injects Cf-Access-Jwt-Assertion for ANY program on that device. A human principal
// is admitted only when the VERIFIED assertion carries the signed `oauth` claim of a
// client registered on a loopback redirect (a CLI on this machine), and is not a device
// session (`warp_as_auth`). The caller's headers, cookies and Authorization do not count.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  oauthClaim,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  settleAudit,
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

/** whoami, one READ request made with an assertion carrying `extra` claims. */
async function whoami(extra: Record<string, unknown>, headers: Record<string, string> = {}): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims(WRITER, extra));
  return callGate("/v1/whoami", { headers: authHeader(jwt, headers) });
}

describe("an assertion without the caller's own OAuth session does not admit a human", () => {
  it("no oauth claim (browser or device session) → 401 DEVICE_SESSION_ONLY and a deny audit row", async () => {
    const res = await whoami({ oauth: undefined });
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

  it("the refusal tells the caller to run wapps login", async () => {
    const res = await whoami({ oauth: undefined });
    expect(((await res.json()) as { message: string }).message).toContain("wapps login");
  });

  it("a cf-access-token header no longer admits anything", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER, { oauth: undefined }));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt, { "cf-access-token": jwt }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("a cf-access-token header changes nothing for an OAuth session either", async () => {
    const res = await whoami({}, { "cf-access-token": "not-a-jwt" });
    expect(res.status).toBe(200);
  });

  it("an Authorization bearer does not stand in for the oauth claim", async () => {
    const res = await whoami({ oauth: undefined }, { Authorization: "Bearer anything" });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  // Measured live 2026-11-23: for a device-session request Access itself adds the
  // CF_Authorization cookie to what reaches the Worker, so the cookie proves nothing.
  it("a matching CF_Authorization cookie alone → 401 (Access adds that cookie itself)", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER, { oauth: undefined }));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt, { Cookie: `theme=dark; CF_Authorization=${jwt}; other=1` }) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });
});

describe("an assertion with an oauth claim on a loopback redirect admits the human", () => {
  it("redirect on 127.0.0.1 → admitted", async () => {
    const res = await whoami({ oauth: oauthClaim({ client_redirect_uri: "http://127.0.0.1:5555/callback" }) });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { principal: string }).principal).toBe(`human:${WRITER}`);
  });

  it("redirect on localhost → admitted", async () => {
    const res = await whoami({ oauth: oauthClaim({ client_redirect_uri: "http://localhost:8123/callback" }) });
    expect(res.status).toBe(200);
  });

  it("redirect on 127.0.0.1 without a port → admitted", async () => {
    const res = await whoami({ oauth: oauthClaim({ client_redirect_uri: "http://127.0.0.1/callback" }) });
    expect(res.status).toBe(200);
  });

  it("extra oauth fields are ignored", async () => {
    const res = await whoami({ oauth: oauthClaim({ scope: "openid", extra: 1 }) });
    expect(res.status).toBe(200);
  });

  it("the WRITE assertion with an oauth claim reaches the admin route; without one it is refused", async () => {
    const ok = await callGate("/v1/admin/policy", { headers: authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL))) });
    expect(ok.status).toBe(200);

    const denied = await callGate("/v1/admin/policy", {
      headers: authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL, { oauth: undefined }))),
    });
    expect(denied.status).toBe(401);
    expect(await errorOf(denied)).toBe("DEVICE_SESSION_ONLY");
  });
});

describe("a device session is refused even when an oauth claim is present (warp_as_auth)", () => {
  it("warp_as_auth true with a valid oauth claim → 401 DEVICE_SESSION_ONLY", async () => {
    const res = await whoami({ warp_as_auth: true });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("warp_as_auth true without an oauth claim → 401 DEVICE_SESSION_ONLY", async () => {
    const res = await whoami({ warp_as_auth: true, oauth: undefined });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("warp_as_auth false with a valid oauth claim → admitted", async () => {
    const res = await whoami({ warp_as_auth: false });
    expect(res.status).toBe(200);
  });
});

describe("an oauth claim whose redirect is not exactly a loopback http URL is refused", () => {
  const redirects = [
    "https://evil.example/cb",
    "http://evil.example/cb",
    "http://127.0.0.1.evil.example/cb",
    "http://localhost.evil.example/cb",
    "http://evil.example/127.0.0.1",
    "http://evil.example/?next=http://127.0.0.1/",
    "http://127.0.0.1@evil.example/cb",
    "http://notlocalhost/cb",
    "http://[::1]:5555/cb",
    "http://127.0.0.2:5555/cb",
    "https://127.0.0.1:5555/cb",
    "ftp://127.0.0.1/cb",
  ];
  for (const uri of redirects) {
    it(`${uri} → 401 DEVICE_SESSION_ONLY`, async () => {
      const res = await whoami({ oauth: oauthClaim({ client_redirect_uri: uri }) });
      expect(res.status).toBe(401);
      expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
    });
  }

  for (const uri of ["", "not a url", "127.0.0.1:5555/cb", "/callback", 5555, null, ["http://127.0.0.1/cb"]]) {
    it(`redirect ${JSON.stringify(uri)} (not a URL) → 401 DEVICE_SESSION_ONLY`, async () => {
      const res = await whoami({ oauth: oauthClaim({ client_redirect_uri: uri }) });
      expect(res.status).toBe(401);
      expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
    });
  }

  it("no client_redirect_uri → 401 DEVICE_SESSION_ONLY", async () => {
    const res = await whoami({ oauth: { client_id: "client-test" } });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });
});

describe("a malformed oauth claim is refused", () => {
  const claims: [string, unknown][] = [
    ["a string", "http://127.0.0.1/cb"],
    ["a number", 1],
    ["true", true],
    ["null", null],
    ["an array", [{ client_id: "client-test", client_redirect_uri: "http://127.0.0.1/cb" }]],
    ["an empty object", {}],
    ["an empty client_id", oauthClaim({ client_id: "" })],
    ["a missing client_id", { client_redirect_uri: "http://127.0.0.1/cb" }],
    ["a numeric client_id", oauthClaim({ client_id: 7 })],
    ["a null client_id", oauthClaim({ client_id: null })],
  ];
  for (const [what, oauth] of claims) {
    it(`oauth as ${what} → 401 DEVICE_SESSION_ONLY`, async () => {
      const res = await whoami({ oauth });
      expect(res.status).toBe(401);
      expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
    });
  }
});

describe("the service-token path is unchanged", () => {
  it("a service token with no oauth claim → admitted", async () => {
    const jwt = await signer.makeJWT(serviceTokenClaims("svc-woodpecker"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { principal: string }).principal).toBe("service:svc-woodpecker");
  });

  it("a service token with a cf-access-token header → admitted as before", async () => {
    const jwt = await signer.makeJWT(serviceTokenClaims("svc-woodpecker"));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt, { "cf-access-token": "ignored" }) });
    expect(res.status).toBe(200);
  });
});
