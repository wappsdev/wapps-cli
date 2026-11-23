// The long READ session (work item 204fffcc). `wapps login` keeps the 6h READ app on the
// gate's own host; `wapps login --long` signs in to a second READ app on a sibling host
// (ACCESS_LONG_HOST, gw-long.meapps.dev) whose session is 24h. One Access app gives one
// session length, so the long session has its own app and its own AUD
// (ACCESS_AUD_READ_LONG). The Worker binds each AUD to its host:
//   - the long AUD is accepted only on the long host, and there only the long AUD;
//   - the long host serves no admin route: the WRITE app (gw.meapps.dev/v1/admin, 15m)
//     stays the only way to one;
//   - the caller's own OAuth session (the signed `oauth` claim) is required on the long host too.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  authHeader,
  callGate,
  callGateAt,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  ADMIN_EMAIL,
  AUD_READ_LONG,
  LONG_HOST,
} from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set(ADMIN_EMAIL, ["admins@wapps.co"]);
});

const WRITER = "writer@wapps.dev";

function longClaims(email = WRITER, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return validClaims(email, { aud: [AUD_READ_LONG], ...extra });
}

async function errorOf(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { error?: string }).error;
}

describe("the long READ app's AUD is bound to the long host (204fffcc)", () => {
  it("a long token on the long host → admitted", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { principal: string }).principal).toBe(`human:${WRITER}`);
  });

  it("a long token reads and writes keys on the long host as the READ token does", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const put = await callGateAt(LONG_HOST, "/v1/projects/vaulter/keys/DATABASE_URL", {
      method: "PUT",
      headers: authHeader(jwt),
      body: JSON.stringify({ value: "postgres://long" }),
    });
    expect(put.status).toBe(200);
    const read = await callGateAt(LONG_HOST, "/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(jwt),
      body: JSON.stringify({ keys: ["DATABASE_URL"] }),
    });
    expect(read.status).toBe(200);
    expect(((await read.json()) as { values: Record<string, string> }).values.DATABASE_URL).toBe("postgres://long");
  });

  it("a long token on the gate's own host → 403 AUD_MISMATCH", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("AUD_MISMATCH");
  });

  it("the 6h READ token on the long host → 403 AUD_MISMATCH", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("AUD_MISMATCH");
  });

  it("a WRITE token on a data route of the long host → 403 AUD_MISMATCH", async () => {
    const jwt = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("AUD_MISMATCH");
  });

  it("the 6h READ token still works on the gate's own host", async () => {
    const jwt = await signer.makeJWT(validClaims(WRITER));
    const res = await callGate("/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
  });
});

describe("the caller's own OAuth session is required on the long host too (1cb9a4c1)", () => {
  it("a long assertion without an oauth claim → 401 DEVICE_SESSION_ONLY", async () => {
    const jwt = await signer.makeJWT(longClaims(WRITER, { oauth: undefined }));
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });

  it("a long assertion on a device session (warp_as_auth) → 401 DEVICE_SESSION_ONLY", async () => {
    const jwt = await signer.makeJWT(longClaims(WRITER, { warp_as_auth: true }));
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("DEVICE_SESSION_ONLY");
  });
});

describe("the long host serves no admin route", () => {
  for (const [what, claims] of [
    ["a WRITE token", () => validClaimsWrite(ADMIN_EMAIL)],
    ["a long token", () => longClaims(ADMIN_EMAIL)],
  ] as const) {
    it(`${what} on /v1/admin/policy of the long host → 403 LONG_HOST_NO_ADMIN`, async () => {
      const jwt = await signer.makeJWT(claims());
      const res = await callGateAt(LONG_HOST, "/v1/admin/policy", { headers: authHeader(jwt) });
      expect(res.status).toBe(403);
      expect(await errorOf(res)).toBe("LONG_HOST_NO_ADMIN");
    });
  }

  it("a request without any token on /v1/admin of the long host → 403 LONG_HOST_NO_ADMIN", async () => {
    const res = await callGateAt(LONG_HOST, "/v1/admin/scheduler/arm", { method: "POST" });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("LONG_HOST_NO_ADMIN");
  });

  it("the WRITE token on the gate's own host still reaches the admin route", async () => {
    const jwt = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const res = await callGate("/v1/admin/policy", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
  });
});

describe("configuration", () => {
  it("the long host without its AUD → 503 SERVICE_MISCONFIGURED there, the gate's own host unchanged", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) }, { ACCESS_AUD_READ_LONG: "" });
    expect(res.status).toBe(503);
    expect(await errorOf(res)).toBe("SERVICE_MISCONFIGURED");

    const read = await signer.makeJWT(validClaims(WRITER));
    const own = await callGate("/v1/whoami", { headers: authHeader(read) }, { ACCESS_AUD_READ_LONG: "" });
    expect(own.status).toBe(200);
  });

  it("without a long host the long AUD is accepted nowhere", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const res = await callGateAt(LONG_HOST, "/v1/whoami", { headers: authHeader(jwt) }, { ACCESS_LONG_HOST: "" });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("AUD_MISMATCH");
  });

  it("the host is matched without regard to case", async () => {
    const jwt = await signer.makeJWT(longClaims());
    const res = await callGateAt(LONG_HOST.toUpperCase(), "/v1/whoami", { headers: authHeader(jwt) });
    expect(res.status).toBe(200);
  });
});
