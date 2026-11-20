// E-M4 (security review 2026-11-19): request bodies are read only after the request
// is authorized, through a bounded reader. A body over its route's cap is 413
// BODY_TOO_LARGE; the reader checks Content-Length first and stops pulling a stream
// once it passes the cap.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  ADMIN_EMAIL,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  allAuditRows,
} from "./helpers.js";
import { BODY_CAP, readBodyBounded } from "../src/body.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("stranger@wapps.dev", []);
});

const CHUNK = 16 * 1024;

/** countingStream yields `total` bytes of non-JSON filler in CHUNK pieces, only on
 * demand (highWaterMark 0), and records how many bytes were pulled. */
function countingStream(total: number): { stream: ReadableStream<Uint8Array>; pulled: () => number } {
  let sent = 0;
  const filler = new Uint8Array(CHUNK).fill(0x7a); // "zzzz…": not JSON
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (sent >= total) {
          controller.close();
          return;
        }
        sent += CHUNK;
        controller.enqueue(filler.slice());
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, pulled: () => sent };
}

async function human(email: string): Promise<Record<string, string>> {
  return authHeader(await signer.makeJWT(validClaims(email)));
}

describe("authorize before the body is read", () => {
  // A huge non-JSON body: reading it first would give 400 (not JSON) or 413 (too
  // large). 403 GRANT_DENIED with almost nothing pulled shows the refusal came first.
  for (const route of ["read", "import"] as const) {
    it(`/${route}: a principal with no grant in the project gets 403 before the body is read`, async () => {
      const big = countingStream(64 * 1024 * 1024);
      const res = await callGate(`/v1/projects/vaulter/${route}`, { method: "POST", headers: await human("stranger@wapps.dev"), body: big.stream });
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe("GRANT_DENIED");
      expect(big.pulled()).toBeLessThan(1024 * 1024);
      const rows = await allAuditRows();
      expect(rows.some((r) => r.principal === "human:stranger@wapps.dev" && r.decision === "deny" && r.project === "vaulter")).toBe(true);
    });
  }

  it("/token: a service no policy row names gets 403 before the body is read", async () => {
    const big = countingStream(64 * 1024 * 1024);
    const res = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(serviceTokenClaims("svc-nobody"))),
      body: big.stream,
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_SCOPE_EXCEEDED");
    expect(big.pulled()).toBeLessThan(1024 * 1024);
  });
});

describe("over-cap bodies are 413 BODY_TOO_LARGE", () => {
  it("/read: a body one byte over the cap (sized body)", async () => {
    const res = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: await human("writer@wapps.dev"), body: "z".repeat(BODY_CAP.read + 1) });
    expect(res.status).toBe(413);
    const b = (await res.json()) as { error: string; limit: number };
    expect(b.error).toBe("BODY_TOO_LARGE");
    expect(b.limit).toBe(BODY_CAP.read);
  });

  it("/import: a streamed body with no length stops being read just past the cap", async () => {
    const big = countingStream(64 * 1024 * 1024);
    const res = await callGate("/v1/projects/vaulter/import", { method: "POST", headers: await human("writer@wapps.dev"), body: big.stream });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("BODY_TOO_LARGE");
    expect(big.pulled()).toBeGreaterThan(BODY_CAP.import);
    // The runtime may buffer a little ahead of the reader; 1 MiB of slack, not 64 MiB.
    expect(big.pulled()).toBeLessThanOrEqual(BODY_CAP.import + 1024 * 1024);
  });

  it("/token: an authorized service with an over-cap body", async () => {
    const res = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(serviceTokenClaims("svc-woodpecker"))),
      body: "z".repeat(BODY_CAP.token + 1),
    });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("BODY_TOO_LARGE");
  });
});

describe("admin bodies are bounded too", () => {
  it("policy PUT over its cap is 413 and the policy stays at v1", async () => {
    const admin = authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL)));
    const res = await callGate("/v1/admin/policy", { method: "PUT", headers: admin, body: "z".repeat(BODY_CAP.policy + 1) });
    expect(res.status).toBe(413);
    const get = await callGate("/v1/admin/policy", { headers: admin });
    expect(((await get.json()) as { version: number }).version).toBe(1);
  });
});

describe("readBodyBounded", () => {
  it("refuses on a Content-Length over the cap without pulling a byte", async () => {
    const big = countingStream(64 * 1024 * 1024);
    const req = { headers: new Headers({ "content-length": String(10 * 1024 * 1024) }), body: big.stream } as unknown as Request;
    const r = await readBodyBounded(req, 1024);
    expect(r).toBeInstanceOf(Response);
    expect((r as Response).status).toBe(413);
    expect(big.pulled()).toBe(0);
  });

  it("returns the bytes of a body within the cap", async () => {
    const req = new Request("https://gate/x", { method: "POST", body: "hello" });
    const r = await readBodyBounded(req, 5);
    expect(r).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(r as Uint8Array)).toBe("hello");
  });

  it("one byte over the cap is refused", async () => {
    const req = new Request("https://gate/x", { method: "POST", body: "hello!" });
    const r = await readBodyBounded(req, 5);
    expect((r as Response).status).toBe(413);
  });
});

describe("normal bodies still work", () => {
  it("import, read and token mint with ordinary bodies", async () => {
    const values: Record<string, string> = {};
    for (let i = 0; i < 50; i++) values[`DB_K${i}`] = "v".repeat(2000);
    const imp = await callGate("/v1/projects/vaulter/import", { method: "POST", headers: await human("writer@wapps.dev"), body: JSON.stringify({ values }) });
    expect(imp.status).toBe(200);
    const rd = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: await human("writer@wapps.dev"), body: JSON.stringify({ keys: Object.keys(values) }) });
    expect(rd.status).toBe(200);
    expect(Object.keys(((await rd.json()) as { values: Record<string, string> }).values).length).toBe(50);
    const mint = await callGate("/v1/token", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(serviceTokenClaims("svc-woodpecker"))),
      body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["DB_K1"] } }),
    });
    expect(mint.status).toBe(200);
  });
});
