// Alert kuralları testleri (SPEC §6.10): en az bir alert Discord webhook'una gider
// (fetchMock ile yakalanır). token-revoke → A8; commit'te audit-DO down → A8.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  seedTrust,
  ensureJwks,
  validClaims,
  validClaimsWrite,
  authHeader,
  callGate,
  resetWorld,
  serviceTokenClaims,
  signDataManifest,
  putBlob,
  discordCalls,
  runInDoRetry,
  TrustContext,
} from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

function fullWraps(t: TrustContext) {
  return [
    { recipient: t.writerDevice, wrap: "a" },
    { recipient: t.writerBackup, wrap: "b" },
    { recipient: t.escrowFp, wrap: "c" },
  ];
}

describe("alert rules → Discord (§6.10)", () => {
  it("A8: token revoke posts an alert to the Discord webhook (mocked)", async () => {
    const t = await seedTrust();
    // Mint (jti al).
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const mintRes = await callGate("/v1/token", { method: "POST", headers: authHeader(seedJwt), body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 }) }, t.pin);
    const { jti } = (await mintRes.json()) as { jti: string };

    // Revoke → A8 alert fire.
    const adminJwt = await signer.makeJWT(validClaimsWrite(t.adminEmail));
    const rev = await callGate("/v1/token/revoke", { method: "POST", headers: authHeader(adminJwt), body: JSON.stringify({ jti }) }, t.pin);
    expect(rev.status).toBe(200);

    // Discord webhook çağrıldı (A8 + jti).
    expect(discordCalls.length).toBeGreaterThanOrEqual(1);
    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.includes(jti))).toBe(true);
  });

  it("A8: audit DO unavailable on commit fires an alert", async () => {
    const t = await seedTrust();
    // Genesis commit → PROJECT_WRITER DO'yu warm et.
    const blob1 = await putBlob("vaulter", new Uint8Array([9, 9, 9, 9]));
    const w1 = signDataManifest({ project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob1, wraps: fullWraps(t) }] }, t.writer);
    const c1 = await callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))), body: w1.wrapperStr }, t.pin);
    expect(c1.status).toBe(200);
    const prevSha = ((await c1.json()) as { manifestSha256: string }).manifestSha256;
    discordCalls.length = 0; // genesis commit alert üretmedi ama garanti temizle

    // auditLog'u fail eden namespace ile değiştir.
    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
    const failing = { idFromName: () => ({}), get: () => ({ fetch: async () => { throw new Error("down"); } }) } as unknown as DurableObjectNamespace;
    let saved: DurableObjectNamespace | undefined;
    await runInDoRetry(stub, (i: unknown) => { const h = i as { auditLog: DurableObjectNamespace }; saved = h.auditLog; h.auditLog = failing; });

    const blob2 = await putBlob("vaulter", new Uint8Array([2, 2]));
    const w2 = signDataManifest({ project: "vaulter", epoch: 2, prev: prevSha, trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob2, wraps: fullWraps(t) }] }, t.writer);
    const c2 = await callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))), body: w2.wrapperStr }, t.pin);
    expect(c2.status).toBe(503);

    expect(discordCalls.some((c) => c.body.includes("A8") && c.body.toLowerCase().includes("audit"))).toBe(true);

    await runInDoRetry(stub, (i: unknown) => { if (saved) (i as { auditLog: DurableObjectNamespace }).auditLog = saved; });
  });
});
