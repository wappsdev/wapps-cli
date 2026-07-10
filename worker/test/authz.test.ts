// Per-key authorization testleri (SPEC §6.3): blob read, blob→key eşlemesiyle
// PER-KEY grant'a sıkılaştırılır (G6 proje-seviyesiydi). Makine principal'ları
// grants ∩ token scope ile SINIRLI.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, resetWorld, serviceTokenClaims, signDataManifest, seedManifestObject, putBlob, TrustContext } from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

async function seedMultiKey(t: TrustContext): Promise<{ blobShared: string; blobSecret: string; blobMachine: string }> {
  const blobShared = await putBlob("vaulter", new Uint8Array([1, 1]));
  const blobSecret = await putBlob("vaulter", new Uint8Array([2, 2, 2]));
  const blobMachine = await putBlob("vaulter", new Uint8Array([3, 3, 3, 3]));
  const w = signDataManifest(
    {
      project: "vaulter",
      epoch: 1,
      prev: "",
      trustEpoch: 1,
      entries: [
        { keyName: "SHARED_KEY", keyVersion: 1, blobHash: blobShared, wraps: [{ recipient: t.readerDevice, wrap: "s" }] },
        { keyName: "SECRET_KEY", keyVersion: 1, blobHash: blobSecret, wraps: [{ recipient: t.writerDevice, wrap: "x" }] },
        { keyName: "MACHINE_KEY", keyVersion: 1, blobHash: blobMachine, wraps: [{ recipient: t.machineDevice, wrap: "m" }] },
      ],
    },
    t.writer,
  );
  await seedManifestObject("vaulter", 1, w);
  return { blobShared, blobSecret, blobMachine };
}

describe("per-key blob authz (§6.3)", () => {
  it("HUMAN: reader (read on SHARED_KEY only) → 200 on SHARED_KEY blob, 403 on SECRET_KEY blob", async () => {
    const t = await seedTrust();
    const { blobShared, blobSecret } = await seedMultiKey(t);
    const jwt = await signer.makeJWT(validClaims("reader@wapps.dev"));
    // SHARED_KEY blob → izinli.
    const ok = await callGate(`/v1/projects/vaulter/blobs/${blobShared}`, { headers: authHeader(jwt) }, t.pin);
    expect(ok.status).toBe(200);
    // SECRET_KEY blob → per-key reject (reader'ın SECRET_KEY read grant'ı YOK).
    const denied = await callGate(`/v1/projects/vaulter/blobs/${blobSecret}`, { headers: authHeader(jwt) }, t.pin);
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: string }).error).toBe("GRANT_DENIED");
  });

  it("MACHINE: token scoped to MACHINE_KEY → 200 on MACHINE_KEY blob, 403 on SHARED_KEY blob", async () => {
    const t = await seedTrust();
    const { blobShared, blobMachine } = await seedMultiKey(t);
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const mintRes = await callGate("/v1/token", { method: "POST", headers: authHeader(seedJwt), body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 }) }, t.pin);
    const { token } = (await mintRes.json()) as { token: string };
    const h = authHeader(seedJwt, { authorization: `Bearer ${token}` });

    // MACHINE_KEY blob → grant ∩ scope içinde → 200.
    const ok = await callGate(`/v1/projects/vaulter/blobs/${blobMachine}`, { headers: h }, t.pin);
    expect(ok.status).toBe(200);
    // SHARED_KEY blob → makinenin grant'ı YOK (ve scope dışı) → 403.
    const denied = await callGate(`/v1/projects/vaulter/blobs/${blobShared}`, { headers: h }, t.pin);
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: string }).error).toBe("GRANT_DENIED");
  });

  it("MACHINE (P3-a): token scoped to MACHINE_KEY → 403 on an UNREFERENCED/historical blob hash (NO fall-through to project gate)", async () => {
    const t = await seedTrust();
    await seedMultiKey(t);
    // Current manifest'te HİÇBİR anahtarın göstermediği orphan/historical blob (R2'de VAR).
    // Kaba proje-read gate'ine düşülseydi makine bunu okurdu (200) → per-key confinement bypass.
    const orphan = await putBlob("vaulter", new Uint8Array([9, 8, 7, 6, 5]));
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const mintRes = await callGate("/v1/token", { method: "POST", headers: authHeader(seedJwt), body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 }) }, t.pin);
    const { token } = (await mintRes.json()) as { token: string };
    const h = authHeader(seedJwt, { authorization: `Bearer ${token}` });
    // MAKİNE: unreferenced hash → proje-gate'e düşME → 403 (§6.3 per-key/token-key confinement).
    const res = await callGate(`/v1/projects/vaulter/blobs/${orphan}`, { headers: h }, t.pin);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GRANT_DENIED");
  });
});
