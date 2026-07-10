// Read-path testleri (SPEC §5.5 DO-free serving): conditional GET → 304 (manifest
// current, manifest by-epoch, blob, trust current). ETag = içerik-adresli hash.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, signDataManifest, seedManifestObject, putBlob, clearBucket } from "./helpers.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(clearBucket);

async function setup() {
  const t = await seedTrust();
  // Genesis data manifest (epoch 1) — read için wrap-set doğrulanmaz.
  const blobHash = await putBlob("vaulter", new Uint8Array([1, 2, 3, 4]));
  const wrapper = signDataManifest(
    {
      project: "vaulter",
      epoch: 1,
      prev: "",
      trustEpoch: 1,
      entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: [{ recipient: t.writerDevice, wrap: "w" }] }],
    },
    t.writer,
  );
  await seedManifestObject("vaulter", 1, wrapper);
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  return { t, wrapper, blobHash, jwt };
}

describe("read path (conditional GET → 304)", () => {
  it("manifests/current: 200 then 304 with matching If-None-Match", async () => {
    const { t, wrapper, jwt } = await setup();
    const res = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
    const etag = res.headers.get("etag");
    expect(etag).toBe(`"${wrapper.objectSha256}"`);
    const res304 = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(jwt, { "If-None-Match": etag! }) }, t.pin);
    expect(res304.status).toBe(304);
  });

  it("manifests/{epoch}: 200 then 304", async () => {
    const { t, wrapper, jwt } = await setup();
    const res = await callGate("/v1/projects/vaulter/manifests/1", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
    const etag = res.headers.get("etag");
    expect(etag).toBe(`"${wrapper.objectSha256}"`);
    const res304 = await callGate("/v1/projects/vaulter/manifests/1", { headers: authHeader(jwt, { "If-None-Match": etag! }) }, t.pin);
    expect(res304.status).toBe(304);
  });

  it("blobs/{sha}: 200 then 304", async () => {
    const { t, blobHash, jwt } = await setup();
    const res = await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toBe(`"${blobHash}"`);
    const res304 = await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(jwt, { "If-None-Match": `"${blobHash}"` }) }, t.pin);
    expect(res304.status).toBe(304);
  });

  it("trust/current: 200 then 304", async () => {
    const { t, jwt } = await setup();
    const res = await callGate("/v1/trust/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
    const etag = res.headers.get("etag")!;
    const res304 = await callGate("/v1/trust/current", { headers: authHeader(jwt, { "If-None-Match": etag }) }, t.pin);
    expect(res304.status).toBe(304);
  });

  it("nonexistent blob under a valid read grant → 404", async () => {
    const { t, jwt } = await setup();
    const res = await callGate(`/v1/projects/vaulter/blobs/${"0".repeat(64)}`, { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(404);
  });
});
