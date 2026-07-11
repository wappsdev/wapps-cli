// Read-path testleri (SPEC §5.5 DO-free serving): conditional GET → 304 (manifest
// current, manifest by-epoch, blob, trust current). ETag = içerik-adresli hash.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, signDataManifest, seedManifestObject, putBlob, resetWorld, p256Key } from "./helpers.js";
import { keyManifest } from "../src/storage.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

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

// Fix #6 (§5.4 tamper): blob-read authz, current manifest'i KULLANMADAN ÖNCE
// pointer-hash + yazar imzasını doğrular. Storage tamper (manifest'i yeniden yazıp
// bir blob'u okunabilir bir anahtar altında göstermek) authz'DEN ÖNCE reddedilir.
describe("blob-read tamper guard (Fix #6)", () => {
  it("bad pointer-hash: manifest object rewritten but pointer unchanged → 503 (not used for authz)", async () => {
    const { t, blobHash, jwt } = await setup();
    // Yasal blob read çalışıyor (writer keys:["*"] okur).
    expect((await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(jwt) }, t.pin)).status).toBe(200);
    // Manifest objesini FARKLI baytlarla ez, pointer'ı ESKİ hash'te bırak → pointer↔obje bağı kopar.
    const tampered = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "SHARED_KEY", keyVersion: 1, blobHash, wraps: [{ recipient: t.readerDevice, wrap: "r" }] }] },
      t.writer,
    );
    await env.SECRETS_BUCKET.put(keyManifest("vaulter", 1), tampered.wrapperBytes);
    const res = await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("SERVICE_MISCONFIGURED");
  });

  it("forged signature: manifest re-writes a blob under a reader-readable key + fixes pointer hash → 503 (blob NOT leaked)", async () => {
    const t = await seedTrust();
    // Yasal: blob B, reader'ın OKUYAMADIĞI DATABASE_URL altında.
    const blobHash = await putBlob("vaulter", new Uint8Array([1, 2, 3, 4]));
    const legit = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: [{ recipient: t.writerDevice, wrap: "w" }] }] },
      t.writer,
    );
    await seedManifestObject("vaulter", 1, legit);
    const readerJwt = await signer.makeJWT(validClaims("reader@wapps.dev"));
    // Baseline: reader B'yi OKUYAMAZ (DATABASE_URL'de grant yok) → 403.
    expect((await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(readerJwt) }, t.pin)).status).toBe(403);

    // SALDIRI: manifest'i B'yi SHARED_KEY (reader OKUR) altında gösterecek şekilde yeniden yaz;
    // ENROLLED OLMAYAN bir anahtarla imzala; pointer hash'ini de eşleşecek şekilde güncelle.
    const forgeKey = p256Key(0x99); // trust ring'de YOK
    const forged = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "SHARED_KEY", keyVersion: 1, blobHash, wraps: [{ recipient: t.readerDevice, wrap: "r" }] }] },
      { keyID: forgeKey.keyID, alg: forgeKey.alg, sign: (m: Uint8Array) => forgeKey.sign(m) },
    );
    await seedManifestObject("vaulter", 1, forged); // hem obje hem pointer (hash tutarlı)

    const res = await callGate(`/v1/projects/vaulter/blobs/${blobHash}`, { headers: authHeader(readerJwt) }, t.pin);
    // Yazar imzası ring'de çözülmediğinden manifest doğrulanmaz → fail-closed 503 (leak DEĞİL).
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("SERVICE_MISCONFIGURED");
  });
});
