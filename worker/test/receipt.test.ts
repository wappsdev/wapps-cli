// Freshness receipt testleri (SPEC §6.6): receipt üretilir + attestation pubkey ile
// imza doğrulanır (client'ın §3.6.2 verifyRaw disiplini). Commit yanıtına da gömülür.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { seedTrust, ensureJwks, validClaims, validClaimsWrite, authHeader, callGate, resetWorld, signDataManifest, seedManifestObject, putBlob, TrustContext } from "./helpers.js";
import { newVerifierKey, verifyRaw, hexToBytes, b64ToBytes, ALG_ECDSA_P256_SHA256 } from "../src/crypto/verify.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

interface Receipt {
  payload: string;
  kid: string;
  sig: string;
}

async function seedManifest(t: TrustContext): Promise<void> {
  const blob = await putBlob("vaulter", new Uint8Array([1, 2, 3, 4]));
  const w = signDataManifest({ project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "SHARED_KEY", keyVersion: 1, blobHash: blob, wraps: [{ recipient: t.readerDevice, wrap: "x" }] }] }, t.writer);
  await seedManifestObject("vaulter", 1, w);
}

async function attestationSec1(t: TrustContext): Promise<string> {
  const adminJwt = await signer.makeJWT(validClaimsWrite(t.adminEmail));
  const res = await callGate("/v1/admin/attestation", { headers: authHeader(adminJwt) }, t.pin);
  expect(res.status).toBe(200);
  return ((await res.json()) as { sec1_hex: string }).sec1_hex;
}

function verifyReceipt(receipt: Receipt, sec1Hex: string): { schema: string; manifestSha256: string; epoch: number; iat: number } {
  const vk = newVerifierKey(ALG_ECDSA_P256_SHA256, hexToBytes(sec1Hex));
  const payloadBytes = b64ToBytes(receipt.payload);
  const sig = b64ToBytes(receipt.sig);
  // §3.6.2 disiplini: verifyRaw(vk, payload, sig) — d=sha256(payload) üstünde doğrular.
  expect(verifyRaw(vk, payloadBytes, sig)).toBe(true);
  return JSON.parse(new TextDecoder().decode(payloadBytes));
}

describe("freshness receipts (§6.6)", () => {
  it("GET receipt → signed receipt whose signature verifies with the pinned attestation pubkey", async () => {
    const t = await seedTrust();
    await seedManifest(t);
    const res = await callGate("/v1/projects/vaulter/receipt", { headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))) }, t.pin);
    expect(res.status).toBe(200);
    const receipt = (await res.json()) as Receipt;
    expect(receipt.kid).toBe("att-1");
    const sec1 = await attestationSec1(t);
    const payload = verifyReceipt(receipt, sec1);
    expect(payload.schema).toBe("receipt/v1");
    expect(payload.epoch).toBe(1);
    expect(typeof payload.iat).toBe("number");
  });

  it("TAMPER: a modified payload fails signature verification", async () => {
    const t = await seedTrust();
    await seedManifest(t);
    const res = await callGate("/v1/projects/vaulter/receipt", { headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))) }, t.pin);
    const receipt = (await res.json()) as Receipt;
    const sec1 = await attestationSec1(t);
    const vk = newVerifierKey(ALG_ECDSA_P256_SHA256, hexToBytes(sec1));
    const tampered = b64ToBytes(receipt.payload);
    tampered[tampered.length - 2] ^= 0xff; // payload'ı boz
    expect(verifyRaw(vk, tampered, b64ToBytes(receipt.sig))).toBe(false);
  });

  it("COMMIT: successful commit response embeds a verifiable receipt (§6.2 step 18)", async () => {
    const t = await seedTrust();
    const blob = await putBlob("vaulter", new Uint8Array([9, 9, 9, 9]));
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob, wraps: [{ recipient: t.writerDevice, wrap: "a" }, { recipient: t.writerBackup, wrap: "b" }, { recipient: t.escrowFp, wrap: "c" }] }] },
      t.writer,
    );
    const res = await callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))), body: w.wrapperStr }, t.pin);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { epoch: number; manifestSha256: string; receipt: Receipt };
    expect(body.receipt).toBeTruthy();
    const sec1 = await attestationSec1(t);
    const payload = verifyReceipt(body.receipt, sec1);
    expect(payload.manifestSha256).toBe(body.manifestSha256);
    expect(payload.epoch).toBe(1);
  });
});
