// Blob PUT endpoint testleri (SPEC §6.2 blob upload): framing-length + hash +
// write-grant + idempotent content-addressed write.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { seedTrust, ensureJwks, validClaims, authHeader, callGate, resetWorld } from "./helpers.js";
import { sha256Hex } from "../src/crypto/verify.js";
import { keyBlob } from "../src/storage.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

// Geçerli framing uzunluğu: magic(4)+nonce(24)+tag(16)=44 + bucket(256) = 300.
function validBlob(fill = 7): Uint8Array {
  return new Uint8Array(300).fill(fill);
}
async function put(pin: string, email: string, sha: string, body: Uint8Array): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims(email));
  return callGate(`/v1/projects/vaulter/blobs/${sha}`, { method: "PUT", headers: authHeader(jwt), body }, pin);
}
async function errCode(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { error?: string }).error;
}

describe("blob PUT", () => {
  it("valid framing + matching hash + write grant → 200, idempotent re-PUT → 200", async () => {
    const t = await seedTrust();
    const body = validBlob();
    const sha = sha256Hex(body);
    const res = await put(t.pin, "writer@wapps.dev", sha, body);
    expect(res.status).toBe(200);
    const again = await put(t.pin, "writer@wapps.dev", sha, body); // idempotent no-op
    expect(again.status).toBe(200);
  });

  it("bytes do not hash to the path → 400 BLOB_HASH_MISMATCH", async () => {
    const t = await seedTrust();
    const res = await put(t.pin, "writer@wapps.dev", "0".repeat(64), validBlob());
    expect(res.status).toBe(400);
    expect(await errCode(res)).toBe("BLOB_HASH_MISMATCH");
  });

  it("content-addressing invariant (P1-B): a hash-mismatched body is REJECTED and NEVER stored under the path", async () => {
    const t = await seedTrust();
    const realBody = validBlob(3);
    const sha = sha256Hex(realBody); // gerçek adres
    const otherBody = validBlob(4); // aynı framing-uzunluğu ama FARKLI hash
    // sha path'i + hash'i uyuşmayan gövde → PUT reddetmeli (sha256(body) !== path).
    const res = await put(t.pin, "writer@wapps.dev", sha, otherBody);
    expect(res.status).toBe(400);
    expect(await errCode(res)).toBe("BLOB_HASH_MISMATCH");
    // Değişmezlik: içerik-adresi uyuşmayan hiçbir gövde R2'ye YAZILAMAZ → commit-zamanı
    // yeniden-hash gereksiz kalır (kanonik anahtardaki her blob zaten içerik-adreslidir).
    expect(await env.SECRETS_BUCKET.head(keyBlob("vaulter", sha))).toBeNull();
  });

  it("length not a valid framing bucket → 400 PADDING_INVALID", async () => {
    const t = await seedTrust();
    const body = new Uint8Array(123).fill(1); // 123-44=79, geçersiz bucket
    const sha = sha256Hex(body);
    const res = await put(t.pin, "writer@wapps.dev", sha, body);
    expect(res.status).toBe(400);
    expect(await errCode(res)).toBe("PADDING_INVALID");
  });

  it("no write grant in project → 403 GRANT_DENIED (reader has read-only)", async () => {
    const t = await seedTrust();
    const body = validBlob(9);
    const sha = sha256Hex(body);
    const res = await put(t.pin, "reader@wapps.dev", sha, body);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("GRANT_DENIED");
  });
});
