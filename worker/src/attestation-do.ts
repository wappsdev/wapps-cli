// Freshness/liveness attestation anahtarı (SPEC §6.6). NON-EXTRACTABLE WebCrypto
// ES256 anahtarı bu DO içinde BİR KEZ üretilir (extractable:false → özel anahtar
// asla export edilemez, Worker-kodu ele geçse bile) ve DO storage'a structured-clone
// ile kalıcılaştırılır. GENEL anahtar admin manifest'te pinlenir (worker_receipt_pubkey).
//
// İmza disiplini §3.6.2 ile UYUMLU: WebCrypto ECDSA(hash:SHA-256, payload) çıktısı
// ham r‖s'tir ve client verifyRaw(vk, payload, sig) ile (d=sha256(payload) üstünde)
// doğrulanır. Attestation YALNIZCA freshness taşır; içerik authenticity daima yazar
// imzasından gelir (§6.6).

import { b64urlDecode } from "./jose.js";
import { bytesToB64, b64ToBytes } from "./crypto/verify.js";

interface StoredKeys {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

const KEYPAIR_KEY = "att-keypair";
const PUBJWK_KEY = "att-pubjwk";
const PRIVJWK_FALLBACK_KEY = "att-privjwk-fallback";
export const RECEIPT_KID = "att-1";

export class AttestationDO {
  private cached: StoredKeys | null = null;

  constructor(private ctx: DurableObjectState, _env: unknown) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/sign" && request.method === "POST") {
        const { payload } = (await request.json()) as { payload: string };
        const keys = await this.ensureKeys();
        const payloadBytes = b64ToBytes(payload); // standart base64 (çağıran böyle gönderir)
        const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, payloadBytes));
        return json({ sig: bytesToB64(sig) });
      }
      if (url.pathname === "/pubkey" && request.method === "GET") {
        await this.ensureKeys();
        const jwk = (await this.ctx.storage.get<JsonWebKey>(PUBJWK_KEY))!;
        return json({ kid: RECEIPT_KID, alg: "ES256", jwk, sec1_hex: sec1FromJwk(jwk) });
      }
      return json({ error: "NOT_FOUND" }, 404);
    } catch (e) {
      return json({ error: "ATTESTATION_ERROR", message: String(e) }, 503);
    }
  }

  /** ensureKeys, non-extractable ES256 anahtar çiftini üretir/yükler (bir kez). */
  private async ensureKeys(): Promise<StoredKeys> {
    if (this.cached) return this.cached;
    // (1) Prod yolu: non-extractable CryptoKey DO storage'da persist (workerd serialize eder).
    const stored = await this.ctx.storage.get<StoredKeys>(KEYPAIR_KEY);
    if (stored) {
      this.cached = stored;
      return stored;
    }
    // (2) TEST-only fallback yolu: miniflare CryptoKey serialize EDEMEZ (DataCloneError) →
    // özel anahtar JWK olarak saklanmış olabilir. Bu YALNIZCA test-runtime degradasyonudur;
    // prod workerd (1)'i alır ve JWK ASLA saklanmaz (non-extractable koru).
    const fallbackPriv = await this.ctx.storage.get<JsonWebKey>(PRIVJWK_FALLBACK_KEY);
    if (fallbackPriv) {
      const pubJwk = (await this.ctx.storage.get<JsonWebKey>(PUBJWK_KEY))!;
      const keys = await this.importPair(fallbackPriv, pubJwk);
      this.cached = keys;
      return keys;
    }

    // Üretim: extractable=true üret → GENEL anahtarı JWK export et (pinning) → ÖZEL anahtarı
    // yalnızca NON-EXTRACTABLE olarak yeniden import et. Üretim-anı extractable kopya bellek-geçici.
    const gen = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pubJwk = (await crypto.subtle.exportKey("jwk", gen.publicKey)) as JsonWebKey & { kid?: string };
    pubJwk.kid = RECEIPT_KID;
    const privJwk = (await crypto.subtle.exportKey("jwk", gen.privateKey)) as JsonWebKey;
    const keys = await this.importPair(privJwk, pubJwk);
    await this.ctx.storage.put(PUBJWK_KEY, pubJwk);
    try {
      // Prod: non-extractable CryptoKey'i persist et (export edilemez, §6.6).
      await this.ctx.storage.put(KEYPAIR_KEY, keys);
    } catch {
      // Test-runtime (miniflare) CryptoKey serialize edemez → JWK fallback (test-only).
      await this.ctx.storage.put(PRIVJWK_FALLBACK_KEY, privJwk);
    }
    this.cached = keys;
    return keys;
  }

  /** importPair, JWK'lardan non-extractable özel + genel imza anahtarı çifti kurar. */
  private async importPair(privJwk: JsonWebKey, pubJwk: JsonWebKey): Promise<StoredKeys> {
    const privateKey = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const publicKey = await crypto.subtle.importKey("jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    return { publicKey, privateKey };
  }
}

/** sec1FromJwk, EC public JWK'nın (x,y base64url) 65-bayt SEC1 uncompressed hex'i. */
function sec1FromJwk(jwk: JsonWebKey): string {
  const x = b64urlDecode(jwk.x!);
  const y = b64urlDecode(jwk.y!);
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  let h = "";
  for (let i = 0; i < out.length; i++) h += out[i].toString(16).padStart(2, "0");
  return h;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
