// Freshness (liveness) receipt üretimi (SPEC §6.6). Worker LIVENESS anchor'lar;
// yazar imzaları CONTENT anchor'lar (pinned split). Receipt = {payload, kid, sig};
// payload = {schema:"receipt/v1", manifestSha256, epoch, iat}'nın TAM UTF-8 baytları.
// İmza ATTESTATION DO'nun non-extractable ES256 anahtarıyla atılır. Client ham
// payload baytlarını doğrular SONRA parse eder (§3.6.2 exact-bytes disiplini).

import { RECEIPT_KID } from "./attestation-do.js";
import { bytesToB64, utf8 } from "./crypto/verify.js";
import { doStubFetch } from "./do-util.js";

export const RECEIPT_SCHEMA = "receipt/v1";

export interface Receipt {
  payload: string; // base64(exact UTF-8 bytes)
  kid: string;
  sig: string; // base64 ES256 (client verifyRaw ile doğrular)
}

interface ReceiptEnv {
  ATTESTATION: DurableObjectNamespace;
}

function makeAttestationStub(ns: DurableObjectNamespace): () => DurableObjectStub {
  // Tekil attestation DO (idFromName sabit) — anahtar tek yerde.
  return () => ns.get(ns.idFromName("__attestation__"));
}

/**
 * issueReceipt, bir manifest epoch'u için imzalı liveness receipt üretir (§6.6).
 * payload baytları AYNEN imzalanır ve base64 taşınır — client TAM baytları doğrular.
 */
export async function issueReceipt(env: ReceiptEnv, manifestSha256: string, epoch: number): Promise<Receipt> {
  const iat = Math.floor(Date.now() / 1000);
  // Exact-bytes: payload string'i deterministik kurulur, aynen imzalanır+taşınır.
  const payloadStr = JSON.stringify({ schema: RECEIPT_SCHEMA, manifestSha256, epoch, iat });
  const payloadBytes = utf8(payloadStr);
  const payloadB64 = bytesToB64(payloadBytes);
  const res = await doStubFetch(makeAttestationStub(env.ATTESTATION), "https://att/sign", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ payload: payloadB64 }),
  });
  if (!res.ok) throw new Error(`attestation sign failed: ${res.status}`);
  const { sig } = (await res.json()) as { sig: string };
  return { payload: payloadB64, kid: RECEIPT_KID, sig };
}

/** attestationPubkey, pinlenen liveness-receipt genel anahtarını döner (metadata/test). */
export async function attestationPubkey(env: ReceiptEnv): Promise<{ kid: string; alg: string; jwk: JsonWebKey; sec1_hex: string }> {
  const res = await doStubFetch(makeAttestationStub(env.ATTESTATION), "https://att/pubkey", { method: "GET" });
  if (!res.ok) throw new Error(`attestation pubkey failed: ${res.status}`);
  return (await res.json()) as { kid: string; alg: string; jwk: JsonWebKey; sec1_hex: string };
}
