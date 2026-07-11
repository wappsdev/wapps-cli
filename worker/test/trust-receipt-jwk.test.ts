// Go↔TS CONSENSUS: worker_receipt_pubkey / worker_mint_pubkeys `jwk` BYTE-EXACT
// karşılaştırması (§4.5 compareUnchanged, COORD c-jwk). Go, jwk'yı json.RawMessage
// olarak body'de göründüğü TAM baytlarla saklar ve reflect.DeepEqual ile byte-bayt
// karşılaştırır → NON-ROSTER (1-admin) bir epoch'un jwk'sındaki SADECE-boşluk
// değişikliği Go'da "değişti" (TRUST_CHAIN_BROKEN) olur. Eski Worker JSON.stringify
// (re-parse normalize) ile karşılaştırdığından boşluk farkını YUTUP "değişmedi"
// sayardı → yüksek-değerli receipt/mint anahtarı 1-admin epoch'uyla (roster M-of-N
// OLMADAN) sessizce değiştirilebilir görünürdü → consensus split. Bu testler
// düzeltmenin (ham jwk aralığı === byte-exact) load-bearing olduğunu kilitler.
//
// compareUnchanged yalnızca non-roster epoch'ta çalışır ve registry/policy/grant
// sınıfları ADMIN (P-256) imza ister → test gerçek genesis(roster,ed25519)→
// registry(admin,P-256) zincirini verifyRosterChain üzerinden sürer.

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import {
  ALG_ECDSA_P256_SHA256,
  ALG_ED25519,
  SIG_SCHEMA,
  Signature,
  SignedObject,
  bytesToB64,
  fingerprint,
  sha256,
  sha256Hex,
  utf8,
} from "../src/crypto/verify.js";
import { Pin, TrustError, verifyRosterChain } from "../src/trust.js";

// --- İmzalayıcı fikstürleri --------------------------------------------------

interface Signer {
  keyID: string;
  pubB64: string;
  sign(body: Uint8Array): Signature;
}

/** edKey, ed25519 root imzalayıcı (İmza = sign(sha256(body))). */
function edKey(seedByte: number): Signer {
  const seed = new Uint8Array(32).fill(seedByte);
  const pub = ed25519.getPublicKey(seed);
  const keyID = fingerprint(pub);
  return {
    keyID,
    pubB64: bytesToB64(pub),
    sign: (body) => ({ schema: SIG_SCHEMA, key_id: keyID, alg: ALG_ED25519, sig: ed25519.sign(sha256(body), seed) }),
  };
}

/** p256Compact, noble P-256 imzasının 64-bayt r‖s (compact) formunu döner. */
function p256Compact(sig: unknown): Uint8Array {
  const s = sig as { toBytes?: (f: string) => Uint8Array; toCompactRawBytes?: () => Uint8Array };
  if (typeof s.toBytes === "function") return s.toBytes("compact");
  return (s.toCompactRawBytes as () => Uint8Array)();
}

/** p256Key, admin presence P-256 imzalayıcı (registry epoch'unu imzalar). */
function p256Key(privByte: number): Signer {
  const priv = new Uint8Array(32).fill(privByte);
  const pub = p256.getPublicKey(priv, false); // 65B SEC1
  const keyID = fingerprint(pub);
  return {
    keyID,
    pubB64: bytesToB64(pub),
    sign: (body) => ({ schema: SIG_SCHEMA, key_id: keyID, alg: ALG_ECDSA_P256_SHA256, sig: p256Compact(p256.sign(sha256(body), priv, { lowS: false })) }),
  };
}

const HOLDER = "human:h@x";
const r0 = edKey(0x11);
const r1 = edKey(0x12);
const admin = p256Key(0x31);
const ADMIN_ID = "human:admin@x";

// jwk metnini birebir yerleştirmek için placeholder desen: JSON.stringify jwk'yı
// bir string token yapar; sonra token RAW jwk metniyle değiştirilir → iç boşluğu
// TAM kontrol ederiz (imza bu tam baytlar üzerinedir). roster/identities SABİT
// kalır → compareUnchanged yalnızca değiştirdiğimiz jwk'da tökezler.
const RECEIPT_TOKEN = "__RECEIPT_JWK__";
const MINT_TOKEN = "__MINT_JWK__";

function bodyStr(epoch: number, prev: string, changeClass: string, receiptJwk: string, mintJwk: string | null): string {
  const obj: Record<string, unknown> = {
    schema: "wapps-trust/v1",
    admin_epoch: epoch,
    prev_trust_sha256: prev,
    created_at: "2026-07-10T12:00:00Z",
    change_class: changeClass,
    bootstrap_solo: true, // 2 kök tek holder → maxHolderShare 2 >= m 2
    quorum: { m: 2, n: 2 },
    roots: [
      { key_id: r0.keyID, alg: "ed25519", pubkey: r0.pubB64, media: "a", holder: HOLDER, status: "active" },
      { key_id: r1.keyID, alg: "ed25519", pubkey: r1.pubB64, media: "b", holder: HOLDER, status: "active" },
    ],
    admins: [ADMIN_ID],
    identities: [
      {
        id: ADMIN_ID,
        type: "human",
        enc_keys: [],
        signing_keys: [{ key_id: admin.keyID, class: "admin", alg: "ecdsa-p256-sha256", pubkey: admin.pubB64, media: "yubikey-piv", status: "active" }],
        status: "active",
      },
    ],
    grants: [],
    writer_allowlists: [],
    worker_receipt_pubkey: { kid: "att-1", alg: "ES256", jwk: RECEIPT_TOKEN },
    worker_mint_pubkeys: mintJwk === null ? null : [{ kid: "mint-1", alg: "ES256", jwk: MINT_TOKEN }],
    epoch_reset: null,
  };
  let s = JSON.stringify(obj).replace(`"${RECEIPT_TOKEN}"`, receiptJwk);
  if (mintJwk !== null) s = s.replace(`"${MINT_TOKEN}"`, mintJwk);
  return s;
}

function signed(bodyString: string, signers: Signer[]): { obj: SignedObject; hash: string } {
  const bytes = utf8(bodyString);
  return { obj: { bytes, sigs: signers.map((k) => k.sign(bytes)) }, hash: sha256Hex(bytes) };
}

// İki jwk AYNI değere parse olur ama iç boşlukları FARKLIDIR (byte-exact ≠).
const COMPACT_JWK = '{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}';
const SPACED_JWK = '{"kty":"EC", "crv":"P-256", "x":"AAAA", "y":"BBBB"}';

function walk(genesisReceipt: string, genesisMint: string | null, childReceipt: string, childMint: string | null): () => void {
  return () => {
    const { obj: g, hash: gHash } = signed(bodyStr(1, "", "roster", genesisReceipt, genesisMint), [r0, r1]);
    const { obj: child } = signed(bodyStr(2, gHash, "registry", childReceipt, childMint), [admin]);
    const gPin: Pin = { admin_epoch: 1, sha256: gHash };
    verifyRosterChain(gPin, gPin, [g, child], null);
  };
}

describe("worker_receipt_pubkey / worker_mint_pubkeys jwk BYTE-EXACT compareUnchanged (COORD c-jwk)", () => {
  it("sanity: the two jwk encodings parse to the SAME value (old JSON.stringify compare would PASS)", () => {
    expect(JSON.stringify(JSON.parse(COMPACT_JWK))).toBe(JSON.stringify(JSON.parse(SPACED_JWK)));
  });

  it("baseline: a registry epoch copying receipt jwk BYTE-IDENTICAL is ACCEPTED", () => {
    const { obj: g, hash: gHash } = signed(bodyStr(1, "", "roster", COMPACT_JWK, null), [r0, r1]);
    const { obj: child } = signed(bodyStr(2, gHash, "registry", COMPACT_JWK, null), [admin]);
    const head = verifyRosterChain({ admin_epoch: 1, sha256: gHash }, { admin_epoch: 1, sha256: gHash }, [g, child], null);
    expect(head.manifest.admin_epoch).toBe(2);
  });

  it("baseline: a registry epoch copying mint jwk BYTE-IDENTICAL is ACCEPTED", () => {
    const { obj: g, hash: gHash } = signed(bodyStr(1, "", "roster", COMPACT_JWK, COMPACT_JWK), [r0, r1]);
    const { obj: child } = signed(bodyStr(2, gHash, "registry", COMPACT_JWK, COMPACT_JWK), [admin]);
    const head = verifyRosterChain({ admin_epoch: 1, sha256: gHash }, { admin_epoch: 1, sha256: gHash }, [g, child], null);
    expect(head.manifest.admin_epoch).toBe(2);
  });

  it("REJECTS a whitespace-only change INSIDE the receipt jwk (Go json.RawMessage byte-exact parity)", () => {
    let err: unknown;
    try {
      walk(COMPACT_JWK, null, SPACED_JWK, null)();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TrustError);
    expect((err as TrustError).code).toBe("TRUST_CHAIN_BROKEN");
    expect((err as TrustError).message).toContain("worker_receipt_pubkey");
  });

  it("REJECTS a whitespace-only change INSIDE a worker_mint_pubkeys[] jwk", () => {
    let err: unknown;
    try {
      // receipt AYNI (COMPACT), yalnızca mint jwk'sının iç boşluğu değişir.
      walk(COMPACT_JWK, COMPACT_JWK, COMPACT_JWK, SPACED_JWK)();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TrustError);
    expect((err as TrustError).code).toBe("TRUST_CHAIN_BROKEN");
    expect((err as TrustError).message).toContain("worker_mint_pubkeys");
  });
});

// --- COORD round-5 (a): worker_mint_pubkeys null <-> [] EŞDEĞER (locked array) ----
//
// worker_mint_pubkeys "girdi yok" iki biçimde yazılabilir: JSON null/absent (Go nil
// dilim) VEYA [] (Go boş dilim). Round-5 consensus: bu locked-array için null/[]
// EŞDEĞERdir → non-roster bir epoch'ta null->[] (veya []->null) değişimi "değişmedi"
// sayılır (Go tarafı da reflect.DeepEqual(nil,[]) ayrımını bırakır → iki taraf AYNI
// karar verir, consensus split yok). GERÇEK eleman ekleme/çıkarma HÂLÂ reddedilir.
// receipt jwk (COMPACT) her iki epoch'ta byte-identical → compareUnchanged yalnızca
// mint alanının null/[] biçim farkında test edilir.

const MINT_LIT = "__MINT_LIT__";

/** bodyMint, worker_mint_pubkeys'i ham LİTERAL olarak yerleştirir ("null" / "[]" /
 * gerçek dizi) → compareUnchanged'ın null/[] eşdeğerliğini birebir sürebiliriz. */
function bodyMint(epoch: number, prev: string, changeClass: string, mintLiteral: string): string {
  const obj: Record<string, unknown> = {
    schema: "wapps-trust/v1",
    admin_epoch: epoch,
    prev_trust_sha256: prev,
    created_at: "2026-07-10T12:00:00Z",
    change_class: changeClass,
    bootstrap_solo: true,
    quorum: { m: 2, n: 2 },
    roots: [
      { key_id: r0.keyID, alg: "ed25519", pubkey: r0.pubB64, media: "a", holder: HOLDER, status: "active" },
      { key_id: r1.keyID, alg: "ed25519", pubkey: r1.pubB64, media: "b", holder: HOLDER, status: "active" },
    ],
    admins: [ADMIN_ID],
    identities: [
      {
        id: ADMIN_ID,
        type: "human",
        enc_keys: [],
        signing_keys: [{ key_id: admin.keyID, class: "admin", alg: "ecdsa-p256-sha256", pubkey: admin.pubB64, media: "yubikey-piv", status: "active" }],
        status: "active",
      },
    ],
    grants: [],
    writer_allowlists: [],
    worker_receipt_pubkey: { kid: "att-1", alg: "ES256", jwk: RECEIPT_TOKEN },
    worker_mint_pubkeys: MINT_LIT,
    epoch_reset: null,
  };
  let s = JSON.stringify(obj).replace(`"${RECEIPT_TOKEN}"`, COMPACT_JWK);
  s = s.replace(`"${MINT_LIT}"`, mintLiteral);
  return s;
}

/** walkMint, genesis(roster)->registry(non-roster) zincirini verilen mint literalleriyle sürer. */
function walkMint(genesisMint: string, childMint: string): void {
  const { obj: g, hash: gHash } = signed(bodyMint(1, "", "roster", genesisMint), [r0, r1]);
  const { obj: child } = signed(bodyMint(2, gHash, "registry", childMint), [admin]);
  const gPin: Pin = { admin_epoch: 1, sha256: gHash };
  verifyRosterChain(gPin, gPin, [g, child], null);
}

const MINT_ONE = `[{"kid":"mint-1","alg":"ES256","jwk":${COMPACT_JWK}}]`;

describe("worker_mint_pubkeys null <-> [] equivalence in non-roster compareUnchanged (COORD round-5 a)", () => {
  it("ACCEPTS a non-roster null -> [] change (both are 'no entries')", () => {
    expect(() => walkMint("null", "[]")).not.toThrow();
  });

  it("ACCEPTS a non-roster [] -> null change (symmetric)", () => {
    expect(() => walkMint("[]", "null")).not.toThrow();
  });

  it("ACCEPTS null -> null and [] -> [] (unchanged baselines)", () => {
    expect(() => walkMint("null", "null")).not.toThrow();
    expect(() => walkMint("[]", "[]")).not.toThrow();
  });

  it("still REJECTS a REAL change (null -> [one mint key]) — normalization does not over-accept", () => {
    let err: unknown;
    try {
      walkMint("null", MINT_ONE);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TrustError);
    expect((err as TrustError).code).toBe("TRUST_CHAIN_BROKEN");
    expect((err as TrustError).message).toContain("worker_mint_pubkeys");
  });
});
