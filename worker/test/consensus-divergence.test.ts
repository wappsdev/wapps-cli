// Go↔TS CONSENSUS divergence negatifleri (WORKER tarafı). Bu dosya, Worker'ın
// Go çekirdeğinden AYRIŞABİLECEĞİ (bir tarafın kabul edip diğerinin reddettiği)
// noktaları kilitler — hepsi read/trust DESYNC (brick) riskidir. COORD pinlenmiş
// kararlar (a-e) burada negatif vektörlerle doğrulanır.

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  b64ToBytes,
  bytesToB64,
  fingerprint,
  fingerprintRecipient,
  parseSignedObject,
  sha256,
  sha256Hex,
  utf8,
} from "../src/crypto/verify.js";
import {
  parseTrustBody,
  findWriterSigningIdentity,
  verifyGenesis,
  TrustError,
  Pin,
  VerifiedEpoch,
} from "../src/trust.js";
import { parseManifestBody, ManifestVerifyError } from "../src/manifest.js";

// --- Fix #1 (COORD e): strict canonical base64 in signed wrappers/pubkeys ----

describe("b64ToBytes strict canonical (COORD e)", () => {
  it("accepts a canonical padded base64 and roundtrips", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const canonical = bytesToB64(bytes); // "AQIDBAU="
    expect(Array.from(b64ToBytes(canonical))).toEqual([1, 2, 3, 4, 5]);
  });

  it("REJECTS unpadded base64 (length not %4 — Go base64.StdEncoding padding'li ister)", () => {
    // "AQIDBAU=" → padding düşürülürse ("AQIDBAU") uzunluk %4 != 0.
    expect(() => b64ToBytes("AQIDBAU")).toThrow();
  });

  it("REJECTS whitespace-embedded base64 (atob yutardı → yeniden-kodlama açığı)", () => {
    expect(() => b64ToBytes("AQID BAU=")).toThrow();
    expect(() => b64ToBytes("AQIDBAU=\n")).toThrow();
  });

  it("REJECTS non-canonical trailing bits (roundtrip != input — StdEncoding.Strict paritesi)", () => {
    // "AA==" → [0]. "AB==" da atob'da [0]'a çözülür ama kanonik kodlama "AA==".
    expect(Array.from(b64ToBytes("AA=="))).toEqual([0]);
    expect(() => b64ToBytes("AB==")).toThrow();
  });

  it("REJECTS base64url variant ('-'/'_') in a std-base64 slot", () => {
    // 0xFB,0xFF → std "+/8=" ; b64url "-_8=" aynı baytlar ama kanonik std DEĞİL.
    expect(Array.from(b64ToBytes("+/8="))).toEqual([0xfb, 0xff]);
    expect(() => b64ToBytes("-_8=")).toThrow();
  });

  it("a re-encoded signed wrapper (unpadded bytes) is REJECTED at parseSignedObject", () => {
    const bodyBytes = utf8('{"x":1}');
    const okWrapper = { bytes: bytesToB64(bodyBytes), sigs: [] };
    expect(() => parseSignedObject(okWrapper)).not.toThrow();
    // Saldırgan: aynı baytlar, padding düşürülmüş base64 → decode farkı yok ama
    // wrapper metni değişti; imzasız sarmalayıcı → strict decode fail-closed reddeder.
    const tampered = { bytes: bytesToB64(bodyBytes).replace(/=+$/, ""), sigs: [] };
    expect(() => parseSignedObject(tampered)).toThrow();
  });
});

// --- Ortak: bir imzalama anahtarı fixture'ı -----------------------------------

function edKey(seedByte: number): { pub: Uint8Array; pubB64: string; fp: string } {
  const pub = ed25519.getPublicKey(new Uint8Array(32).fill(seedByte));
  return { pub, pubB64: bytesToB64(pub), fp: fingerprint(pub) };
}

// Minimal geçerli-parse edilebilir roster body (verify DEĞİL; sadece parseTrustBody).
function trustBodyWith(overrides: Record<string, unknown>): string {
  const base: Record<string, unknown> = {
    schema: "wapps-trust/v1",
    admin_epoch: 1,
    prev_trust_sha256: "",
    created_at: "2026-07-10T12:00:00Z",
    change_class: "roster",
    bootstrap_solo: true,
    quorum: { m: 2, n: 3 },
    roots: [],
    admins: [],
    identities: [],
    grants: [],
    writer_allowlists: [],
    worker_receipt_pubkey: null,
    worker_mint_pubkeys: null,
    epoch_reset: null,
  };
  return JSON.stringify({ ...base, ...overrides });
}

function signingKeyEntry(pubB64: string, keyId: string, cls = "daily"): Record<string, unknown> {
  return { key_id: keyId, class: cls, alg: "ed25519", pubkey: pubB64, media: "software", status: "active" };
}
function identity(id: string, type: string, signingKeys: unknown[]): Record<string, unknown> {
  return { id, type, enc_keys: [], signing_keys: signingKeys, status: "active" };
}

// --- Fix #2 (COORD d): array-typed signed fields reject non-array ------------

describe("array-typed signed fields reject a non-array concrete value (COORD d)", () => {
  it('grants:{} is REJECTED (not silently treated as empty)', () => {
    expect(() => parseTrustBody(utf8(trustBodyWith({ grants: {} })))).toThrow(TrustError);
  });
  it('identities:{} is REJECTED', () => {
    expect(() => parseTrustBody(utf8(trustBodyWith({ identities: {} })))).toThrow(TrustError);
  });
  it('writer_allowlists:{} is REJECTED', () => {
    expect(() => parseTrustBody(utf8(trustBodyWith({ writer_allowlists: {} })))).toThrow(TrustError);
  });
  it('roots:"x" (string) is REJECTED', () => {
    expect(() => parseTrustBody(utf8(trustBodyWith({ roots: "x" })))).toThrow(TrustError);
  });
  it("absent/null grants are still accepted as empty", () => {
    const m = parseTrustBody(utf8(trustBodyWith({ grants: null })));
    expect(m.grants).toEqual([]);
  });
});

// --- COORD (c): signed-body parsers reject TRAILING content after the JSON ----

describe("signed-body parsers reject trailing content (COORD c)", () => {
  const TRUST_OK = trustBodyWith({});
  const DATA_OK =
    '{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-10T12:00:00Z","entries":[]}';

  it("parseTrustBody rejects a trailing token after the JSON value", () => {
    expect(() => parseTrustBody(utf8(TRUST_OK))).not.toThrow();
    expect(() => parseTrustBody(utf8(TRUST_OK + "x"))).toThrow(TrustError);
    expect(() => parseTrustBody(utf8(TRUST_OK + "{}"))).toThrow(TrustError);
  });

  it("parseManifestBody rejects a trailing token after the JSON value", () => {
    expect(() => parseManifestBody(utf8(DATA_OK))).not.toThrow();
    expect(() => parseManifestBody(utf8(DATA_OK + "x"))).toThrow(ManifestVerifyError);
  });
});

// --- Fix #3 (COORD b): writer resolution by DERIVED fingerprint --------------

describe("findWriterSigningIdentity derives key_id from pubkey (COORD b)", () => {
  it("resolves by derived fingerprint when declared key_id is CONSISTENT (non-empty, == fingerprint)", () => {
    const k = edKey(0x21);
    const m = parseTrustBody(
      utf8(trustBodyWith({ identities: [identity("human:w@x", "human", [signingKeyEntry(k.pubB64, k.fp)])] })),
    );
    // Worker türetilmiş fp ile eşler → sahibi çözer (declared key_id yalnızca tutarlılık kapısı).
    const got = findWriterSigningIdentity(m, k.fp);
    expect(got?.identity.id).toBe("human:w@x");
    expect(got?.cls).toBe("daily");
  });

  it("REJECTS an entry whose declared key_id != fingerprint(pubkey) (misattribution guard)", () => {
    const real = edKey(0x21);
    const other = edKey(0x22);
    // Kimlik B, BAŞKASININ (real) parmak izini declared key_id olarak koyuyor ama
    // pubkey'i other → declared != türetilen → tutarsız kayıt reddedilir.
    const m = parseTrustBody(
      utf8(trustBodyWith({ identities: [identity("human:b@x", "human", [signingKeyEntry(other.pubB64, real.fp)])] })),
    );
    expect(() => findWriterSigningIdentity(m, real.fp)).toThrow(TrustError);
  });

  it("does NOT misattribute: matching is by pubkey, not the self-declared key_id", () => {
    const a = edKey(0x21); // gerçek imzalayan
    const b = edKey(0x22);
    // A doğru; B'nin declared key_id'si kendi türetilenine EŞİT (tutarlı) ama farklı fp.
    const m = parseTrustBody(
      utf8(
        trustBodyWith({
          identities: [
            identity("human:a@x", "human", [signingKeyEntry(a.pubB64, a.fp)]),
            identity("human:b@x", "human", [signingKeyEntry(b.pubB64, b.fp)]),
          ],
        }),
      ),
    );
    // A'nın fp'siyle sorgu → A çözülür (B'ye asla mal edilmez).
    expect(findWriterSigningIdentity(m, a.fp)?.identity.id).toBe("human:a@x");
    expect(findWriterSigningIdentity(m, b.fp)?.identity.id).toBe("human:b@x");
  });
});

// --- F3 (matrix §F3.1): empty key_id rejected at parse on BOTH sides ----------

describe("F3: an empty key_id is rejected at parse (matrix §F3.1; both sides reject '')", () => {
  it("REJECTS an empty signing_keys[].key_id", () => {
    const k = edKey(0x21);
    expect(() =>
      parseTrustBody(utf8(trustBodyWith({ identities: [identity("human:w@x", "human", [signingKeyEntry(k.pubB64, "")])] }))),
    ).toThrow(TrustError);
  });

  it("REJECTS an empty enc_keys[].key_id", () => {
    const enc = { key_id: "", class: "device", pubkey: "age1x", media: "software", added_at: 1, status: "active" };
    const id = { id: "human:w@x", type: "human", enc_keys: [enc], signing_keys: [], status: "active" };
    expect(() => parseTrustBody(utf8(trustBodyWith({ identities: [id] })))).toThrow(TrustError);
  });

  it("REJECTS an empty roots[].key_id", () => {
    const root = { key_id: "", alg: "ed25519", pubkey: "AA==", media: "m", holder: "h", status: "active" };
    expect(() => parseTrustBody(utf8(trustBodyWith({ roots: [root] })))).toThrow(TrustError);
  });

  it("ACCEPTS a non-empty (consistent) key_id at parse", () => {
    const k = edKey(0x21);
    const m = parseTrustBody(
      utf8(trustBodyWith({ identities: [identity("human:w@x", "human", [signingKeyEntry(k.pubB64, k.fp)])] })),
    );
    expect(m.identities[0].signing_keys[0].key_id).toBe(k.fp);
  });
});

// --- Fix #5 (registry semantics): machine wildcard rejected in verified epoch -

// Signed genesis kurucu (2-of-3 ed25519 root) — verifyGenesis'i gerçek yoldan sürer.
function signedGenesis(bodyObj: Record<string, unknown>, seeds: number[]): { obj: ReturnType<typeof parseSignedObject>; pin: Pin } {
  const bodyBytes = utf8(JSON.stringify(bodyObj));
  const sigs = seeds.map((sb) => {
    const seed = new Uint8Array(32).fill(sb);
    const pub = ed25519.getPublicKey(seed);
    return { schema: "wapps-secrets/sig/v1", key_id: fingerprint(pub), alg: "ed25519", sig: bytesToB64(ed25519.sign(sha256(bodyBytes), seed)) };
  });
  const wrapper = { bytes: bytesToB64(bodyBytes), sigs };
  const obj = parseSignedObject(wrapper);
  return { obj, pin: { admin_epoch: 1, sha256: sha256Hex(bodyBytes) } };
}

function genesisBody(grants: unknown[], writerAllow: unknown[]): Record<string, unknown> {
  const rootSeeds = [0x11, 0x12, 0x13];
  const holder = "human:h@x";
  return {
    schema: "wapps-trust/v1",
    admin_epoch: 1,
    prev_trust_sha256: "",
    created_at: "2026-07-10T12:00:00Z",
    change_class: "roster",
    bootstrap_solo: true, // tek holder → maxHolderShare(3) >= m(2)
    quorum: { m: 2, n: 3 },
    roots: rootSeeds.map((sb, i) => {
      const pub = ed25519.getPublicKey(new Uint8Array(32).fill(sb));
      return { key_id: fingerprint(pub), alg: "ed25519", pubkey: bytesToB64(pub), media: ["a", "b", "c"][i], holder, status: "active" };
    }),
    admins: [],
    identities: [
      {
        id: "machine:ci",
        type: "machine",
        enc_keys: [{ key_id: fingerprintRecipient("age1x"), class: "device", pubkey: "age1x", media: "software", added_at: 1, status: "active" }],
        signing_keys: [signingKeyEntry(edKey(0x44).pubB64, edKey(0x44).fp, "automation")],
        status: "active",
        rotate_by: "2099-01-01T00:00:00Z",
      },
    ],
    grants,
    writer_allowlists: writerAllow,
    worker_receipt_pubkey: null,
    worker_mint_pubkeys: null,
    epoch_reset: null,
  };
}

describe("registry semantics in a verified epoch: machine wildcard rejected (Fix #5)", () => {
  it("baseline: machine grant with an EXPLICIT key verifies (verifyGenesis passes)", () => {
    const body = genesisBody([{ principal: "machine:ci", project: "p", verbs: ["read"], keys: ["CI_KEY"] }], []);
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    const head: VerifiedEpoch = verifyGenesis(pin, obj);
    expect(head.manifest.admin_epoch).toBe(1);
  });

  it('machine GRANT keys:["*"] is REJECTED (blast-radius; Go registry.Validate parity)', () => {
    const body = genesisBody([{ principal: "machine:ci", project: "p", verbs: ["read"], keys: ["*"] }], []);
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).toThrow(TrustError);
  });

  it('machine WRITER-ALLOWLIST keys:["*"] is REJECTED', () => {
    const body = genesisBody([], [{ principal: "machine:ci", project: "p", keys: ["*"] }]);
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).toThrow(TrustError);
  });

  it('a HUMAN grant keys:["*"] is still ALLOWED (project-level wildcard, §6.3)', () => {
    const body = genesisBody([], []);
    // İnsan kimliği + wildcard grant ekle.
    (body.identities as unknown[]).push(identity("human:admin@x", "human", [signingKeyEntry(edKey(0x55).pubB64, edKey(0x55).fp)]));
    (body.grants as unknown[]).push({ principal: "human:admin@x", project: "p", verbs: ["read"], keys: ["*"] });
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).not.toThrow();
  });
});

// --- Fix #2 (COORD d): key_id ↔ fingerprint(pubkey) for EVERY identity key ----

describe("verified epoch enforces key_id ↔ fingerprint for EVERY identity key (Fix #2)", () => {
  // genesisBody'nin makine kimliği enc(pubkey="age1x", key_id="") + signing(key_id="")
  // taşır; declared key_id'yi TUTARSIZ yapınca validateRegistrySemantics reddetmeli.
  type MutIds = { enc_keys: { key_id: string; pubkey: string }[]; signing_keys: { key_id: string }[] }[];
  const grant = [{ principal: "machine:ci", project: "p", verbs: ["read"], keys: ["CI_KEY"] }];

  it("ACCEPTS an enc key whose declared key_id EQUALS fingerprint(pubkey)", () => {
    const body = genesisBody(grant, []);
    (body.identities as MutIds)[0].enc_keys[0].key_id = fingerprintRecipient("age1x"); // doğru
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).not.toThrow();
  });

  it("REJECTS a non-empty enc_keys[].key_id that != fingerprint(pubkey) (Go registry.Validate parity)", () => {
    const body = genesisBody(grant, []);
    (body.identities as MutIds)[0].enc_keys[0].key_id = "sha256:deadbeef"; // tutarsız
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).toThrow(TrustError);
  });

  it("REJECTS a non-empty signing_keys[].key_id that != fingerprint(pubkey)", () => {
    const body = genesisBody(grant, []);
    (body.identities as MutIds)[0].signing_keys[0].key_id = "sha256:deadbeef"; // tutarsız
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).toThrow(TrustError);
  });

  it("REJECTS an empty enc pubkey (structurally invalid; Go rejects too)", () => {
    const body = genesisBody(grant, []);
    (body.identities as MutIds)[0].enc_keys[0].pubkey = "";
    const { obj, pin } = signedGenesis(body, [0x11, 0x12]);
    expect(() => verifyGenesis(pin, obj)).toThrow(TrustError);
  });
});

// --- Fix #1 (COORD a): data manifest `wrap` is strict canonical base64 --------

describe("data manifest wrap is strict canonical base64 (Fix #1)", () => {
  const dataWithWrap = (wrap: string): string =>
    `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-10T12:00:00Z","entries":[{"keyName":"K","keyVersion":1,"blobHash":"aa","wraps":[{"recipient":"sha256:r","wrap":${JSON.stringify(wrap)}}]}]}`;

  it("ACCEPTS a canonical padded base64 wrap (btoa parity)", () => {
    const m = parseManifestBody(utf8(dataWithWrap("YQ==")));
    expect(m.entries[0].wraps[0].wrapB64).toBe("YQ==");
  });

  it('REJECTS wrap:"not-base64" (Go decodes wrap as []byte base64 → unmarshal error)', () => {
    expect(() => parseManifestBody(utf8(dataWithWrap("not-base64")))).toThrow(ManifestVerifyError);
  });

  it("REJECTS an unpadded wrap (length %4 != 0 — Go StdEncoding padding'li ister)", () => {
    expect(() => parseManifestBody(utf8(dataWithWrap("YQ")))).toThrow(ManifestVerifyError);
  });

  it("REJECTS a non-canonical trailing-bits wrap (roundtrip != input)", () => {
    // "AB==" atob'da [0]'a çözülür ama kanonik kodlama "AA==".
    expect(() => parseManifestBody(utf8(dataWithWrap("AB==")))).toThrow(ManifestVerifyError);
  });
});

// --- Fix #4 (COORD e): full Go Identity shape modeled + validated -------------

describe("full Go Identity shape is modeled + validated, not dropped (Fix #4)", () => {
  const idWith = (extra: Record<string, unknown>): string =>
    trustBodyWith({
      identities: [{ id: "machine:ci", type: "machine", enc_keys: [], signing_keys: [], status: "active", ...extra }],
    });

  it("retains enrolled_at / vouched_by / rotate_by (previously silently dropped)", () => {
    const m = parseTrustBody(
      utf8(idWith({ enrolled_at: "2026-01-01T00:00:00Z", vouched_by: ["human:a@x"], rotate_by: "2026-04-01T00:00:00Z" })),
    );
    expect(m.identities[0].enrolled_at).toBe("2026-01-01T00:00:00Z");
    expect(m.identities[0].vouched_by).toEqual(["human:a@x"]);
    expect(m.identities[0].rotate_by).toBe("2026-04-01T00:00:00Z");
  });

  it("defaults absent enrolled_at/vouched_by/rotate_by to zero/empty/null (Go zero values)", () => {
    const m = parseTrustBody(utf8(idWith({})));
    expect(m.identities[0].enrolled_at).toBe("");
    expect(m.identities[0].vouched_by).toEqual([]);
    expect(m.identities[0].rotate_by).toBeNull();
  });

  it("REJECTS a non-RFC3339 rotate_by (Go *time.Time parse parity)", () => {
    expect(() => parseTrustBody(utf8(idWith({ rotate_by: "soon" })))).toThrow(TrustError);
  });

  it("REJECTS a numeric rotate_by (Go: input is not a JSON string)", () => {
    expect(() => parseTrustBody(utf8(idWith({ rotate_by: 12345 })))).toThrow(TrustError);
  });

  it("REJECTS a non-RFC3339 enrolled_at", () => {
    expect(() => parseTrustBody(utf8(idWith({ enrolled_at: "yesterday" })))).toThrow(TrustError);
  });

  it("REJECTS a non-array vouched_by (Go []string parity)", () => {
    expect(() => parseTrustBody(utf8(idWith({ vouched_by: "human:b@x" })))).toThrow(TrustError);
  });
});
