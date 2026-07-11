// Parse katılığı paritesi (P3): TS body parse'ı, imzalı alanlarda Go json
// decode'undan DAHA GEVŞEK olmamalı. Go: `1e3`/`1.0` gibi non-integer literalleri
// REDDEDER, >2^53'ü TAM taşır (JS yuvarlar → reddedilir), createdAt'ı KATİ RFC3339
// ister, worker_receipt_pubkey/mint ve epoch_reset alanlarında bilinmeyen anahtar
// reddedilir. Bu test tightening'in Go ile eşleştiğini kilitler.

import { describe, it, expect } from "vitest";
import { utf8, isRFC3339 } from "../src/crypto/verify.js";
import { parseTrustBody, TrustError } from "../src/trust.js";
import { parseManifestBody, ManifestVerifyError } from "../src/manifest.js";

// Geçerli minimal trust body (roster). parseTrustBody yapısal + tip + literal
// katılığı uygular; fingerprint/quorum değişmezleri verifyGenesis/Next katmanındadır.
const TRUST = `{"schema":"wapps-trust/v1","admin_epoch":1,"prev_trust_sha256":"","created_at":"2026-07-10T12:00:00Z","change_class":"roster","bootstrap_solo":true,"quorum":{"m":2,"n":3},"roots":[],"admins":[],"identities":[],"grants":[],"writer_allowlists":[],"worker_receipt_pubkey":null,"worker_mint_pubkeys":null,"epoch_reset":null}`;

const DATA = `{"schema":"wapps-secrets/data-manifest/v1","project":"vaulter","epoch":1,"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-10T12:00:00Z","entries":[{"keyName":"K","keyVersion":1,"blobHash":"aa","wraps":[]}]}`;

function trustThrows(body: string): string {
  expect(body).not.toBe(TRUST); // substitution gerçekten değişti mi
  try {
    parseTrustBody(utf8(body));
  } catch (e) {
    return (e as TrustError).code;
  }
  throw new Error("expected parseTrustBody to throw");
}

function dataThrows(body: string): string {
  expect(body).not.toBe(DATA);
  try {
    parseManifestBody(utf8(body));
  } catch (e) {
    return (e as ManifestVerifyError).code;
  }
  throw new Error("expected parseManifestBody to throw");
}

describe("trust body parse strictness (Go decode parity)", () => {
  it("accepts the valid baseline (and epoch_reset stays null)", () => {
    const m = parseTrustBody(utf8(TRUST));
    expect(m.admin_epoch).toBe(1);
    expect(m.epoch_reset).toBeNull();
  });

  it("rejects exponent integer literal 1e3 in a signed integer field", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":1e3,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects decimal literal 1.0 in a signed integer field", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":1.0,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects an integer literal > 2^53 (JS silently rounds; Go carries exactly)", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":9007199254740993,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("COORD (a): ACCEPTS admin_epoch = 2^53-1 (inclusive upper bound; Go now also rejects >2^53-1)", () => {
    const m = parseTrustBody(utf8(TRUST.replace('"admin_epoch":1,', '"admin_epoch":9007199254740991,')));
    expect(m.admin_epoch).toBe(9007199254740991);
  });

  it("COORD (a): REJECTS admin_epoch = 2^53 (first value outside the shared domain)", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":9007199254740992,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("COORD (b): REJECTS a negative integer literal -1 (unsigned 0..2^53-1 domain)", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":-1,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("COORD (b): REJECTS negative-zero -0 in a signed integer field", () => {
    expect(trustThrows(TRUST.replace('"admin_epoch":1,', '"admin_epoch":-0,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("COORD (b): ACCEPTS admin_epoch = 0 (lower bound of the unsigned domain)", () => {
    const m = parseTrustBody(utf8(TRUST.replace('"admin_epoch":1,', '"admin_epoch":0,')));
    expect(m.admin_epoch).toBe(0);
  });

  it("COORD round-5 (a): admins null / absent / [] all normalize to [] (locked-array equivalence)", () => {
    // compareUnchanged, admins'i deepEqual(parent.admins, cur.admins) ile karşılaştırır;
    // parse HER üç biçimi de []'e indirger → non-roster null<->[] admins değişimi
    // "değişmedi" sayılır (Go tarafı da nil-vs-[] ayrımını bırakır). Not: TAM-zincir
    // (verifyRosterChain) ile admins-null test EDİLEMEZ çünkü non-roster child'ı imzalayan
    // admin, parent'ın `admins` listesinde OLMAK zorundadır → boş admins ile imza yetmez.
    const asNull = parseTrustBody(utf8(TRUST.replace('"admins":[],', '"admins":null,')));
    const asEmpty = parseTrustBody(utf8(TRUST));
    const asAbsent = parseTrustBody(utf8(TRUST.replace('"admins":[],', "")));
    expect(asNull.admins).toEqual([]);
    expect(asEmpty.admins).toEqual([]);
    expect(asAbsent.admins).toEqual([]);
    expect(asNull.admins).toEqual(asEmpty.admins);
  });

  it("rejects a non-RFC3339 created_at (Date.parse would accept it)", () => {
    expect(trustThrows(TRUST.replace('"2026-07-10T12:00:00Z"', '"2026-07-10"'))).toBe("TRUST_CHAIN_BROKEN");
    expect(trustThrows(TRUST.replace('"2026-07-10T12:00:00Z"', '"July 10, 2026"'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects an unknown field in worker_receipt_pubkey ({kid,alg,jwk} shape enforced)", () => {
    expect(trustThrows(TRUST.replace('"worker_receipt_pubkey":null', '"worker_receipt_pubkey":{"kid":"a","alg":"ES256","jwk":{},"rogue":1}'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects a non-object worker_receipt_pubkey", () => {
    expect(trustThrows(TRUST.replace('"worker_receipt_pubkey":null', '"worker_receipt_pubkey":"oops"'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects an unknown field inside worker_mint_pubkeys entries", () => {
    expect(trustThrows(TRUST.replace('"worker_mint_pubkeys":null', '"worker_mint_pubkeys":[{"kid":"m","alg":"ES256","jwk":{},"rogue":1}]'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rejects an unknown field inside epoch_reset", () => {
    const rogue = '"epoch_reset":{"schema":"wapps-trust-reset/v1","reset_id":"x","reason":"y","prior_chain":{"last_admin_epoch":1,"last_trust_sha256":"z"},"snapshot_ref":"","rogue":1}';
    expect(trustThrows(TRUST.replace('"epoch_reset":null', rogue))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("parses a well-formed epoch_reset into the typed record", () => {
    const ok = '"epoch_reset":{"schema":"wapps-trust-reset/v1","reset_id":"rid","reason":"escrow_restore","prior_chain":{"last_admin_epoch":3,"last_trust_sha256":"abc"},"snapshot_ref":"snap"}';
    const m = parseTrustBody(utf8(TRUST.replace('"epoch_reset":null', ok)));
    expect(m.epoch_reset?.reset_id).toBe("rid");
    expect(m.epoch_reset?.prior_chain.last_admin_epoch).toBe(3);
  });

  // bootstrap_solo = strict-bool (matrix §2): present JSON true/false only.
  it("REJECTS bootstrap_solo = null (strict-bool; not a JSON boolean)", () => {
    expect(trustThrows(TRUST.replace('"bootstrap_solo":true,', '"bootstrap_solo":null,'))).toBe("TRUST_CHAIN_BROKEN");
  });
  it('REJECTS bootstrap_solo = "true" (string, not a JSON boolean)', () => {
    expect(trustThrows(TRUST.replace('"bootstrap_solo":true,', '"bootstrap_solo":"true",'))).toBe("TRUST_CHAIN_BROKEN");
  });
  it("REJECTS a missing bootstrap_solo (must be present)", () => {
    expect(trustThrows(TRUST.replace('"bootstrap_solo":true,', ""))).toBe("TRUST_CHAIN_BROKEN");
  });

  // quorum = present non-null object (matrix §2).
  it("REJECTS quorum = null (present non-null object required)", () => {
    expect(trustThrows(TRUST.replace('"quorum":{"m":2,"n":3},', '"quorum":null,'))).toBe("TRUST_CHAIN_BROKEN");
  });

  // epoch_reset strict-shape (matrix §3): prior_chain present-non-null; strict fields.
  it("REJECTS an epoch_reset with a null prior_chain (present non-null object required)", () => {
    const bad = '"epoch_reset":{"schema":"wapps-trust-reset/v1","reset_id":"x","reason":"y","prior_chain":null,"snapshot_ref":""}';
    expect(trustThrows(TRUST.replace('"epoch_reset":null', bad))).toBe("TRUST_CHAIN_BROKEN");
  });
  it("REJECTS an epoch_reset with a numeric reset_id (strict-string)", () => {
    const bad = '"epoch_reset":{"schema":"wapps-trust-reset/v1","reset_id":123,"reason":"y","prior_chain":{"last_admin_epoch":1,"last_trust_sha256":"z"},"snapshot_ref":""}';
    expect(trustThrows(TRUST.replace('"epoch_reset":null', bad))).toBe("TRUST_CHAIN_BROKEN");
  });
  it("REJECTS an epoch_reset with a null last_admin_epoch (strict-uint)", () => {
    const bad = '"epoch_reset":{"schema":"wapps-trust-reset/v1","reset_id":"x","reason":"y","prior_chain":{"last_admin_epoch":null,"last_trust_sha256":"z"},"snapshot_ref":""}';
    expect(trustThrows(TRUST.replace('"epoch_reset":null', bad))).toBe("TRUST_CHAIN_BROKEN");
  });

  // F3 (matrix §F3.1): empty key_id rejected at parse.
  it("REJECTS an empty roots[].key_id (matrix §F3.1)", () => {
    const root = '"roots":[{"key_id":"","alg":"ed25519","pubkey":"AA==","media":"m","holder":"h","status":"active"}]';
    expect(trustThrows(TRUST.replace('"roots":[]', root))).toBe("TRUST_CHAIN_BROKEN");
  });
});

describe("data manifest body parse strictness (Go decode parity)", () => {
  it("accepts the valid baseline", () => {
    const m = parseManifestBody(utf8(DATA));
    expect(m.epoch).toBe(1);
    expect(m.entries[0].keyVersion).toBe(1);
  });

  it("rejects exponent integer literal 1e3 for epoch", () => {
    expect(dataThrows(DATA.replace('"epoch":1,', '"epoch":1e3,'))).toBe("MANIFEST_MALFORMED");
  });

  it("rejects exponent integer literal 1e3 for keyVersion", () => {
    expect(dataThrows(DATA.replace('"keyVersion":1,', '"keyVersion":1e3,'))).toBe("MANIFEST_MALFORMED");
  });

  it("rejects an integer literal > 2^53 for epoch", () => {
    expect(dataThrows(DATA.replace('"epoch":1,', '"epoch":9007199254740993,'))).toBe("MANIFEST_MALFORMED");
  });

  it("COORD (a): rejects trustEpoch > 2^53-1 (epoch/trustEpoch/keyVersion/admin_epoch share the domain)", () => {
    expect(dataThrows(DATA.replace('"trustEpoch":1,', '"trustEpoch":9007199254740993,'))).toBe("MANIFEST_MALFORMED");
  });

  it("COORD (a): ACCEPTS trustEpoch = 2^53-1 (inclusive upper bound)", () => {
    const m = parseManifestBody(utf8(DATA.replace('"trustEpoch":1,', '"trustEpoch":9007199254740991,')));
    expect(m.trustEpoch).toBe(9007199254740991);
  });

  it("COORD (b): REJECTS a negative integer literal -1 for keyVersion (unsigned domain)", () => {
    expect(dataThrows(DATA.replace('"keyVersion":1,', '"keyVersion":-1,'))).toBe("MANIFEST_MALFORMED");
  });

  it("COORD (b): REJECTS negative-zero -0 for epoch", () => {
    expect(dataThrows(DATA.replace('"epoch":1,', '"epoch":-0,'))).toBe("MANIFEST_MALFORMED");
  });

  it("rejects a non-RFC3339 createdAt", () => {
    expect(dataThrows(DATA.replace('"2026-07-10T12:00:00Z"', '"10 Jul 2026"'))).toBe("MANIFEST_MALFORMED");
  });
});

// --- TS-1 (COORD c): IMKANSIZ RFC3339 zaman damgaları (Go time.Parse paritesi) ----
//
// `Date.parse` GEVŞEK değil, TAKVİM-NORMALLEŞTİRİCİ'dir: 2026-02-31 → 3 Mart,
// 2026-01-01T24:00:00 → ertesi gün gibi imkansız tarihleri sessizce geçerli
// bir Date'e taşır → Go REDDEDER / Worker KABUL eder AYRIŞMASI (read/trust brick).
// Bu blok isRFC3339'un artık STRICT takvim ayrıştırması yaptığını (Date.parse YOK)
// ve her imzalı zaman-damgası kapısına (created_at/createdAt/enrolled_at/rotate_by)
// yansıdığını kilitler. Kabul/red değerleri Go time.Parse(time.RFC3339, ...) ile
// bire bir doğrulandı.

describe("isRFC3339 strict calendar semantics (Go time.Parse parity — TS-1)", () => {
  it("REJECTS 2026-02-31 (impossible day; Date.parse normalizes → Mar 3)", () => {
    expect(isRFC3339("2026-02-31T00:00:00Z")).toBe(false);
  });
  it("REJECTS 2026-01-01T24:00:00Z (hour 24; Date.parse normalizes → next day)", () => {
    expect(isRFC3339("2026-01-01T24:00:00Z")).toBe(false);
  });
  it("REJECTS 2026-13-01 (month 13)", () => {
    expect(isRFC3339("2026-13-01T00:00:00Z")).toBe(false);
  });
  it("REJECTS 2025-02-29 (Feb 29 in a NON-leap year)", () => {
    expect(isRFC3339("2025-02-29T00:00:00Z")).toBe(false);
  });
  it("ACCEPTS 2024-02-29 (Feb 29 in a leap year)", () => {
    expect(isRFC3339("2024-02-29T00:00:00Z")).toBe(true);
  });
  it("ACCEPTS a normal UTC timestamp", () => {
    expect(isRFC3339("2026-07-10T12:00:00Z")).toBe(true);
  });

  // Ek sınır vektörleri (hepsi Go time.Parse ile karşılaştırıldı).
  it("REJECTS month 00 and day 00", () => {
    expect(isRFC3339("2026-00-10T12:00:00Z")).toBe(false);
    expect(isRFC3339("2026-01-00T12:00:00Z")).toBe(false);
  });
  it("REJECTS minute 60 and second 60 (Go rejects leap-second 60)", () => {
    expect(isRFC3339("2026-01-01T00:60:00Z")).toBe(false);
    expect(isRFC3339("2026-06-30T23:59:60Z")).toBe(false);
  });
  it("ACCEPTS 2100-02-28 but REJECTS 2100-02-29 (century non-leap)", () => {
    expect(isRFC3339("2100-02-28T00:00:00Z")).toBe(true);
    expect(isRFC3339("2100-02-29T00:00:00Z")).toBe(false);
  });
  it("ACCEPTS 2000-02-29 (400-year leap)", () => {
    expect(isRFC3339("2000-02-29T00:00:00Z")).toBe(true);
  });
  it("ACCEPTS fractional seconds and numeric offsets", () => {
    expect(isRFC3339("2026-07-10T12:00:00.500Z")).toBe(true);
    expect(isRFC3339("2026-07-10T12:00:00+02:30")).toBe(true);
  });
  it("matches Go's timezone-offset range: accepts +24:00 / +00:60, rejects +25:00 / +00:61", () => {
    expect(isRFC3339("2026-01-01T00:00:00+24:00")).toBe(true);
    expect(isRFC3339("2026-01-01T00:00:00+00:60")).toBe(true);
    expect(isRFC3339("2026-01-01T00:00:00+25:00")).toBe(false);
    expect(isRFC3339("2026-01-01T00:00:00+00:61")).toBe(false);
  });
  it("REJECTS shapes Date.parse would swallow (missing T/seconds/zone)", () => {
    expect(isRFC3339("2026-07-10")).toBe(false);
    expect(isRFC3339("2026-07-10T12:00Z")).toBe(false);
    expect(isRFC3339("2026-07-10T12:00:00")).toBe(false);
    expect(isRFC3339("July 10, 2026")).toBe(false);
  });
});

describe("impossible timestamps are rejected at EVERY signed gate (TS-1 integration)", () => {
  // Bir makine kimliği: enrolled_at + rotate_by imzalı zaman-damgası kapılarını sürer.
  const idBlock = (extra: string): string =>
    `"identities":[{"id":"machine:ci","type":"machine","enc_keys":[],"signing_keys":[],"status":"active"${extra}}]`;

  it("created_at: parseTrustBody rejects an impossible date", () => {
    expect(trustThrows(TRUST.replace('"2026-07-10T12:00:00Z"', '"2026-02-31T00:00:00Z"'))).toBe("TRUST_CHAIN_BROKEN");
  });

  it("createdAt: parseManifestBody rejects an impossible date", () => {
    expect(dataThrows(DATA.replace('"2026-07-10T12:00:00Z"', '"2026-01-01T24:00:00Z"'))).toBe("MANIFEST_MALFORMED");
  });

  it("enrolled_at: parseTrustBody rejects an impossible date", () => {
    const body = TRUST.replace('"identities":[]', idBlock(',"enrolled_at":"2026-02-31T00:00:00Z"'));
    expect(trustThrows(body)).toBe("TRUST_CHAIN_BROKEN");
  });

  it("rotate_by: parseTrustBody rejects an impossible date", () => {
    const body = TRUST.replace('"identities":[]', idBlock(',"rotate_by":"2026-13-01T00:00:00Z"'));
    expect(trustThrows(body)).toBe("TRUST_CHAIN_BROKEN");
  });

  it("enrolled_at/rotate_by: a valid leap-day timestamp is ACCEPTED", () => {
    const body = TRUST.replace(
      '"identities":[]',
      idBlock(',"enrolled_at":"2024-02-29T00:00:00Z","rotate_by":"2024-02-29T00:00:00Z"'),
    );
    const m = parseTrustBody(utf8(body));
    expect(m.identities[0].enrolled_at).toBe("2024-02-29T00:00:00Z");
    expect(m.identities[0].rotate_by).toBe("2024-02-29T00:00:00Z");
  });
});
