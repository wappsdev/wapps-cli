// Parse katılığı paritesi (P3): TS body parse'ı, imzalı alanlarda Go json
// decode'undan DAHA GEVŞEK olmamalı. Go: `1e3`/`1.0` gibi non-integer literalleri
// REDDEDER, >2^53'ü TAM taşır (JS yuvarlar → reddedilir), createdAt'ı KATİ RFC3339
// ister, worker_receipt_pubkey/mint ve epoch_reset alanlarında bilinmeyen anahtar
// reddedilir. Bu test tightening'in Go ile eşleştiğini kilitler.

import { describe, it, expect } from "vitest";
import { utf8 } from "../src/crypto/verify.js";
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

  it("rejects a non-RFC3339 createdAt", () => {
    expect(dataThrows(DATA.replace('"2026-07-10T12:00:00Z"', '"10 Jul 2026"'))).toBe("MANIFEST_MALFORMED");
  });
});
