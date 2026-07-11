// KEK/kid/WKW1 frozen vektör + davranış testleri (SPEC §2.2–§2.5, build gate 2).
// kid + HKDF beklenen değerleri BAĞIMSIZ bir implementasyonla (node:crypto
// hkdfSync + createHash) üretildi ve burada literal olarak DONDURULDU — @noble
// zincirinden bağımsız çapraz doğrulama. Go tarafı aynı vektörleri ayrıca üretecek.

import { beforeEach, describe, it, expect } from "vitest";
import {
  MasterKey,
  loadMasterKeys,
  kekKid,
  deriveProjectKEK,
  slotAAD,
  wrapDEK,
  unwrapDEK,
  WrapError,
  WRAP_RECIPIENT,
  WRAP_TOTAL_LEN,
  __resetKekCache,
} from "../src/crypto/kek.js";
import { bytesToHex, hexToBytes, b64ToBytes, utf8 } from "../src/crypto/encoding.js";

const MASTER_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
const MASTER2_HEX = "3333333333333333333333333333333333333333333333333333333333333333";

// BAĞIMSIZ üretilmiş frozen değerler (node:crypto):
const FROZEN_KID = "9f72ea0cf49536e3";
const FROZEN_KID2 = "deb0e38ced1e41de";
const FROZEN_KEK_VAULTER = "14de5786d70663c6fd42879ed2c391fbb2fd6d109b532410312cf2564e0902d5";
const FROZEN_KEK_LUMIRA = "1413fbc058690c0ef5c01322013c1c80b2212cdaf6a99ba11e02084dd77555f0";

function master(hex = MASTER_HEX): MasterKey {
  const raw = hexToBytes(hex);
  return { kid: kekKid(raw), key: raw };
}

beforeEach(() => __resetKekCache());

describe("kid derivation (§2.2, frozen)", () => {
  it("kid = first 16 hex of SHA-256 over the 32 RAW bytes (NOT the hex string)", () => {
    expect(kekKid(hexToBytes(MASTER_HEX))).toBe(FROZEN_KID);
    expect(kekKid(hexToBytes(MASTER2_HEX))).toBe(FROZEN_KID2);
    // ASCII hex string'i hash'lemek FARKLI sonuç verir — regresyon tuzağı.
    expect(kekKid(utf8(MASTER_HEX).slice(0, 32))).not.toBe(FROZEN_KID);
  });
});

describe("HKDF per-project KEK (§2.3, frozen)", () => {
  it("reproduces the independently-generated HKDF vectors", () => {
    expect(bytesToHex(deriveProjectKEK(master(), "vaulter"))).toBe(FROZEN_KEK_VAULTER);
    expect(bytesToHex(deriveProjectKEK(master(), "lumira"))).toBe(FROZEN_KEK_LUMIRA);
  });

  it("project isolation: different projects derive different KEKs", () => {
    expect(bytesToHex(deriveProjectKEK(master(), "vaulter"))).not.toBe(bytesToHex(deriveProjectKEK(master(), "lumira")));
  });
});

describe("loadMasterKeys (§2.2/§2.5)", () => {
  it("loads current (+prev) and orders current first", () => {
    const keys = loadMasterKeys({ MASTER_KEK: MASTER_HEX, MASTER_KEK_PREV: MASTER2_HEX });
    expect(keys).not.toBeNull();
    expect(keys!.length).toBe(2);
    expect(keys![0].kid).toBe(FROZEN_KID);
    expect(keys![1].kid).toBe(FROZEN_KID2);
  });

  it("fails closed on missing/malformed MASTER_KEK; ignores malformed PREV", () => {
    expect(loadMasterKeys({})).toBeNull();
    expect(loadMasterKeys({ MASTER_KEK: "deadbeef" })).toBeNull(); // 64-hex değil
    expect(loadMasterKeys({ MASTER_KEK: MASTER_HEX, MASTER_KEK_PREV: "junk" })!.length).toBe(1);
  });
});

describe("slotAAD (§2.4 — blob AEAD ile AYNI bağlama)", () => {
  it("project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ version(decimal ASCII)", () => {
    const aad = slotAAD("vaulter", "DATABASE_URL", 3);
    // "vaulter" ‖ 00 ‖ "DATABASE_URL" ‖ 00 ‖ "3" (frozen bayt dizisi)
    expect(bytesToHex(aad)).toBe("7661756c7465720044415441424153455f55524c0033");
  });
});

describe("WKW1 wrap/unwrap (§2.4)", () => {
  const dek = new Uint8Array(32).map((_, i) => i);

  it("wrap is exactly 76 bytes: WKW1 ‖ nonce(24) ‖ ct(48); recipient/kid stamped", () => {
    const w = wrapDEK(master(), "vaulter", "DATABASE_URL", 3, dek);
    expect(w.recipient).toBe(WRAP_RECIPIENT);
    expect(w.kid).toBe(FROZEN_KID);
    const bytes = b64ToBytes(w.wrap);
    expect(bytes.length).toBe(WRAP_TOTAL_LEN);
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe("WKW1");
  });

  it("frozen wrap vector: fixed nonce reproduces byte-identical output + unwraps", () => {
    const nonce = new Uint8Array(24).fill(0x11);
    const w1 = wrapDEK(master(), "vaulter", "DATABASE_URL", 3, dek, nonce);
    const w2 = wrapDEK(master(), "vaulter", "DATABASE_URL", 3, dek, nonce);
    expect(w1.wrap).toBe(w2.wrap); // determinizm (aynı nonce)
    // FROZEN literal (bu implementasyonun ilk üretimi — regresyon kilidi; Go
    // tarafı §8.7 gate 2'de aynı baytları üretmek zorunda).
    expect(bytesToHex(b64ToBytes(w1.wrap))).toBe(
      "574b57311111111111111111111111111111111111111111111111116b49240ff0794bdd40325b287aa07262210022543431c351962af0dc9cce4a3b77b991429a00d593e2891becfa64346e",
    );
    expect(bytesToHex(unwrapDEK([master()], "vaulter", "DATABASE_URL", 3, w1))).toBe(bytesToHex(dek));
  });

  it("AAD slot binding: wrap cannot be replayed onto another key/project/version", () => {
    const w = wrapDEK(master(), "vaulter", "DATABASE_URL", 3, dek);
    expect(() => unwrapDEK([master()], "vaulter", "API_KEY", 3, w)).toThrowError(WrapError);
    expect(() => unwrapDEK([master()], "lumira", "DATABASE_URL", 3, w)).toThrowError(WrapError);
    expect(() => unwrapDEK([master()], "vaulter", "DATABASE_URL", 4, w)).toThrowError(WrapError);
  });

  it("rotation window (§2.5): prev-kid wrap unwraps while PREV installed, fails after removal", () => {
    const old = master(MASTER2_HEX);
    const cur = master(MASTER_HEX);
    const w = wrapDEK(old, "vaulter", "K", 1, dek);
    expect(w.kid).toBe(FROZEN_KID2);
    // current + prev kurulu → açılır.
    expect(bytesToHex(unwrapDEK([cur, old], "vaulter", "K", 1, w))).toBe(bytesToHex(dek));
    // PREV silindi → kid eşleşmez → WRAP_INVALID (fail-closed).
    expect(() => unwrapDEK([cur], "vaulter", "K", 1, w)).toThrowError(WrapError);
  });

  it("tamper/format failures → WRAP_INVALID; unknown recipient → ALG_UNSUPPORTED", () => {
    const w = wrapDEK(master(), "vaulter", "K", 1, dek);
    const bytes = b64ToBytes(w.wrap);
    bytes[10] ^= 0x01; // nonce bit flip
    const tampered = { ...w, wrap: btoa(String.fromCharCode(...bytes)) };
    expect(() => unwrapDEK([master()], "vaulter", "K", 1, tampered)).toThrowError(WrapError);
    let caught: unknown = null;
    try {
      unwrapDEK([master()], "vaulter", "K", 1, { ...w, recipient: "x25519:v1" });
    } catch (e) {
      caught = e;
    }
    expect((caught as WrapError).code).toBe("ALG_UNSUPPORTED");
    expect(() => unwrapDEK([master()], "vaulter", "K", 1, { ...w, wrap: "AAAA" })).toThrowError(WrapError); // 76 bayt değil
  });
});
