// CROSS-LANGUAGE PARITY ORACLE (TS/Worker tarafı).
//
// Bu test, TS `parseManifestBody`/`parseTrustBody` ile Go `ParseManifestBody`/
// `ParseTrustBody`'nin HER crafted JSON gövdesinde AYNI accept/reject kararını
// verdiğini kanıtlar. Vektörler `./parity-vectors.json` dosyasında TEK KAYNAK
// olarak tutulur ve AYNI dosya Go tarafında da okunur (internal/manifest +
// internal/trust parity_vectors_test.go) → iki tablo LİTERAL olarak aynı girdileri
// sürer. Bir vektörün TS verdict'i beklenenle uyuşmazsa (veya Go ile ayrışırsa)
// bu bir CONSENSUS DIVERGENCE'tır ve testi gevşeterek DEĞİL, parser'ı hizalayarak
// çözülmelidir.

import { describe, it, expect } from "vitest";
import { utf8 } from "../src/crypto/verify.js";
import { parseManifestBody } from "../src/manifest.js";
import { parseTrustBody } from "../src/trust.js";
import vectors from "./parity-vectors.json";

interface ParityVector {
  name: string;
  kind: "manifest" | "trust";
  verdict: "accept" | "reject";
  body: string;
}

const all = vectors as ParityVector[];

// parse, bir vektörü kind'ına göre gerçek parser'a sürer (throw = reject, ok = accept).
function parse(v: ParityVector): void {
  const bytes = utf8(v.body);
  if (v.kind === "manifest") parseManifestBody(bytes);
  else parseTrustBody(bytes);
}

describe("cross-language parity vectors (shared file; Go Parse*Body parity)", () => {
  it("exercises a non-empty, kind-balanced vector set", () => {
    expect(all.length).toBeGreaterThan(0);
    expect(all.filter((v) => v.kind === "manifest").length).toBeGreaterThan(0);
    expect(all.filter((v) => v.kind === "trust").length).toBeGreaterThan(0);
  });

  for (const v of all) {
    it(`${v.kind}: ${v.name} → ${v.verdict}`, () => {
      if (v.verdict === "accept") {
        expect(() => parse(v), `vector ${v.name} must be ACCEPTED (TS); body=${v.body}`).not.toThrow();
      } else {
        expect(() => parse(v), `vector ${v.name} must be REJECTED (TS); body=${v.body}`).toThrow();
      }
    });
  }
});
