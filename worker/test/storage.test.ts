// Anahtar-adı / proje-adı doğrulama testleri (SPEC §4.1). KEYNAME_RE POSIX env-var
// adıdır (karışık harf) — gerçek infra sırları (TF_VAR_<lower>, vaulter_pg_*_password,
// lab_01_id) kabul edilmeli; boşluk/tire/nokta/lead-digit/non-ASCII reddedilmeli.

import { describe, it, expect } from "vitest";
import { validKeyName, validProject } from "../src/storage.js";

describe("validKeyName", () => {
  it("accepts real infra key names (mixed case, tofu vars, outputs)", () => {
    for (const k of [
      "DATABASE_URL",
      "TF_VAR_cloudflare_api_token",
      "vaulter_pg_admin_password",
      "lab_01_id",
      "lab_01_private_ip",
      "coolify_project_uuid",
      "_leading_underscore",
      "a",
    ]) {
      expect(validKeyName(k), k).toBe(true);
    }
  });

  it("rejects malformed key names", () => {
    for (const k of [
      "",
      "1leading_digit",
      "has space",
      "has-dash",
      "has.dot",
      "has/slash",
      "über", // non-ASCII
    ]) {
      expect(validKeyName(k), k).toBe(false);
    }
  });

  it("bounds length to 128", () => {
    expect(validKeyName("A".repeat(128))).toBe(true);
    expect(validKeyName("A".repeat(129))).toBe(false);
  });
});

describe("validProject", () => {
  it("accepts lab/vaulter/vibe-pro", () => {
    for (const p of ["lab", "vaulter", "vibe-pro"]) expect(validProject(p), p).toBe(true);
  });

  it("rejects uppercase / underscore / bad projects", () => {
    for (const p of ["", "Lab", "has_underscore", "-lead", "has space"]) expect(validProject(p), p).toBe(false);
  });
});
