// Anahtar-adı / proje-adı doğrulama testleri (SPEC §4.1). KEYNAME_RE POSIX env-var
// adıdır (karışık harf) — gerçek infra sırları (TF_VAR_<lower>, vaulter_pg_*_password,
// lab_01_id) kabul edilmeli; boşluk/tire/nokta/lead-digit/non-ASCII reddedilmeli.

import { beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  validKeyName,
  validProject,
  validSharedId,
  keyBlob,
  keyCurrent,
  keyManifest,
  keyPointerEvent,
  deriveProjects,
  deleteProjectObjects,
} from "../src/storage.js";
import { clearBucket } from "./helpers.js";

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

  it("rejects JS prototype-special names (regex would otherwise accept them)", () => {
    // Bunlar regex'ten geçer ama plain-object response haritalarında sırrı düşürür /
    // prototype-pollution eder → açıkça reddet.
    for (const k of ["__proto__", "constructor", "prototype"]) {
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

// Shared named secrets (design 2026-11-11): `<namespace>/<name>`, each part
// [a-z0-9][a-z0-9-]{0,30}, exactly one `/`. Project names have no `/`, so the two
// grammars cannot collide.
describe("validSharedId", () => {
  it("accepts <namespace>/<name> with parts of 1 to 31 characters", () => {
    for (const id of ["apple/asc", "a/b", "apple/app-store-connect", "0/9", `${"a".repeat(31)}/${"b".repeat(31)}`]) {
      expect(validSharedId(id), id).toBe(true);
    }
  });

  it("refuses malformed ids", () => {
    for (const id of [
      "",
      "~",
      "/",
      "apple",
      "apple/",
      "/asc",
      "a/b/c",
      "apple//asc",
      "apple~asc",
      "Apple/asc",
      "apple/ASC",
      "-apple/asc",
      "apple/-asc",
      "apple/as_c",
      "apple/as c",
      `${"a".repeat(32)}/asc`,
      `apple/${"b".repeat(32)}`,
      "äpple/asc",
    ]) {
      expect(validSharedId(id), id).toBe(false);
    }
  });

  it("no project name is a shared id and no shared id is a project name", () => {
    for (const p of ["apple", "apple-asc", "vaulter"]) expect(validSharedId(p), p).toBe(false);
    expect(validProject("apple/asc")).toBe(false);
  });
});

describe("storage key encoding (one encoder: `/` -> `~`)", () => {
  it("project names map to their own prefix unchanged", () => {
    expect(keyCurrent("vaulter")).toBe("secrets/vaulter/current");
    expect(keyManifest("vaulter", 3)).toBe("secrets/vaulter/manifests/3.json");
    expect(keyBlob("vaulter", "ab")).toBe("secrets/vaulter/blobs/ab");
    expect(keyPointerEvent("vaulter", 3)).toBe("pointer-events/vaulter/3.json");
  });

  it("a shared id maps to secrets/<ns>~<name>/", () => {
    expect(keyCurrent("apple/asc")).toBe("secrets/apple~asc/current");
    expect(keyManifest("apple/asc", 2)).toBe("secrets/apple~asc/manifests/2.json");
    expect(keyBlob("apple/asc", "ab")).toBe("secrets/apple~asc/blobs/ab");
    expect(keyPointerEvent("apple/asc", 2)).toBe("pointer-events/apple~asc/2.json");
  });

  it("refuses a name that could alias another prefix (`~`, extra `/`, empty part)", () => {
    for (const bad of ["apple~asc", "~", "a/b/c", "apple/", "/asc", "Apple/asc"]) {
      expect(() => keyCurrent(bad), bad).toThrow();
      expect(() => keyBlob(bad, "ab"), bad).toThrow();
      expect(() => keyManifest(bad, 1), bad).toThrow();
      expect(() => keyPointerEvent(bad, 1), bad).toThrow();
    }
  });
});

describe("deriveProjects / deleteProjectObjects with shared ids", () => {
  beforeEach(async () => {
    await clearBucket();
  });

  async function seed(name: string): Promise<void> {
    await env.SECRETS_BUCKET.put(keyCurrent(name), "c");
    await env.SECRETS_BUCKET.put(keyBlob(name, "ab"), "b");
  }

  it("decodes `<ns>~<name>` back to the shared id next to project names", async () => {
    await seed("apple");
    await seed("apple/asc");
    await seed("apple-asc");
    expect((await deriveProjects(env.SECRETS_BUCKET)).sort()).toEqual(["apple", "apple-asc", "apple/asc"]);
  });

  it("skips a `~` prefix that does not decode to a valid shared id", async () => {
    await seed("vaulter");
    await env.SECRETS_BUCKET.put("secrets/a~b~c/current", "c");
    await env.SECRETS_BUCKET.put("secrets/~/current", "c");
    expect(await deriveProjects(env.SECRETS_BUCKET)).toEqual(["vaulter"]);
  });

  it("deleting project `apple` never touches secrets/apple~asc/", async () => {
    await seed("apple");
    await seed("apple/asc");
    expect(await deleteProjectObjects(env.SECRETS_BUCKET, "apple")).toBe(2);
    expect(await env.SECRETS_BUCKET.head(keyCurrent("apple/asc"))).not.toBeNull();
    expect(await env.SECRETS_BUCKET.head(keyBlob("apple/asc", "ab"))).not.toBeNull();
    expect(await deriveProjects(env.SECRETS_BUCKET)).toEqual(["apple/asc"]);
  });

  it("deleting shared `apple/asc` removes only its own prefix", async () => {
    await seed("apple");
    await seed("apple/asc");
    await seed("apple/asc2");
    expect(await deleteProjectObjects(env.SECRETS_BUCKET, "apple/asc")).toBe(2);
    expect((await deriveProjects(env.SECRETS_BUCKET)).sort()).toEqual(["apple", "apple/asc2"]);
  });

  it("refuses to delete under a name that is not a store name", async () => {
    await expect(deleteProjectObjects(env.SECRETS_BUCKET, "apple~asc")).rejects.toThrow();
  });
});
