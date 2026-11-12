// Key codes (owner decision 2026-11-12). Every key gets a short code when it is
// first created: 6 characters of Crockford base32 (0-9 A-Z without I L O U), random,
// unique across the whole gate (projects and shared ids). A key's name at its issuer
// is `wapps-<CODE> <store id> <KEY>`. The code sits on the key's manifest entry next
// to its card and stays across value rotations; the uniqueness index is R2
// `key-codes/<CODE>`, written create-only and never deleted, so a deleted key's code
// is never given out again. GET /v1/codes/<CODE> resolves a code (case-insensitive)
// to {store, keyName, card} with the authorisation of reading that key's card, and a
// caller who may not read it gets the same answer as for an unknown code.
// POST /v1/admin/key-codes/backfill gives every key without a code one.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  serviceTokenClaims,
  authHeader,
  callGate,
  seedPolicy,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  ADMIN_EMAIL,
} from "./helpers.js";
import { PolicyRule } from "../src/policy.js";
import { CODE_ALPHABET, keyCodeIndex, normalizeCode, randomCode, reserveCode } from "../src/keycode.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { SCHEMA_CURRENT_POINTER, manifestObjectHash, parseCurrentPointer, parseManifest, serializeManifest } from "../src/manifest.js";
import { utf8 } from "../src/crypto/encoding.js";

const CODE_RE = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{6}$/;

function rules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*", "*/*"], keys: ["*", "!*_PROD_*"], verbs: ["read", "write", "rotate", "delete"] },
    { group: "admins@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["*"] },
    { group: "vaulter-only@wapps.co", projects: ["vaulter"], keys: ["*"], verbs: ["read"] },
    { group: "keys-only@wapps.co", projects: ["lab"], keys: ["PUBLIC_*"], verbs: ["read"] },
    { service: "svc-ci", projects: ["*", "*/*"], keys: ["*"], verbs: ["read", "write"] },
  ];
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(rules());
  groupsByEmail.set("dev@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
  groupsByEmail.set("vonly@wapps.dev", ["vaulter-only@wapps.co"]);
  groupsByEmail.set("konly@wapps.dev", ["keys-only@wapps.co"]);
  groupsByEmail.set("stranger@wapps.dev", []);
  groupsByEmail.set(ADMIN_EMAIL, []);
});

interface KeyRow {
  keyName: string;
  keyVersion: number;
  code?: string;
  note?: string;
  expires?: string;
}
interface Commit {
  project: string;
  epoch: number;
  keyVersions: Record<string, number>;
  keyCodes?: Record<string, string>;
  created?: string[];
}

async function hdr(email: string): Promise<Record<string, string>> {
  return authHeader(await signer.makeJWT(validClaims(email)));
}
async function put(email: string, base: string, key: string, body: Record<string, unknown>): Promise<Response> {
  return callGate(`${base}/keys/${key}`, { method: "PUT", headers: await hdr(email), body: JSON.stringify(body) });
}
async function imp(email: string, base: string, values: Record<string, string>): Promise<Response> {
  return callGate(`${base}/import`, { method: "POST", headers: await hdr(email), body: JSON.stringify({ values }) });
}
async function del(email: string, base: string, key: string): Promise<Response> {
  return callGate(`${base}/keys/${key}`, { method: "DELETE", headers: await hdr(email) });
}
async function keys(email: string, base: string): Promise<KeyRow[]> {
  const res = await callGate(`${base}/keys`, { headers: await hdr(email) });
  expect(res.status).toBe(200);
  return ((await res.json()) as { keys: KeyRow[] }).keys;
}
async function codeOf(base: string, key: string): Promise<string | undefined> {
  return (await keys("boss@wapps.dev", base)).find((k) => k.keyName === key)?.code;
}
async function find(email: string, code: string, extra: Record<string, string> = {}): Promise<Response> {
  return callGate(`/v1/codes/${code}`, { headers: { ...(await hdr(email)), ...extra } });
}
async function backfill(claims: Record<string, unknown> = validClaimsWrite(ADMIN_EMAIL)): Promise<Response> {
  return callGate("/v1/admin/key-codes/backfill", { method: "POST", headers: authHeader(await signer.makeJWT(claims)) });
}

/** stripCodes rewrites a store's current manifest as the next epoch without any
 * code, the way a store written before key codes looks. */
async function stripCodes(store: string): Promise<void> {
  const cur = await env.SECRETS_BUCKET.get(keyCurrent(store));
  const ptr = parseCurrentPointer(new Uint8Array(await cur!.arrayBuffer()));
  const man = parseManifest(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyManifest(store, ptr.epoch)))!.arrayBuffer()));
  const epoch = ptr.epoch + 1;
  const bytes = serializeManifest({ ...man, epoch, prevManifestSha256: ptr.manifestSha256, entries: man.entries.map(({ code: _code, ...e }) => e) });
  await env.SECRETS_BUCKET.put(keyManifest(store, epoch), bytes);
  await env.SECRETS_BUCKET.put(keyCurrent(store), utf8(JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project: store, epoch, manifestSha256: manifestObjectHash(bytes) })));
}

describe("the code itself", () => {
  it("is 6 characters of Crockford base32 without I, L, O and U", () => {
    expect(CODE_ALPHABET).toBe("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const c = randomCode();
      expect(c).toMatch(CODE_RE);
      seen.add(c);
    }
    // 2000 draws from 32^6 values: a repeat would mean a broken generator.
    expect(seen.size).toBe(2000);
  });

  it("is read case-insensitively and only in its own alphabet", () => {
    expect(normalizeCode("k7q2m4")).toBe("K7Q2M4");
    expect(normalizeCode("K7Q2M4")).toBe("K7Q2M4");
    for (const bad of ["", "K7Q2M", "K7Q2M45", "K7Q2MI", "K7Q2ML", "K7Q2MO", "K7Q2MU", "K7Q-M4", "K7Q2M ", "wapps-K7Q2M4"]) {
      expect(normalizeCode(bad), bad).toBeNull();
    }
  });
});

describe("the uniqueness index", () => {
  it("skips a code that is already taken and takes the next one the RNG gives", async () => {
    const draws = ["AAAAAA", "AAAAAA", "BBBBBB"];
    const rng = (): string => draws.shift()!;
    expect(await reserveCode(env.SECRETS_BUCKET, "vaulter", "ONE", rng)).toBe("AAAAAA");
    expect(await reserveCode(env.SECRETS_BUCKET, "apple/asc", "TWO", rng)).toBe("BBBBBB");
    const held = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCodeIndex("AAAAAA")))!.text()) as { store: string; key: string };
    expect(held).toMatchObject({ store: "vaulter", key: "ONE" });
  });

  it("gives up with an error when every draw collides", async () => {
    await reserveCode(env.SECRETS_BUCKET, "vaulter", "ONE", () => "CCCCCC");
    await expect(reserveCode(env.SECRETS_BUCKET, "vaulter", "TWO", () => "CCCCCC")).rejects.toThrow(/KEY_CODE_UNAVAILABLE/);
  });
});

describe("codes on write", () => {
  for (const base of ["/v1/projects/vaulter", "/v1/shared/apple/asc"]) {
    it(`${base}: a new key gets a code; the set answer names it as created`, async () => {
      const res = await put("boss@wapps.dev", base, "API_KEY", { value: "v1" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Commit;
      expect(body.created).toEqual(["API_KEY"]);
      expect(body.keyCodes?.API_KEY).toMatch(CODE_RE);
      expect(await codeOf(base, "API_KEY")).toBe(body.keyCodes?.API_KEY);
      // The index row points back at the key.
      const idx = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCodeIndex(body.keyCodes!.API_KEY)))!.text()) as { store: string; key: string };
      expect(idx).toMatchObject({ store: base.endsWith("asc") ? "apple/asc" : "vaulter", key: "API_KEY" });
    });
  }

  it("a rotation, a card change and an import of an existing key keep its code", async () => {
    const base = "/v1/projects/vaulter";
    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v1" })).status).toBe(200);
    const code = await codeOf(base, "API_KEY");
    expect(code).toMatch(CODE_RE);

    const rot = await put("boss@wapps.dev", base, "API_KEY", { value: "v2" });
    const rb = (await rot.json()) as Commit;
    expect(rb.created).toEqual([]);
    expect(rb.keyCodes).toEqual({ API_KEY: code });
    expect((await callGate(`${base}/keys/API_KEY/meta`, { method: "PUT", headers: await hdr("boss@wapps.dev"), body: JSON.stringify({ note: "n" }) })).status).toBe(200);
    expect((await imp("boss@wapps.dev", base, { API_KEY: "v3" })).status).toBe(200);

    const row = (await keys("boss@wapps.dev", base)).find((k) => k.keyName === "API_KEY");
    expect(row).toMatchObject({ keyVersion: 3, code, note: "n" });
  });

  it("an import gives each new key its own code and says which keys it created", async () => {
    const base = "/v1/projects/vaulter";
    expect((await put("boss@wapps.dev", base, "OLD", { value: "o" })).status).toBe(200);
    const old = await codeOf(base, "OLD");
    const res = await imp("boss@wapps.dev", base, { OLD: "o2", NEW_A: "a", NEW_B: "b" });
    const body = (await res.json()) as Commit;
    expect(body.created).toEqual(["NEW_A", "NEW_B"]);
    const listed = await keys("boss@wapps.dev", base);
    const codes = listed.map((k) => k.code);
    expect(new Set(codes).size).toBe(3);
    expect(listed.find((k) => k.keyName === "OLD")?.code).toBe(old);
    for (const c of codes) expect(c).toMatch(CODE_RE);
  });

  it("a deleted key's code is never freed: a new key of the same name gets another code", async () => {
    const base = "/v1/projects/vaulter";
    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v1" })).status).toBe(200);
    const first = (await codeOf(base, "API_KEY"))!;
    expect((await del("boss@wapps.dev", base, "API_KEY")).status).toBe(200);
    // The index row stays as a tombstone, so no later reservation can take the code.
    expect(await env.SECRETS_BUCKET.head(keyCodeIndex(first))).not.toBeNull();
    const draws = [first, "ZZZZZZ"];
    expect(await reserveCode(env.SECRETS_BUCKET, "lab", "OTHER", () => draws.shift()!)).toBe("ZZZZZZ");

    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v2" })).status).toBe(200);
    const second = await codeOf(base, "API_KEY");
    expect(second).toMatch(CODE_RE);
    expect(second).not.toBe(first);
    // The old code no longer resolves.
    expect((await find("boss@wapps.dev", first)).status).toBe(404);
  });

  it("a stored manifest whose entry carries a malformed code is refused", async () => {
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "API_KEY", { value: "v1" })).status).toBe(200);
    const raw = await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1)))!.text();
    const doc = JSON.parse(raw) as { entries: { code?: string }[] };
    expect(doc.entries[0].code).toMatch(CODE_RE);
    doc.entries[0].code = "ILOU00";
    expect(() => parseManifest(utf8(JSON.stringify(doc)))).toThrow(/not a key code/);
  });

  it("a project purge keeps the codes of its keys taken", async () => {
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "API_KEY", { value: "v1" })).status).toBe(200);
    const code = (await codeOf("/v1/projects/vaulter", "API_KEY"))!;
    const purge = await callGate("/v1/admin/projects/vaulter", {
      method: "DELETE",
      headers: authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL))),
      body: JSON.stringify({ confirm: "vaulter" }),
    });
    expect(purge.status).toBe(200);
    expect(await env.SECRETS_BUCKET.head(keyCodeIndex(code))).not.toBeNull();
    expect((await find("boss@wapps.dev", code)).status).toBe(404);
  });
});

describe("GET /v1/codes/<CODE>", () => {
  async function seed(): Promise<{ code: string; secret: string }> {
    const res = await put("boss@wapps.dev", "/v1/shared/apple/asc", "ASC_API_KEY_P8", { value: "p8-body", note: "App Manager role", expires: "2027-03-31" });
    expect(res.status).toBe(200);
    const code = ((await res.json()) as Commit).keyCodes!.ASC_API_KEY_P8;
    return { code, secret: "p8-body" };
  }

  it("resolves a code to its store, key and card, never the value, in any letter case", async () => {
    const { code, secret } = await seed();
    for (const asked of [code, code.toLowerCase()]) {
      const res = await find("dev@wapps.dev", asked);
      expect(res.status, asked).toBe(200);
      const text = await res.text();
      expect(text).not.toContain(secret);
      expect(JSON.parse(text)).toMatchObject({
        code,
        store: "apple/asc",
        keyName: "ASC_API_KEY_P8",
        keyVersion: 1,
        note: "App Manager role",
        expires: "2027-03-31",
      });
    }
    const rows = await settleAudit("apple/asc", (r) => r.some((x) => x.verb === "key.find"));
    const allow = rows.filter((r) => r.verb === "key.find" && r.decision === "allow");
    expect(allow.length).toBe(2);
    expect(allow[0]).toMatchObject({ principal: "human:dev@wapps.dev", project: "apple/asc", key: "ASC_API_KEY_P8" });
  });

  it("answers a caller who cannot read the key exactly as it answers an unknown code", async () => {
    const { code } = await seed();
    expect((await put("boss@wapps.dev", "/v1/projects/lab", "PRIVATE_KEY", { value: "x" })).status).toBe(200);
    const labCode = (await codeOf("/v1/projects/lab", "PRIVATE_KEY"))!;
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "API_PROD_KEY", { value: "x" })).status).toBe(200);
    const prodCode = (await codeOf("/v1/projects/vaulter", "API_PROD_KEY"))!;
    const unknown = code === "000000" ? "111111" : "000000";

    const base = await find("stranger@wapps.dev", unknown);
    expect(base.status).toBe(404);
    const refusal = await base.text();
    for (const [who, c] of [
      ["stranger@wapps.dev", code], // no rule at all
      ["vonly@wapps.dev", code], // reads another project only
      ["konly@wapps.dev", labCode], // reads the store, not this key
      ["dev@wapps.dev", prodCode], // a key glob denies it
      ["boss@wapps.dev", unknown],
    ] as const) {
      const res = await find(who, c);
      expect(res.status, `${who} ${c}`).toBe(404);
      expect(await res.text(), `${who} ${c}`).toBe(refusal);
    }
    const deny = (await allAuditRows()).filter((r) => r.verb === "key.find" && r.decision === "deny");
    expect(deny.length).toBe(6);
  });

  it("a minted token for another project gets the same refusal", async () => {
    const { code } = await seed();
    const svc = authHeader(await signer.makeJWT(serviceTokenClaims("svc-ci")));
    const mint = await callGate("/v1/token", { method: "POST", headers: svc, body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["ASC_API_KEY_P8"] } }) });
    expect(mint.status).toBe(200);
    const { token } = (await mint.json()) as { token: string };
    const res = await callGate(`/v1/codes/${code}`, { headers: { ...svc, Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "NOT_FOUND", message: "unknown code" });
  });

  it("refuses a malformed code before any lookup", async () => {
    for (const bad of ["K7Q2M", "K7Q2MI", "K7Q2M45"]) {
      const res = await find("boss@wapps.dev", bad);
      expect(res.status, bad).toBe(400);
    }
  });
});

describe("POST /v1/admin/key-codes/backfill", () => {
  it("gives every key without a code one, keeps every existing code, and is idempotent", async () => {
    expect((await imp("boss@wapps.dev", "/v1/projects/vaulter", { A: "a", B: "b" })).status).toBe(200);
    expect((await imp("boss@wapps.dev", "/v1/shared/apple/asc", { ASC_KEY_ID: "k" })).status).toBe(200);
    await stripCodes("vaulter");
    await stripCodes("apple/asc");
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "C", { value: "c" })).status).toBe(200);
    const kept = (await codeOf("/v1/projects/vaulter", "C"))!;
    expect(await codeOf("/v1/projects/vaulter", "A")).toBeUndefined();

    const res = await backfill();
    expect(res.status).toBe(200);
    const body = (await res.json()) as { stores: Record<string, Commit & { noop?: boolean }>; assigned: number; failed: number };
    expect(body.failed).toBe(0);
    expect(body.assigned).toBe(3);
    expect(Object.keys(body.stores.vaulter.keyCodes ?? {}).sort()).toEqual(["A", "B"]);

    const listed = await keys("boss@wapps.dev", "/v1/projects/vaulter");
    expect(listed.find((k) => k.keyName === "C")?.code).toBe(kept);
    for (const k of listed) expect(k.code, k.keyName).toMatch(CODE_RE);
    expect(listed.map((k) => k.keyVersion)).toEqual([1, 1, 1]);
    expect(await codeOf("/v1/shared/apple/asc", "ASC_KEY_ID")).toMatch(CODE_RE);
    // A backfilled code resolves.
    const a = listed.find((k) => k.keyName === "A")!.code!;
    expect(((await (await find("boss@wapps.dev", a)).json()) as { keyName: string }).keyName).toBe("A");
    // The value is untouched.
    const rd = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: await hdr("boss@wapps.dev"), body: JSON.stringify({ keys: ["A"] }) });
    expect(((await rd.json()) as { values: Record<string, string> }).values.A).toBe("a");

    const rows = await settleAudit("vaulter", (r) => r.filter((x) => x.verb === "admin.key_code_backfill").length >= 3);
    const audited = rows.filter((r) => r.verb === "admin.key_code_backfill");
    expect(audited.map((r) => `${r.project} ${r.key}`).sort()).toEqual(["apple/asc ASC_KEY_ID", "vaulter A", "vaulter B"]);
    expect(audited.find((r) => r.key === "A")?.intent).toBe(`code:${a}`);

    // Again: nothing to do, no new epoch.
    const epochBefore = ((await (await callGate("/v1/projects/vaulter/keys", { headers: await hdr("boss@wapps.dev") })).json()) as { epoch: number }).epoch;
    const again = (await (await backfill()).json()) as { stores: Record<string, { noop?: boolean }>; assigned: number };
    expect(again.assigned).toBe(0);
    expect(again.stores.vaulter.noop).toBe(true);
    const epochAfter = ((await (await callGate("/v1/projects/vaulter/keys", { headers: await hdr("boss@wapps.dev") })).json()) as { epoch: number }).epoch;
    expect(epochAfter).toBe(epochBefore);
  });

  it("needs the admin verb", async () => {
    const res = await backfill(validClaimsWrite("dev@wapps.dev"));
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "GRANT_DENIED" });
  });
});
