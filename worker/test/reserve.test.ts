// Key code reservation (owner request 2026-11-12). An issuer that cannot rename a
// credential (Anthropic) needs the credential's name, `wapps-<CODE> <store> <KEY>`,
// BEFORE the credential exists, so before its value is stored. POST
// …/keys/<KEY>/code answers the key's code first: the code of the existing key,
// else the code already reserved for (store, key), else a fresh code taken from
// the gate-wide index. The set that then creates the key takes the reserved code.
// It is authorised exactly like writing the key.

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  serviceTokenClaims,
  authHeader,
  callGate,
  seedPolicy,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  runInDoRetry,
} from "./helpers.js";
import { PolicyRule } from "../src/policy.js";
import { keyCodeIndex, reserveCode } from "../src/keycode.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { SCHEMA_CURRENT_POINTER, manifestObjectHash, parseCurrentPointer, parseManifest, serializeManifest } from "../src/manifest.js";
import { utf8 } from "../src/crypto/encoding.js";

const CODE_RE = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{6}$/;
const STORES = ["vaulter", "lab", "apple/asc"];
const BASES = ["/v1/projects/vaulter", "/v1/shared/apple/asc"];

function rules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*", "*/*"], keys: ["*", "!*_PROD_*"], verbs: ["read", "write", "rotate", "delete"] },
    { group: "admins@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["*"] },
    { group: "readers@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["read"] },
    { service: "svc-ci", projects: ["*", "*/*"], keys: ["*"], verbs: ["read", "write"] },
  ];
}

/** clearReservations empties the writer DO of every store these tests use:
 * resetWorld clears R2, KV and the audit DO, not a writer DO's own storage. */
async function clearReservations(): Promise<void> {
  for (const s of STORES) {
    await runInDoRetry(env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(s)), (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
  }
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await clearReservations();
  await seedPolicy(rules());
  groupsByEmail.set("dev@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
  groupsByEmail.set("reader@wapps.dev", ["readers@wapps.co"]);
  groupsByEmail.set("stranger@wapps.dev", []);
});
afterEach(async () => {
  await clearReservations();
});

interface Reserved {
  store: string;
  keyName: string;
  code: string;
}
interface Commit {
  keyCodes?: Record<string, string>;
  created?: string[];
}

async function hdr(email: string): Promise<Record<string, string>> {
  return authHeader(await signer.makeJWT(validClaims(email)));
}
async function reserve(email: string, base: string, key: string): Promise<Response> {
  return callGate(`${base}/keys/${key}/code`, { method: "POST", headers: await hdr(email) });
}
async function reserved(email: string, base: string, key: string): Promise<Reserved> {
  const res = await reserve(email, base, key);
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as Reserved;
}
async function put(email: string, base: string, key: string, value: string): Promise<Response> {
  return callGate(`${base}/keys/${key}`, { method: "PUT", headers: await hdr(email), body: JSON.stringify({ value }) });
}
async function listed(base: string): Promise<{ keyName: string; code?: string }[]> {
  const res = await callGate(`${base}/keys`, { headers: await hdr("boss@wapps.dev") });
  return ((await res.json()) as { keys: { keyName: string; code?: string }[] }).keys;
}
async function codeIndexCount(): Promise<number> {
  return (await env.SECRETS_BUCKET.list({ prefix: "key-codes/" })).objects.length;
}
function storeOf(base: string): string {
  return base.endsWith("asc") ? "apple/asc" : "vaulter";
}

describe("POST …/keys/<KEY>/code", () => {
  for (const base of BASES) {
    it(`${base}: reserves a fresh code for a key that does not exist yet`, async () => {
      const r = await reserved("dev@wapps.dev", base, "ANTHROPIC_API_KEY");
      expect(r).toEqual({ store: storeOf(base), keyName: "ANTHROPIC_API_KEY", code: expect.stringMatching(CODE_RE) });
      // The index holds the code for this (store, key), create-only like any code.
      const idx = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCodeIndex(r.code)))!.text()) as { store: string; key: string };
      expect(idx).toMatchObject({ store: storeOf(base), key: "ANTHROPIC_API_KEY" });
      // No key, no value: the list does not show it and the code does not resolve.
      expect(await listed(base)).toEqual([]);
      expect((await callGate(`/v1/codes/${r.code}`, { headers: await hdr("boss@wapps.dev") })).status).toBe(404);
    });
  }

  it("answers the same code again for the same key", async () => {
    const a = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "K");
    const b = await reserved("boss@wapps.dev", "/v1/projects/vaulter", "K");
    expect(b.code).toBe(a.code);
    expect(await codeIndexCount()).toBe(1);
  });

  it("answers one code to concurrent reservations of the same key", async () => {
    const all = await Promise.all(Array.from({ length: 6 }, () => reserved("dev@wapps.dev", "/v1/shared/apple/asc", "K")));
    expect(new Set(all.map((r) => r.code)).size).toBe(1);
    expect(await codeIndexCount()).toBe(1);
  });

  it("gives two keys two codes", async () => {
    const a = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "A");
    const b = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "B");
    const c = await reserved("dev@wapps.dev", "/v1/projects/lab", "A");
    expect(new Set([a.code, b.code, c.code]).size).toBe(3);
  });

  for (const base of BASES) {
    it(`${base}: the set that creates the key takes the reserved code`, async () => {
      const r = await reserved("dev@wapps.dev", base, "K");
      const res = await put("dev@wapps.dev", base, "K", "v1");
      expect(res.status).toBe(200);
      const body = (await res.json()) as Commit;
      expect(body.created).toEqual(["K"]);
      expect(body.keyCodes).toEqual({ K: r.code });
      expect((await listed(base)).find((k) => k.keyName === "K")?.code).toBe(r.code);
      // No second code was drawn for the key.
      expect(await codeIndexCount()).toBe(1);
      const found = await callGate(`/v1/codes/${r.code}`, { headers: await hdr("dev@wapps.dev") });
      expect(found.status).toBe(200);
      expect(await found.json()).toMatchObject({ code: r.code, store: storeOf(base), keyName: "K" });
    });
  }

  it("an import that creates the key takes the reserved code too", async () => {
    const r = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "B");
    const res = await callGate("/v1/projects/vaulter/import", { method: "POST", headers: await hdr("dev@wapps.dev"), body: JSON.stringify({ values: { A: "a", B: "b" } }) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Commit;
    expect(body.created).toEqual(["A", "B"]);
    expect(body.keyCodes?.B).toBe(r.code);
    expect(body.keyCodes?.A).toMatch(CODE_RE);
    expect(body.keyCodes?.A).not.toBe(r.code);
  });

  it("answers an existing key's own code and reserves nothing", async () => {
    expect((await put("dev@wapps.dev", "/v1/projects/vaulter", "K", "v1")).status).toBe(200);
    const code = (await listed("/v1/projects/vaulter"))[0].code;
    expect(code).toMatch(CODE_RE);
    expect((await reserved("dev@wapps.dev", "/v1/projects/vaulter", "K")).code).toBe(code);
    expect(await codeIndexCount()).toBe(1);
    // A rotation keeps it.
    const rot = (await (await put("dev@wapps.dev", "/v1/projects/vaulter", "K", "v2")).json()) as Commit;
    expect(rot.keyCodes).toEqual({ K: code });
  });

  it("a set consumes the reservation: after the key is deleted, the name gets a new code", async () => {
    const first = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "K");
    expect((await put("dev@wapps.dev", "/v1/projects/vaulter", "K", "v1")).status).toBe(200);
    expect((await callGate("/v1/projects/vaulter/keys/K", { method: "DELETE", headers: await hdr("dev@wapps.dev") })).status).toBe(200);
    const second = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "K");
    expect(second.code).not.toBe(first.code);
    const res = (await (await put("dev@wapps.dev", "/v1/projects/vaulter", "K", "v2")).json()) as Commit;
    expect(res.keyCodes).toEqual({ K: second.code });
  });

  it("a reserved code is given to no other key", async () => {
    const r = await reserved("dev@wapps.dev", "/v1/projects/vaulter", "K");
    // The index refuses the code to a draw for any other key.
    const draws = [r.code, "ZZZZZZ"];
    expect(await reserveCode(env.SECRETS_BUCKET, "lab", "OTHER", () => draws.shift()!)).toBe("ZZZZZZ");
    // A set of another key in the same store does not take the reservation.
    const other = (await (await put("dev@wapps.dev", "/v1/projects/vaulter", "OTHER", "o")).json()) as Commit;
    expect(other.keyCodes?.OTHER).toMatch(CODE_RE);
    expect(other.keyCodes?.OTHER).not.toBe(r.code);
    const mine = (await (await put("dev@wapps.dev", "/v1/projects/vaulter", "K", "k")).json()) as Commit;
    expect(mine.keyCodes).toEqual({ K: r.code });
  });

  it("refuses a caller who may not write the key exactly as a write refuses it", async () => {
    for (const [who, key] of [
      ["reader@wapps.dev", "K"], // read only
      ["stranger@wapps.dev", "K"], // no rule
      ["dev@wapps.dev", "API_PROD_KEY"], // a key glob denies it
    ] as const) {
      const r = await reserve(who, "/v1/projects/vaulter", key);
      const w = await put(who, "/v1/projects/vaulter", key, "v");
      expect(r.status, `${who} ${key}`).toBe(403);
      expect(await r.json(), `${who} ${key}`).toEqual(await w.json());
    }
    expect(await codeIndexCount()).toBe(0);
    const deny = await settleAudit("vaulter", (rows) => rows.filter((x) => x.verb === "key.reserve" && x.decision === "deny").length >= 3);
    expect(deny.filter((x) => x.verb === "key.reserve" && x.decision === "deny").map((x) => x.key)).toEqual(["K", "K", "API_PROD_KEY"]);
  });

  it("applies a minted token's scope like a write", async () => {
    const svc = authHeader(await signer.makeJWT(serviceTokenClaims("svc-ci")));
    const mint = async (scope: { verbs: string[]; keys: string[] }, project = "vaulter"): Promise<string> => {
      const res = await callGate("/v1/token", { method: "POST", headers: svc, body: JSON.stringify({ project, scope }) });
      expect(res.status).toBe(200);
      return ((await res.json()) as { token: string }).token;
    };
    const as = async (token: string, key: string): Promise<Response> =>
      callGate(`/v1/projects/vaulter/keys/${key}/code`, { method: "POST", headers: { ...svc, Authorization: `Bearer ${token}` } });

    for (const [token, dimension] of [
      [await mint({ verbs: ["read"], keys: ["K"] }), "token_verb"],
      [await mint({ verbs: ["write"], keys: ["OTHER"] }), "token_key"],
      [await mint({ verbs: ["write"], keys: ["K"] }, "lab"), "token_project"],
    ] as const) {
      const res = await as(token, "K");
      expect(res.status, dimension).toBe(403);
      expect(await res.json()).toEqual({ error: "GRANT_DENIED", message: "write denied", key: "K", dimension });
    }
    const ok = await as(await mint({ verbs: ["write"], keys: ["K"] }), "K");
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as Reserved).code).toMatch(CODE_RE);
  });

  it("writes an allow row naming the code", async () => {
    const r = await reserved("dev@wapps.dev", "/v1/shared/apple/asc", "K");
    await reserved("dev@wapps.dev", "/v1/shared/apple/asc", "K");
    const rows = (await allAuditRows()).filter((x) => x.verb === "key.reserve");
    expect(rows.length).toBe(2);
    for (const row of rows) {
      expect(row).toMatchObject({ principal: "human:dev@wapps.dev", project: "apple/asc", key: "K", decision: "allow", intent: `code:${r.code}` });
    }
  });

  it("checks the key name and the store name as a write does", async () => {
    const bad = await reserve("boss@wapps.dev", "/v1/projects/vaulter", "1BAD");
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "BAD_REQUEST", message: "invalid key name" });
    expect((await reserve("boss@wapps.dev", "/v1/projects/Bad_Project", "K")).status).toBe(422);
    expect((await reserve("boss@wapps.dev", "/v1/shared/apple/Bad", "K")).status).toBe(422);
    // Only POST.
    expect((await callGate("/v1/projects/vaulter/keys/K/code", { method: "GET", headers: await hdr("boss@wapps.dev") })).status).toBe(404);
    expect(await codeIndexCount()).toBe(0);
  });

  it("refuses an existing key that has no code yet with KEY_CODE_MISSING", async () => {
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "K", "v1")).status).toBe(200);
    // Rewrite the manifest without codes, the way a store written before key codes looks.
    const ptr = parseCurrentPointer(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyCurrent("vaulter")))!.arrayBuffer()));
    const man = parseManifest(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", ptr.epoch)))!.arrayBuffer()));
    const epoch = ptr.epoch + 1;
    const bytes = serializeManifest({ ...man, epoch, prevManifestSha256: ptr.manifestSha256, entries: man.entries.map(({ code: _c, ...e }) => e) });
    await env.SECRETS_BUCKET.put(keyManifest("vaulter", epoch), bytes);
    await env.SECRETS_BUCKET.put(keyCurrent("vaulter"), utf8(JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project: "vaulter", epoch, manifestSha256: manifestObjectHash(bytes) })));

    const res = await reserve("boss@wapps.dev", "/v1/projects/vaulter", "K");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "KEY_CODE_MISSING", key: "K" });
  });
});
