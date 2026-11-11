// Key information card (design 2026-11-11): a non-secret card next to a key's value,
// stored on the key's manifest entry. `note` (1-500 printable characters) and
// `expires` (YYYY-MM-DD). GET …/keys returns {keyName, keyVersion, note?, expires?,
// updatedAt}; PUT …/keys/<K>/meta writes the card with the `write` verb, never
// touches the value or its version, and is audited as key.meta. A card patch field
// that is absent keeps the old value, null clears it, a value sets it.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  authHeader,
  callGate,
  seedPolicy,
  groupsByEmail,
  allAuditRows,
  settleAudit,
} from "./helpers.js";
import { PolicyRule } from "../src/policy.js";

function cardRules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*", "*/*"], keys: ["*", "!*_PROD_*"], verbs: ["read", "write", "rotate"] },
    { group: "admins@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["*"] },
    { group: "release@wapps.co", projects: ["apple/asc"], keys: ["*"], verbs: ["read"] },
  ];
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(cardRules());
  groupsByEmail.set("dev@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
  groupsByEmail.set("rel@wapps.dev", ["release@wapps.co"]);
  groupsByEmail.set("stranger@wapps.dev", []);
});

const BASES = ["/v1/projects/vaulter", "/v1/shared/apple/asc"];

interface KeyRow {
  keyName: string;
  keyVersion: number;
  note?: string;
  expires?: string;
  updatedAt: string | null;
}

async function hdr(email: string): Promise<Record<string, string>> {
  return authHeader(await signer.makeJWT(validClaims(email)));
}
async function put(email: string, base: string, key: string, body: Record<string, unknown>): Promise<Response> {
  return callGate(`${base}/keys/${key}`, { method: "PUT", headers: await hdr(email), body: JSON.stringify(body) });
}
async function meta(email: string, base: string, key: string, body: unknown): Promise<Response> {
  return callGate(`${base}/keys/${key}/meta`, { method: "PUT", headers: await hdr(email), body: JSON.stringify(body) });
}
async function imp(email: string, base: string, body: Record<string, unknown>): Promise<Response> {
  return callGate(`${base}/import`, { method: "POST", headers: await hdr(email), body: JSON.stringify(body) });
}
async function list(email: string, base: string): Promise<{ status: number; text: string; keys: KeyRow[]; epoch: number }> {
  const res = await callGate(`${base}/keys`, { headers: await hdr(email) });
  const text = await res.text();
  const body = res.status === 200 ? (JSON.parse(text) as { keys: KeyRow[]; epoch: number }) : { keys: [], epoch: -1 };
  return { status: res.status, text, keys: body.keys, epoch: body.epoch };
}
async function card(email: string, base: string, key: string): Promise<KeyRow | undefined> {
  return (await list(email, base)).keys.find((k) => k.keyName === key);
}
async function value(email: string, base: string, key: string): Promise<string> {
  const res = await callGate(`${base}/read`, { method: "POST", headers: await hdr(email), body: JSON.stringify({ keys: [key] }) });
  expect(res.status).toBe(200);
  return ((await res.json()) as { values: Record<string, string> }).values[key];
}

describe("card round trip", () => {
  for (const base of BASES) {
    it(`${base}: meta sets, keeps and clears note and expires; value and version stay`, async () => {
      expect((await put("boss@wapps.dev", base, "API_KEY", { value: "secret-1" })).status).toBe(200);
      const before = await card("boss@wapps.dev", base, "API_KEY");
      expect(before).toMatchObject({ keyName: "API_KEY", keyVersion: 1 });
      expect(before?.note).toBeUndefined();
      expect(before?.expires).toBeUndefined();
      expect(typeof before?.updatedAt).toBe("string");

      const note = "App Store Connect API key, App Manager role, issued as wapps-ci";
      const res = await meta("boss@wapps.dev", base, "API_KEY", { note, expires: "2027-03-31" });
      expect(res.status).toBe(200);
      const rb = (await res.json()) as { project: string; epoch: number; keyVersions: Record<string, number> };
      expect(rb.epoch).toBe(2);
      expect(rb.keyVersions).toEqual({ API_KEY: 1 });

      const after = await card("boss@wapps.dev", base, "API_KEY");
      expect(after).toMatchObject({ keyName: "API_KEY", keyVersion: 1, note, expires: "2027-03-31" });
      expect(Date.parse(after!.updatedAt!)).toBeGreaterThanOrEqual(Date.parse(before!.updatedAt!));
      expect(await value("boss@wapps.dev", base, "API_KEY")).toBe("secret-1");

      // An absent field keeps; null clears.
      expect((await meta("boss@wapps.dev", base, "API_KEY", { expires: null })).status).toBe(200);
      const noExpiry = await card("boss@wapps.dev", base, "API_KEY");
      expect(noExpiry?.note).toBe(note);
      expect(noExpiry?.expires).toBeUndefined();
      expect((await meta("boss@wapps.dev", base, "API_KEY", { note: null })).status).toBe(200);
      const empty = await card("boss@wapps.dev", base, "API_KEY");
      expect(empty?.note).toBeUndefined();
      expect(empty?.keyVersion).toBe(1);
    });
  }

  it("a card write is audited as key.meta, with no value-read or value-write verb", async () => {
    const base = "/v1/shared/apple/asc";
    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v" })).status).toBe(200);
    expect((await meta("boss@wapps.dev", base, "API_KEY", { note: "n" })).status).toBe(200);
    const rows = await settleAudit("apple/asc", (r) => r.some((x) => x.verb === "key.meta"));
    expect(rows.some((r) => r.verb === "key.meta" && r.decision === "allow" && r.project === "apple/asc" && r.key === "API_KEY")).toBe(true);
    expect(rows.filter((r) => r.verb === "key.set").length).toBe(1);
  });

  it("a card on a key that does not exist answers 404 NOT_FOUND", async () => {
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "OTHER", { value: "v" })).status).toBe(200);
    const res = await meta("boss@wapps.dev", "/v1/projects/vaulter", "MISSING", { note: "n" });
    expect(res.status).toBe(404);
    // The writer names the key; an unknown route would not.
    expect(await res.json()).toMatchObject({ error: "NOT_FOUND", key: "MISSING" });
  });
});

describe("value writes keep the card", () => {
  for (const base of BASES) {
    it(`${base}: set and import keep the card unless they carry a new one`, async () => {
      expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v1" })).status).toBe(200);
      expect((await meta("boss@wapps.dev", base, "API_KEY", { note: "kept", expires: "2027-01-01" })).status).toBe(200);

      expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v2" })).status).toBe(200);
      expect(await card("boss@wapps.dev", base, "API_KEY")).toMatchObject({ keyVersion: 2, note: "kept", expires: "2027-01-01" });

      expect((await imp("boss@wapps.dev", base, { values: { API_KEY: "v3", OTHER_KEY: "o" } })).status).toBe(200);
      expect(await card("boss@wapps.dev", base, "API_KEY")).toMatchObject({ keyVersion: 3, note: "kept", expires: "2027-01-01" });

      // A value write that carries card fields replaces only those fields.
      expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v4", note: "replaced" })).status).toBe(200);
      expect(await card("boss@wapps.dev", base, "API_KEY")).toMatchObject({ keyVersion: 4, note: "replaced", expires: "2027-01-01" });
      expect(await value("boss@wapps.dev", base, "API_KEY")).toBe("v4");

      // An import's card fields apply to every key it writes.
      expect((await imp("boss@wapps.dev", base, { values: { API_KEY: "v5", OTHER_KEY: "o2" }, note: "one credential", expires: null })).status).toBe(200);
      const keys = (await list("boss@wapps.dev", base)).keys;
      for (const k of keys) {
        expect(k.note, k.keyName).toBe("one credential");
        expect(k.expires, k.keyName).toBeUndefined();
      }
    });
  }
});

describe("who may write and who may see a card", () => {
  it("a principal without write on the key cannot set its card; the deny is audited as key.meta", async () => {
    const base = "/v1/shared/apple/asc";
    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v" })).status).toBe(200);
    expect((await meta("boss@wapps.dev", base, "API_KEY", { note: "original" })).status).toBe(200);

    const res = await meta("rel@wapps.dev", base, "API_KEY", { note: "hijacked" });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string; dimension: string }).dimension).toBe("verb");
    // A key-glob deny inside the writer's own rule also blocks the card.
    expect((await put("boss@wapps.dev", "/v1/projects/vaulter", "DB_PROD_URL", { value: "p" })).status).toBe(200);
    const prod = await meta("dev@wapps.dev", "/v1/projects/vaulter", "DB_PROD_URL", { note: "x" });
    expect(prod.status).toBe(403);
    expect(((await prod.json()) as { dimension: string }).dimension).toBe("key_denied");

    expect((await card("boss@wapps.dev", base, "API_KEY"))?.note).toBe("original");
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "key.meta" && r.decision === "deny" && r.principal === "human:rel@wapps.dev" && r.intent === "verb")).toBe(true);
  });

  it("a principal who cannot list a key never sees its card, on keys or on manifests", async () => {
    const base = "/v1/projects/vaulter";
    expect((await imp("boss@wapps.dev", base, { values: { APP_KEY: "a", DB_PROD_URL: "p" } })).status).toBe(200);
    expect((await meta("boss@wapps.dev", base, "APP_KEY", { note: "app card" })).status).toBe(200);
    expect((await meta("boss@wapps.dev", base, "DB_PROD_URL", { note: "prod card 7731", expires: "2026-12-31" })).status).toBe(200);

    const dev = await list("dev@wapps.dev", base);
    expect(dev.status).toBe(200);
    expect(dev.keys.map((k) => k.keyName)).toEqual(["APP_KEY"]);
    expect(dev.keys[0].note).toBe("app card");
    expect(dev.text).not.toContain("prod card 7731");
    expect(dev.text).not.toContain("2026-12-31");
    const man = await callGate(`${base}/manifests/current`, { headers: await hdr("dev@wapps.dev") });
    expect(man.status).toBe(200);
    expect(await man.text()).not.toContain("prod card 7731");

    const stranger = await list("stranger@wapps.dev", base);
    expect(stranger.status).toBe(403);
    expect(stranger.text).not.toContain("card");
    // A shared reader sees no project card either.
    const rel = await list("rel@wapps.dev", base);
    expect(rel.status).toBe(403);
    expect(rel.text).not.toContain("card");
  });
});

describe("the gate checks the card", () => {
  const BAD_NOTES: [string, unknown][] = [
    ["empty", ""],
    ["501 characters", "n".repeat(501)],
    ["newline", "line one\nline two"],
    ["tab", "a\tb"],
    ["ESC", "\x1b[31mred"],
    ["DEL", "x\x7f"],
    ["C1 NEL", "a\u0085b"],
    ["bidi override", "abc‮def"],
    ["zero-width space", "a​b"],
    ["line separator", "a b"],
    ["not a string", 5],
  ];
  const BAD_DATES: [string, unknown][] = [
    ["month 13", "2026-13-01"],
    ["Feb 30", "2026-02-30"],
    ["short year", "26-01-01"],
    ["no zero pad", "2026-1-1"],
    ["datetime", "2026-01-01T00:00:00Z"],
    ["slashes", "2026/01/01"],
    ["number", 20260101],
    ["empty", ""],
  ];

  for (const base of BASES) {
    it(`${base}: meta refuses a bad note or date with 400 and changes nothing`, async () => {
      expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v" })).status).toBe(200);
      const epochBefore = (await list("boss@wapps.dev", base)).epoch;
      for (const [name, note] of BAD_NOTES) {
        const res = await meta("boss@wapps.dev", base, "API_KEY", { note });
        expect(res.status, name).toBe(400);
        expect(await res.json(), name).toMatchObject({ error: "BAD_REQUEST", field: "note" });
      }
      for (const [name, expires] of BAD_DATES) {
        const res = await meta("boss@wapps.dev", base, "API_KEY", { expires });
        expect(res.status, name).toBe(400);
        expect(await res.json(), name).toMatchObject({ error: "BAD_REQUEST", field: "expires" });
      }
      for (const body of [{}, { other: "x" }, [], "note"]) {
        const res = await meta("boss@wapps.dev", base, "API_KEY", body);
        expect(res.status, JSON.stringify(body)).toBe(400);
      }
      expect((await list("boss@wapps.dev", base)).epoch).toBe(epochBefore);
    });
  }

  it("set and import refuse a bad card the same way, before any write", async () => {
    const base = "/v1/shared/apple/asc";
    const s = await put("boss@wapps.dev", base, "API_KEY", { value: "v", note: "a\x1bb" });
    expect(s.status).toBe(400);
    expect(((await s.json()) as { field: string }).field).toBe("note");
    const i = await imp("boss@wapps.dev", base, { values: { API_KEY: "v" }, expires: "2026-02-30" });
    expect(i.status).toBe(400);
    expect(((await i.json()) as { field: string }).field).toBe("expires");
    expect((await list("boss@wapps.dev", base)).epoch).toBe(0);
  });

  it("accepts a 500-character note, non-ASCII letters included, and a past date", async () => {
    const base = "/v1/projects/vaulter";
    expect((await put("boss@wapps.dev", base, "API_KEY", { value: "v" })).status).toBe(200);
    const long = "ş".repeat(500);
    expect((await meta("boss@wapps.dev", base, "API_KEY", { note: long, expires: "2024-02-29" })).status).toBe(200);
    expect(await card("boss@wapps.dev", base, "API_KEY")).toMatchObject({ note: long, expires: "2024-02-29" });
  });
});
