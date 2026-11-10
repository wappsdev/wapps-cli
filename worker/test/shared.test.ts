// Shared named secrets on the wire (design 2026-11-11). A shared id `<ns>/<name>`
// (e.g. `apple/asc`) is a store unit next to the projects: the routes
// /v1/shared/<ns>/<name>/{keys, read, import, manifests/<sel>, keys/<K>} reuse the
// project handlers; storage holds it under secrets/<ns>~<name>/; policy reaches it
// only through a glob with exactly one `/`.

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
  ADMIN_EMAIL,
} from "./helpers.js";
import { PolicyRule } from "../src/policy.js";
import { deriveProjects, keyBlob, keyCurrent, keyManifest } from "../src/storage.js";
import { runGC } from "../src/gc.js";
import { sha256Hex, utf8 } from "../src/crypto/encoding.js";
import {
  DataManifest,
  SCHEMA_CURRENT_POINTER,
  manifestObjectHash,
  parseCurrentPointer,
  parseManifest,
  serializeManifest,
} from "../src/manifest.js";

const ASC = { ASC_ISSUER_ID: "issuer-0001", ASC_KEY_ID: "key-0001", ASC_API_KEY_P8: "p8-body-0001" };

function sharedRules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "write", "rotate"] },
    { group: "release@wapps.co", projects: ["apple/asc"], keys: ["*"], verbs: ["read"] },
    { group: "admins@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["*"] },
    { group: "tv@wapps.co", projects: ["wapps-tv-remote", "*"], keys: ["*"], verbs: ["read", "write", "rotate", "delete"] },
    { group: "apple-all@wapps.co", projects: ["apple/*"], keys: ["*"], verbs: ["read"] },
    { group: "all-shared@wapps.co", projects: ["*/*"], keys: ["*"], verbs: ["read"] },
    { group: "apple-other@wapps.co", projects: ["apple/other"], keys: ["*"], verbs: ["read"] },
    { service: "svc-ci", projects: ["wapps-tv-remote", "apple/asc"], keys: ["*"], verbs: ["read"] },
  ];
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(sharedRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("rel@wapps.dev", ["release@wapps.co"]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
  groupsByEmail.set("tv@wapps.dev", ["tv@wapps.co"]);
  groupsByEmail.set("appleall@wapps.dev", ["apple-all@wapps.co"]);
  groupsByEmail.set("allshared@wapps.dev", ["all-shared@wapps.co"]);
  groupsByEmail.set("appleother@wapps.dev", ["apple-other@wapps.co"]);
  groupsByEmail.set(ADMIN_EMAIL, []);
});

async function jwt(email: string): Promise<string> {
  return signer.makeJWT(validClaims(email));
}
async function adminWriteJwt(): Promise<string> {
  return signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
}
async function importAs(email: string, base: string, values: Record<string, string>): Promise<Response> {
  return callGate(`${base}/import`, { method: "POST", headers: authHeader(await jwt(email)), body: JSON.stringify({ values }) });
}
async function readAs(email: string, base: string, keys: string[], headers: Record<string, string> = {}): Promise<Response> {
  return callGate(`${base}/read`, { method: "POST", headers: authHeader(await jwt(email), headers), body: JSON.stringify({ keys }) });
}
async function seedAsc(): Promise<void> {
  const res = await importAs("boss@wapps.dev", "/v1/shared/apple/asc", ASC);
  expect(res.status).toBe(200);
}
async function r2Keys(prefix: string): Promise<string[]> {
  const out: string[] = [];
  let cursor: string | undefined;
  do {
    const l = await env.SECRETS_BUCKET.list({ prefix, cursor });
    out.push(...l.objects.map((o) => o.key));
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  return out;
}

describe("shared secret round trip", () => {
  it("one import writes the three keys as one epoch under secrets/apple~asc/; a reader gets them back", async () => {
    const imp = await importAs("boss@wapps.dev", "/v1/shared/apple/asc", ASC);
    expect(imp.status).toBe(200);
    const ib = (await imp.json()) as { project: string; epoch: number; keyVersions: Record<string, number> };
    expect(ib.project).toBe("apple/asc");
    expect(ib.epoch).toBe(1);
    expect(Object.keys(ib.keyVersions).sort()).toEqual(Object.keys(ASC).sort());

    // Storage: the one encoder; the record's project field is the shared id.
    expect(await env.SECRETS_BUCKET.head("secrets/apple~asc/current")).not.toBeNull();
    expect(await r2Keys("secrets/apple/")).toEqual([]);
    const man = parseManifest(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyManifest("apple/asc", 1)))!.arrayBuffer()));
    expect(man.project).toBe("apple/asc");
    const ptr = parseCurrentPointer(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyCurrent("apple/asc")))!.arrayBuffer()));
    expect(ptr.project).toBe("apple/asc");

    const rd = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", Object.keys(ASC));
    expect(rd.status).toBe(200);
    expect(((await rd.json()) as { epoch: number; values: Record<string, string> }).values).toEqual(ASC);

    const keys = await callGate("/v1/shared/apple/asc/keys", { headers: authHeader(await jwt("rel@wapps.dev")) });
    expect(keys.status).toBe(200);
    const kb = (await keys.json()) as { project: string; epoch: number; keys: { keyName: string; keyVersion: number }[] };
    expect(kb.project).toBe("apple/asc");
    expect(kb.epoch).toBe(1);
    expect(kb.keys.map((k) => k.keyName).sort()).toEqual(Object.keys(ASC).sort());

    for (const sel of ["current", "1"]) {
      const m = await callGate(`/v1/shared/apple/asc/manifests/${sel}`, { headers: authHeader(await jwt("rel@wapps.dev")) });
      expect(m.status, sel).toBe(200);
      const mb = (await m.json()) as { project: string; entries: unknown[] };
      expect(mb.project).toBe("apple/asc");
      expect(mb.entries.length).toBe(3);
    }
  });

  it("set and delete of one key go through the same writer", async () => {
    await seedAsc();
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", {
      method: "PUT",
      headers: authHeader(await jwt("boss@wapps.dev")),
      body: JSON.stringify({ value: "key-0002" }),
    });
    expect(put.status).toBe(200);
    expect(((await put.json()) as { epoch: number }).epoch).toBe(2);
    const rd = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    expect(((await rd.json()) as { values: Record<string, string> }).values.ASC_KEY_ID).toBe("key-0002");

    const del = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", { method: "DELETE", headers: authHeader(await jwt("boss@wapps.dev")) });
    expect(del.status).toBe(200);
    const gone = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    expect(gone.status).toBe(404);
  });

  it("GET /v1/projects lists apple/asc only to principals whose glob reaches it", async () => {
    await seedAsc();
    expect((await importAs("writer@wapps.dev", "/v1/projects/vaulter", { K: "v" })).status).toBe(200);
    const list = async (email: string): Promise<string[]> =>
      ((await (await callGate("/v1/projects", { headers: authHeader(await jwt(email)) })).json()) as { projects: string[] }).projects;
    expect(await list("writer@wapps.dev")).toEqual(["vaulter"]);
    expect(await list("rel@wapps.dev")).toEqual(["apple/asc"]);
    expect(await list("boss@wapps.dev")).toEqual(["apple/asc", "vaulter"]);
  });
});

describe("policy on the shared routes", () => {
  it("a principal granted wapps-tv-remote and [\"*\"] is refused on apple/asc, with a deny audit row", async () => {
    await seedAsc();
    const rd = await readAs("tv@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    expect(rd.status).toBe(403);
    const body = (await rd.json()) as { error: string; key: string; dimension: string };
    expect(body).toMatchObject({ error: "GRANT_DENIED", key: "ASC_KEY_ID", dimension: "project" });

    const keys = await callGate("/v1/shared/apple/asc/keys", { headers: authHeader(await jwt("tv@wapps.dev")) });
    expect(keys.status).toBe(403);
    const write = await importAs("tv@wapps.dev", "/v1/shared/apple/asc", { ASC_KEY_ID: "evil" });
    expect(write.status).toBe(403);

    const rows = await allAuditRows();
    expect(
      rows.some((r) => r.principal === "human:tv@wapps.dev" && r.project === "apple/asc" && r.key === "ASC_KEY_ID" && r.verb === "value.read" && r.decision === "deny" && r.intent === "project"),
    ).toBe(true);
    expect(rows.some((r) => r.project === "apple/asc" && r.verb === "key.list" && r.decision === "deny")).toBe(true);
  });

  it("apple/* and */* read apple/asc; apple/other does not", async () => {
    await seedAsc();
    expect((await readAs("appleall@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"])).status).toBe(200);
    expect((await readAs("allshared@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"])).status).toBe(200);
    const other = await readAs("appleother@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    expect(other.status).toBe(403);
    expect(((await other.json()) as { dimension: string }).dimension).toBe("project");
  });

  it("a token minted for a project is refused on /v1/shared/apple/asc/read; one minted for apple/asc reads", async () => {
    await seedAsc();
    const svc = await signer.makeJWT(serviceTokenClaims("svc-ci"));
    // The service row itself reaches apple/asc: the refusal below is the token's.
    expect((await callGate("/v1/shared/apple/asc/read", { method: "POST", headers: authHeader(svc), body: JSON.stringify({ keys: ["ASC_KEY_ID"] }) })).status).toBe(200);

    const mint = async (project: string): Promise<string> => {
      const res = await callGate("/v1/token", {
        method: "POST",
        headers: authHeader(svc),
        body: JSON.stringify({ project, scope: { verbs: ["read"], keys: ["ASC_KEY_ID"] } }),
      });
      expect(res.status, project).toBe(200);
      return ((await res.json()) as { token: string }).token;
    };
    const projectToken = await mint("wapps-tv-remote");
    const denied = await callGate("/v1/shared/apple/asc/read", {
      method: "POST",
      headers: authHeader(svc, { Authorization: `Bearer ${projectToken}` }),
      body: JSON.stringify({ keys: ["ASC_KEY_ID"] }),
    });
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { dimension: string }).dimension).toBe("token_project");

    const sharedToken = await mint("apple/asc");
    const ok = await callGate("/v1/shared/apple/asc/read", {
      method: "POST",
      headers: authHeader(svc, { Authorization: `Bearer ${sharedToken}` }),
      body: JSON.stringify({ keys: ["ASC_KEY_ID"] }),
    });
    expect(ok.status).toBe(200);
  });

  it("a read-only principal cannot set, import or delete", async () => {
    await seedAsc();
    const h = authHeader(await jwt("rel@wapps.dev"));
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", { method: "PUT", headers: h, body: JSON.stringify({ value: "x" }) });
    const imp = await callGate("/v1/shared/apple/asc/import", { method: "POST", headers: h, body: JSON.stringify({ values: { ASC_KEY_ID: "x" } }) });
    const del = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", { method: "DELETE", headers: h });
    for (const res of [put, imp, del]) {
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string; dimension: string }).dimension).toBe("verb");
    }
    const keys = await callGate("/v1/shared/apple/asc/keys", { headers: h });
    expect(((await keys.json()) as { epoch: number }).epoch).toBe(1);
  });
});

describe("name isolation", () => {
  it("listing and deleting project apple never touches secrets/apple~asc/", async () => {
    await seedAsc();
    expect((await importAs("boss@wapps.dev", "/v1/projects/apple", { ASC_KEY_ID: "project-apple" })).status).toBe(200);
    const sharedObjects = await r2Keys("secrets/apple~asc/");
    expect(sharedObjects.length).toBeGreaterThan(0);

    const keys = await callGate("/v1/projects/apple/keys", { headers: authHeader(await jwt("boss@wapps.dev")) });
    const kb = (await keys.json()) as { project: string; keys: { keyName: string }[] };
    expect(kb.project).toBe("apple");
    expect(kb.keys.map((k) => k.keyName)).toEqual(["ASC_KEY_ID"]);

    const del = await callGate("/v1/admin/projects/apple", {
      method: "DELETE",
      headers: authHeader(await adminWriteJwt()),
      body: JSON.stringify({ confirm: "apple" }),
    });
    expect(del.status).toBe(200);
    expect(await r2Keys("secrets/apple/")).toEqual([]);
    expect(await r2Keys("secrets/apple~asc/")).toEqual(sharedObjects);
    const rd = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    expect(((await rd.json()) as { values: Record<string, string> }).values.ASC_KEY_ID).toBe(ASC.ASC_KEY_ID);
  });

  it("the admin delete route accepts a shared id and removes only its prefix", async () => {
    await seedAsc();
    expect((await importAs("boss@wapps.dev", "/v1/projects/apple-asc", { ASC_KEY_ID: "project-apple-asc" })).status).toBe(200);
    const del = (confirm: string, path = "/v1/admin/shared/apple/asc", token?: string) =>
      (async () =>
        callGate(path, { method: "DELETE", headers: authHeader(token ?? (await adminWriteJwt())), body: JSON.stringify({ confirm }) }))();

    // The confirm body repeats the full shared id.
    const mismatch = await del("apple");
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as { error: string }).error).toBe("CONFIRM_MISMATCH");
    // A per-key delete grant is not enough: the admin verb is required.
    const notAdmin = await del("apple/asc", "/v1/admin/shared/apple/asc", await signer.makeJWT(validClaimsWrite("tv@wapps.dev")));
    expect(notAdmin.status).toBe(403);
    expect((await r2Keys("secrets/apple~asc/")).length).toBeGreaterThan(0);

    const ok = await del("apple/asc");
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { project: string }).project).toBe("apple/asc");
    expect(await r2Keys("secrets/apple~asc/")).toEqual([]);
    expect((await r2Keys("secrets/apple-asc/")).length).toBeGreaterThan(0);
    expect((await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"])).status).toBe(404);
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "project.delete" && r.decision === "allow" && r.project === "apple/asc")).toBe(true);

    const again = await del("apple/asc");
    expect(again.status).toBe(404);
    const bad = await del("apple~x/asc", "/v1/admin/shared/apple~x/asc");
    expect(bad.status).toBe(422);
    expect(((await bad.json()) as { error: string }).error).toBe("PROJECT_MISMATCH");
  });

  // Copies one store name's manifest entries and blobs under another name with a
  // consistent manifest chain, so the read reaches the DEK unwrap.
  async function transplant(from: DataManifest, to: string): Promise<void> {
    const curObj = await env.SECRETS_BUCKET.get(keyCurrent(to));
    const cur = parseCurrentPointer(new Uint8Array(await curObj!.arrayBuffer()));
    for (const e of from.entries) {
      const blob = await env.SECRETS_BUCKET.get(keyBlob(from.project, e.blobHash));
      await env.SECRETS_BUCKET.put(keyBlob(to, e.blobHash), await blob!.arrayBuffer());
    }
    const epoch = cur.epoch + 1;
    const bytes = serializeManifest({ ...from, project: to, epoch, prevManifestSha256: cur.manifestSha256 });
    await env.SECRETS_BUCKET.put(keyManifest(to, epoch), bytes);
    await env.SECRETS_BUCKET.put(
      keyCurrent(to),
      utf8(JSON.stringify({ schema: SCHEMA_CURRENT_POINTER, project: to, epoch, manifestSha256: manifestObjectHash(bytes) })),
    );
  }
  it("bytes swapped between apple/asc and project apple-asc fail to decrypt, both ways", async () => {
    await seedAsc();
    expect((await importAs("boss@wapps.dev", "/v1/projects/apple-asc", { ASC_KEY_ID: "project-value-77" })).status).toBe(200);
    const shared = await currentManifestOf("apple/asc");
    const project = await currentManifestOf("apple-asc");

    await transplant(shared, "apple-asc");
    await transplant(project, "apple/asc");

    const a = await readAs("boss@wapps.dev", "/v1/projects/apple-asc", ["ASC_KEY_ID"]);
    const b = await readAs("boss@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"]);
    for (const res of [a, b]) {
      expect(res.status).toBe(503);
      const txt = await res.text();
      expect(JSON.parse(txt).error).toBe("WRAP_INVALID");
      expect(txt).not.toContain(ASC.ASC_KEY_ID);
      expect(txt).not.toContain("project-value-77");
    }
  });

  it("a raw copy of secrets/apple~asc/ into secrets/apple-asc/ is refused by the record's project field", async () => {
    await seedAsc();
    for (const k of await r2Keys("secrets/apple~asc/")) {
      const o = await env.SECRETS_BUCKET.get(k);
      await env.SECRETS_BUCKET.put(k.replace("secrets/apple~asc/", "secrets/apple-asc/"), await o!.arrayBuffer());
    }
    const res = await readAs("boss@wapps.dev", "/v1/projects/apple-asc", ["ASC_KEY_ID"]);
    expect(res.status).toBe(503);
    const txt = await res.text();
    expect(JSON.parse(txt).error).toBe("SERVICE_MISCONFIGURED");
    expect(txt).not.toContain(ASC.ASC_KEY_ID);
  });
});

describe("malformed ids are refused", () => {
  it("a/b/c, apple/, ~ and other bad ids write nothing", async () => {
    const h = authHeader(await jwt("boss@wapps.dev"));
    const put = (path: string) => callGate(path, { method: "PUT", headers: h, body: JSON.stringify({ value: "v" }) });
    const cases: { path: string; status: number; error: string }[] = [
      // a/b/c: the id is always two segments, so `c` is read as an unknown kind.
      { path: "/v1/shared/a/b/c/keys/K", status: 404, error: "NOT_FOUND" },
      // apple/: an empty name leaves no id at all.
      { path: "/v1/shared/apple//keys/K", status: 404, error: "NOT_FOUND" },
      { path: "/v1/shared/~/asc/keys/K", status: 422, error: "PROJECT_MISMATCH" },
      { path: "/v1/shared/apple~asc/x/keys/K", status: 422, error: "PROJECT_MISMATCH" },
      { path: "/v1/shared/Apple/asc/keys/K", status: 422, error: "PROJECT_MISMATCH" },
      { path: `/v1/shared/apple/${"b".repeat(32)}/keys/K`, status: 422, error: "PROJECT_MISMATCH" },
      // The storage segment is not a name: no route reaches secrets/apple~asc/ by it.
      { path: "/v1/projects/apple~asc/keys/K", status: 422, error: "PROJECT_MISMATCH" },
      { path: "/v1/projects/~/keys/K", status: 422, error: "PROJECT_MISMATCH" },
    ];
    for (const c of cases) {
      const res = await put(c.path);
      expect(res.status, c.path).toBe(c.status);
      expect(((await res.json()) as { error: string }).error, c.path).toBe(c.error);
    }
    const read = await callGate("/v1/shared/~/asc/read", { method: "POST", headers: h, body: JSON.stringify({ keys: ["K"] }) });
    expect(read.status).toBe(422);
    expect(await r2Keys("secrets/")).toEqual([]);
    expect(await r2Keys("pointer-events/")).toEqual([]);
  });
});

describe("read audit carries X-Wapps-Intent", () => {
  it("value.read rows record the intent; no header records null", async () => {
    await seedAsc();
    const bulk = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", Object.keys(ASC), { "X-Wapps-Intent": "use:wapps-tv-remote" });
    expect(bulk.status).toBe(200);
    const one = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": "use:emlak-radar" });
    expect(one.status).toBe(200);
    const plain = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_ISSUER_ID"]);
    expect(plain.status).toBe(200);

    const rows = (await allAuditRows()).filter((r) => r.decision === "allow" && r.verb.startsWith("value.read"));
    const bulkRows = rows.filter((r) => r.verb === "value.read.bulk");
    expect(bulkRows.map((r) => r.key).sort()).toEqual(Object.keys(ASC).sort());
    for (const r of bulkRows) {
      expect(r.project).toBe("apple/asc");
      expect(r.intent).toBe("use:wapps-tv-remote");
    }
    const single = rows.filter((r) => r.verb === "value.read");
    expect(single.map((r) => [r.key, r.intent])).toEqual([
      ["ASC_KEY_ID", "use:emlak-radar"],
      ["ASC_ISSUER_ID", null],
    ]);
  });

  it("project reads record the intent too (one read handler)", async () => {
    expect((await importAs("writer@wapps.dev", "/v1/projects/vaulter", { K: "v" })).status).toBe(200);
    expect((await readAs("writer@wapps.dev", "/v1/projects/vaulter", ["K"], { "X-Wapps-Intent": "epoch-reset" })).status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "value.read" && r.project === "vaulter" && r.intent === "epoch-reset")).toBe(true);
  });

  it("an intent over 512 characters is refused with 400 and returns no value", async () => {
    await seedAsc();
    const res = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": "u".repeat(513) });
    expect(res.status).toBe(400);
    const txt = await res.text();
    expect(JSON.parse(txt).error).toBe("BAD_REQUEST");
    expect(txt).not.toContain(ASC.ASC_KEY_ID);
    expect((await allAuditRows()).some((r) => r.verb.startsWith("value.read"))).toBe(false);
  });
});

// The label is client text that lands in the ledger: only printable ASCII
// (0x20-0x7e) is accepted, so no control byte (ESC, DEL, TAB) or non-ASCII byte
// can reach an audit row or a terminal that renders it.
describe("X-Wapps-Intent accepts only printable ASCII", () => {
  const BAD: [string, string][] = [
    ["ESC", "use:\x1b[31mred"],
    ["DEL", "use:x\x7f"],
    ["TAB", "use:a\tb"],
    ["BEL", "use:\x07"],
    ["latin-1", "use:café"],
  ];

  it("a read with a control or non-ASCII byte in the label is refused with 400 and returns no value", async () => {
    await seedAsc();
    for (const [name, label] of BAD) {
      const res = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": label });
      expect(res.status, name).toBe(400);
      const txt = await res.text();
      expect(JSON.parse(txt).error, name).toBe("BAD_REQUEST");
      expect(txt, name).not.toContain(ASC.ASC_KEY_ID);
    }
    expect((await allAuditRows()).some((r) => r.verb.startsWith("value.read"))).toBe(false);
  });

  it("a set, import or delete with a control byte in the label is refused with 400 before any commit", async () => {
    await seedAsc();
    const h = authHeader(await jwt("boss@wapps.dev"), { "X-Wapps-Intent": "sync\x1b" });
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", { method: "PUT", headers: h, body: JSON.stringify({ value: "x" }) });
    const imp = await callGate("/v1/shared/apple/asc/import", { method: "POST", headers: h, body: JSON.stringify({ values: { ASC_KEY_ID: "x" } }) });
    const del = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", { method: "DELETE", headers: h });
    for (const res of [put, imp, del]) {
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe("BAD_REQUEST");
    }
    const rows = await allAuditRows();
    expect(rows.filter((r) => r.verb === "commit.attempt").length).toBe(1); // the seed import only
    expect(rows.some((r) => (r.intent ?? "").includes("\x1b"))).toBe(false);
  });

  it("every printable ASCII character is accepted and recorded as sent", async () => {
    await seedAsc();
    let printable = "";
    for (let c = 0x21; c <= 0x7e; c++) printable += String.fromCharCode(c);
    const label = `use: ${printable}`;
    const res = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": label });
    expect(res.status).toBe(200);
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "value.read" && r.intent === label)).toBe(true);
  });
});

// Deny rows: `intent` = `<reason>|<label>`. The reason is a server word with no `|`,
// so the first `|` splits it from the caller's label; no label leaves `<reason>`.
// The label cap (448 = AUDIT_FIELD_MAX - 64) keeps room for the reason.
describe("deny rows keep the reason and the label apart", () => {
  const LABEL_MAX = 448;

  it("an edge read and list deny record <reason>|<label>; no label records <reason>", async () => {
    await seedAsc();
    const label = "use:wapps-tv-remote";
    expect((await readAs("tv@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": label })).status).toBe(403);
    expect((await readAs("tv@wapps.dev", "/v1/shared/apple/asc", ["ASC_ISSUER_ID"])).status).toBe(403);
    const list = await callGate("/v1/shared/apple/asc/keys", { headers: authHeader(await jwt("tv@wapps.dev"), { "X-Wapps-Intent": label }) });
    expect(list.status).toBe(403);

    const deny = (await allAuditRows()).filter((r) => r.decision === "deny");
    expect(deny.find((r) => r.verb === "value.read" && r.key === "ASC_KEY_ID")?.intent).toBe("project|use:wapps-tv-remote");
    expect(deny.find((r) => r.verb === "value.read" && r.key === "ASC_ISSUER_ID")?.intent).toBe("project");
    expect(deny.find((r) => r.verb === "key.list")?.intent).toBe("project|use:wapps-tv-remote");
  });

  it("an edge write deny records <reason>|<label>", async () => {
    await seedAsc();
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", {
      method: "PUT",
      headers: authHeader(await jwt("rel@wapps.dev"), { "X-Wapps-Intent": "sync" }),
      body: JSON.stringify({ value: "x" }),
    });
    expect(put.status).toBe(403);
    const row = (await allAuditRows()).find((r) => r.verb === "key.set" && r.decision === "deny");
    expect(row?.intent).toBe("verb|sync");
  });

  it("a writer deny records <code>|<label>", async () => {
    await seedAsc();
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", {
      method: "PUT",
      headers: authHeader(await jwt("boss@wapps.dev"), { "X-Wapps-Intent": "use:release" }),
      body: JSON.stringify({ value: "x", ifEpoch: 99 }),
    });
    expect(put.status).toBe(412);
    const row = (await allAuditRows()).find((r) => r.verb === "key.set" && r.decision === "deny");
    expect(row?.intent).toBe("EPOCH_CONFLICT|use:release");
  });

  it("a label of the full cap still fits a deny row; one character more is refused", async () => {
    await seedAsc();
    const label = "u".repeat(LABEL_MAX);
    expect((await readAs("tv@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": label })).status).toBe(403);
    const put = await callGate("/v1/shared/apple/asc/keys/ASC_KEY_ID", {
      method: "PUT",
      headers: authHeader(await jwt("boss@wapps.dev"), { "X-Wapps-Intent": label }),
      body: JSON.stringify({ value: "x", ifEpoch: 99 }),
    });
    expect(put.status).toBe(412);
    const deny = (await allAuditRows()).filter((r) => r.decision === "deny");
    expect(deny.find((r) => r.verb === "value.read")?.intent).toBe(`project|${label}`);
    expect(deny.find((r) => r.verb === "key.set")?.intent).toBe(`EPOCH_CONFLICT|${label}`);

    const over = await readAs("rel@wapps.dev", "/v1/shared/apple/asc", ["ASC_KEY_ID"], { "X-Wapps-Intent": "u".repeat(LABEL_MAX + 1) });
    expect(over.status).toBe(400);
  });
});

describe("keys and read on a store name with no data (CLI contract)", () => {
  it("granted: keys 200 empty, read 404 NOT_FOUND; not granted: both 403 GRANT_DENIED", async () => {
    const keys = async (email: string, base: string) => callGate(`${base}/keys`, { headers: authHeader(await jwt(email)) });
    for (const [email, base] of [
      ["rel@wapps.dev", "/v1/shared/apple/asc"],
      ["writer@wapps.dev", "/v1/projects/wapps-tv-remote"],
    ]) {
      const k = await keys(email, base);
      expect(k.status, base).toBe(200);
      const kb = (await k.json()) as { project: string; epoch: number; keys: unknown[] };
      expect(kb.epoch).toBe(0);
      expect(kb.keys).toEqual([]);
      const r = await readAs(email, base, ["ANY_KEY"]);
      expect(r.status, base).toBe(404);
      expect(((await r.json()) as { error: string }).error).toBe("NOT_FOUND");
    }
    for (const [email, base] of [
      ["tv@wapps.dev", "/v1/shared/apple/asc"],
      ["rel@wapps.dev", "/v1/projects/wapps-tv-remote"],
    ]) {
      const k = await keys(email, base);
      expect(k.status, base).toBe(403);
      expect(((await k.json()) as { error: string }).error).toBe("GRANT_DENIED");
      const r = await readAs(email, base, ["ANY_KEY"]);
      expect(r.status, base).toBe(403);
      expect(((await r.json()) as { error: string }).error).toBe("GRANT_DENIED");
    }
  });
});

describe("store-wide admin ops cover shared ids", () => {
  it("rewrap-kek runs the writer for apple/asc", async () => {
    await seedAsc();
    const res = await callGate("/v1/admin/rewrap-kek", { method: "POST", headers: authHeader(await adminWriteJwt()) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { projects: Record<string, { epoch: number; rewrapped: number }>; failed: number };
    expect(body.failed).toBe(0);
    expect(body.projects["apple/asc"]).toMatchObject({ epoch: 1, rewrapped: 0 });
  });

  it("GC over deriveProjects collects an orphan blob of apple/asc and keeps the referenced ones", async () => {
    await seedAsc();
    const referenced = (await currentManifestOf("apple/asc")).entries.map((e) => e.blobHash);
    const orphan = new Uint8Array(300).fill(7);
    const orphanHash = sha256Hex(orphan);
    await env.SECRETS_BUCKET.put(keyBlob("apple/asc", orphanHash), orphan);

    const report = await runGC(env.SECRETS_BUCKET, await deriveProjects(env.SECRETS_BUCKET), {
      now: new Date(Date.now() + 100 * 24 * 3600 * 1000),
      enabledAt: new Date(Date.now() - 200 * 24 * 3600 * 1000),
      escrowHas: async () => true,
      auditDelete: async () => {},
      alert: () => {},
    });
    expect(report.deleted).toEqual([{ project: "apple/asc", sha: orphanHash }]);
    expect(await env.SECRETS_BUCKET.head(keyBlob("apple/asc", orphanHash))).toBeNull();
    for (const h of referenced) expect(await env.SECRETS_BUCKET.head(keyBlob("apple/asc", h))).not.toBeNull();
  });
});

async function currentManifestOf(name: string): Promise<DataManifest> {
  const ptr = parseCurrentPointer(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyCurrent(name)))!.arrayBuffer()));
  return parseManifest(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyManifest(name, ptr.epoch)))!.arrayBuffer()));
}
