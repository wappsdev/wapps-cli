// E-M3 / work item b7bbe826: create-only key writes. `PUT …/keys/<K>` with
// `If-None-Match: *` writes the key only when it does not exist yet; the check runs
// inside the writer DO's serialized commit, so it is atomic: of two concurrent
// create-only writes of one new key exactly one lands (201) and the other gets
// 409 KEY_EXISTS. The `create` policy verb permits create-only writes without
// `write`: such a principal can add a key but never overwrite one.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { ensureJwks, resetWorld, validClaims, authHeader, callGate, seedPolicy, groupsByEmail, allAuditRows, settleAudit } from "./helpers.js";
import { PolicyRule } from "../src/policy.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { parseCurrentPointer } from "../src/manifest.js";

const STORE = "vaulter";

function rules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "write"] },
    { group: "creators@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read", "create"] },
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
  groupsByEmail.set("agent@wapps.dev", ["creators@wapps.co"]);
});

async function put(email: string, key: string, value: string, createOnly: boolean): Promise<Response> {
  const extra: Record<string, string> = createOnly ? { "If-None-Match": "*" } : {};
  return callGate(`/v1/projects/${STORE}/keys/${key}`, {
    method: "PUT",
    headers: authHeader(await signer.makeJWT(validClaims(email)), extra),
    body: JSON.stringify({ value }),
  });
}

async function epochNow(): Promise<number> {
  const o = await env.SECRETS_BUCKET.get(keyCurrent(STORE));
  return o ? parseCurrentPointer(new Uint8Array(await o.arrayBuffer())).epoch : 0;
}

async function readValue(key: string): Promise<string> {
  const res = await callGate(`/v1/projects/${STORE}/read`, {
    method: "POST",
    headers: authHeader(await signer.makeJWT(validClaims("dev@wapps.dev"))),
    body: JSON.stringify({ keys: [key] }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { values: Record<string, string> }).values[key];
}

describe("create-only writes (If-None-Match: *)", () => {
  it("two concurrent create-only writes of a new key: one 201, one 409 KEY_EXISTS", async () => {
    const [a, b] = await Promise.all([put("dev@wapps.dev", "NEW_KEY", "first-a", true), put("dev@wapps.dev", "NEW_KEY", "first-b", true)]);
    expect([a.status, b.status].sort()).toEqual([201, 409]);
    const winner = a.status === 201 ? a : b;
    const loser = a.status === 201 ? b : a;
    const won = (await winner.json()) as { epoch: number; created: string[] };
    expect(won.epoch).toBe(1);
    expect(won.created).toEqual(["NEW_KEY"]);
    const lost = (await loser.json()) as { error: string; key: string };
    expect(lost.error).toBe("KEY_EXISTS");
    expect(lost.key).toBe("NEW_KEY");

    expect(await epochNow()).toBe(1);
    expect(["first-a", "first-b"]).toContain(await readValue("NEW_KEY"));

    const rows = await settleAudit(STORE, (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "NEW_KEY"));
    expect(rows.filter((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "NEW_KEY").length).toBe(1);
    expect(rows.filter((x) => x.verb === "key.set" && x.decision === "deny" && x.key === "NEW_KEY" && x.intent === "KEY_EXISTS").length).toBe(1);
  });

  it("create-only on an existing key: 409, nothing written, deny row", async () => {
    expect((await put("dev@wapps.dev", "OLD_KEY", "kept", false)).status).toBe(200);
    const res = await put("dev@wapps.dev", "OLD_KEY", "replacement", true);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("KEY_EXISTS");

    expect(await epochNow()).toBe(1);
    expect(await env.SECRETS_BUCKET.head(keyManifest(STORE, 2))).toBeNull();
    expect(await readValue("OLD_KEY")).toBe("kept");

    const rows = await allAuditRows();
    expect(rows.some((x) => x.verb === "key.set" && x.decision === "deny" && x.key === "OLD_KEY" && x.intent === "KEY_EXISTS")).toBe(true);
    // Refused before the attempt row: only the first write attempted a commit.
    expect(rows.filter((x) => x.verb === "commit.attempt").length).toBe(1);
  });

  it("a `create`-only principal creates a new key but cannot overwrite one", async () => {
    const created = await put("agent@wapps.dev", "AGENT_KEY", "agent-value", true);
    expect(created.status).toBe(201);
    expect(await readValue("AGENT_KEY")).toBe("agent-value");

    // Overwrite with create-only: the DO refuses it.
    const again = await put("agent@wapps.dev", "AGENT_KEY", "other", true);
    expect(again.status).toBe(409);
    expect(((await again.json()) as { error: string }).error).toBe("KEY_EXISTS");

    // A plain PUT needs `write`: refused at the edge, existing key or not.
    const plain = await put("agent@wapps.dev", "AGENT_KEY", "other", false);
    expect(plain.status).toBe(403);
    expect(((await plain.json()) as { dimension: string }).dimension).toBe("verb");
    const plainNew = await put("agent@wapps.dev", "FRESH_KEY", "other", false);
    expect(plainNew.status).toBe(403);

    expect(await readValue("AGENT_KEY")).toBe("agent-value");
    expect(await epochNow()).toBe(1);

    const rows = await settleAudit(STORE, (r) => r.some((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "AGENT_KEY"));
    expect(rows.filter((x) => x.principal === "human:agent@wapps.dev" && x.verb === "key.set" && x.decision === "allow").length).toBe(1);
    expect(rows.filter((x) => x.principal === "human:agent@wapps.dev" && x.verb === "key.set" && x.decision === "deny" && x.intent === "KEY_EXISTS").length).toBe(1);
    expect(rows.filter((x) => x.principal === "human:agent@wapps.dev" && x.verb === "key.set" && x.decision === "deny" && x.intent === "verb").length).toBe(2);
  });

  it("a principal with neither `create` nor `write` cannot create-only write", async () => {
    groupsByEmail.set("stranger@wapps.dev", []);
    const res = await put("stranger@wapps.dev", "NEW_KEY", "v", true);
    expect(res.status).toBe(403);
    expect(await epochNow()).toBe(0);
  });

  it("If-None-Match other than `*` is refused (no etag preconditions on PUT)", async () => {
    const res = await callGate(`/v1/projects/${STORE}/keys/NEW_KEY`, {
      method: "PUT",
      headers: authHeader(await signer.makeJWT(validClaims("dev@wapps.dev")), { "If-None-Match": '"abc"' }),
      body: JSON.stringify({ value: "v" }),
    });
    expect(res.status).toBe(400);
    expect(await epochNow()).toBe(0);
  });

  it("a normal write is unchanged: 200, overwrites, allow row", async () => {
    expect((await put("dev@wapps.dev", "PLAIN_KEY", "one", false)).status).toBe(200);
    const res = await put("dev@wapps.dev", "PLAIN_KEY", "two", false);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { epoch: number }).epoch).toBe(2);
    expect(await readValue("PLAIN_KEY")).toBe("two");
    const rows = await settleAudit(STORE, (r) => r.filter((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "PLAIN_KEY").length >= 2);
    expect(rows.filter((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "PLAIN_KEY").length).toBe(2);
  });
});
