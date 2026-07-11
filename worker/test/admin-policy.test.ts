// Control-plane testleri (SPEC §4.1/§4.4/§4.5/§6.3): policy GET/PUT (CAS +
// validation + A9 + senkron audit), kök admin çapası, rotate-plan oracle'ı.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  discordCalls,
  ADMIN_EMAIL,
} from "./helpers.js";
import { SCHEMA_POLICY, validatePolicy } from "../src/policy.js";
import { keyPolicyVersion } from "../src/storage.js";
import { utf8 } from "../src/crypto/encoding.js";
import { env } from "cloudflare:test";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set(ADMIN_EMAIL, []); // kök admin: grup GEREKMEZ (§4.5)
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
});

async function adminJwt(): Promise<string> {
  return signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
}

describe("policy GET/PUT (§4.1/§4.4)", () => {
  it("root admin (ADMIN_EMAILS) reads policy regardless of policy.json (§4.5)", async () => {
    const res = await callGate("/v1/policy", { headers: authHeader(await adminJwt()) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { version: number; policy: { rules: unknown[] } };
    expect(body.version).toBe(1);
    expect(body.policy.rules.length).toBe(3);
  });

  it("policy-group admin (admins@) also holds the admin verb", async () => {
    const res = await callGate("/v1/policy", { headers: authHeader(await signer.makeJWT(validClaimsWrite("boss@wapps.dev"))) });
    expect(res.status).toBe(200);
  });

  it("non-admin human on the write app → GRANT_DENIED; deny is audited", async () => {
    const res = await callGate("/v1/policy", { headers: authHeader(await signer.makeJWT(validClaimsWrite("writer@wapps.dev"))) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GRANT_DENIED");
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "policy.read" && r.decision === "deny")).toBe(true);
  });

  it("PUT v2: 200 + A9 alert + synchronous policy.write audit row; next GET sees v2", async () => {
    const newDoc = {
      schema: SCHEMA_POLICY,
      version: 2,
      rules: [...defaultRules(), { group: "contractors@wapps.co", projects: ["lumira"], keys: ["PUB_*"], verbs: ["read"] }],
    };
    const put = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(newDoc) });
    expect(put.status).toBe(200);
    expect(((await put.json()) as { version: number }).version).toBe(2);

    expect(discordCalls.some((c) => c.body.includes("A9"))).toBe(true); // §4.1 alert A9
    const rows = await allAuditRows();
    const w = rows.find((r) => r.verb === "policy.write" && r.decision === "allow");
    expect(w).toBeTruthy();
    expect(w!.intent).toContain("v1:");
    expect(w!.intent).toContain("->v2:");

    const get = await callGate("/v1/policy", { headers: authHeader(await adminJwt()) });
    expect(((await get.json()) as { version: number }).version).toBe(2);
  });

  it("PUT with wrong version → 412 POLICY_CONFLICT (CAS)", async () => {
    const doc = { schema: SCHEMA_POLICY, version: 5, rules: defaultRules() };
    const res = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(doc) });
    expect(res.status).toBe(412);
    expect(((await res.json()) as { error: string }).error).toBe("POLICY_CONFLICT");
  });

  it("PUT invalid rule → 422 POLICY_INVALID naming the rule index (§4.4)", async () => {
    const doc = { schema: SCHEMA_POLICY, version: 2, rules: [...defaultRules(), { group: "x@y.z", projects: ["*"], keys: ["!ALL"], verbs: ["read"] }] };
    const res = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(doc) });
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string; rule_index: number };
    expect(body.error).toBe("POLICY_INVALID");
    expect(body.rule_index).toBe(3);
  });

  it("occupied version slot with IDENTICAL bytes → idempotent continue (liveness wedge recovery, §4.1)", async () => {
    // Önceki bir PUT'un slot-yazımı ile pointer-CAS'i ARASINDA düştüğünü simüle et:
    // versions/2.json aynı normalize baytlarla dolu, pointer hâlâ v1'de.
    const newDoc = { schema: SCHEMA_POLICY, version: 2, rules: defaultRules() };
    const normalized = validatePolicy(newDoc, "primary", [ADMIN_EMAIL]);
    await env.SECRETS_BUCKET.put(keyPolicyVersion(2), utf8(JSON.stringify(normalized)));

    const put = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(newDoc) });
    expect(put.status).toBe(200); // retry wedge'i iyileştirir: pointer CAS'ine idempotent devam
    const get = await callGate("/v1/policy", { headers: authHeader(await adminJwt()) });
    expect(((await get.json()) as { version: number }).version).toBe(2);
  });

  it("occupied version slot with DIFFERENT content → still 412 POLICY_CONFLICT", async () => {
    await env.SECRETS_BUCKET.put(keyPolicyVersion(2), utf8(`{"other":true}`));
    const doc = { schema: SCHEMA_POLICY, version: 2, rules: defaultRules() };
    const res = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(doc) });
    expect(res.status).toBe(412);
    expect(((await res.json()) as { error: string }).error).toBe("POLICY_CONFLICT");
  });

  it("PRIMARY topology: aud selector REJECTED on PUT (§3.3/§4.4)", async () => {
    const doc = { schema: SCHEMA_POLICY, version: 2, rules: [{ aud: "someaud", projects: ["*"], keys: ["*"], verbs: ["read"] }] };
    const res = await callGate("/v1/policy", { method: "PUT", headers: authHeader(await adminJwt()), body: JSON.stringify(doc) });
    expect(res.status).toBe(422);
  });

  it("admin routes REQUIRE the write AUD (read-AUD JWT → AUD_MISMATCH)", async () => {
    const res = await callGate("/v1/policy", { headers: authHeader(await signer.makeJWT(validClaims(ADMIN_EMAIL))) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("AUD_MISMATCH");
  });
});

describe("rotate-plan — audit ledger as rotate-set oracle (§6.3)", () => {
  it("returns every key the identity read, wrote and bulk-imported (per-key rows)", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    // set + import + read → hepsi oracle verb kümesinde.
    await callGate("/v1/projects/vaulter/keys/RP_SET", { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value: "a" }) });
    await callGate("/v1/projects/vaulter/import", { method: "POST", headers: authHeader(jwt), body: JSON.stringify({ values: { RP_IMP_ONE: "1", RP_IMP_TWO: "2" } }) });
    await callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(jwt), body: JSON.stringify({ keys: ["RP_SET"] }) });
    // Harness invalidation'ında outcome batch pending kalabilir → oracle sorgusundan önce settle.
    await settleAudit("vaulter", (r) => r.filter((x) => x.verb === "key.import").length >= 2 && r.some((x) => x.verb === "key.set"));

    const res = await callGate("/v1/admin/rotate-plan?identity=human:writer@wapps.dev", { headers: authHeader(await adminJwt()) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { identity: string; items: { project: string; key: string; reads: number }[] };
    const keys = body.items.map((i) => i.key).sort();
    // Bulk-import edilen anahtarlar per-key satırlarla plana girer (gate 7c).
    expect(keys).toEqual(["RP_IMP_ONE", "RP_IMP_TWO", "RP_SET"]);
    expect(body.items.find((i) => i.key === "RP_SET")!.reads).toBeGreaterThanOrEqual(2); // set + read
    // rotate-plan çağrısının kendisi senkron audit'lenir.
    const rows = await allAuditRows();
    expect(rows.some((r) => r.verb === "admin.rotate_plan" && r.decision === "allow" && r.intent === "human:writer@wapps.dev")).toBe(true);
  });

  it("assume-policy unions keys the identity's rules COULD read (paranoid superset)", async () => {
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    await callGate("/v1/projects/vaulter/keys/NEVER_READ", { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value: "x" }) });
    // Hiç okumamış bir identity için assume-policy: policy'ye göre OKUYABİLECEĞİ anahtar plana girer.
    const res = await callGate("/v1/admin/rotate-plan?identity=human:ghost@wapps.dev&assume_policy=1", { headers: authHeader(await adminJwt()) });
    const body = (await res.json()) as { items: { key: string; reads: number }[] };
    expect(body.items.some((i) => i.key === "NEVER_READ" && i.reads === 0)).toBe(true);
  });

  it("identity param required", async () => {
    const res = await callGate("/v1/admin/rotate-plan", { headers: authHeader(await adminJwt()) });
    expect(res.status).toBe(400);
  });
});
