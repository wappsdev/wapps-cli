// v2 uçtan uca rota testleri (SPEC §7.6): plaintext yaz→oku round-trip, policy
// gate'leri, bulk import per-key audit, silme, liste/manifest FİLTRELEME, senkron
// read-audit fail-closed (gate 5), iki-yazar yarışı (gate 4), rewrap-kek (§2.5),
// canary: hata yollarında değer sızmaz (gate 6).

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
  defaultRules,
  groupsByEmail,
  allAuditRows,
  settleAudit,
  runInDoRetry,
  ADMIN_EMAIL,
  MASTER_KEK_HEX,
} from "./helpers.js";
import { keyManifest, keyCurrent } from "../src/storage.js";
import { loadMasterKeys } from "../src/crypto/kek.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
  groupsByEmail.set("stranger@wapps.dev", []);
});

async function writerJwt(): Promise<string> {
  return signer.makeJWT(validClaims("writer@wapps.dev"));
}
async function putKey(key: string, value: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Promise<Response> {
  return callGate(`/v1/projects/vaulter/keys/${key}`, {
    method: "PUT",
    headers: authHeader(await writerJwt(), headers),
    body: JSON.stringify({ value, ...extra }),
  });
}
async function readKeys(keys: string[], envOverride: Record<string, unknown> = {}): Promise<Response> {
  return callGate(
    "/v1/projects/vaulter/read",
    { method: "POST", headers: authHeader(await writerJwt()), body: JSON.stringify({ keys }) },
    envOverride,
  );
}

describe("write → read plaintext round-trip (§2.7/§7.4)", () => {
  it("PUT creates epoch 1; read returns the exact plaintext; keyVersion increments on re-set", async () => {
    const r1 = await putKey("DATABASE_URL", "postgres://u:p@h/db");
    expect(r1.status).toBe(200);
    const b1 = (await r1.json()) as { epoch: number; keyVersions: Record<string, number> };
    expect(b1.epoch).toBe(1);
    expect(b1.keyVersions.DATABASE_URL).toBe(1);

    const rd = await readKeys(["DATABASE_URL"]);
    expect(rd.status).toBe(200);
    const body = (await rd.json()) as { epoch: number; values: Record<string, string> };
    expect(body.epoch).toBe(1);
    expect(body.values.DATABASE_URL).toBe("postgres://u:p@h/db");

    // Re-set → keyVersion 2, epoch 2, yeni değer okunur (AAD benzersizliği §2.1).
    const r2 = await putKey("DATABASE_URL", "postgres://new");
    const b2 = (await r2.json()) as { epoch: number; keyVersions: Record<string, number> };
    expect(b2.epoch).toBe(2);
    expect(b2.keyVersions.DATABASE_URL).toBe(2);
    const rd2 = await readKeys(["DATABASE_URL"]);
    expect(((await rd2.json()) as { values: Record<string, string> }).values.DATABASE_URL).toBe("postgres://new");
  });

  it("epoch chain: manifest 2 links to manifest 1 by object hash (§2.6)", async () => {
    await putKey("A_KEY", "v1");
    await putKey("B_KEY", "v2");
    const m1 = await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1));
    const m2 = await env.SECRETS_BUCKET.get(keyManifest("vaulter", 2));
    expect(m1).not.toBeNull();
    expect(m2).not.toBeNull();
    const m1Bytes = new Uint8Array(await m1!.arrayBuffer());
    const { sha256Hex } = await import("../src/crypto/encoding.js");
    const doc2 = JSON.parse(new TextDecoder().decode(await m2!.arrayBuffer())) as { prevManifestSha256: string; entries: unknown[]; policyVersion: number };
    expect(doc2.prevManifestSha256).toBe(sha256Hex(m1Bytes));
    expect(doc2.entries.length).toBe(2);
    expect(doc2.policyVersion).toBe(1);
  });

  it("bulk import: one atomic epoch; delete removes the key (absence, §2.6)", async () => {
    const imp = await callGate("/v1/projects/vaulter/import", {
      method: "POST",
      headers: authHeader(await writerJwt()),
      body: JSON.stringify({ values: { K_ONE: "1", K_TWO: "2", K_THREE: "3" } }),
    });
    expect(imp.status).toBe(200);
    expect(((await imp.json()) as { epoch: number }).epoch).toBe(1);

    const del = await callGate("/v1/projects/vaulter/keys/K_TWO", { method: "DELETE", headers: authHeader(await writerJwt()) });
    expect(del.status).toBe(200);

    const rd = await readKeys(["K_TWO"]);
    expect(rd.status).toBe(404);
    const list = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(await writerJwt()) });
    const names = ((await list.json()) as { keys: { keyName: string }[] }).keys.map((k) => k.keyName);
    expect(names.sort()).toEqual(["K_ONE", "K_THREE"]);

    // Silinmiş anahtarı tekrar silmek → 404.
    const del2 = await callGate("/v1/projects/vaulter/keys/K_TWO", { method: "DELETE", headers: authHeader(await writerJwt()) });
    expect(del2.status).toBe(404);
  });

  it("mixed-case anahtar adları (POSIX env-var) yazılıp okunur — farklı-case = farklı kimlik", async () => {
    // Storage case-sensitive kimlik: TF_VAR_* (tofu) gibi karışık-harf adlar yazılabilir;
    // farklı-case varyantlar (Api_Token vs API_TOKEN) AYRI anahtarlardır.
    expect((await putKey("TF_VAR_cloudflare_api_token", "tk")).status).toBe(200);
    expect((await putKey("vaulter_pg_admin_password", "pw")).status).toBe(200);
    const rd = await readKeys(["TF_VAR_cloudflare_api_token", "vaulter_pg_admin_password"]);
    const vals = ((await rd.json()) as { values: Record<string, string> }).values;
    expect(vals.TF_VAR_cloudflare_api_token).toBe("tk");
    expect(vals.vaulter_pg_admin_password).toBe("pw");
  });

  it("VALUE_TOO_LARGE: >61436B plaintext refused pre-upload (§2.1)", async () => {
    const res = await putKey("BIG_KEY", "x".repeat(61437));
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe("VALUE_TOO_LARGE");
  });
});

describe("policy gates on the wire (§4.3/§7.6)", () => {
  it("deny-glob: developer cannot read/write *_PROD_* keys; admin group can", async () => {
    const bossJwt = await signer.makeJWT(validClaims("boss@wapps.dev"));
    // Admin yazar (developers deny'i admins'i vetolamaz — kurallar-arası birleşim).
    const w = await callGate("/v1/projects/vaulter/keys/DB_PROD_URL", {
      method: "PUT",
      headers: authHeader(bossJwt),
      body: JSON.stringify({ value: "prod-secret" }),
    });
    expect(w.status).toBe(200);
    // Developer okuyamaz (all-or-nothing: karışık listede reddedilen anahtar adlandırılır).
    const rd = await readKeys(["DB_PROD_URL"]);
    expect(rd.status).toBe(403);
    const body = (await rd.json()) as { error: string; key: string };
    expect(body.error).toBe("GRANT_DENIED");
    expect(body.key).toBe("DB_PROD_URL");
    // Developer yazamaz.
    const wr = await putKey("DB_PROD_URL", "x");
    expect(wr.status).toBe(403);
    // Admin okur.
    const rdBoss = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(bossJwt), body: JSON.stringify({ keys: ["DB_PROD_URL"] }) });
    expect(rdBoss.status).toBe(200);
  });

  it("all-or-nothing bulk read: one denied key fails the WHOLE call naming it (§7.6)", async () => {
    const bossJwt = await signer.makeJWT(validClaims("boss@wapps.dev"));
    await callGate("/v1/projects/vaulter/keys/DB_PROD_URL", { method: "PUT", headers: authHeader(bossJwt), body: JSON.stringify({ value: "s" }) });
    await putKey("SAFE_KEY", "ok");
    const rd = await readKeys(["SAFE_KEY", "DB_PROD_URL"]);
    expect(rd.status).toBe(403);
    const txt = await rd.text();
    expect(txt).toContain("DB_PROD_URL");
    expect(txt).not.toContain("prod-secret"); // canary
    expect(txt).not.toContain("ok"); // izinli anahtarın değeri de sızmaz
  });

  it("groupless human: deny-by-default (no_rule)", async () => {
    const jwt = await signer.makeJWT(validClaims("stranger@wapps.dev"));
    const res = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(jwt), body: JSON.stringify({ keys: ["ANY_KEY"] }) });
    expect(res.status).toBe(403);
  });

  it("list + manifest entries are FILTERED to readable keys (§4.3.3)", async () => {
    const bossJwt = await signer.makeJWT(validClaims("boss@wapps.dev"));
    await putKey("APP_KEY", "a");
    await callGate("/v1/projects/vaulter/keys/DB_PROD_URL", { method: "PUT", headers: authHeader(bossJwt), body: JSON.stringify({ value: "p" }) });

    // Developer listesi prod anahtarını GÖRMEZ.
    const list = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(await writerJwt()) });
    const names = ((await list.json()) as { keys: { keyName: string }[] }).keys.map((k) => k.keyName);
    expect(names).toEqual(["APP_KEY"]);

    // Manifest entries de filtrelenir; tek-anahtarlı principal tam kümeyi sayamaz.
    const man = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(await writerJwt()) });
    expect(man.status).toBe(200);
    const doc = (await man.json()) as { entries: { keyName: string }[] };
    expect(doc.entries.map((e) => e.keyName)).toEqual(["APP_KEY"]);

    // Admin her ikisini görür.
    const manBoss = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(bossJwt) });
    const docBoss = (await manBoss.json()) as { entries: { keyName: string }[] };
    expect(docBoss.entries.map((e) => e.keyName).sort()).toEqual(["APP_KEY", "DB_PROD_URL"]);
  });

  it("service token rides the data plane DIRECTLY (§5.1) within its policy rows", async () => {
    await putKey("DEPLOY_TOKEN", "tok123");
    await putKey("OTHER_KEY", "nope");
    const svcJwt = await signer.makeJWT(serviceTokenClaims("svc-woodpecker"));
    const ok = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(svcJwt), body: JSON.stringify({ keys: ["DEPLOY_TOKEN"] }) });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { values: Record<string, string> }).values.DEPLOY_TOKEN).toBe("tok123");
    // Policy satırı dışı anahtar → deny; yazma verb'i yok → deny.
    const denied = await callGate("/v1/projects/vaulter/read", { method: "POST", headers: authHeader(svcJwt), body: JSON.stringify({ keys: ["OTHER_KEY"] }) });
    expect(denied.status).toBe(403);
    const wr = await callGate("/v1/projects/vaulter/keys/DEPLOY_TOKEN", { method: "PUT", headers: authHeader(svcJwt), body: JSON.stringify({ value: "x" }) });
    expect(wr.status).toBe(403);
  });
});

describe("synchronous read audit — fail-closed (gate 5, §6.4)", () => {
  it("audit DO down → 503 AUDIT_UNAVAILABLE, NO plaintext in the response", async () => {
    await putKey("SECRET_KEY", "hunter2-value");
    const failing = {
      idFromName: () => ({}),
      get: () => ({ fetch: async () => { throw new Error("audit down"); } }),
    } as unknown as DurableObjectNamespace;
    const res = await readKeys(["SECRET_KEY"], { AUDIT_LOG: failing });
    expect(res.status).toBe(503);
    const txt = await res.text();
    expect(txt).toContain("AUDIT_UNAVAILABLE");
    expect(txt).not.toContain("hunter2-value"); // plaintext YOK (fail-closed)
  });

  it("per-key rows: bulk read appends ONE row PER KEY (value.read.bulk); import per-key (key.import)", async () => {
    await callGate("/v1/projects/vaulter/import", {
      method: "POST",
      headers: authHeader(await writerJwt()),
      body: JSON.stringify({ values: { K_A: "1", K_B: "2", K_C: "3" } }),
    });
    const rd = await readKeys(["K_A", "K_B", "K_C"]);
    expect(rd.status).toBe(200);
    const rows = await settleAudit("vaulter", (r) => r.filter((x) => x.verb === "key.import" && x.decision === "allow").length >= 3);
    const importRows = rows.filter((r) => r.verb === "key.import" && r.decision === "allow");
    expect(importRows.map((r) => r.key).sort()).toEqual(["K_A", "K_B", "K_C"]); // aggregate keys:N YASAK
    const bulkRows = rows.filter((r) => r.verb === "value.read.bulk" && r.decision === "allow");
    expect(bulkRows.map((r) => r.key).sort()).toEqual(["K_A", "K_B", "K_C"]);
    // Tek anahtar okuma → value.read.
    await readKeys(["K_A"]);
    expect((await allAuditRows()).some((r) => r.verb === "value.read" && r.key === "K_A")).toBe(true);
  });

  it("rotation header labels the write rotate.step (informative, §6.4)", async () => {
    await putKey("ROT_KEY", "v1", {}, { "X-Wapps-Rotation": "recipe-42" });
    const rows = await settleAudit("vaulter", (r) => r.some((x) => x.verb === "rotate.step"));
    expect(rows.some((r) => r.verb === "rotate.step" && r.key === "ROT_KEY" && r.decision === "allow")).toBe(true);
  });
});

describe("writer serialization + EPOCH_CONFLICT (gate 4)", () => {
  it("two concurrent writers with the same ifEpoch: exactly one 200, one 412", async () => {
    await putKey("RACE_KEY", "base"); // epoch 1
    const [a, b] = await Promise.all([
      putKey("RACE_KEY", "writer-A", { ifEpoch: 1 }),
      putKey("RACE_KEY", "writer-B", { ifEpoch: 1 }),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 412]);
    const loser = a.status === 412 ? a : b;
    expect(((await loser.json()) as { error: string }).error).toBe("EPOCH_CONFLICT");
    // Kazanan epoch 2'yi yazdı; pointer tutarlı.
    const cur = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCurrent("vaulter")))!.text()) as { epoch: number };
    expect(cur.epoch).toBe(2);
  });

  it("concurrent writes WITHOUT ifEpoch both land (serialized epochs)", async () => {
    const [a, b] = await Promise.all([putKey("K_X", "1"), putKey("K_Y", "2")]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const epochs = [((await a.json()) as { epoch: number }).epoch, ((await b.json()) as { epoch: number }).epoch].sort();
    expect(epochs).toEqual([1, 2]);
  });
});

describe("rewrap-kek (§2.5)", () => {
  const NEW_KEK = "3333333333333333333333333333333333333333333333333333333333333333";

  it("re-wraps every DEK under the new KEK; blobs untouched; old-key reads fail after PREV removal", async () => {
    await putKey("RW_KEY", "keep-me");
    const m1 = JSON.parse(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1)))!.text()) as { entries: { wrap: { kid: string }; blobHash: string }[] };
    const oldKid = m1.entries[0].wrap.kid;

    // DO'nun master'larını rotasyon penceresine geçir (env DO'ya per-request
    // geçirilemez → instance enjeksiyonu, audit-down testleriyle aynı desen).
    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
    await runInDoRetry(stub, (instance: unknown) => {
      (instance as { masters: unknown }).masters = loadMasterKeys({ MASTER_KEK: NEW_KEK, MASTER_KEK_PREV: MASTER_KEK_HEX });
    });

    const adminJwt = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const res = await callGate("/v1/admin/rewrap-kek", { method: "POST", headers: authHeader(adminJwt) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { projects: Record<string, { epoch: number; rewrapped: number }>; failed: number };
    expect(body.failed).toBe(0);
    expect(body.projects.vaulter.rewrapped).toBe(1);
    expect(body.projects.vaulter.epoch).toBe(2);

    // Manifest v2: kid değişti, blobHash AYNI (blob'lara dokunulmaz), keyVersion aynı.
    const m2 = JSON.parse(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 2)))!.text()) as { entries: { wrap: { kid: string }; blobHash: string; keyVersion: number }[] };
    expect(m2.entries[0].wrap.kid).not.toBe(oldKid);
    expect(m2.entries[0].blobHash).toBe(m1.entries[0].blobHash);
    expect(m2.entries[0].keyVersion).toBe(1);

    // Yeni KEK ile okuma çalışır (PREV'siz — rotasyon tamam).
    const rdNew = await readKeys(["RW_KEY"], { MASTER_KEK: NEW_KEK, MASTER_KEK_PREV: "" });
    expect(rdNew.status).toBe(200);
    expect(((await rdNew.json()) as { values: Record<string, string> }).values.RW_KEY).toBe("keep-me");

    // ESKİ anahtarla okuma artık WRAP_INVALID (kid uyuşmaz) — fail-closed.
    const rdOld = await readKeys(["RW_KEY"]);
    expect(rdOld.status).toBe(503);
    expect(((await rdOld.json()) as { error: string }).error).toBe("WRAP_INVALID");

    // İkinci rewrap idempotent no-op (yeni epoch üretmez).
    await runInDoRetry(stub, (instance: unknown) => {
      (instance as { masters: unknown }).masters = loadMasterKeys({ MASTER_KEK: NEW_KEK });
    });
    const res2 = await callGate("/v1/admin/rewrap-kek", { method: "POST", headers: authHeader(adminJwt) });
    const body2 = (await res2.json()) as { projects: Record<string, { epoch: number; rewrapped: number; noop?: boolean }> };
    expect(body2.projects.vaulter.rewrapped).toBe(0);
    expect(body2.projects.vaulter.epoch).toBe(2);

    // DO master'larını varsayılana geri döndür (paylaşılan instance).
    await runInDoRetry(stub, (instance: unknown) => {
      (instance as { masters: unknown }).masters = loadMasterKeys({ MASTER_KEK: MASTER_KEK_HEX });
    });
  });
});

describe("canary: error paths never leak values (gate 6, C2)", () => {
  it("denied/404/conflict/misconfig responses contain no secret material", async () => {
    const secret = "super-secret-canary-value-9f8e7d";
    await putKey("CANARY_KEY", secret);

    const denied = await callGate("/v1/projects/vaulter/read", {
      method: "POST",
      headers: authHeader(await signer.makeJWT(validClaims("stranger@wapps.dev"))),
      body: JSON.stringify({ keys: ["CANARY_KEY"] }),
    });
    const notFound = await readKeys(["MISSING_KEY"]);
    const conflict = await putKey("CANARY_KEY", "new", { ifEpoch: 99 });
    const misconfig = await callGate("/v1/whoami", { headers: authHeader(await writerJwt()) }, { MASTER_KEK: "" });

    for (const res of [denied, notFound, conflict, misconfig]) {
      expect(await res.text()).not.toContain(secret);
    }
    expect(denied.status).toBe(403);
    expect(notFound.status).toBe(404);
    expect(conflict.status).toBe(412);
    expect(misconfig.status).toBe(503);
  });
});
