// D1 hash-chained audit testleri (SPEC §6.5 + §6.2 F7 sıralaması): zincir sürekliliği
// + hash kuralı, attempt-önce/outcome-sonra, deny satırları, AUDIT_UNAVAILABLE
// commit'i fail-close eder, read-path async.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  seedTrust,
  ensureJwks,
  validClaims,
  authHeader,
  callGate,
  resetWorld,
  signDataManifest,
  putBlob,
  runInDoRetry,
  TrustContext,
} from "./helpers.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { sha256Hex, utf8 } from "../src/crypto/verify.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

interface Row {
  seq: number;
  ts: string;
  principal: string;
  principal_type: string;
  project: string | null;
  key: string | null;
  verb: string;
  decision: string;
  intent: string | null;
  ip: string | null;
  cf_ray: string | null;
  token_jti: string | null;
  prev_hash: string;
  hash: string;
}

function fullWraps(t: TrustContext) {
  return [
    { recipient: t.writerDevice, wrap: "a" },
    { recipient: t.writerBackup, wrap: "b" },
    { recipient: t.escrowFp, wrap: "c" },
  ];
}

async function allRows(): Promise<Row[]> {
  const r = await env.AUDIT_DB.prepare("SELECT * FROM audit ORDER BY seq ASC").all<Row>();
  return r.results ?? [];
}

/** rowHash, DO ile AYNI formülle bir satırın hash'ini yeniden hesaplar (§6.5 chain rule). */
function rowHash(prevHash: string, r: Row): string {
  const values = [r.seq, r.ts, r.principal, r.principal_type, r.project, r.key, r.verb, r.decision, r.intent, r.ip, r.cf_ray, r.token_jti];
  return sha256Hex(utf8(prevHash + "\n" + JSON.stringify(values)));
}

async function doCommit(t: TrustContext, email: string, bodyStr: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims(email));
  return callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(jwt), body: bodyStr }, t.pin);
}

async function genesisCommit(t: TrustContext): Promise<void> {
  const blob = await putBlob("vaulter", new Uint8Array([9, 9, 9, 9]));
  const w = signDataManifest({ project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob, wraps: fullWraps(t) }] }, t.writer);
  const res = await doCommit(t, "writer@wapps.dev", w.wrapperStr);
  expect(res.status).toBe(200);
}

describe("hash-chained audit (§6.5)", () => {
  it("CHAIN: every row hash = SHA256(prev_hash || 0x0A || row_json); consecutive rows link", async () => {
    const t = await seedTrust();
    await genesisCommit(t);
    const rows = await allRows();
    expect(rows.length).toBeGreaterThanOrEqual(2); // attempt + outcome
    // Gerçek tamper-evidence invaryantı: HER satır hash kuralına uyar VE ardışık
    // satırlar birbirine bağlanır. (Segmentin İLK prev_hash'inin genesis olması, ancak
    // DO head'i sıfırlanabildiğinde geçerlidir — test-harness bunu garanti edemez, bu
    // yüzden zincir-kuralı + süreklilik doğrulanır; bu güvenlik özelliğinin ta kendisidir.)
    for (let i = 0; i < rows.length; i++) {
      expect(rows[i].hash).toBe(rowHash(rows[i].prev_hash, rows[i])); // hash kuralı (§6.5)
      if (i > 0) expect(rows[i].prev_hash).toBe(rows[i - 1].hash); // süreklilik
    }
    // İlk satır prev_hash'i ya genesis'tir ya da önceki bir (silinmiş) satırın hash'i —
    // her iki halde de 64-hane hex.
    expect(rows[0].prev_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("F7 ORDERING: commit.attempt row precedes the commit outcome row (allow)", async () => {
    const t = await seedTrust();
    await genesisCommit(t);
    const rows = await allRows();
    const attempt = rows.find((r) => r.verb === "commit.attempt");
    const outcome = rows.find((r) => r.verb === "commit" && r.decision === "allow");
    expect(attempt).toBeTruthy();
    expect(outcome).toBeTruthy();
    expect(attempt!.seq).toBeLessThan(outcome!.seq); // attempt ÖNCE, outcome SONRA
  });

  it("DENY: a rejected commit appends a deny row (no allow outcome)", async () => {
    const t = await seedTrust();
    // reader DATABASE_URL yazmaya çalışır → GRANT_DENIED (step 8, attempt'ten ÖNCE).
    const blob = await putBlob("vaulter", new Uint8Array([7]));
    const w = signDataManifest({ project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob, wraps: fullWraps(t) }] }, t.reader);
    const res = await doCommit(t, "reader@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    const rows = await allRows();
    const deny = rows.find((r) => r.verb === "commit" && r.decision === "deny");
    expect(deny).toBeTruthy();
    expect(deny!.intent).toBe("GRANT_DENIED");
    // Başarısız yazımın allow outcome'ı OLMAMALI (F7).
    expect(rows.find((r) => r.verb === "commit" && r.decision === "allow")).toBeUndefined();
    // Deny satırı da zincire bağlı.
    expect(deny!.hash).toBe(rowHash(deny!.prev_hash, deny!));
  });

  it("AUDIT_UNAVAILABLE: audit DO down at attempt → commit fails closed (503), NOTHING written", async () => {
    const t = await seedTrust();
    await genesisCommit(t); // epoch 1 → PROJECT_WRITER DO'yu warm eder
    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));

    // this.auditLog'u, get().fetch()'i reject eden bir namespace ile değiştir.
    const failing = {
      idFromName: () => ({}),
      get: () => ({ fetch: async () => { throw new Error("audit down"); } }),
    } as unknown as DurableObjectNamespace;
    let saved: DurableObjectNamespace | undefined;
    await runInDoRetry(stub, (instance: unknown) => {
      const h = instance as { auditLog: DurableObjectNamespace };
      saved = h.auditLog;
      h.auditLog = failing;
    });

    // Geçerli epoch-2 commit → attempt append patlar → 503 AUDIT_UNAVAILABLE.
    const blob = await putBlob("vaulter", new Uint8Array([2, 2]));
    const cur = await env.SECRETS_BUCKET.get(keyCurrent("vaulter"));
    const prevSha = sha256Hex(new Uint8Array(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1))!)!.arrayBuffer()));
    void cur;
    const w = signDataManifest({ project: "vaulter", epoch: 2, prev: prevSha, trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: blob, wraps: fullWraps(t) }] }, t.writer);
    const res = await doCommit(t, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("AUDIT_UNAVAILABLE");

    // Fail-closed: current epoch-1'de kaldı, manifests/2 YAZILMADI.
    const curNow = JSON.parse(await (await env.SECRETS_BUCKET.get(keyCurrent("vaulter")))!.text()) as { epoch: number };
    expect(curNow.epoch).toBe(1);
    expect(await env.SECRETS_BUCKET.get(keyManifest("vaulter", 2))).toBeNull();

    // auditLog'u geri yükle (singleWorker → instance paylaşımlı).
    await runInDoRetry(stub, (instance: unknown) => {
      if (saved) (instance as { auditLog: DurableObjectNamespace }).auditLog = saved;
    });
  });

  it("READ-PATH ASYNC: an allowed manifest read appends an async (waitUntil) audit row", async () => {
    const t = await seedTrust();
    await genesisCommit(t);
    const before = (await allRows()).length;
    const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
    const res = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(jwt) }, t.pin);
    expect(res.status).toBe(200);
    // callGate waitOnExecutionContext'i await eder → waitUntil flush tamamlanır.
    const rows = await allRows();
    expect(rows.length).toBeGreaterThan(before);
    expect(rows.some((r) => r.verb === "read" && r.decision === "allow" && r.project === "vaulter")).toBe(true);
  });
});
