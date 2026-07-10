// Commit transaction testleri (SPEC §6.2): iki-yazar CAS yarışı, semantik-diff
// authz (accept + reject sınıfları), pointer-event yazımı. Worker→DO tam yol.
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env, runInDurableObject, runDurableObjectAlarm } from "cloudflare:test";
import {
  seedTrust,
  ensureJwks,
  validClaims,
  authHeader,
  callGate,
  signDataManifest,
  seedManifestObject,
  putBlob,
  resetWorld,
  p256Key,
  recip,
  serviceTokenClaims,
  TrustContext,
} from "./helpers.js";
import { keyCurrent, keyPointerEvent } from "../src/storage.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

async function doCommit(pin: string, email: string, bodyStr: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims(email));
  return callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(jwt), body: bodyStr }, pin);
}
async function errCode(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { error?: string }).error;
}
// DATABASE_URL için tam-geçerli wrap-set (writer read via * + escrow).
function fullWraps(t: TrustContext): { recipient: string; wrap: string }[] {
  return [
    { recipient: t.writerDevice, wrap: "a" },
    { recipient: t.writerBackup, wrap: "b" },
    { recipient: t.escrowFp, wrap: "c" },
  ];
}

async function setup(): Promise<TrustContext> {
  return seedTrust();
}

/**
 * failPointerEventPutOnce, bir R2Bucket'ı sarmalayan Proxy döner: pointer-event
 * anahtarına (pointer-events/…) İLK put'ta bir kez transient hata fırlatır, sonra
 * tüm çağrıları gerçek bucket'a delege eder. Diğer tüm metotlar aynen delege edilir.
 * Step-17 fail-soft testi için commit sırasında pointer-event yazımını düşürür.
 */
function failPointerEventPutOnce(real: R2Bucket): R2Bucket {
  let armed = true;
  return new Proxy(real, {
    get(target, prop) {
      if (prop === "put") {
        return (key: unknown, value: unknown, options?: unknown) => {
          if (armed && typeof key === "string" && key.startsWith("pointer-events/")) {
            armed = false;
            return Promise.reject(new Error("injected transient R2 failure (pointer-event)"));
          }
          return (target.put as (k: unknown, v: unknown, o?: unknown) => Promise<unknown>).call(target, key, value, options);
        };
      }
      const v = Reflect.get(target, prop, target);
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  }) as unknown as R2Bucket;
}

type BucketHolder = { bucket: R2Bucket };

describe("commit — semantic-diff authz + CAS", () => {
  it("ACCEPT: genesis commit within grant + exact wrap-set + escrow → 200, advances current, writes pointer event", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([9, 9, 9, 9]));
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { epoch: number; manifestSha256: string };
    expect(body.epoch).toBe(1);
    expect(body.manifestSha256).toBe(w.objectSha256);

    // current ilerledi.
    const cur = await env.SECRETS_BUCKET.get(keyCurrent("vaulter"));
    expect(cur).not.toBeNull();
    const ptr = JSON.parse(await cur!.text()) as { epoch: number; manifestSha256: string };
    expect(ptr.epoch).toBe(1);
    expect(ptr.manifestSha256).toBe(w.objectSha256);

    // append-only pointer event yazıldı (§9.2.3 / F2).
    const ev = await env.SECRETS_BUCKET.get(keyPointerEvent("vaulter", 1));
    expect(ev).not.toBeNull();
    const evj = JSON.parse(await ev!.text()) as { schema: string; epoch: number; manifestSha256: string; committed_at: string };
    expect(evj.schema).toBe("wapps.pointer-event.v1");
    expect(evj.epoch).toBe(1);
    expect(evj.manifestSha256).toBe(w.objectSha256);
    expect(typeof evj.committed_at).toBe("string");
  });

  it("CAS RACE: two concurrent writes to one project → exactly one 200, one 412", async () => {
    const t = await setup();
    const bA = await putBlob("vaulter", new Uint8Array([1]));
    const bB = await putBlob("vaulter", new Uint8Array([2, 2]));
    const wA = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: bA, wraps: fullWraps(t) }] },
      t.writer,
    );
    const wB = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "API_KEY", keyVersion: 1, blobHash: bB, wraps: fullWraps(t) }] },
      t.writer,
    );
    const [r1, r2] = await Promise.all([doCommit(t.pin, "writer@wapps.dev", wA.wrapperStr), doCommit(t.pin, "writer@wapps.dev", wB.wrapperStr)]);
    const statuses = [r1.status, r2.status].sort((a, b) => a - b);
    expect(statuses).toEqual([200, 412]);
    const loser = r1.status === 412 ? r1 : r2;
    expect(await errCode(loser)).toBe("EPOCH_CONFLICT");
  });

  it("REJECT: write outside grant → 403 GRANT_DENIED (reader has no write)", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([7]));
    // reader imzalar + principal=reader; reader'ın DATABASE_URL'de write grant'ı yok.
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.reader,
    );
    const res = await doCommit(t.pin, "reader@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("GRANT_DENIED");
  });

  it("REJECT: wrap-set shrink without re-key → 403 WRAPSET_VIOLATION", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([3, 3, 3]));
    const extra = recip("extra-unauth").fp;
    // Seed epoch-1 DOĞRUDAN (commit validasyonunu atlar) — EXTRA recipient içerir.
    const w1 = signDataManifest(
      {
        project: "vaulter",
        epoch: 1,
        prev: "",
        trustEpoch: 1,
        entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: [...fullWraps(t), { recipient: extra, wrap: "x" }] }],
      },
      t.writer,
    );
    await seedManifestObject("vaulter", 1, w1);
    // epoch-2: EXTRA düştü ama aynı keyVersion + aynı blob (re-key YOK) → şart 10.
    const w2 = signDataManifest(
      { project: "vaulter", epoch: 2, prev: w1.objectSha256, trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w2.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("WRAPSET_VIOLATION");
  });

  it("REJECT: epoch skip → 412 EPOCH_CONFLICT", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([4]));
    const w1 = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    await seedManifestObject("vaulter", 1, w1);
    const w3 = signDataManifest(
      { project: "vaulter", epoch: 3, prev: w1.objectSha256, trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w3.wrapperStr);
    expect(res.status).toBe(412);
    expect(await errCode(res)).toBe("EPOCH_CONFLICT");
  });

  it("REJECT: prevManifestSha256 mismatch → 412 EPOCH_CONFLICT", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([5]));
    const w1 = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    await seedManifestObject("vaulter", 1, w1);
    const w2 = signDataManifest(
      { project: "vaulter", epoch: 2, prev: "deadbeef".repeat(8), trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w2.wrapperStr);
    expect(res.status).toBe(412);
    expect(await errCode(res)).toBe("EPOCH_CONFLICT");
  });

  it("REJECT: referenced blob missing → 422 BLOB_MISSING", async () => {
    const t = await setup();
    const fakeBlob = "a".repeat(64);
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: fakeBlob, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(422);
    expect(await errCode(res)).toBe("BLOB_MISSING");
  });

  it("REJECT: missing escrow wrap → 422 ESCROW_WRAP_MISSING", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([6]));
    const w = signDataManifest(
      {
        project: "vaulter",
        epoch: 1,
        prev: "",
        trustEpoch: 1,
        entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: [{ recipient: t.writerDevice, wrap: "a" }, { recipient: t.writerBackup, wrap: "b" }] }],
      },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(422);
    expect(await errCode(res)).toBe("ESCROW_WRAP_MISSING");
  });

  it("REJECT: extra unauthorized recipient → 403 WRAPSET_VIOLATION", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([8]));
    const w = signDataManifest(
      {
        project: "vaulter",
        epoch: 1,
        prev: "",
        trustEpoch: 1,
        entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: [...fullWraps(t), { recipient: recip("exfil").fp, wrap: "z" }] }],
      },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("WRAPSET_VIOLATION");
  });

  it("REJECT: missing required reader recipient on a shared key → 403 WRAPSET_VIOLATION", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([1, 0, 1]));
    // SHARED_KEY: reader read-granted → required set includes reader dev+backup.
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "SHARED_KEY", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("WRAPSET_VIOLATION");
  });

  it("REJECT: signature by someone else's key under your session → 403 PRINCIPAL_KEY_MISMATCH", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([2, 0, 2]));
    // writer imzalar, ama oturum principal = reader (JWT email reader).
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const res = await doCommit(t.pin, "reader@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("PRINCIPAL_KEY_MISMATCH");
  });

  it("REJECT: tampered manifest bytes → 403 SIG_INVALID", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([3, 0, 3]));
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    const obj = JSON.parse(w.wrapperStr) as { bytes: string; sigs: unknown };
    obj.bytes = (obj.bytes[0] === "A" ? "B" : "A") + obj.bytes.slice(1); // decoded body baytını boz
    const res = await doCommit(t.pin, "writer@wapps.dev", JSON.stringify(obj));
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("SIG_INVALID");
  });

  it("REJECT: writer key not enrolled → 403 WRITER_NOT_ALLOWED", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([4, 0, 4]));
    const stranger = p256Key(0x99); // trust roster'da yok
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      stranger,
    );
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("WRITER_NOT_ALLOWED");
  });

  // §6.2(d)/step-17: pointer-event yazım hatası commit'i DÜŞÜREMEZ (fail-soft).
  it("FAIL-SOFT: pointer-event write throws once → STILL 200, current advances, pending marker + alarm; alarm() drains it", async () => {
    const t = await setup();
    const blobHash = await putBlob("vaulter", new Uint8Array([9, 9, 9, 9]));
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );

    // Worker'ın ulaşacağı DO singleton'ı (idFromName=project) — aynı isolate/dosya.
    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
    const pendingKey = "pending-pointer-event:vaulter:1";

    // Instance'ın bucket'ını, pointer-event put'unu bir kez düşüren Proxy ile değiştir.
    let realBucket: R2Bucket | null = null;
    await runInDurableObject(stub, (instance) => {
      const holder = instance as unknown as BucketHolder;
      realBucket = holder.bucket;
      holder.bucket = failPointerEventPutOnce(realBucket);
    });

    // Commit: pointer-event yazımı patlar ama commit 200 döner (fail-soft).
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { epoch: number; manifestSha256: string };
    expect(body.epoch).toBe(1);
    expect(body.manifestSha256).toBe(w.objectSha256);

    // Commit KALICI: current pointer ilerledi (CAS başarılı).
    const cur = await env.SECRETS_BUCKET.get(keyCurrent("vaulter"));
    expect(cur).not.toBeNull();
    const ptr = JSON.parse(await cur!.text()) as { epoch: number };
    expect(ptr.epoch).toBe(1);

    // Pointer-event R2'ye HENÜZ yazılmadı (put patladı).
    expect(await env.SECRETS_BUCKET.get(keyPointerEvent("vaulter", 1))).toBeNull();

    // DO storage'da "pending" marker + zamanlanmış alarm var.
    const marker = await runInDurableObject(stub, (_i, state) => state.storage.get<{ r2Key: string; body: string }>(pendingKey));
    expect(marker).toBeTruthy();
    expect(marker!.r2Key).toBe(keyPointerEvent("vaulter", 1));
    const alarmAt = await runInDurableObject(stub, (_i, state) => state.storage.getAlarm());
    expect(alarmAt).not.toBeNull();

    // Alarm'ı çalıştır → bekleyen pointer-event idempotent olarak drene edilir.
    const ran = await runDurableObjectAlarm(stub);
    expect(ran).toBe(true);

    // Şimdi pointer-event R2'de var ve doğru içerikte.
    const ev = await env.SECRETS_BUCKET.get(keyPointerEvent("vaulter", 1));
    expect(ev).not.toBeNull();
    const evj = JSON.parse(await ev!.text()) as { schema: string; epoch: number; manifestSha256: string };
    expect(evj.schema).toBe("wapps.pointer-event.v1");
    expect(evj.epoch).toBe(1);
    expect(evj.manifestSha256).toBe(w.objectSha256);

    // Marker temizlendi.
    const cleared = await runInDurableObject(stub, (_i, state) => state.storage.get(pendingKey));
    expect(cleared).toBeUndefined();

    // Temizlik: instance bucket'ını geri koy (singleWorker → instance testler arası paylaşımlı).
    await runInDurableObject(stub, (instance) => {
      if (realBucket) (instance as unknown as BucketHolder).bucket = realBucket;
    });
  });
});

// P2 (§6.3 / §6.2 step 8): minted machine-token SCOPE (verbs+keys) yazma yolunda
// zorlanır — dar mint edilmiş bir token, kimliğin write-allowlist'i geniş olsa bile
// commit süremez (grants ∩ token scope). Bu, machineScopeOk'un okuma+blob-PUT dışında
// commit'te de geçerli olmasını kanıtlar.
describe("commit — machine token scope enforcement (P2, §6.3)", () => {
  it("REJECT: READ-scoped machine token drives a write-granted commit → 403 TOKEN_SCOPE_EXCEEDED (identity holds the write grant)", async () => {
    const t = await setup();
    // Makine MACHINE_KEY'i YAZABİLİR (writer_allowlist) VE OKUYABİLİR (grant). Ama token
    // yalnızca READ scope ile mint edilir → commit ENGELLENMELİDİR (least-privilege).
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const mintRes = await callGate(
      "/v1/token",
      { method: "POST", headers: authHeader(seedJwt), body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 }) },
      t.pin,
    );
    expect(mintRes.status).toBe(200);
    const { token } = (await mintRes.json()) as { token: string };

    // MACHINE_KEY için AKSİ HÂLDE tam-geçerli genesis commit (makine device + escrow wrap,
    // automation Ed25519 imzası) — tek engel token scope olsun diye her şey doğru kurulur.
    const blobHash = await putBlob("vaulter", new Uint8Array([7, 7, 7, 7]));
    const w = signDataManifest(
      {
        project: "vaulter",
        epoch: 1,
        prev: "",
        trustEpoch: 1,
        entries: [{ keyName: "MACHINE_KEY", keyVersion: 1, blobHash, wraps: [{ recipient: t.machineDevice, wrap: "m" }, { recipient: t.escrowFp, wrap: "e" }] }],
      },
      { keyID: t.machineKey.keyID, alg: "ed25519", sign: (m: Uint8Array) => t.machineKey.sign(m) },
    );
    const res = await callGate(
      "/v1/projects/vaulter/commit",
      { method: "POST", headers: authHeader(seedJwt, { authorization: `Bearer ${token}` }), body: w.wrapperStr },
      t.pin,
    );
    expect(res.status).toBe(403);
    expect(await errCode(res)).toBe("TOKEN_SCOPE_EXCEEDED");
  });
});
