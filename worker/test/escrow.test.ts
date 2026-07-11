// Escrow write-through fail-soft testleri (SPEC §6.8 / §9.2). MOCK S3 (fetchMock)
// ile kanıtlar: (1) B2 push HATASI kalıcı commit'i DÜŞÜREMEZ (commit yine 200 +
// retry kuyruğa alınır — B2 write path'te DEĞİL), (2) alarm() bekleyen push'ları
// drene eder (F2: MUTABLE current ASLA push edilmez, yalnızca pointer EVENT), (3)
// drenaj retry mantığı: 3 başarısız denemeden sonra alert A4 (§6.10) — deterministik
// birim testi (DO alarm harness'ının invalidation flakiness'ından bağımsız).
//
// B2, DO instance'ına enjekte edilir (runInDurableObject) — global binding'lerde
// B2 YOK, böylece diğer test dosyaları escrow yoluna girmez.

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env, fetchMock, runInDurableObject, runDurableObjectAlarm } from "cloudflare:test";
import {
  seedTrust,
  ensureJwks,
  validClaims,
  authHeader,
  callGate,
  signDataManifest,
  putBlob,
  resetWorld,
  TrustContext,
} from "./helpers.js";
import { keyBlob, keyManifest, keyPointerEvent } from "../src/storage.js";
import { EscrowConfig, enqueueEscrowPushes, drainEscrowPushes, EscrowPushItem, EscrowAlert } from "../src/escrow.js";

const B2_HOST = "https://s3.test-region.backblazeb2.com";
const TEST_ESCROW: EscrowConfig = {
  endpoint: "s3.test-region.backblazeb2.com",
  region: "test-region",
  bucket: "wapps-secrets-escrow",
  keyId: "0004b2keyid",
  appKey: "K004appkeysecret",
};

let b2Mode: "ok" | "fail" = "ok";
const b2Puts: string[] = [];

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
  fetchMock
    .get(B2_HOST)
    .intercept({ path: () => true, method: "PUT" })
    .reply((opts: { path?: string }) => {
      if (b2Mode === "fail") return { statusCode: 500, data: "" };
      b2Puts.push(decodeURIComponent(String(opts.path ?? "")));
      return { statusCode: 200, data: "" };
    })
    .persist();
});
beforeEach(async () => {
  await resetWorld();
  b2Mode = "ok";
  b2Puts.length = 0;
});

function fullWraps(t: TrustContext): { recipient: string; wrap: string }[] {
  return [
    { recipient: t.writerDevice, wrap: "a" },
    { recipient: t.writerBackup, wrap: "b" },
    { recipient: t.escrowFp, wrap: "c" },
  ];
}

function writerStub() {
  return env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
}
// doRetry, bir DO-harness çağrısını (runInDurableObject/runDurableObjectAlarm)
// TRANSIENT invalidation'a (singleWorker cross-file modül reload) karşı GENİŞ bir
// bütçeyle (~6s) yeniden dener; fn her denemede TAZE stub kurar (bayat stub kalıcı
// patlar). Yalnızca test-harness ops için — ürün yolu (callGate→doStubFetch) zaten
// dayanıklı. Bu, request-yolu DIŞINDA olan DO storage/alarm erişimlerini korur.
async function doRetry<T>(fn: () => T | Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (i >= 40 || !/invalidating|broken|please retry/i.test(String(e))) throw e;
      await new Promise((r) => setTimeout(r, Math.min(200, 10 * (i + 1))));
    }
  }
}
function inDO<T>(cb: (i: unknown, s: DurableObjectState) => T | Promise<T>): Promise<T> {
  return doRetry(() => runInDurableObject(writerStub(), cb as never)) as Promise<T>;
}
async function alarmOnce(): Promise<void> {
  await doRetry(() => runDurableObjectAlarm(writerStub()));
}

// setEscrow, escrow config'i DO STORAGE'a yazar (instance mutasyonu DEĞİL) —
// böylece config bir instance-recreation SONRASI sağ kalır; commit/alarm
// effectiveEscrow() ile storage'dan okur.
async function setEscrow(cfg: EscrowConfig | null): Promise<void> {
  await inDO((_i, state) =>
    (async () => {
      if (cfg) await state.storage.put("escrow-config", cfg);
      else await state.storage.delete("escrow-config");
    })(),
  );
}
async function readMarkers(keys: string[]): Promise<Record<string, unknown>> {
  return inDO((_i, state) =>
    (async () => {
      const out: Record<string, unknown> = {};
      for (const k of keys) out[k] = await state.storage.get(k);
      return out;
    })(),
  );
}

afterEach(async () => {
  await inDO((_i, state) => state.storage.deleteAll());
  await setEscrow(null);
});

async function doCommit(pin: string, email: string, bodyStr: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims(email));
  return callGate("/v1/projects/vaulter/commit", { method: "POST", headers: authHeader(jwt), body: bodyStr }, pin);
}

describe("escrow write-through — fail-soft B2 push (§6.8/§9.2)", () => {
  it("FAIL-SOFT: B2 unavailable → commit STILL 200, escrow pushes enqueued, B2 untouched on the write path", async () => {
    const t = await seedTrust();
    await setEscrow(TEST_ESCROW);
    const blob = new Uint8Array(256 + 44).fill(7);
    const blobHash = await putBlob("vaulter", blob);
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );

    b2Mode = "fail"; // B2 tamamen düşük
    const res = await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr);
    expect(res.status).toBe(200); // commit KALICI — B2 write path'te değil

    const pendingKeys = ["pending-escrow-push:" + keyManifest("vaulter", 1), "pending-escrow-push:" + keyPointerEvent("vaulter", 1), "pending-escrow-push:" + keyBlob("vaulter", blobHash)];
    const enq = await readMarkers(pendingKeys);
    for (const k of pendingKeys) expect(enq[k], `marker ${k} enqueued`).toBeTruthy();
    expect(b2Puts.length, "B2 not contacted on the write path").toBe(0);
  });

  it("DRAIN: enqueued escrow pushes are drained by the alarm; MUTABLE current is NEVER pushed (F2)", async () => {
    const t = await seedTrust();
    await setEscrow(TEST_ESCROW);
    const blob = new Uint8Array(256 + 44).fill(9);
    const blobHash = await putBlob("vaulter", blob);
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );

    b2Mode = "ok";
    expect((await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr)).status).toBe(200);

    const pendingKeys = ["pending-escrow-push:" + keyManifest("vaulter", 1), "pending-escrow-push:" + keyPointerEvent("vaulter", 1), "pending-escrow-push:" + keyBlob("vaulter", blobHash)];
    await alarmOnce(); // TEK alarm → drene (commit.test fail-soft ile aynı stabil profil)

    const drained = await readMarkers(pendingKeys);
    for (const k of pendingKeys) expect(drained[k], `marker ${k} drained`).toBeUndefined();
    expect(b2Puts.some((p) => p.includes(keyManifest("vaulter", 1)))).toBe(true);
    expect(b2Puts.some((p) => p.includes(keyPointerEvent("vaulter", 1)))).toBe(true);
    expect(b2Puts.some((p) => p.includes(keyBlob("vaulter", blobHash)))).toBe(true);
    // F2: mutable `current` ASLA push edilmedi (yalnızca pointer EVENT).
    expect(b2Puts.some((p) => p.endsWith("/current"))).toBe(false);
  });

  it("escrow disabled (no B2 config) → commit 200, NO escrow markers", async () => {
    const t = await seedTrust();
    await setEscrow(null);
    const blob = new Uint8Array(256 + 44).fill(5);
    const blobHash = await putBlob("vaulter", blob);
    const w = signDataManifest(
      { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "API_KEY", keyVersion: 1, blobHash, wraps: fullWraps(t) }] },
      t.writer,
    );
    expect((await doCommit(t.pin, "writer@wapps.dev", w.wrapperStr)).status).toBe(200);
    const markers = await inDO((_i, state) => state.storage.list({ prefix: "pending-escrow-push:" }));
    expect(markers.size).toBe(0);
  });
});

// --- drainEscrowPushes birim testi (deterministik, DO harness'sız) ------------
// Retry + A4 mantığını doğrudan fake storage + fetchMock B2 ile sürer — çok-alarm
// DO harness'ının invalidation flakiness'ından bağımsız.
describe("drainEscrowPushes — retry + A4 (§6.8)", () => {
  it("push fails → item persists + attempts increment; 3rd attempt → A4; B2 recovers → drains", async () => {
    const storage = new FakeStorage();
    const items: EscrowPushItem[] = [{ b2Key: "audit/segments/1.json", bodyB64: btoa(JSON.stringify({ seq: 1 })), contentType: "application/json" }];
    await enqueueEscrowPushes(storage as unknown as DurableObjectStorage, items);
    expect(storage.map.size).toBe(1);
    expect(storage.alarmAt).not.toBeNull();

    const alerts: string[] = [];
    const alert: EscrowAlert = async (rule) => {
      alerts.push(rule);
    };

    // 3 başarısız drenaj → attempts 1,2,3; 3. denemede A4.
    b2Mode = "fail";
    for (let i = 1; i <= 3; i++) {
      const remaining = await drainEscrowPushes(storage as unknown as DurableObjectStorage, TEST_ESCROW, null, alert);
      expect(remaining).toBe(1);
      const rec = storage.map.get("pending-escrow-push:audit/segments/1.json") as { attempts: number };
      expect(rec.attempts).toBe(i);
    }
    expect(alerts.filter((r) => r === "A4").length).toBe(1); // === 3 guard: tam bir kez

    // B2 açılır → drene, marker silinir, obje B2'ye yazılır.
    b2Mode = "ok";
    const remaining = await drainEscrowPushes(storage as unknown as DurableObjectStorage, TEST_ESCROW, null, alert);
    expect(remaining).toBe(0);
    expect(storage.map.size).toBe(0);
    expect(b2Puts.some((p) => p.includes("audit/segments/1.json"))).toBe(true);
  });

  it("no config → items stay pending (cannot drain), no throw", async () => {
    const storage = new FakeStorage();
    await enqueueEscrowPushes(storage as unknown as DurableObjectStorage, [{ b2Key: "audit/segments/2.json", bodyB64: btoa("x"), contentType: "application/json" }]);
    const remaining = await drainEscrowPushes(storage as unknown as DurableObjectStorage, null, null, async () => {});
    expect(remaining).toBe(1);
    expect(storage.map.size).toBe(1);
  });
});

// FakeStorage, drainEscrowPushes'un kullandığı DurableObjectStorage alt kümesinin
// bellek-içi taklidir (list/get/put/delete/setAlarm/getAlarm).
class FakeStorage {
  map = new Map<string, unknown>();
  alarmAt: number | null = null;
  async list<T>(opts?: { prefix?: string }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const [k, v] of this.map) if (!opts?.prefix || k.startsWith(opts.prefix)) out.set(k, v as T);
    return out;
  }
  async get<T>(k: string): Promise<T | undefined> {
    return this.map.get(k) as T | undefined;
  }
  async put(k: string, v: unknown): Promise<void> {
    this.map.set(k, v);
  }
  async delete(k: string): Promise<boolean> {
    return this.map.delete(k);
  }
  async setAlarm(t: number): Promise<void> {
    this.alarmAt = t;
  }
  async getAlarm(): Promise<number | null> {
    return this.alarmAt;
  }
}
