// Escrow write-through fail-soft testleri (SPEC §8.3 — KEPT, ciphertext-only
// replika). MOCK S3 (fetchMock) ile kanıtlar: (1) B2 push HATASI kalıcı commit'i
// DÜŞÜREMEZ (write path'te B2 YOK), (2) alarm() bekleyen push'ları drene eder
// (MUTABLE current ASLA push edilmez — yalnızca pointer EVENT), (3) retry: 3
// başarısız denemeden sonra alert A4 (deterministik birim testi).

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env, fetchMock, runInDurableObject, runDurableObjectAlarm } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  groupsByEmail,
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
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  b2Mode = "ok";
  b2Puts.length = 0;
});

function writerStub() {
  return env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
}
// doRetry: DO-harness çağrılarını transient invalidation'a karşı geniş bütçeyle dener.
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

// setEscrow, escrow config'i DO STORAGE'a yazar — instance-recreation'a dayanıklı
// test seam'i; commit/alarm effectiveEscrow() ile storage'dan okur.
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
});

async function putKey(key: string, value: string): Promise<Response> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  return callGate(`/v1/projects/vaulter/keys/${key}`, { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value }) });
}

describe("escrow write-through — fail-soft B2 push (§8.3)", () => {
  it("FAIL-SOFT: B2 unavailable → write STILL 200, escrow pushes enqueued, B2 untouched on the write path", async () => {
    await setEscrow(TEST_ESCROW);
    b2Mode = "fail";
    const res = await putKey("DATABASE_URL", "v");
    expect(res.status).toBe(200); // commit KALICI — B2 write path'te değil

    const man = JSON.parse(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1)))!.text()) as { entries: { blobHash: string }[] };
    const blobHash = man.entries[0].blobHash;
    const pendingKeys = [
      "pending-escrow-push:" + keyManifest("vaulter", 1),
      "pending-escrow-push:" + keyPointerEvent("vaulter", 1),
      "pending-escrow-push:" + keyBlob("vaulter", blobHash),
    ];
    const enq = await readMarkers(pendingKeys);
    for (const k of pendingKeys) expect(enq[k], `marker ${k} enqueued`).toBeTruthy();
    expect(b2Puts.length, "B2 not contacted on the write path").toBe(0);
  });

  it("DRAIN: enqueued escrow pushes drained by the alarm; MUTABLE current NEVER pushed", async () => {
    await setEscrow(TEST_ESCROW);
    b2Mode = "ok";
    expect((await putKey("DATABASE_URL", "v")).status).toBe(200);
    const man = JSON.parse(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1)))!.text()) as { entries: { blobHash: string }[] };
    const blobHash = man.entries[0].blobHash;

    await alarmOnce();
    const pendingKeys = [
      "pending-escrow-push:" + keyManifest("vaulter", 1),
      "pending-escrow-push:" + keyPointerEvent("vaulter", 1),
      "pending-escrow-push:" + keyBlob("vaulter", blobHash),
    ];
    const drained = await readMarkers(pendingKeys);
    for (const k of pendingKeys) expect(drained[k], `marker ${k} drained`).toBeUndefined();
    expect(b2Puts.some((p) => p.includes(keyManifest("vaulter", 1)))).toBe(true);
    expect(b2Puts.some((p) => p.includes(keyPointerEvent("vaulter", 1)))).toBe(true);
    expect(b2Puts.some((p) => p.includes(keyBlob("vaulter", blobHash)))).toBe(true);
    expect(b2Puts.some((p) => p.endsWith("/current"))).toBe(false); // mutable current ASLA
  });

  it("escrow disabled (no B2 config) → write 200, NO escrow markers", async () => {
    await setEscrow(null);
    expect((await putKey("API_KEY", "v")).status).toBe(200);
    const markers = await inDO((_i, state) => state.storage.list({ prefix: "pending-escrow-push:" }));
    expect(markers.size).toBe(0);
  });
});

// --- drainEscrowPushes birim testi (deterministik, DO harness'sız) ---------------
describe("drainEscrowPushes — retry + A4 (§8.3)", () => {
  it("push fails → attempts increment; 3rd attempt → A4 (once); B2 recovers → drains", async () => {
    const storage = new FakeStorage();
    const items: EscrowPushItem[] = [{ b2Key: "audit/segments/1.json", bodyB64: btoa(JSON.stringify({ seq: 1 })), contentType: "application/json" }];
    await enqueueEscrowPushes(storage as unknown as DurableObjectStorage, items);
    expect(storage.map.size).toBe(1);
    expect(storage.alarmAt).not.toBeNull();

    const alerts: string[] = [];
    const alert: EscrowAlert = async (rule) => {
      alerts.push(rule);
    };

    b2Mode = "fail";
    for (let i = 1; i <= 3; i++) {
      const remaining = await drainEscrowPushes(storage as unknown as DurableObjectStorage, TEST_ESCROW, null, alert);
      expect(remaining).toBe(1);
      const rec = storage.map.get("pending-escrow-push:audit/segments/1.json") as { attempts: number };
      expect(rec.attempts).toBe(i);
    }
    expect(alerts.filter((r) => r === "A4").length).toBe(1);

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

// FakeStorage, drainEscrowPushes'un kullandığı DurableObjectStorage alt kümesinin taklidi.
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
