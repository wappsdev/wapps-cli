// E-M2 (security review 2026-11-19): a fault between the manifest PUT and the
// pointer CAS left epoch N+1 written while the pointer stayed at N, and every later
// write failed EPOCH_CONFLICT forever, so a leaked credential could be neither
// rotated nor deleted. The writer now records a commit intent in DO storage before
// the manifest PUT; the next commit and alarm() roll it forward (finish the CAS
// when the written manifest is the intended one) or discard it.
//
// L3: the project purge runs inside the writer DO, under the same lock, and drops
// a pending intent first, so a purged store is never rolled forward again.

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env, runDurableObjectAlarm } from "cloudflare:test";
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
  settleAudit,
  runInDoRetry,
  ADMIN_EMAIL,
} from "./helpers.js";
import { keyCurrent, keyManifest } from "../src/storage.js";
import { manifestObjectHash, parseCurrentPointer, parseManifest } from "../src/manifest.js";

const STORE = "vaulter";
const INTENT_KEY = "commit-intent";

function writerStub(): DurableObjectStub {
  return env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(STORE));
}

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await runInDoRetry(writerStub(), (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
  groupsByEmail.set(ADMIN_EMAIL, []);
});
afterEach(async () => {
  await runInDoRetry(writerStub(), async (_i: unknown, state: DurableObjectState) => {
    await state.storage.deleteAll();
    await state.storage.deleteAlarm();
  });
});

async function putKey(key: string, value: string): Promise<Response> {
  return callGate(`/v1/projects/${STORE}/keys/${key}`, {
    method: "PUT",
    headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))),
    body: JSON.stringify({ value }),
  });
}

async function readValues(keys: string[]): Promise<Record<string, string>> {
  const res = await callGate(`/v1/projects/${STORE}/read`, {
    method: "POST",
    headers: authHeader(await signer.makeJWT(validClaims("writer@wapps.dev"))),
    body: JSON.stringify({ keys }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { values: Record<string, string> }).values;
}

/** faultyBucket delegates to the real bucket, but its first put of `failKey`
 * throws: the stand-in for a crash or an R2 error at that exact step. */
function faultyBucket(real: R2Bucket, failKey: string): R2Bucket {
  let armed = true;
  return {
    get: (k: string, o?: R2GetOptions) => real.get(k, o),
    head: (k: string) => real.head(k),
    list: (o?: R2ListOptions) => real.list(o),
    delete: (k: string | string[]) => real.delete(k),
    put: (k: string, v: Parameters<R2Bucket["put"]>[1], o?: R2PutOptions) => {
      if (armed && k === failKey) {
        armed = false;
        return Promise.reject(new Error(`injected fault: put ${k}`));
      }
      return real.put(k, v, o);
    },
  } as unknown as R2Bucket;
}

/**
 * faultedSet runs one `set` commit in the writer DO with a fault on the put of
 * `failKey`, and checks that the commit failed on that fault. It calls the commit
 * directly (the lock around it is the caller's), so the DO instance is not reset
 * by the throw and the real bucket is put back afterwards.
 */
async function faultedSet(failKey: string, key: string, value: string): Promise<void> {
  const seen = await runInDoRetry(writerStub(), async (instance: unknown) => {
    const w = instance as { bucket: R2Bucket; commit(project: string, meta: unknown, op: unknown): Promise<Response> };
    const real = w.bucket;
    w.bucket = faultyBucket(real, failKey);
    try {
      const meta = {
        principalId: "human:writer@wapps.dev",
        principalType: "human",
        tokenJti: null,
        intent: null,
        auditVerb: "key.set",
        policyVersion: 1,
        ip: null,
        cfRay: null,
      };
      await w.commit(STORE, meta, { op: "set", values: { [key]: value } });
      return "no fault";
    } catch (e) {
      return String(e);
    } finally {
      w.bucket = real;
    }
  });
  expect(seen).toContain("injected fault");
}

async function pointer(): Promise<{ epoch: number; manifestSha256: string } | null> {
  const o = await env.SECRETS_BUCKET.get(keyCurrent(STORE));
  return o ? parseCurrentPointer(new Uint8Array(await o.arrayBuffer())) : null;
}

/** assertConsistent: the pointer names a manifest whose bytes hash to the pointer's
 * hash, and each manifest links to the one before it. */
async function assertConsistent(): Promise<number> {
  const p = await pointer();
  expect(p).not.toBeNull();
  let prevSha = "";
  for (let e = 1; e <= p!.epoch; e++) {
    const o = await env.SECRETS_BUCKET.get(keyManifest(STORE, e));
    expect(o).not.toBeNull();
    const bytes = new Uint8Array(await o!.arrayBuffer());
    expect(parseManifest(bytes).prevManifestSha256).toBe(prevSha);
    prevSha = manifestObjectHash(bytes);
  }
  expect(prevSha).toBe(p!.manifestSha256);
  return p!.epoch;
}

async function intentLeft(): Promise<unknown> {
  return runInDoRetry(writerStub(), (_i: unknown, state: DurableObjectState) => state.storage.get(INTENT_KEY));
}

describe("E-M2: a fault between the manifest PUT and the pointer CAS", () => {
  it("leaves a commit intent that the next write rolls forward; the store stays consistent", async () => {
    expect((await putKey("API_TOKEN", "value-1")).status).toBe(200);

    await faultedSet(keyCurrent(STORE), "API_TOKEN", "value-2");
    // The fault hit where the finding says: manifest 2 written, pointer still at 1.
    expect(await env.SECRETS_BUCKET.head(keyManifest(STORE, 2))).not.toBeNull();
    expect((await pointer())!.epoch).toBe(1);
    expect(await intentLeft()).toBeDefined();

    // The next write is not wedged: it first finishes epoch 2, then commits epoch 3.
    const next = await putKey("OTHER_KEY", "value-3");
    expect(next.status).toBe(200);
    expect(((await next.json()) as { epoch: number }).epoch).toBe(3);
    expect(await assertConsistent()).toBe(3);
    expect(await readValues(["API_TOKEN", "OTHER_KEY"])).toEqual({ API_TOKEN: "value-2", OTHER_KEY: "value-3" });
    expect(await intentLeft()).toBeUndefined();

    // The rolled-forward commit still has its outcome row (the rotate-plan oracle).
    const tokenSets = (r: { verb: string; decision: string; key: string | null }[]) => r.filter((x) => x.verb === "key.set" && x.decision === "allow" && x.key === "API_TOKEN").length;
    const rows = await settleAudit(STORE, (r) => tokenSets(r) >= 2);
    expect(tokenSets(rows)).toBe(2);
  });

  it("alarm() alone repairs it: the fault schedules the alarm, and the alarm finishes the CAS", async () => {
    expect((await putKey("API_TOKEN", "value-1")).status).toBe(200);
    await faultedSet(keyCurrent(STORE), "API_TOKEN", "value-2");
    expect((await pointer())!.epoch).toBe(1);

    expect(await runDurableObjectAlarm(writerStub())).toBe(true);
    expect(await assertConsistent()).toBe(2);
    expect(await readValues(["API_TOKEN"])).toEqual({ API_TOKEN: "value-2" });
    expect(await intentLeft()).toBeUndefined();
  });

  it("a genesis commit faulted before its pointer exists is rolled forward too", async () => {
    await faultedSet(keyCurrent(STORE), "API_TOKEN", "value-1");
    expect(await pointer()).toBeNull();

    expect(await runDurableObjectAlarm(writerStub())).toBe(true);
    expect(await assertConsistent()).toBe(1);
    expect(await readValues(["API_TOKEN"])).toEqual({ API_TOKEN: "value-1" });
  });

  it("an intent whose manifest never landed is discarded; the next write takes the same epoch", async () => {
    expect((await putKey("API_TOKEN", "value-1")).status).toBe(200);
    await faultedSet(keyManifest(STORE, 2), "API_TOKEN", "value-2");
    expect(await env.SECRETS_BUCKET.head(keyManifest(STORE, 2))).toBeNull();

    const next = await putKey("OTHER_KEY", "value-3");
    expect(next.status).toBe(200);
    expect(((await next.json()) as { epoch: number }).epoch).toBe(2);
    expect(await assertConsistent()).toBe(2);
    expect(await readValues(["API_TOKEN", "OTHER_KEY"])).toEqual({ API_TOKEN: "value-1", OTHER_KEY: "value-3" });
    expect(await intentLeft()).toBeUndefined();
  });

  it("a successful commit leaves no intent behind", async () => {
    expect((await putKey("API_TOKEN", "value-1")).status).toBe(200);
    expect(await intentLeft()).toBeUndefined();
  });
});

describe("L3: the project purge runs in the writer DO", () => {
  it("drops a pending commit intent, so the purged store is not rolled forward again", async () => {
    expect((await putKey("API_TOKEN", "value-1")).status).toBe(200);
    await faultedSet(keyCurrent(STORE), "API_TOKEN", "value-2");
    expect(await intentLeft()).toBeDefined();

    const res = await callGate(`/v1/admin/projects/${STORE}`, {
      method: "DELETE",
      headers: authHeader(await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL))),
      body: JSON.stringify({ confirm: STORE }),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { deleted_objects: number }).deleted_objects).toBeGreaterThan(0);
    expect(await intentLeft()).toBeUndefined();

    await runDurableObjectAlarm(writerStub());
    expect(await pointer()).toBeNull();
    const left = await env.SECRETS_BUCKET.list({ prefix: `secrets/${STORE}/` });
    expect(left.objects).toEqual([]);

    // A new write starts the store again at epoch 1.
    const again = await putKey("API_TOKEN", "value-3");
    expect(again.status).toBe(200);
    expect(((await again.json()) as { epoch: number }).epoch).toBe(1);
  });
});
