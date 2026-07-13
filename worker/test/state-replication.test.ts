// tofu state → B2 replikasyonu testleri (arch §5.2, plan P2.1). MOCK S3
// (fetchMock, escrow.test.ts modeli) + FakeR2Bucket ile kanıtlar:
// (1) content-addressed anahtar `tofu-state/<r2key>/<sha256>` + immutable
//     `wapps.state-snapshot.v1` event'i (yalnızca *.tfstate objeleri),
// (2) HEAD-skip: snapshot B2'de zaten varsa PUT YOK (idempotent),
// (3) no-op: B2 config'i veya STATE_BUCKET binding'i yoksa hiçbir çağrı yok,
// (4) fail-soft: obje-başına hata → alert, throw yok, diğer objeler devam.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { fetchMock } from "cloudflare:test";
import { utf8, sha256Hex } from "../src/crypto/encoding.js";
import { EscrowConfig } from "../src/escrow.js";
import {
  runStateReplication,
  keyStateSnapshot,
  keyStateSnapshotEvent,
  StateReplicationEnv,
} from "../src/state-replication.js";

// escrow.test.ts'ten FARKLI host: singleWorker'da fetchMock intercept'leri
// dosyalar arası paylaşılır — çakışmayı önlemek için ayrı endpoint.
const B2_HOST = "https://s3.state-region.backblazeb2.com";
const TEST_CFG: EscrowConfig = {
  endpoint: "s3.state-region.backblazeb2.com",
  region: "state-region",
  bucket: "wapps-secrets-escrow",
  keyId: "0004b2keyid",
  appKey: "K004appkeysecret",
};
const CFG_ENV = {
  B2_ENDPOINT: TEST_CFG.endpoint,
  B2_REGION: TEST_CFG.region,
  B2_BUCKET: TEST_CFG.bucket,
  B2_KEY_ID: TEST_CFG.keyId,
  B2_APP_KEY: TEST_CFG.appKey,
};

// Mock B2 durumu: var olan anahtarlar (HEAD 200) + kaydedilen PUT'lar.
let b2Mode: "ok" | "fail" = "ok";
const b2Existing = new Set<string>();
const b2Puts: { key: string; contentType: string }[] = [];

function stripBucket(path: string): string {
  // path-style: /<bucket>/<key> → <key>
  return decodeURIComponent(path).replace(`/${TEST_CFG.bucket}/`, "");
}

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
  fetchMock
    .get(B2_HOST)
    .intercept({ path: () => true, method: "PUT" })
    .reply((opts: { path?: string; headers?: Headers | Record<string, string> }) => {
      if (b2Mode === "fail") return { statusCode: 500, data: "" };
      const key = stripBucket(String(opts.path ?? ""));
      const h = opts.headers;
      const contentType = h instanceof Headers ? (h.get("content-type") ?? "") : String(h?.["content-type"] ?? "");
      b2Puts.push({ key, contentType });
      b2Existing.add(key);
      return { statusCode: 200, data: "" };
    })
    .persist();
  fetchMock
    .get(B2_HOST)
    .intercept({ path: () => true, method: "HEAD" })
    .reply((opts: { path?: string }) => {
      if (b2Mode === "fail") return { statusCode: 500, data: "" };
      const key = stripBucket(String(opts.path ?? ""));
      return { statusCode: b2Existing.has(key) ? 200 : 404, data: "" };
    })
    .persist();
});

beforeEach(() => {
  b2Mode = "ok";
  b2Existing.clear();
  b2Puts.length = 0;
});

// FakeR2Bucket, runner'ın kullandığı R2Bucket alt kümesinin taklidi (list + get).
// pageSize ile cursor'lı sayfalama da sürülür.
class FakeR2Bucket {
  constructor(
    private objects: Map<string, Uint8Array>,
    private pageSize = 2,
  ) {}
  listCalls = 0;
  async list(opts?: { cursor?: string }): Promise<unknown> {
    this.listCalls++;
    const keys = [...this.objects.keys()].sort();
    const start = opts?.cursor ? Number(opts.cursor) : 0;
    const page = keys.slice(start, start + this.pageSize);
    const truncated = start + this.pageSize < keys.length;
    return {
      objects: page.map((key) => ({ key })),
      truncated,
      cursor: truncated ? String(start + this.pageSize) : undefined,
    };
  }
  async get(key: string): Promise<unknown> {
    const body = this.objects.get(key);
    if (body === undefined) return null;
    return { arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
  }
}

function envWith(bucket: FakeR2Bucket | undefined, cfg = true): StateReplicationEnv {
  return {
    ...(cfg ? CFG_ENV : {}),
    STATE_BUCKET: bucket as unknown as R2Bucket,
  };
}

describe("runStateReplication — tofu state → B2 (§5.2)", () => {
  it("content-addressed snapshot + immutable event; non-tfstate keys skipped; pagination followed", async () => {
    const stateA = utf8('{"version":4,"serial":1}');
    const stateB = utf8('{"version":4,"serial":9}');
    const bucket = new FakeR2Bucket(
      new Map([
        ["projects/vaulter/terraform.tfstate", stateA],
        ["projects/lab/terraform.tfstate", stateB],
        ["projects/vaulter/terraform.tfstate.backup", utf8("x")], // *.tfstate DEĞİL → atlanır
      ]),
      1, // pageSize=1 → 3 sayfa: cursor takibi de kanıtlanır
    );
    const alerts: string[] = [];
    const now = new Date("2026-07-12T02:00:00.000Z");
    await runStateReplication(envWith(bucket), (s) => alerts.push(s), now);

    expect(alerts).toEqual([]);
    expect(bucket.listCalls).toBe(3); // sayfalama sonuna kadar izlendi

    const shaA = sha256Hex(stateA);
    const shaB = sha256Hex(stateB);
    const putKeys = b2Puts.map((p) => p.key);
    expect(putKeys).toContain(keyStateSnapshot("projects/vaulter/terraform.tfstate", shaA));
    expect(putKeys).toContain(keyStateSnapshot("projects/lab/terraform.tfstate", shaB));
    expect(putKeys).toContain(keyStateSnapshotEvent("projects/vaulter/terraform.tfstate", now.toISOString()));
    expect(putKeys).toContain(keyStateSnapshotEvent("projects/lab/terraform.tfstate", now.toISOString()));
    expect(putKeys.length).toBe(4); // .backup için NE snapshot NE event
    expect(putKeys.some((k) => k.includes("tfstate.backup"))).toBe(false);

    // Event gövde sözleşmesi: snapshot PUT'u application/octet-stream, event json.
    const snap = b2Puts.find((p) => p.key === keyStateSnapshot("projects/vaulter/terraform.tfstate", shaA));
    expect(snap?.contentType).toBe("application/octet-stream");
    const ev = b2Puts.find((p) => p.key === keyStateSnapshotEvent("projects/vaulter/terraform.tfstate", now.toISOString()));
    expect(ev?.contentType).toBe("application/json");
  });

  it("HEAD-skip: snapshot already in B2 → NO puts (idempotent re-run)", async () => {
    const state = utf8('{"version":4,"serial":2}');
    const bucket = new FakeR2Bucket(new Map([["projects/vaulter/terraform.tfstate", state]]));
    // Snapshot'ı B2'de "var" işaretle (önceki run'ın çıktısı).
    b2Existing.add(keyStateSnapshot("projects/vaulter/terraform.tfstate", sha256Hex(state)));

    const alerts: string[] = [];
    await runStateReplication(envWith(bucket), (s) => alerts.push(s));

    expect(alerts).toEqual([]);
    expect(b2Puts.length).toBe(0); // ne snapshot ne event — tam skip
  });

  it("changed state → NEW content-addressed key (old key never rewritten)", async () => {
    const v1 = utf8('{"serial":1}');
    const v2 = utf8('{"serial":2}');
    const r2Key = "projects/vaulter/terraform.tfstate";
    // v1 snapshot'ı zaten B2'de; bucket artık v2 içeriyor.
    b2Existing.add(keyStateSnapshot(r2Key, sha256Hex(v1)));
    const bucket = new FakeR2Bucket(new Map([[r2Key, v2]]));

    await runStateReplication(envWith(bucket), () => {});

    const putKeys = b2Puts.map((p) => p.key);
    expect(putKeys).toContain(keyStateSnapshot(r2Key, sha256Hex(v2))); // yeni anahtar
    expect(putKeys).not.toContain(keyStateSnapshot(r2Key, sha256Hex(v1))); // eskisine dokunulmadı
  });

  it("no-op: B2 config missing → no list, no fetch", async () => {
    const bucket = new FakeR2Bucket(new Map([["projects/vaulter/terraform.tfstate", utf8("s")]]));
    const alerts: string[] = [];
    await runStateReplication(envWith(bucket, false), (s) => alerts.push(s));
    expect(alerts).toEqual([]);
    expect(bucket.listCalls).toBe(0);
    expect(b2Puts.length).toBe(0);
  });

  it("no-op: STATE_BUCKET binding missing → silent return", async () => {
    const alerts: string[] = [];
    await runStateReplication(envWith(undefined), (s) => alerts.push(s));
    expect(alerts).toEqual([]);
    expect(b2Puts.length).toBe(0);
  });

  it("fail-soft: B2 down → per-key alert, no throw, all keys attempted", async () => {
    b2Mode = "fail";
    const bucket = new FakeR2Bucket(
      new Map([
        ["projects/vaulter/terraform.tfstate", utf8("a")],
        ["projects/lab/terraform.tfstate", utf8("b")],
      ]),
    );
    const alerts: { summary: string; detail?: Record<string, unknown> }[] = [];
    await runStateReplication(envWith(bucket), (summary, detail) => alerts.push({ summary, detail }));

    expect(alerts.length).toBe(2); // her state için ayrı alert; run devam etti
    expect(alerts.every((a) => a.summary.startsWith("state replication: push failed"))).toBe(true);
    expect(b2Puts.length).toBe(0);
  });
});
