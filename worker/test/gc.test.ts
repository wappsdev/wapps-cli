// GC cron testleri (KEPT, v2). runGC saf çekirdeği miniflare R2'ye karşı sürülür;
// escrowHas/now/enabledAt/audit/alert ENJEKTE edilir. Kanıtlar: (1) ilk 30 gün
// DRY-RUN, (2) B2-replika koşulu (c) — escrowHas false ise silme YOK, (3)
// enabledAt bilinmiyorsa fail-safe report-only, (4) manifest'ler + referanslı
// blob'lar korunur. v2 delta: witness gate SİLİNDİ; manifest'ler v2 formatında
// gerçek yazma yolundan üretilir.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
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
import { runGC, GCDeps } from "../src/gc.js";
import { keyBlob, keyManifest } from "../src/storage.js";
import { sha256Hex } from "../src/crypto/encoding.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy(defaultRules());
  groupsByEmail.set("writer@wapps.dev", ["developers@wapps.co"]);
});

// seedProject: gerçek yazma yoluyla epoch-1 manifest (referanslı blob R) + R2'ye
// elle eklenmiş referanssız blob U (GC adayı).
async function seedProject(): Promise<{ refHash: string; orphanHash: string }> {
  const jwt = await signer.makeJWT(validClaims("writer@wapps.dev"));
  const res = await callGate("/v1/projects/vaulter/keys/DATABASE_URL", { method: "PUT", headers: authHeader(jwt), body: JSON.stringify({ value: "seed" }) });
  if (res.status !== 200) throw new Error(`seed write failed: ${res.status}`);
  const man = JSON.parse(await (await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1)))!.text()) as { entries: { blobHash: string }[] };
  const refHash = man.entries[0].blobHash;
  const orphanBytes = new Uint8Array(256 + 44).fill(2);
  const orphanHash = sha256Hex(orphanBytes);
  await env.SECRETS_BUCKET.put(keyBlob("vaulter", orphanHash), orphanBytes);
  return { refHash, orphanHash };
}

function baseDeps(overrides: Partial<GCDeps>): GCDeps {
  const alerts: { rule: string; summary: string }[] = [];
  const deletes: { project: string; sha: string }[] = [];
  const deps: GCDeps = {
    now: new Date(Date.now() + 100 * 24 * 3600 * 1000), // +100 gün → seed blob'lar >90d
    enabledAt: new Date(Date.now() - 200 * 24 * 3600 * 1000), // DRY-RUN penceresi bitmiş
    escrowHas: async () => true,
    auditDelete: async (project, sha) => {
      deletes.push({ project, sha });
    },
    alert: (rule, summary) => alerts.push({ rule, summary }),
    ...overrides,
  };
  (deps as unknown as { _alerts: typeof alerts })._alerts = alerts;
  (deps as unknown as { _deletes: typeof deletes })._deletes = deletes;
  return deps;
}

describe("GC cron (KEPT, v2)", () => {
  it("DRY-RUN (first 30 days): reports candidates but deletes NOTHING (A8 informational)", async () => {
    const { orphanHash } = await seedProject();
    const deps = baseDeps({ enabledAt: new Date(Date.now() + 100 * 24 * 3600 * 1000 - 5 * 24 * 3600 * 1000) }); // pencere içinde
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.skipped).toBe(false);
    expect(report.dryRun).toBe(true);
    expect(report.candidates.some((c) => c.sha === orphanHash)).toBe(true);
    expect(report.deleted.length).toBe(0);
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
    const alerts = (deps as unknown as { _alerts: { rule: string; summary: string }[] })._alerts;
    expect(alerts.some((a) => a.rule === "A8" && a.summary.includes("dry-run"))).toBe(true);
  });

  it("FAIL-SAFE: enabledAt=null (GC_ENABLED_AT unset) → report-only + alert", async () => {
    const { orphanHash } = await seedProject();
    const deps = baseDeps({ enabledAt: null });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.dryRun).toBe(true);
    expect(report.deleted.length).toBe(0);
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
    const alerts = (deps as unknown as { _alerts: { rule: string; summary: string }[] })._alerts;
    expect(alerts.some((a) => a.rule === "A8" && a.summary.includes("GC_ENABLED_AT unset"))).toBe(true);
  });

  it("condition (c): unreferenced + >90d but NOT in the B2 replica → NOT deleted", async () => {
    const { orphanHash } = await seedProject();
    const deps = baseDeps({ escrowHas: async () => false });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.dryRun).toBe(false);
    expect(report.candidates.length).toBe(0);
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
  });

  it("real run: deletes ONLY the unreferenced+old+replica-confirmed blob; keeps referenced blob + manifests", async () => {
    const { refHash, orphanHash } = await seedProject();
    const deps = baseDeps({ escrowHas: async (_p, sha) => sha === orphanHash });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.dryRun).toBe(false);
    expect(report.deleted).toEqual([{ project: "vaulter", sha: orphanHash }]);
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).toBeNull();
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", refHash))).not.toBeNull();
    expect(await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1))).not.toBeNull(); // manifest'ler sonsuza kadar
    const deletes = (deps as unknown as { _deletes: { sha: string }[] })._deletes;
    expect(deletes).toEqual([{ project: "vaulter", sha: orphanHash }]); // gc.delete audit satırı
  });

  it("fresh blobs (≤90d) are never candidates", async () => {
    const { orphanHash } = await seedProject();
    const deps = baseDeps({ now: new Date() }); // blob'lar taze
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.candidates.length).toBe(0);
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
  });
});
