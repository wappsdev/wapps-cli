// GC cron testleri (SPEC §6.7). runGC saf çekirdeği miniflare R2'ye karşı sürülür;
// witness/escrowHas/now/enabledAt/audit/alert ENJEKTE edilir. Kanıtlar: (1) ilk 30
// gün DRY-RUN (rapor, silme YOK), (2) escrow-doğrulanmış koşul (c) — escrowHas
// false ise (a)+(b) tutsa bile silme YOK, (3) witness bayat/failing/unreachable →
// TÜM run atlanır (A6), (4) audit ASLA GC'lenmez, manifest'ler korunur.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { seedTrust, ensureJwks, signDataManifest, seedManifestObject, putBlob, resetWorld, TrustContext } from "./helpers.js";
import { runGC, GCDeps, GCWitnessReport } from "../src/gc.js";
import { keyBlob, keyManifest } from "../src/storage.js";

beforeAll(async () => {
  await ensureJwks();
});
beforeEach(resetWorld);

function fullWraps(t: TrustContext): { recipient: string; wrap: string }[] {
  return [
    { recipient: t.writerDevice, wrap: "a" },
    { recipient: t.writerBackup, wrap: "b" },
    { recipient: t.escrowFp, wrap: "c" },
  ];
}

// seedProject: epoch-1 manifest (referenced blob R) + ekstra referanssız blob U.
async function seedProject(t: TrustContext): Promise<{ refHash: string; orphanHash: string }> {
  const refBlob = new Uint8Array(256 + 44).fill(1);
  const refHash = await putBlob("vaulter", refBlob);
  const w = signDataManifest(
    { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: "DATABASE_URL", keyVersion: 1, blobHash: refHash, wraps: fullWraps(t) }] },
    t.writer,
  );
  await seedManifestObject("vaulter", 1, w);
  // Hiçbir manifest'in referanslamadığı eski blob (GC adayı).
  const orphanBlob = new Uint8Array(256 + 44).fill(2);
  const orphanHash = await putBlob("vaulter", orphanBlob);
  return { refHash, orphanHash };
}

const freshOk: GCWitnessReport = { reachable: true, failing: false, ageMs: 60_000 };

function baseDeps(overrides: Partial<GCDeps>): GCDeps {
  const alerts: { rule: string; summary: string }[] = [];
  const deletes: { project: string; sha: string }[] = [];
  const deps: GCDeps = {
    now: new Date(Date.now() + 100 * 24 * 3600 * 1000), // +100 gün → seed blob'lar >90d
    enabledAt: new Date(Date.now() - 200 * 24 * 3600 * 1000), // 200 gün önce → DRY-RUN penceresi bitmiş
    witness: async () => freshOk,
    escrowHas: async () => true,
    auditDelete: async (project, sha) => {
      deletes.push({ project, sha });
    },
    alert: (rule, summary) => alerts.push({ rule, summary }),
    ...overrides,
  };
  // Test'in gözlemlemesi için diziyi deps'e iliştir.
  (deps as unknown as { _alerts: typeof alerts })._alerts = alerts;
  (deps as unknown as { _deletes: typeof deletes })._deletes = deletes;
  return deps;
}

describe("GC cron (§6.7)", () => {
  it("skips the ENTIRE run + fires A6 when witness is stale (>2h)", async () => {
    const t = await seedTrust();
    const { orphanHash } = await seedProject(t);
    const deps = baseDeps({ witness: async () => ({ reachable: true, failing: false, ageMs: 3 * 3600_000 }) });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.skipped).toBe(true);
    expect(report.reason).toBe("witness_stale");
    const alerts = (deps as unknown as { _alerts: { rule: string }[] })._alerts;
    expect(alerts.some((a) => a.rule === "A6")).toBe(true);
    // Hiçbir şey silinmedi.
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
  });

  it("skips + A6 when witness is failing OR unreachable", async () => {
    const t = await seedTrust();
    await seedProject(t);
    for (const w of [{ reachable: true, failing: true, ageMs: 1000 }, { reachable: false, failing: false, ageMs: 1000 }]) {
      const deps = baseDeps({ witness: async () => w });
      const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
      expect(report.skipped).toBe(true);
    }
  });

  it("DRY-RUN (first 30 days): reports candidates but deletes NOTHING (A6 informational)", async () => {
    const t = await seedTrust();
    const { orphanHash } = await seedProject(t);
    const deps = baseDeps({ enabledAt: new Date(Date.now() + 100 * 24 * 3600 * 1000 - 5 * 24 * 3600 * 1000) }); // now-5g → 30g penceresi içinde
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.skipped).toBe(false);
    expect(report.dryRun).toBe(true);
    expect(report.candidates.some((c) => c.sha === orphanHash)).toBe(true);
    expect(report.deleted.length).toBe(0);
    // Blob HÂLÂ var (dry-run silmez).
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
    const alerts = (deps as unknown as { _alerts: { rule: string; summary: string }[] })._alerts;
    expect(alerts.some((a) => a.rule === "A6" && a.summary.includes("dry-run"))).toBe(true);
    const deletes = (deps as unknown as { _deletes: unknown[] })._deletes;
    expect(deletes.length).toBe(0);
  });

  it("FAIL-SAFE: enabledAt=null (GC_ENABLED_AT unset) → report-only, deletes NOTHING + A6", async () => {
    const t = await seedTrust();
    const { orphanHash } = await seedProject(t);
    // enabledAt null: etkinleşme tarihi bilinmiyor → gerçek silmeye ASLA düşme.
    const deps = baseDeps({ enabledAt: null });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.skipped).toBe(false);
    // Aday tespit edilir ama dry-run zorlanır → silme YOK.
    expect(report.dryRun).toBe(true);
    expect(report.candidates.some((c) => c.sha === orphanHash)).toBe(true);
    expect(report.deleted.length).toBe(0);
    // Blob hâlâ var (silinmedi).
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
    // A6 alarmı: operatöre GC_ENABLED_AT'i ayarlamasını söyler.
    const alerts = (deps as unknown as { _alerts: { rule: string; summary: string }[] })._alerts;
    expect(alerts.some((a) => a.rule === "A6" && a.summary.includes("GC_ENABLED_AT unset"))).toBe(true);
    // Hiçbir gc.delete audit satırı yazılmadı.
    const deletes = (deps as unknown as { _deletes: unknown[] })._deletes;
    expect(deletes.length).toBe(0);
  });

  it("condition (c): unreferenced + >90d but escrowHas=FALSE → NOT deleted", async () => {
    const t = await seedTrust();
    const { orphanHash } = await seedProject(t);
    const deps = baseDeps({ escrowHas: async () => false });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.dryRun).toBe(false);
    expect(report.candidates.length).toBe(0); // (c) gate → aday YOK
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).not.toBeNull();
  });

  it("real run: deletes ONLY the unreferenced+old+escrow-verified blob; keeps referenced blob + manifests + audit", async () => {
    const t = await seedTrust();
    const { refHash, orphanHash } = await seedProject(t);
    // escrowHas yalnızca orphan için true → koşul (c) yalnızca onu geçirir.
    const deps = baseDeps({ escrowHas: async (_p, sha) => sha === orphanHash });
    const report = await runGC(env.SECRETS_BUCKET, ["vaulter"], deps);
    expect(report.dryRun).toBe(false);
    expect(report.deleted).toEqual([{ project: "vaulter", sha: orphanHash }]);

    // Orphan silindi, referenced blob + manifest KORUNDU (manifest'ler sonsuza tutulur).
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", orphanHash))).toBeNull();
    expect(await env.SECRETS_BUCKET.get(keyBlob("vaulter", refHash))).not.toBeNull();
    expect(await env.SECRETS_BUCKET.get(keyManifest("vaulter", 1))).not.toBeNull();

    // gc.delete audit satırı yazıldı.
    const deletes = (deps as unknown as { _deletes: { sha: string }[] })._deletes;
    expect(deletes).toEqual([{ project: "vaulter", sha: orphanHash }]);
  });
});
