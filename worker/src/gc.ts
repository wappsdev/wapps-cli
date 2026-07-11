// GC cron (SPEC §0.1 KEPT). Haftalık Worker cron (pinli `0 3 * * 0` UTC). Bir
// ciphertext blob'u YALNIZCA ÜÇ koşul birden tutunca silinir:
//   (a) projenin son 50 epoch'unun HİÇBİR manifest'i tarafından referanslanmıyor, VE
//   (b) 90 GÜNDEN eski, VE
//   (c) B2 replikasında MEVCUT olduğu teyit edilmiş (escrowHas — append-only key
//       okuyabilir; teyit edilemeyen blob SİLİNMEZ, güvenli taraf).
// v2 delta: ZK tasarımın VM-witness gate'i SİLİNDİ (§0.2) — koşul (c) doğrudan
// B2 HEAD teyididir; GC anomalileri A8 (misconfig/anomali) olarak alarmlanır.
//
// Ek kurallar: manifest'ler SONSUZA kadar tutulur; audit ledger ASLA GC'lenmez
// (bu modül yalnızca `secrets/<project>/blobs/` dokunur). İlk 30 GÜN DRY-RUN.
// Her silme bir audit satırı yazar (verb `gc.delete`, principal `worker`).

import { getObject, keyCurrent, keyManifest, keyBlob } from "./storage.js";
import { parseCurrentPointer, parseManifest } from "./manifest.js";

const RETENTION_MS = 90 * 24 * 3600 * 1000; // 90 gün (b)
const DRYRUN_MS = 30 * 24 * 3600 * 1000; // ilk 30 gün DRY-RUN
const LAST_EPOCHS = 50; // (a)

/** GCDeps, GC'nin enjekte edilebilir dış kenarlarıdır (tam test-edilebilir). */
export interface GCDeps {
  now: Date;
  // enabledAt, GC'nin etkinleştirildiği an (GC_ENABLED_AT). null (unset/blank) →
  // fail-safe: report-only (dry-run), ASLA gerçek silme.
  enabledAt: Date | null;
  // escrowHas, blob'un B2 replikasında bulunduğunu teyit eder (c).
  escrowHas: (project: string, sha: string) => Promise<boolean>;
  // auditDelete, `gc.delete` audit satırı yazar (principal worker).
  auditDelete: (project: string, sha: string) => Promise<void>;
  // alert, A8 (misconfig/anomali) tetikler (best-effort).
  alert: (rule: string, summary: string, detail?: Record<string, unknown>) => void;
}

/** GCReport, bir GC run'ının makine-okunur sonucu. */
export interface GCReport {
  skipped: boolean;
  reason?: string;
  dryRun: boolean;
  candidates: { project: string; sha: string }[];
  deleted: { project: string; sha: string }[];
}

/**
 * referencedBlobs, projenin SON 50 epoch'undaki tüm manifest'lerin referansladığı
 * blob hash kümesini döner (koşul a). current pointer yoksa boş küme.
 */
async function referencedBlobs(bucket: R2Bucket, project: string): Promise<Set<string>> {
  const refs = new Set<string>();
  const cur = await getObject(bucket, keyCurrent(project));
  if (!cur) return refs;
  const ptr = parseCurrentPointer(cur.bytes);
  const lo = Math.max(1, ptr.epoch - (LAST_EPOCHS - 1));
  for (let e = lo; e <= ptr.epoch; e++) {
    const man = await getObject(bucket, keyManifest(project, e));
    if (!man) continue;
    const body = parseManifest(man.bytes);
    for (const entry of body.entries) refs.add(entry.blobHash);
  }
  return refs;
}

/** listBlobs, projenin tüm ciphertext blob'larını {sha, uploaded} olarak döner. */
async function listBlobs(bucket: R2Bucket, project: string): Promise<{ sha: string; uploaded: Date }[]> {
  const prefix = keyBlob(project, "");
  const out: { sha: string; uploaded: Date }[] = [];
  let cursor: string | undefined;
  do {
    const l = await bucket.list({ prefix, cursor });
    for (const o of l.objects) {
      const sha = o.key.slice(prefix.length);
      if (sha) out.push({ sha, uploaded: o.uploaded });
    }
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  return out;
}

/**
 * runGC, GC cron'un saf çekirdeğidir. projects = taranacak projeler. Her proje
 * için (a)∧(b)∧(c) tutan blob'lar aday; ilk 30 gün DRY-RUN (rapor, silme yok),
 * sonra gerçek silme + `gc.delete` audit satırı.
 */
export async function runGC(bucket: R2Bucket, projects: string[], deps: GCDeps): Promise<GCReport> {
  const report: GCReport = { skipped: false, dryRun: false, candidates: [], deleted: [] };

  // DRY-RUN penceresi: ilk 30 gün SADECE-RAPOR. enabledAt BİLİNMİYORSA güvenli
  // taraf: report-only + alert (aksi halde GC_ENABLED_AT unutulunca ilk canlı
  // koşu 30 günlük pencereyi atlayıp blob'ları ANINDA silerdi).
  let dryRun: boolean;
  if (deps.enabledAt === null) {
    dryRun = true;
    deps.alert(
      "A8",
      "GC report-only: GC_ENABLED_AT unset — refusing live deletion until the 30-day window start is known (set GC_ENABLED_AT or skip the run)",
    );
  } else {
    dryRun = deps.now.getTime() - deps.enabledAt.getTime() < DRYRUN_MS;
  }
  report.dryRun = dryRun;

  for (const project of projects) {
    const refs = await referencedBlobs(bucket, project);
    const blobs = await listBlobs(bucket, project);
    for (const b of blobs) {
      // (a) son-50 epoch'ta referanssız.
      if (refs.has(b.sha)) continue;
      // (b) 90 günden eski.
      if (deps.now.getTime() - b.uploaded.getTime() <= RETENTION_MS) continue;
      // (c) B2 replikasında mevcut (teyit edilemedi → silme, güvenli taraf).
      let inReplica = false;
      try {
        inReplica = await deps.escrowHas(project, b.sha);
      } catch {
        inReplica = false;
      }
      if (!inReplica) continue;
      report.candidates.push({ project, sha: b.sha });
    }
  }

  if (dryRun) {
    // İlk 30 gün: sadece rapor et (informational), HİÇBİR ŞEY silme.
    deps.alert("A8", `GC dry-run: ${report.candidates.length} blob(s) would be deleted`, { count: report.candidates.length });
    return report;
  }

  for (const c of report.candidates) {
    try {
      await bucket.delete(keyBlob(c.project, c.sha));
      await deps.auditDelete(c.project, c.sha);
      report.deleted.push(c);
    } catch (err) {
      deps.alert("A8", `GC delete failed for ${c.project}/${c.sha}`, { error: String(err) });
    }
  }
  return report;
}
