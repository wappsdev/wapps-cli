// GC cron (SPEC §6.7). Haftalık Worker cron (pinli `0 3 * * 0` UTC). Bir
// ciphertext blob'u YALNIZCA ÜÇ koşul birden tutunca silinir:
//   (a) projenin son 50 epoch'unun HİÇBİR manifest'i tarafından referanslanmıyor, VE
//   (b) 90 GÜNDEN eski, VE
//   (c) DOĞRULANMIŞ bir escrow snapshot'ında bulunuyor — silmeden ÖNCE non-CF
//       witness origin'inden (§9.3 B2 witness bucket) VM verifier raporu çekilir;
//       rapor erişilemez / bayat (>2h) / FAILING ise TÜM run atlanır ve A6 tetiklenir.
//       Worker escrow durumuna KENDİ tanıklığıyla ASLA silme yapmaz.
//
// Ek kurallar (§6.7): manifest'ler SONSUZA kadar tutulur; audit ledger ASLA
// GC'lenmez (bu modül yalnızca `secrets/<project>/blobs/` dokunur). İlk 30 GÜN
// DRY-RUN: yalnızca RAPOR (A6 informational), silme YOK. Her silme bir audit
// satırı yazar (verb `gc.delete`, principal `worker`).

import { getObject, keyCurrent, keyManifest, keyBlob } from "./storage.js";
import { parseCurrentPointer, parseManifestBody } from "./manifest.js";
import { parseSignedObject } from "./crypto/verify.js";

const RETENTION_MS = 90 * 24 * 3600 * 1000; // 90 gün (b)
const DRYRUN_MS = 30 * 24 * 3600 * 1000; // ilk 30 gün DRY-RUN
const WITNESS_STALE_MS = 2 * 3600 * 1000; // 2 saat (c)
const LAST_EPOCHS = 50; // (a)

/** GCWitnessReport, VM verifier'ın non-CF witness origin'inden çekilen özeti. */
export interface GCWitnessReport {
  reachable: boolean; // origin'e ulaşıldı mı
  failing: boolean; // verifier bir doğrulama HATASI raporladı mı
  ageMs: number; // en son başarılı doğrulamanın yaşı (staleness)
}

/** GCDeps, GC'nin enjekte edilebilir dış kenarlarıdır (tam test-edilebilir). */
export interface GCDeps {
  now: Date;
  // enabledAt, GC'nin etkinleştirildiği an (GC_ENABLED_AT). null (unset/blank) →
  // etkinleşme tarihi BİLİNMİYOR → fail-safe: report-only (dry-run) + A6, ASLA
  // gerçek silme. Bilinen tarih ise ilk 30 gün DRY-RUN, sonrası gerçek silme.
  enabledAt: Date | null;
  // witness, VM verifier raporunu non-CF witness origin'inden çeker (§9.3).
  witness: () => Promise<GCWitnessReport>;
  // escrowHas, blob'un DOĞRULANMIŞ escrow snapshot'ında bulunduğunu teyit eder (c).
  escrowHas: (project: string, sha: string) => Promise<boolean>;
  // auditDelete, `gc.delete` audit satırı yazar (principal worker).
  auditDelete: (project: string, sha: string) => Promise<void>;
  // alert, A6 (§6.10) tetikler (best-effort).
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
 * blob hash kümesini döner (§6.7 koşul a). current pointer yoksa boş küme.
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
    const signed = parseSignedObject(JSON.parse(new TextDecoder().decode(man.bytes)));
    const body = parseManifestBody(signed.bytes);
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
 * runGC, GC cron'un saf çekirdeğidir (§6.7). projects = taranacak projeler.
 * Witness raporu erişilemez/bayat/failing ise TÜM run atlanır (A6). Aksi halde
 * her proje için (a)∧(b)∧(c) tutan blob'lar aday; ilk 30 gün DRY-RUN (sadece
 * A6 informational rapor), sonra gerçek silme + `gc.delete` audit satırı.
 */
export async function runGC(bucket: R2Bucket, projects: string[], deps: GCDeps): Promise<GCReport> {
  const report: GCReport = { skipped: false, dryRun: false, candidates: [], deleted: [] };

  // (c) — silmeden ÖNCE escrow doğrulama durumu. Worker KENDİ tanıklığıyla silmez.
  let w: GCWitnessReport;
  try {
    w = await deps.witness();
  } catch {
    w = { reachable: false, failing: false, ageMs: Infinity };
  }
  if (!w.reachable || w.failing || w.ageMs > WITNESS_STALE_MS) {
    report.skipped = true;
    report.reason = !w.reachable ? "witness_unreachable" : w.failing ? "witness_failing" : "witness_stale";
    deps.alert("A6", `GC run skipped: ${report.reason}`, { ageMs: w.ageMs });
    return report;
  }

  // DRY-RUN penceresi (§6.7 / D9): ilk 30 gün SADECE-RAPOR, silme YOK. enabledAt
  // BİLİNMİYORSA (GC_ENABLED_AT unset/blank → null) etkinleşme tarihi belirsizdir →
  // GÜVENLİ TARAF: "az önce etkinleşti" say (report-only), ASLA "pencere geçti"
  // DEĞİL. Aksi halde B2+WITNESS_ORIGIN bağlanıp GC_ENABLED_AT unutulursa İLK canlı
  // GC koşusu 30 günlük güvenlik penceresini atlayıp blob'ları ANINDA silerdi.
  let dryRun: boolean;
  if (deps.enabledAt === null) {
    dryRun = true;
    deps.alert(
      "A6",
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
      // (c) doğrulanmış escrow snapshot'ında mevcut.
      if (!(await deps.escrowHas(project, b.sha))) continue;
      report.candidates.push({ project, sha: b.sha });
    }
  }

  if (dryRun) {
    // İlk 30 gün: sadece rapor et (A6 informational), HİÇBİR ŞEY silme.
    deps.alert("A6", `GC dry-run: ${report.candidates.length} blob(s) would be deleted`, { count: report.candidates.length });
    return report;
  }

  for (const c of report.candidates) {
    try {
      await bucket.delete(keyBlob(c.project, c.sha));
      await deps.auditDelete(c.project, c.sha);
      report.deleted.push(c);
    } catch (err) {
      deps.alert("A6", `GC delete failed for ${c.project}/${c.sha}`, { error: String(err) });
    }
  }
  return report;
}
