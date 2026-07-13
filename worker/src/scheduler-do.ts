// KESİN scheduler (plan P2.4): cron trigger YERİNE SQLite-backed DO alarm'ı.
// Free-plan schedules API'si cron deploy'unu reddettiği için (d2d171d) §8.3
// pinli zamanlama kümesi (nightly 02:00 UTC audit-head anchor + state
// replication, Pazar 03:00 UTC haftalık GC) buraya taşındı. DO alarm'ları
// Free-plan-safe ve prod-kanıtlıdır (ProjectWriterDO.alarm() escrow drain'i).
//
// Model: TEK instance (idFromName=SCHEDULER_DO_NAME). alarm() bir sonraki
// tetiklenme anını (nightly / weekly hangisi önce gelirse) hesaplar, vadesi
// gelen görevin runner'larını çağırır ve KENDİNİ YENİDEN KURAR (re-arm).
// Bootstrap = one-shot admin rotası (POST /v1/admin/scheduler/arm → DO /arm).
//
// Gate: SCHEDULER_ENABLED="1" YALNIZCA prod'da (wrangler.jsonc vars) — staging
// hiç koşmaz: /arm armed:false döner, (bir şekilde kurulmuş) alarm görev
// ÇALIŞTIRMAZ ve re-arm ETMEZ (dormant kalır).
//
// Runner'lar fail-soft'tur (alert = tespit): tek görev hatası re-arm'ı asla
// düşürmez — kaçırılan bir run zinciri koparmaz, ertesi vadede devam edilir.
// C2: hiçbir console.* / alert çağrısına secret DEĞERİ verilmez.

import { utf8 } from "./crypto/encoding.js";
import { escrowConfig, headObject, putObject, keyEscrowAuditAnchor, EscrowEnv } from "./escrow.js";
import { deriveProjects, keyBlob } from "./storage.js";
import { runGC, GCDeps } from "./gc.js";
import { runStateReplication } from "./state-replication.js";
import { doStubFetch } from "./do-util.js";
import { AuditRow, AUDIT_DO_NAME } from "./audit.js";
import { deliverAlert, ALERT, AlertRule } from "./alerts.js";

/** SchedulerEnv, scheduler + runner'ların ihtiyaç duyduğu env alt kümesi. */
export interface SchedulerEnv extends EscrowEnv {
  SECRETS_BUCKET: R2Bucket;
  AUDIT_LOG: DurableObjectNamespace;
  DISCORD_WEBHOOK_URL?: string;
  GC_ENABLED_AT?: string;
  // Arch §5.2: tofu state → B2 replikasyonu (binding YALNIZCA prod; yoksa no-op).
  STATE_BUCKET?: R2Bucket;
  // Prod-only gate: "1" değilse scheduler tamamen dormant (staging no-op).
  SCHEDULER_ENABLED?: string;
}

/** SchedulerAlert, runner hata bildirimi (alert = tespit, asla enforcement). */
export type SchedulerAlert = (rule: AlertRule, summary: string, detail?: Record<string, unknown>) => void;

export const SCHEDULER_DO_NAME = "__scheduler__";

// §8.3 pinli zamanlar (eski cron'larla BİREBİR: "0 2 * * *" + "0 3 * * 0").
const NIGHTLY_UTC_HOUR = 2;
const WEEKLY_UTC_DOW = 0; // Pazar
const WEEKLY_UTC_HOUR = 3;

export type ScheduleKind = "nightly" | "weekly";

/** PendingFire, arm edilmiş bir sonraki tetiklenme kaydı (DO storage'da). */
export interface PendingFire {
  at: number; // epoch ms
  kind: ScheduleKind;
}

const PENDING_KEY = "scheduler:pending";

/** schedulerEnabled, prod-only gate: SCHEDULER_ENABLED tam olarak "1" olmalı. */
export function schedulerEnabled(env: Pick<SchedulerEnv, "SCHEDULER_ENABLED">): boolean {
  return (env.SCHEDULER_ENABLED ?? "").trim() === "1";
}

/** nextDailyUTC, now'dan KESİN SONRA gelen ilk `hour`:00 UTC anı (epoch ms). */
function nextDailyUTC(now: Date, hour: number): number {
  const candidate = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hour);
  return candidate > now.getTime() ? candidate : candidate + 24 * 3600 * 1000;
}

/** nextWeeklyUTC, now'dan KESİN SONRA gelen ilk `dow` günü `hour`:00 UTC anı. */
function nextWeeklyUTC(now: Date, dow: number, hour: number): number {
  const days = (dow - now.getUTCDay() + 7) % 7;
  const candidate = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + days, hour);
  return candidate > now.getTime() ? candidate : candidate + 7 * 24 * 3600 * 1000;
}

/**
 * computeNextFire, bir sonraki tetiklenmeyi hesaplar: nightly (her gün 02:00
 * UTC) ile weekly (Pazar 03:00 UTC) adaylarından ERKEN olanı kazanır. İkisi
 * asla çakışmaz (02 ≠ 03) → tie-break gerekmez. Sınır: tam tetiklenme anında
 * (örn. alarm 02:00.000'da fire etti) aday "kesin sonra" kuralıyla bir sonraki
 * vadeye atlar — anlık self-loop imkânsız.
 */
export function computeNextFire(now: Date): PendingFire {
  const nightly = nextDailyUTC(now, NIGHTLY_UTC_HOUR);
  const weekly = nextWeeklyUTC(now, WEEKLY_UTC_DOW, WEEKLY_UTC_HOUR);
  return weekly < nightly ? { at: weekly, kind: "weekly" } : { at: nightly, kind: "nightly" };
}

/** SchedulerStorage, DO storage'ın scheduler'ın kullandığı alt kümesi (testte fake'lenir). */
export interface SchedulerStorage {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  setAlarm(scheduledTime: number): Promise<void>;
}

/**
 * armScheduler, bir sonraki tetiklenmeyi kaydeder + DO alarm'ını kurar.
 * İdempotent: tekrar çağrı yalnızca alarm'ı aynı hesapla üzerine yazar.
 * Gate kapalıysa HİÇBİR yan etki üretmez (armed=false; staging no-op).
 */
export async function armScheduler(storage: SchedulerStorage, enabled: boolean, now: Date): Promise<PendingFire | null> {
  if (!enabled) return null;
  const next = computeNextFire(now);
  await storage.put(PENDING_KEY, next);
  await storage.setAlarm(next.at);
  return next;
}

/** FireDeps, alarm tetiklenmesinin enjekte edilebilir kenarları (tam test-edilebilir). */
export interface FireDeps {
  enabled: boolean;
  now(): Date;
  runNightly(): Promise<void>; // nightly audit-anchor + state replication
  runWeekly(): Promise<void>; // haftalık GC
  alert(summary: string, detail?: Record<string, unknown>): void; // A8 kanalı
}

/**
 * fireScheduler, alarm tetiklenmesinin saf çekirdeği: gate kapalıysa TAM no-op
 * (re-arm de yok → dormant); açıksa kayıtlı vadenin görevini çalıştırır ve HER
 * DURUMDA re-arm eder (görev hatası / kayıp pending kaydı zinciri koparmaz).
 */
export async function fireScheduler(storage: SchedulerStorage, deps: FireDeps): Promise<PendingFire | null> {
  if (!deps.enabled) return null; // gate: staging / kapatılmış prod → dormant
  const pending = await storage.get<PendingFire>(PENDING_KEY);
  try {
    if (pending?.kind === "weekly") await deps.runWeekly();
    else if (pending?.kind === "nightly") await deps.runNightly();
    // pending kaydı yoksa: arm izi kaybolmuş — görev çalıştırma, sadece re-arm.
  } catch (e) {
    // Runner'lar zaten fail-soft; buraya düşen beklenmedik hata alert'lenir
    // ama re-arm'ı ASLA engellemez.
    deps.alert("scheduler: task run failed", { kind: pending?.kind ?? null, error: String(e) });
  }
  const next = computeNextFire(deps.now());
  await storage.put(PENDING_KEY, next);
  await storage.setAlarm(next.at);
  return next;
}

// --- Runner'lar (eski scheduled() cron gövdelerinden taşındı, §8.3) -----------------

/** runScheduledGC, haftalık GC'yi üretim bağımlılıklarıyla sürer (Pazar 03:00 UTC). */
export async function runScheduledGC(env: SchedulerEnv, alert: SchedulerAlert): Promise<void> {
  const projects = await deriveProjects(env.SECRETS_BUCKET);
  const cfg = escrowConfig(env);
  const enabledAt = env.GC_ENABLED_AT ? new Date(env.GC_ENABLED_AT) : null;

  const deps: GCDeps = {
    now: new Date(),
    enabledAt: enabledAt && !Number.isNaN(enabledAt.getTime()) ? enabledAt : null,
    // (c) B2 replika teyidi: append-only key OKUYABİLİR (silemez). cfg yoksa
    // GÜVENLİ TARAF: false (silme yok).
    escrowHas: async (project, sha) => {
      if (!cfg) return false;
      try {
        return await headObject(cfg, keyBlob(project, sha));
      } catch {
        return false; // teyit edilemedi → silme (güvenli)
      }
    },
    auditDelete: async (project, sha) => {
      const row: AuditRow = { principal: "worker", principal_type: "worker", project, key: null, verb: "gc.delete", decision: "allow", intent: `blob:${sha.slice(0, 12)}` };
      await doStubFetch(() => env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME)), "https://audit/append-batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ rows: [row] }),
      });
    },
    alert: (rule, summary, detail) => alert(rule as AlertRule, summary, detail),
  };
  await runGC(env.SECRETS_BUCKET, projects, deps);
}

/**
 * runNightlyAnchor, NIGHTLY görevi (§8.3): D1 zincir head'ini ({last_seq,
 * last_hash, ts}) append-only B2'ye çapa olarak iter — CF-seviyesi bir ledger
 * yeniden-yazımı çapalara karşı tespit edilebilir. B2 yapılandırılmamışsa no-op.
 */
export async function runNightlyAnchor(env: SchedulerEnv, alert: SchedulerAlert): Promise<void> {
  const cfg = escrowConfig(env);
  if (!cfg) return;
  try {
    const res = await doStubFetch(() => env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME)), "https://audit/head", { method: "GET" });
    if (!res.ok) throw new Error(`audit head status ${res.status}`);
    const head = (await res.json()) as { seq: number; hash: string };
    const ts = new Date().toISOString();
    const body = utf8(JSON.stringify({ schema: "wapps.audit-anchor.v1", last_seq: head.seq, last_hash: head.hash, ts }));
    await putObject(cfg, keyEscrowAuditAnchor(ts.slice(0, 10)), body, "application/json");
  } catch (e) {
    alert(ALERT.A4, "nightly audit-head anchor push failed", { error: String(e) });
  }
}

// --- SchedulerDO --------------------------------------------------------------------

/**
 * SchedulerDO, tek-instance zamanlayıcı (SQLite-backed, migration v4).
 * Rotalar (yalnızca Worker içinden, admin bootstrap üzerinden erişilir):
 *   POST /arm    → alarm'ı kur (one-shot bootstrap; idempotent)
 *   GET  /status → { enabled, alarm, pending } (teşhis)
 */
export class SchedulerDO {
  constructor(
    private ctx: DurableObjectState,
    private env: SchedulerEnv,
  ) {}

  /** alertFn, fail-soft alert teslimatı (deliverAlert asla reject etmez;
   * fire-and-forget — scheduler görev akışını asla bloklamaz). */
  private alertFn: SchedulerAlert = (rule, summary, detail) => {
    void deliverAlert({ DISCORD_WEBHOOK_URL: this.env.DISCORD_WEBHOOK_URL, AUDIT_LOG: this.env.AUDIT_LOG }, rule, summary, detail);
  };

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/arm" && request.method === "POST") {
      const next = await armScheduler(this.ctx.storage, schedulerEnabled(this.env), new Date());
      if (!next) return json({ armed: false, reason: "SCHEDULER_DISABLED" });
      return json({ armed: true, next_fire: new Date(next.at).toISOString(), kind: next.kind });
    }
    if (url.pathname === "/status" && request.method === "GET") {
      const alarm = await this.ctx.storage.getAlarm();
      const pending = (await this.ctx.storage.get<PendingFire>(PENDING_KEY)) ?? null;
      return json({ enabled: schedulerEnabled(this.env), alarm: alarm !== null ? new Date(alarm).toISOString() : null, pending });
    }
    return json({ error: "NOT_FOUND" }, 404);
  }

  async alarm(): Promise<void> {
    await fireScheduler(this.ctx.storage, {
      enabled: schedulerEnabled(this.env),
      now: () => new Date(),
      runNightly: async () => {
        // Nightly vade = audit-head çapası + tofu state → B2 replikasyonu
        // (her ikisi de kendi içinde fail-soft; sıra önemsiz, seri tutulur).
        await runNightlyAnchor(this.env, this.alertFn);
        await runStateReplication(this.env, (summary, detail) => this.alertFn(ALERT.A4, summary, detail));
      },
      runWeekly: () => runScheduledGC(this.env, this.alertFn),
      alert: (summary, detail) => this.alertFn(ALERT.A8, summary, detail),
    });
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
