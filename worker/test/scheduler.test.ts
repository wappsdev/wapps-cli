// SchedulerDO testleri (plan P2.4). Kanıtlar:
// (1) computeNextFire: nightly 02:00 UTC / Pazar 03:00 UTC weekly — eski cron
//     kümesiyle ("0 2 * * *" + "0 3 * * 0") birebir, "kesin sonra" semantiği,
// (2) armScheduler: pending kaydı + alarm; gate kapalıysa SIFIR yan etki,
// (3) fireScheduler: vadeye göre doğru runner + HER durumda re-arm (runner
//     hatası / kayıp pending dahil); gate kapalıysa TAM no-op (dormant),
// (4) SchedulerDO /arm + /status (gerçek DO, migration v4 binding'i),
// (5) POST /v1/admin/scheduler/arm bootstrap rotası (admin verb + senkron audit).

import { beforeAll, beforeEach, afterEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  validClaimsWrite,
  authHeader,
  callGate,
  seedPolicy,
  defaultRules,
  allAuditRows,
  runInDoRetry,
  ADMIN_EMAIL,
} from "./helpers.js";
import {
  computeNextFire,
  armScheduler,
  fireScheduler,
  schedulerEnabled,
  SchedulerStorage,
  PendingFire,
  SCHEDULER_DO_NAME,
} from "../src/scheduler-do.js";

// --- Saf yardımcılar -------------------------------------------------------------

function utc(y: number, mo: number, d: number, h: number, mi = 0, s = 0, ms = 0): Date {
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s, ms));
}

// FakeStorage, SchedulerStorage'ın kayıt tutan taklidi (DO'suz saf test).
class FakeStorage implements SchedulerStorage {
  map = new Map<string, unknown>();
  alarms: number[] = [];
  puts = 0;
  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put(key: string, value: unknown): Promise<void> {
    this.puts++;
    this.map.set(key, value);
  }
  async setAlarm(at: number): Promise<void> {
    this.alarms.push(at);
  }
}

const PENDING_KEY = "scheduler:pending";

describe("computeNextFire — §8.3 pinli küme (nightly 02:00 + Pazar 03:00 UTC)", () => {
  // 2026-07-12 bir PAZAR'dır (weekly gün çapası); testin kendisi de doğrular.
  it("fixture sanity: 2026-07-12 = Pazar (UTC)", () => {
    expect(utc(2026, 7, 12, 0).getUTCDay()).toBe(0);
  });

  it("hafta içi 02:00'den önce → AYNI gün 02:00 nightly", () => {
    const n = computeNextFire(utc(2026, 7, 8, 1, 30)); // Çarşamba 01:30
    expect(n).toEqual({ at: Date.UTC(2026, 6, 8, 2), kind: "nightly" });
  });

  it("hafta içi 02:00'den sonra → ERTESİ gün 02:00 nightly", () => {
    const n = computeNextFire(utc(2026, 7, 8, 10));
    expect(n).toEqual({ at: Date.UTC(2026, 6, 9, 2), kind: "nightly" });
  });

  it("tam 02:00.000'da → KESİN SONRA kuralı: ertesi gün (anlık self-loop imkânsız)", () => {
    const n = computeNextFire(utc(2026, 7, 8, 2, 0, 0, 0));
    expect(n).toEqual({ at: Date.UTC(2026, 6, 9, 2), kind: "nightly" });
  });

  it("Cumartesi gecesi → Pazar 02:00 NIGHTLY kazanır (weekly 03:00'ten önce)", () => {
    const n = computeNextFire(utc(2026, 7, 11, 23)); // Cumartesi 23:00
    expect(n).toEqual({ at: Date.UTC(2026, 6, 12, 2), kind: "nightly" });
  });

  it("Pazar 02:30 (nightly koştu) → Pazar 03:00 WEEKLY", () => {
    const n = computeNextFire(utc(2026, 7, 12, 2, 30));
    expect(n).toEqual({ at: Date.UTC(2026, 6, 12, 3), kind: "weekly" });
  });

  it("tam Pazar 03:00.000'da → weekly 1 hafta atlar, Pazartesi 02:00 nightly kazanır", () => {
    const n = computeNextFire(utc(2026, 7, 12, 3, 0, 0, 0));
    expect(n).toEqual({ at: Date.UTC(2026, 6, 13, 2), kind: "nightly" });
  });

  it("ay sınırı: 31 Temmuz 10:00 → 1 Ağustos 02:00 (Date.UTC gün taşması)", () => {
    const n = computeNextFire(utc(2026, 7, 31, 10));
    expect(n).toEqual({ at: Date.UTC(2026, 7, 1, 2), kind: "nightly" });
  });
});

describe("schedulerEnabled — prod-only gate", () => {
  it('yalnızca tam "1" açar; unset/boş/whitespace/diğer değerler kapalı', () => {
    expect(schedulerEnabled({ SCHEDULER_ENABLED: "1" })).toBe(true);
    expect(schedulerEnabled({ SCHEDULER_ENABLED: " 1 " })).toBe(true); // trim
    expect(schedulerEnabled({ SCHEDULER_ENABLED: "" })).toBe(false);
    expect(schedulerEnabled({ SCHEDULER_ENABLED: "0" })).toBe(false);
    expect(schedulerEnabled({ SCHEDULER_ENABLED: "true" })).toBe(false);
    expect(schedulerEnabled({})).toBe(false);
  });
});

describe("armScheduler — bootstrap", () => {
  it("enabled: pending kaydı + alarm bir sonraki vadeye kurulur", async () => {
    const st = new FakeStorage();
    const now = utc(2026, 7, 8, 1);
    const next = await armScheduler(st, true, now);
    expect(next).toEqual({ at: Date.UTC(2026, 6, 8, 2), kind: "nightly" });
    expect(st.map.get(PENDING_KEY)).toEqual(next);
    expect(st.alarms).toEqual([next!.at]);
  });

  it("disabled (staging): null döner, HİÇBİR yan etki yok", async () => {
    const st = new FakeStorage();
    const next = await armScheduler(st, false, utc(2026, 7, 8, 1));
    expect(next).toBeNull();
    expect(st.puts).toBe(0);
    expect(st.alarms).toEqual([]);
  });
});

describe("fireScheduler — alarm çekirdeği (re-arm + gating)", () => {
  interface RunLog {
    nightly: number;
    weekly: number;
    alerts: { summary: string; detail?: Record<string, unknown> }[];
  }
  function deps(log: RunLog, now: Date, enabled = true, failWith?: Error) {
    return {
      enabled,
      now: () => now,
      runNightly: async () => {
        log.nightly++;
        if (failWith) throw failWith;
      },
      runWeekly: async () => {
        log.weekly++;
        if (failWith) throw failWith;
      },
      alert: (summary: string, detail?: Record<string, unknown>) => log.alerts.push({ summary, detail }),
    };
  }

  it("nightly vadesi: runNightly çalışır (weekly değil) + yeni vadeye re-arm", async () => {
    const st = new FakeStorage();
    st.map.set(PENDING_KEY, { at: Date.UTC(2026, 6, 8, 2), kind: "nightly" } satisfies PendingFire);
    const log: RunLog = { nightly: 0, weekly: 0, alerts: [] };
    const fireNow = utc(2026, 7, 8, 2, 0, 0, 250); // alarm 02:00'de tetiklendi

    const next = await fireScheduler(st, deps(log, fireNow));

    expect(log.nightly).toBe(1);
    expect(log.weekly).toBe(0);
    expect(log.alerts).toEqual([]);
    // Re-arm: ertesi gün 02:00 (Perşembe) — pending + alarm güncellendi.
    expect(next).toEqual({ at: Date.UTC(2026, 6, 9, 2), kind: "nightly" });
    expect(st.map.get(PENDING_KEY)).toEqual(next);
    expect(st.alarms).toEqual([next!.at]);
  });

  it("weekly vadesi (Pazar 03:00): runWeekly çalışır + Pazartesi 02:00 nightly'ye re-arm", async () => {
    const st = new FakeStorage();
    st.map.set(PENDING_KEY, { at: Date.UTC(2026, 6, 12, 3), kind: "weekly" } satisfies PendingFire);
    const log: RunLog = { nightly: 0, weekly: 0, alerts: [] };

    const next = await fireScheduler(st, deps(log, utc(2026, 7, 12, 3, 0, 1)));

    expect(log.weekly).toBe(1);
    expect(log.nightly).toBe(0);
    expect(next).toEqual({ at: Date.UTC(2026, 6, 13, 2), kind: "nightly" });
    expect(st.alarms).toEqual([next!.at]);
  });

  it("runner hatası: alert üretilir ama re-arm ASLA engellenmez", async () => {
    const st = new FakeStorage();
    st.map.set(PENDING_KEY, { at: Date.UTC(2026, 6, 8, 2), kind: "nightly" } satisfies PendingFire);
    const log: RunLog = { nightly: 0, weekly: 0, alerts: [] };

    const next = await fireScheduler(st, deps(log, utc(2026, 7, 8, 2, 0, 1), true, new Error("boom")));

    expect(log.nightly).toBe(1);
    expect(log.alerts.length).toBe(1);
    expect(log.alerts[0].summary).toBe("scheduler: task run failed");
    expect(log.alerts[0].detail?.kind).toBe("nightly");
    expect(next).toEqual({ at: Date.UTC(2026, 6, 9, 2), kind: "nightly" }); // yine re-arm
    expect(st.alarms).toEqual([next!.at]);
  });

  it("gate kapalı (staging/prod-off): görev YOK, re-arm YOK — dormant", async () => {
    const st = new FakeStorage();
    st.map.set(PENDING_KEY, { at: Date.UTC(2026, 6, 8, 2), kind: "nightly" } satisfies PendingFire);
    const log: RunLog = { nightly: 0, weekly: 0, alerts: [] };

    const next = await fireScheduler(st, deps(log, utc(2026, 7, 8, 2, 0, 1), false));

    expect(next).toBeNull();
    expect(log.nightly).toBe(0);
    expect(log.weekly).toBe(0);
    expect(st.puts).toBe(0); // pending güncellenmedi
    expect(st.alarms).toEqual([]); // alarm kurulmadı
  });

  it("kayıp pending kaydı: görev çalıştırılmaz, yalnızca re-arm (zincir kopmaz)", async () => {
    const st = new FakeStorage();
    const log: RunLog = { nightly: 0, weekly: 0, alerts: [] };

    const next = await fireScheduler(st, deps(log, utc(2026, 7, 8, 10)));

    expect(log.nightly).toBe(0);
    expect(log.weekly).toBe(0);
    expect(log.alerts).toEqual([]);
    expect(next).toEqual({ at: Date.UTC(2026, 6, 9, 2), kind: "nightly" });
    expect(st.alarms).toEqual([next!.at]);
  });
});

// --- Gerçek DO + admin bootstrap rotası ----------------------------------------------

const schedulerStub = () => env.SCHEDULER.get(env.SCHEDULER.idFromName(SCHEDULER_DO_NAME));

/** clearSchedulerDO, testin kurduğu gerçek alarm + storage'ı temizler. */
async function clearSchedulerDO(): Promise<void> {
  await runInDoRetry(schedulerStub(), async (_i: unknown, state: DurableObjectState) => {
    await state.storage.deleteAlarm();
    await state.storage.deleteAll();
  });
}

describe("SchedulerDO — /arm + /status (gerçek DO, migration v4)", () => {
  afterEach(clearSchedulerDO);

  it("POST /arm: armed:true + bir sonraki vade; GET /status alarm'ı gösterir", async () => {
    // Test env'i prod wrangler.jsonc'tan SCHEDULER_ENABLED="1" miras alır.
    const before = Date.now();
    const res = await schedulerStub().fetch("https://scheduler/arm", { method: "POST" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { armed: boolean; next_fire: string; kind: string };
    expect(body.armed).toBe(true);
    expect(["nightly", "weekly"]).toContain(body.kind);
    const at = Date.parse(body.next_fire);
    expect(at).toBeGreaterThan(before); // kesin gelecekte
    expect(at - before).toBeLessThanOrEqual(7 * 24 * 3600 * 1000); // ≤ 1 hafta içinde

    const st = await schedulerStub().fetch("https://scheduler/status", { method: "GET" });
    const status = (await st.json()) as { enabled: boolean; alarm: string | null; pending: PendingFire | null };
    expect(status.enabled).toBe(true);
    expect(status.alarm).toBe(body.next_fire); // alarm gerçekten kuruldu
    expect(status.pending?.kind).toBe(body.kind);
  });

  it("idempotent: ikinci /arm aynı vadeyi yeniden kurar (hata yok)", async () => {
    const r1 = await schedulerStub().fetch("https://scheduler/arm", { method: "POST" });
    const r2 = await schedulerStub().fetch("https://scheduler/arm", { method: "POST" });
    const b1 = (await r1.json()) as { next_fire: string };
    const b2 = (await r2.json()) as { next_fire: string };
    expect(r2.status).toBe(200);
    expect(b2.next_fire).toBe(b1.next_fire);
  });

  it("bilinmeyen DO rotası → 404", async () => {
    const res = await schedulerStub().fetch("https://scheduler/nope", { method: "POST" });
    expect(res.status).toBe(404);
  });
});

describe("POST /v1/admin/scheduler/arm — one-shot bootstrap (write-AUD + admin verb)", () => {
  let signer: Awaited<ReturnType<typeof ensureJwks>>;
  beforeAll(async () => {
    signer = await ensureJwks();
  });
  beforeEach(async () => {
    await resetWorld();
    await seedPolicy(defaultRules());
  });
  afterEach(clearSchedulerDO);

  it("kök admin: 200 armed:true + senkron admin.scheduler_arm audit satırı", async () => {
    const jwt = await signer.makeJWT(validClaimsWrite(ADMIN_EMAIL));
    const res = await callGate("/v1/admin/scheduler/arm", { method: "POST", headers: authHeader(jwt) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { armed: boolean; next_fire?: string; kind?: string };
    expect(body.armed).toBe(true);
    expect(body.next_fire).toBeTruthy();

    const rows = await allAuditRows();
    const row = rows.find((r) => r.verb === "admin.scheduler_arm");
    expect(row).toBeTruthy();
    expect(row!.decision).toBe("allow");
    expect(String(row!.intent)).toContain("armed:");
  });

  it("admin verb'süz principal: 403 GRANT_DENIED (bootstrap yetki ister)", async () => {
    const jwt = await signer.makeJWT(validClaimsWrite("writer@wapps.dev"));
    const res = await callGate("/v1/admin/scheduler/arm", { method: "POST", headers: authHeader(jwt) });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GRANT_DENIED");
  });

  it("read-AUD JWT admin rotasına giremez (write app zorunlu)", async () => {
    const jwt = await signer.makeJWT(validClaims(ADMIN_EMAIL)); // aud=READ
    const res = await callGate("/v1/admin/scheduler/arm", { method: "POST", headers: authHeader(jwt) });
    expect(res.status).toBe(403);
  });
});
