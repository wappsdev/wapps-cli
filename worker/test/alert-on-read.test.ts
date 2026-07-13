// A11 alert-on-read testleri (plan P1.11, arch §2.3 Token A invariant'ı):
// ALERT_ON_READ_KEYS glob'una uyan sentinel anahtarın TEK okunuşu bile A11
// üretir (A2 burst eşiğinin aksine). Eşleşmeyen okuma sessizdir; bulk okumada
// yalnızca eşleşen anahtar(lar) alarmlanır; audit satırları etkilenmez; liste
// okumaları (yalnızca adlar) alarm ÜRETMEZ. Alert fail-soft'tur — yanıt 200 kalır.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import {
  ensureJwks,
  resetWorld,
  validClaims,
  authHeader,
  callGate,
  seedPolicy,
  groupsByEmail,
  discordCalls,
  settleAudit,
} from "./helpers.js";

// Plan örneğiyle aynı biçim: tam ad + glob (boşluklu girdi trim edilir).
const SENTINELS = "TF_VAR_worker_admin_token, CF_TOKEN_A*";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await seedPolicy([{ group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*"] }]);
  groupsByEmail.set("boss@wapps.dev", ["admins@wapps.co"]);
});

async function bossJwt(): Promise<string> {
  return signer.makeJWT(validClaims("boss@wapps.dev"));
}
async function putKey(key: string, value: string): Promise<Response> {
  return callGate(`/v1/projects/vaulter/keys/${key}`, {
    method: "PUT",
    headers: authHeader(await bossJwt()),
    body: JSON.stringify({ value }),
  });
}
async function readKeys(keys: string[]): Promise<Response> {
  return callGate(
    "/v1/projects/vaulter/read",
    { method: "POST", headers: authHeader(await bossJwt()), body: JSON.stringify({ keys }) },
    { ALERT_ON_READ_KEYS: SENTINELS },
  );
}
function a11Calls(): { body: string }[] {
  return discordCalls.filter((c) => c.body.includes("[secrets-gate A11]"));
}

describe("A11 alert-on-read (arch §2.3 — sentinel key single-read alert)", () => {
  it("matching key read fires A11 exactly once per request; response stays 200", async () => {
    expect((await putKey("TF_VAR_worker_admin_token", "tok-A")).status).toBe(200);
    const rd = await readKeys(["TF_VAR_worker_admin_token"]);
    expect(rd.status).toBe(200);
    expect(((await rd.json()) as { values: Record<string, string> }).values.TF_VAR_worker_admin_token).toBe("tok-A");

    const fired = a11Calls();
    expect(fired.length).toBe(1); // TAM bir kez — tekrar/eksik yok
    expect(fired[0].body).toContain("sentinel key read: TF_VAR_worker_admin_token");
    expect(fired[0].body).toContain("boss@wapps.dev");
    expect(fired[0].body).not.toContain("tok-A"); // değer ASLA alert'e sızmaz
  });

  it("glob sentinel (CF_TOKEN_A*) matches; a second read fires again (threshold YOK)", async () => {
    await putKey("CF_TOKEN_A_WORKER", "v");
    expect((await readKeys(["CF_TOKEN_A_WORKER"])).status).toBe(200);
    expect(a11Calls().length).toBe(1);
    expect((await readKeys(["CF_TOKEN_A_WORKER"])).status).toBe(200);
    expect(a11Calls().length).toBe(2); // her okuma bağımsız alarmlanır
  });

  it("non-matching key read is silent (no A11)", async () => {
    await putKey("DATABASE_URL", "postgres://u:p@h/db");
    const rd = await readKeys(["DATABASE_URL"]);
    expect(rd.status).toBe(200);
    expect(a11Calls().length).toBe(0);
  });

  it("bulk read with ONE matching key fires for that key only; audit rows unaffected", async () => {
    await putKey("TF_VAR_worker_admin_token", "tok-A");
    await putKey("PLAIN_KEY", "p");
    const rd = await readKeys(["PLAIN_KEY", "TF_VAR_worker_admin_token"]);
    expect(rd.status).toBe(200);

    const fired = a11Calls();
    expect(fired.length).toBe(1);
    expect(fired[0].body).toContain("sentinel key read: TF_VAR_worker_admin_token");

    // Audit satırları A11'den ETKİLENMEZ: bulk okuma her anahtara bir
    // value.read.bulk allow satırı yazar (§6.4) — sentinel dahil.
    const rows = await settleAudit("vaulter", (r) => r.filter((x) => x.verb === "value.read.bulk" && x.decision === "allow").length >= 2);
    const bulkKeys = rows
      .filter((r) => r.verb === "value.read.bulk" && r.decision === "allow")
      .map((r) => r.key)
      .sort();
    expect(bulkKeys).toEqual(["PLAIN_KEY", "TF_VAR_worker_admin_token"]);
  });

  it("empty/unset ALERT_ON_READ_KEYS never fires (dormant default)", async () => {
    await putKey("TF_VAR_worker_admin_token", "tok-A");
    const rd = await callGate(
      "/v1/projects/vaulter/read",
      { method: "POST", headers: authHeader(await bossJwt()), body: JSON.stringify({ keys: ["TF_VAR_worker_admin_token"] }) },
      { ALERT_ON_READ_KEYS: "" },
    );
    expect(rd.status).toBe(200);
    expect(a11Calls().length).toBe(0);
  });

  it("list read (names only, no values) does NOT alert on a sentinel key", async () => {
    await putKey("TF_VAR_worker_admin_token", "tok-A");
    const list = await callGate("/v1/projects/vaulter/keys", { headers: authHeader(await bossJwt()) }, { ALERT_ON_READ_KEYS: SENTINELS });
    expect(list.status).toBe(200);
    const names = ((await list.json()) as { keys: { keyName: string }[] }).keys.map((k) => k.keyName);
    expect(names).toContain("TF_VAR_worker_admin_token");
    expect(a11Calls().length).toBe(0); // yalnızca value.read/value.read.bulk alarmlanır
  });
});
