// Worker last-verified trust pin (SPEC §4.4 + §4.8) — D1 aynası, MONOTONİK.
// loadTrustHead artık getirilen zinciri HEM pinlenmiş genesis'e HEM de D1'deki
// kalıcı last-verified yüksek-su-işaretine karşı doğrular. Doğrulanan head
// monotonik kalıcılaşır; altına rollback TRUST_DOWNGRADE ile reddedilir.
//
// Bu, "genesis'i İKİ pin olarak kullanma" artçısını kapatır: eskiden pinnedLast =
// genesis olduğundan downgrade guard yalnızca genesis'e demirliydi (izin verici).

import { beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { bytesToB64, bytesToHex, sha256, utf8 } from "../src/crypto/verify.js";
import { keyTrustCurrent, keyTrustManifest } from "../src/storage.js";
import { loadTrustHead } from "../src/trust-loader.js";
import { loadLastVerifiedPin, persistLastVerifiedPin } from "../src/trust-pin.js";
import { Pin, TrustError } from "../src/trust.js";
import { resetWorld, seedTrust, TrustContext } from "./helpers.js";

const HOLDER = "human:adnan@wapps.dev";
const MEDIA = ["yubikey-piv", "secure-enclave", "paper-steel"];

/**
 * buildRoster, genesis root'larıyla (2-of-3) imzalı bir roster trust epoch'u kurar
 * ve R2'ye yazar (trust/manifests/<epoch>.json). Aynı 3 kök → validateRosterInvariants
 * ve M-of-N geçer. payload hash'i (pin) döner. Roster change_class → compareUnchanged
 * çağrılmaz, identities/grants boş bırakılabilir.
 */
function rosterBytes(epoch: number, prev: string, ctx: TrustContext): { wrapperBytes: Uint8Array; pin: string } {
  const body = {
    schema: "wapps-trust/v1",
    admin_epoch: epoch,
    prev_trust_sha256: prev,
    created_at: "2026-07-10T13:00:00Z",
    change_class: "roster",
    bootstrap_solo: true,
    quorum: { m: 2, n: 3 },
    roots: ctx.roots.map((r, i) => ({ key_id: r.keyID, alg: "ed25519", pubkey: r.pubB64, media: MEDIA[i], holder: HOLDER, status: "active" })),
    admins: [],
    identities: [],
    grants: [],
    writer_allowlists: [],
    worker_receipt_pubkey: null,
    worker_mint_pubkeys: null,
  };
  const bytes = utf8(JSON.stringify(body));
  const pin = bytesToHex(sha256(bytes));
  const sigs = [ctx.roots[0], ctx.roots[1]].map((k) => ({ schema: "wapps-secrets/sig/v1", key_id: k.keyID, alg: "ed25519", sig: bytesToB64(k.sign(bytes)) }));
  const wrapper = { bytes: bytesToB64(bytes), sigs };
  return { wrapperBytes: utf8(JSON.stringify(wrapper)), pin };
}

/** setCurrent, trust/current locator'ını verilen epoch/hash'e ayarlar (rollback simülasyonu için de). */
async function setCurrent(epoch: number, sha: string): Promise<void> {
  await env.SECRETS_BUCKET.put(keyTrustCurrent(), utf8(JSON.stringify({ schema: "wapps-trust-current/v1", admin_epoch: epoch, trustSha256: sha })));
}

/** readPin, D1'deki tek-satırlık last-verified pin'i okur (yoksa null). */
async function readPin(): Promise<{ admin_epoch: number; trust_sha256: string } | null> {
  return env.AUDIT_DB.prepare("SELECT admin_epoch, trust_sha256 FROM trust_pin WHERE id = 1").first<{ admin_epoch: number; trust_sha256: string }>();
}

async function expectTrustError(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof TrustError) return e.code;
    throw e;
  }
  throw new Error("expected TrustError, got none");
}

describe("last-verified trust pin (§4.4) — D1 monotonic mirror", () => {
  beforeEach(resetWorld);

  it("verifying a chain to admin_epoch N persists N as the last-verified pin", async () => {
    const ctx = await seedTrust(); // genesis (epoch 1), trust/current → epoch 1
    // epoch 2 roster ekle + current'ı ilerlet.
    const e2 = rosterBytes(2, ctx.pin, ctx);
    await env.SECRETS_BUCKET.put(keyTrustManifest(2), e2.wrapperBytes);
    await setCurrent(2, e2.pin);

    const head = await loadTrustHead(env.SECRETS_BUCKET, ctx.pin, env.AUDIT_DB);
    expect(head.manifest.admin_epoch).toBe(2);

    const pin = await readPin();
    expect(pin?.admin_epoch).toBe(2);
    expect(pin?.trust_sha256).toBe(e2.pin);
  });

  it("a later rolled-back chain (head < N) is REJECTED as TRUST_DOWNGRADE", async () => {
    const ctx = await seedTrust();
    const e2 = rosterBytes(2, ctx.pin, ctx);
    await env.SECRETS_BUCKET.put(keyTrustManifest(2), e2.wrapperBytes);
    await setCurrent(2, e2.pin);

    // İlk yükleme: epoch 2 doğrulanır + pinlenir.
    await loadTrustHead(env.SECRETS_BUCKET, ctx.pin, env.AUDIT_DB);
    expect((await readPin())?.admin_epoch).toBe(2);

    // Rollback: trust/current'ı epoch 1'e (genesis) geri al — head < last-verified.
    await setCurrent(1, ctx.pin);
    const code = await expectTrustError(() => loadTrustHead(env.SECRETS_BUCKET, ctx.pin, env.AUDIT_DB));
    expect(code).toBe("TRUST_DOWNGRADE");

    // Pin MONOTONİK: rollback reddi pin'i düşürmedi (hâlâ epoch 2).
    expect((await readPin())?.admin_epoch).toBe(2);
  });

  it("persist is monotonic — a lower epoch never overwrites the stored high-water mark", async () => {
    await seedTrust();
    await persistLastVerifiedPin(env.AUDIT_DB, { admin_epoch: 5, sha256: "aa".repeat(32) });
    expect((await readPin())?.admin_epoch).toBe(5);

    // Düşük epoch → ezmez.
    await persistLastVerifiedPin(env.AUDIT_DB, { admin_epoch: 3, sha256: "bb".repeat(32) });
    let pin = await readPin();
    expect(pin?.admin_epoch).toBe(5);
    expect(pin?.trust_sha256).toBe("aa".repeat(32));

    // Eşit epoch → fork sha'sı da ezmez (checkPinPassthrough için ilk-doğrulanan sha korunur).
    await persistLastVerifiedPin(env.AUDIT_DB, { admin_epoch: 5, sha256: "cc".repeat(32) });
    expect((await readPin())?.trust_sha256).toBe("aa".repeat(32));

    // Yüksek epoch → ilerletir.
    await persistLastVerifiedPin(env.AUDIT_DB, { admin_epoch: 6, sha256: "dd".repeat(32) });
    pin = await readPin();
    expect(pin?.admin_epoch).toBe(6);
    expect(pin?.trust_sha256).toBe("dd".repeat(32));
  });

  it("loadLastVerifiedPin returns the genesis floor when no row exists or stored epoch < genesis", async () => {
    const genesis: Pin = { admin_epoch: 1, sha256: "ee".repeat(32) };
    await seedTrust();
    // Satır yok → genesis taban-değeri.
    expect(await loadLastVerifiedPin(env.AUDIT_DB, genesis)).toEqual(genesis);
    // Kayıtlı epoch genesis'in altında (savunma) → yine genesis taban-değeri.
    await persistLastVerifiedPin(env.AUDIT_DB, { admin_epoch: 1, sha256: "ff".repeat(32) });
    const withGenesis3: Pin = { admin_epoch: 3, sha256: "ee".repeat(32) };
    expect(await loadLastVerifiedPin(env.AUDIT_DB, withGenesis3)).toEqual(withGenesis3);
  });

  it("without a db binding, loadTrustHead stays backward-compatible (genesis-only)", async () => {
    const ctx = await seedTrust();
    const head = await loadTrustHead(env.SECRETS_BUCKET, ctx.pin); // db yok
    expect(head.manifest.admin_epoch).toBe(1);
    // D1'e hiçbir şey yazılmadı.
    expect(await readPin()).toBeNull();
  });
});
