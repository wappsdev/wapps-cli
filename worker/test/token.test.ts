// Machine-token mint + exchange + scope + revoke/deny-list testleri (SPEC §6.4).
import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import {
  seedTrust,
  ensureJwks,
  authHeader,
  callGate,
  resetWorld,
  serviceTokenClaims,
  validClaimsWrite,
  signDataManifest,
  seedManifestObject,
  putBlob,
  TrustContext,
} from "./helpers.js";
import { mirrorGrantsFor } from "../src/grants-mirror.js";

let signer: Awaited<ReturnType<typeof ensureJwks>>;
beforeAll(async () => {
  signer = await ensureJwks();
});
beforeEach(resetWorld);

async function seedManifest(t: TrustContext): Promise<void> {
  const blob = await putBlob("vaulter", new Uint8Array(new Array(256 + 44).fill(7)));
  const w = signDataManifest(
    { project: "vaulter", epoch: 1, prev: "", trustEpoch: 1, entries: [{ keyName: t.machineGrantKey, keyVersion: 1, blobHash: blob, wraps: [{ recipient: t.machineDevice, wrap: "m" }] }] },
    t.writer,
  );
  await seedManifestObject("vaulter", 1, w);
}

async function mint(t: TrustContext, body: unknown, cn = t.machineCommonName): Promise<Response> {
  const jwt = await signer.makeJWT(serviceTokenClaims(cn));
  return callGate("/v1/token", { method: "POST", headers: authHeader(jwt), body: JSON.stringify(body) }, t.pin);
}

describe("machine-token mint (§6.4)", () => {
  it("MINT: valid seed + in-grant scope → 200 short-TTL scoped token (ttl clamped ≤600)", async () => {
    const t = await seedTrust();
    const res = await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 99999 });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { token: string; jti: string; expires_in: number; sub: string };
    expect(typeof j.token).toBe("string");
    expect(j.expires_in).toBe(600); // 10 dk hard cap (§6.4 rule 3)
    expect(j.sub).toBe(t.machineId);
  });

  it("MINT REJECT: unknown seed → 403 WRITER_NOT_ALLOWED", async () => {
    const t = await seedTrust();
    const res = await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 }, "nonexistent-runner");
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("WRITER_NOT_ALLOWED");
  });

  it("MINT REJECT: scope exceeds grant (write not granted) → 403 TOKEN_SCOPE_EXCEEDED", async () => {
    const t = await seedTrust();
    const res = await mint(t, { project: "vaulter", scope: { verbs: ["write"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_SCOPE_EXCEEDED");
  });

  it("MINT REJECT: scope key not granted → 403 TOKEN_SCOPE_EXCEEDED", async () => {
    const t = await seedTrust();
    const res = await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["OTHER_KEY"] }, ttl_seconds: 600 });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_SCOPE_EXCEEDED");
  });

  it("Fix #5: a machine WILDCARD grant in the mirror no longer authorizes an unlisted key (fallback removed)", async () => {
    const t = await seedTrust();
    // İlk mint → mirror'ı bu epoch için kurar (grants + mirror_state=epoch1, tablolar oluşur).
    expect((await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 })).status).toBe(200);
    // Mirror'a MAKİNE joker ("*") read grant'ı ENJEKTE et. mirror_state epoch=1 kaldığından
    // sonraki mint ensureMirror'da REBUILD ETMEZ (manifest'ten gelmez) → satır hayatta kalır.
    await env.AUDIT_DB.prepare(
      "INSERT OR REPLACE INTO grants (trust_epoch, principal, principal_type, project, key_name, verb, rotate_by) VALUES (1, ?, 'machine', 'vaulter', '*', 'read', NULL)",
    )
      .bind(t.machineId)
      .run();
    // Açıkça listelenmemiş bir anahtar iste: ESKİ kod joker fallback ile mint ederdi;
    // YENİ kod (fallback kaldırıldı) → 403 TOKEN_SCOPE_EXCEEDED.
    const res = await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["OTHER_KEY"] }, ttl_seconds: 600 });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("TOKEN_SCOPE_EXCEEDED");
  });

  it("Fix #4: machine rotate_by flows from the signed manifest into the grants mirror", async () => {
    const t = await seedTrust();
    // İlk mint → ensureMirror grants tablosunu bu epoch için manifest'ten kurar.
    expect((await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 })).status).toBe(200);
    const rows = await mirrorGrantsFor(env, t.machineId, "vaulter");
    expect(rows.length).toBeGreaterThan(0);
    // seedTrust makine kimliği rotate_by = "2099-01-01T00:00:00Z" → modellenip mirror'a taşınır
    // (eski davranış: parseTrustBody rotate_by'ı DROP ederdi → mirror NULL kaydederdi).
    expect(rows.every((r) => r.rotateBy === "2099-01-01T00:00:00Z")).toBe(true);
  });

  it("CONFINEMENT: a human JWT may NOT mint → 403 MACHINE_TOKEN_REQUIRED", async () => {
    const t = await seedTrust();
    const jwt = await signer.makeJWT(validClaimsWrite(t.adminEmail, { aud: ["aud-read-000000000000000000000000000000000000"] }));
    const res = await callGate("/v1/token", { method: "POST", headers: authHeader(jwt), body: JSON.stringify({ project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] } }) }, t.pin);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("MACHINE_TOKEN_REQUIRED");
  });
});

describe("minted-token exchange + confinement (§6.1 step 8-9)", () => {
  it("EXCHANGE: minted token grants data-plane access (manifest read) → 200", async () => {
    const t = await seedTrust();
    await seedManifest(t);
    const minted = (await (await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 })).json()) as { token: string };
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const res = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(seedJwt, { authorization: `Bearer ${minted.token}` }) }, t.pin);
    expect(res.status).toBe(200);
  });

  it("CONFINEMENT: service token on a data route WITHOUT a minted token → 403 MACHINE_TOKEN_REQUIRED", async () => {
    const t = await seedTrust();
    await seedManifest(t);
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));
    const res = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(seedJwt) }, t.pin);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("MACHINE_TOKEN_REQUIRED");
  });
});

describe("revoke → deny-list (§6.4)", () => {
  it("REVOKE: admin revokes jti → subsequent use → 403 TOKEN_REVOKED", async () => {
    const t = await seedTrust();
    await seedManifest(t);
    const minted = (await (await mint(t, { project: "vaulter", scope: { verbs: ["read"], keys: ["MACHINE_KEY"] }, ttl_seconds: 600 })).json()) as { token: string; jti: string };
    const seedJwt = await signer.makeJWT(serviceTokenClaims(t.machineCommonName));

    // İşe yarıyor (revoke ÖNCESİ).
    const before = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(seedJwt, { authorization: `Bearer ${minted.token}` }) }, t.pin);
    expect(before.status).toBe(200);

    // Admin revoke (write-AUD).
    const adminJwt = await signer.makeJWT(validClaimsWrite(t.adminEmail));
    const rev = await callGate("/v1/token/revoke", { method: "POST", headers: authHeader(adminJwt), body: JSON.stringify({ jti: minted.jti }) }, t.pin);
    expect(rev.status).toBe(200);

    // Revoke SONRASI → 403 TOKEN_REVOKED (deny-list).
    const after = await callGate("/v1/projects/vaulter/manifests/current", { headers: authHeader(seedJwt, { authorization: `Bearer ${minted.token}` }) }, t.pin);
    expect(after.status).toBe(403);
    expect(((await after.json()) as { error: string }).error).toBe("TOKEN_REVOKED");
  });

  it("REVOKE REJECT: non-admin (read-AUD) cannot revoke → 403", async () => {
    const t = await seedTrust();
    const readerJwt = await signer.makeJWT({ iss: `https://test-team.cloudflareaccess.com`, aud: ["aud-read-000000000000000000000000000000000000"], email: "reader@wapps.dev", iat: Math.floor(Date.now() / 1000), nbf: Math.floor(Date.now() / 1000) - 10, exp: Math.floor(Date.now() / 1000) + 3600 });
    const res = await callGate("/v1/token/revoke", { method: "POST", headers: authHeader(readerJwt), body: JSON.stringify({ jti: "whatever" }) }, t.pin);
    expect(res.status).toBe(403); // read-AUD → AUD_MISMATCH (write-AUD gerekli)
  });
});
