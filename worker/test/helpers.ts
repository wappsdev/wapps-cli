// Test fixture kurucuları (v2 SERVER-DECRYPT). CF Access ES256 JWT üretir,
// JWKS + get-identity + Discord webhook'unu fetchMock ile servis eder, policy'yi
// R2'ye doğrudan seed'ler. ZK trust/imza fixture'ları pivotla SİLİNDİ (§0.2).

import { env, fetchMock, createExecutionContext, waitOnExecutionContext, runInDurableObject } from "cloudflare:test";
import worker from "../src/index.js";
import { AUDIT_DO_NAME } from "../src/audit.js";
import { bytesToB64, utf8, sha256Hex } from "../src/crypto/encoding.js";
import { __resetPolicyCache, PolicyRule, SCHEMA_POLICY } from "../src/policy.js";
import { __resetKekCache } from "../src/crypto/kek.js";
import { keyPolicyCurrent, keyPolicyVersion } from "../src/storage.js";

// --- Sabitler (vitest.config.ts bindings ile BİREBİR) ------------------------

export const TEAM_DOMAIN = "test-team.cloudflareaccess.com";
export const AUD_READ = "aud-read-000000000000000000000000000000000000";
export const AUD_WRITE = "aud-write-00000000000000000000000000000000000";
export const ISSUER = `https://${TEAM_DOMAIN}`;
export const CERTS_URL = `https://${TEAM_DOMAIN}/cdn-cgi/access/certs`;
export const ADMIN_EMAIL = "admin@wapps.dev"; // ADMIN_EMAILS kök çapası
export const MASTER_KEK_HEX = "2222222222222222222222222222222222222222222222222222222222222222";
export const MINT_KID = "mint-test-1";
export const MINT_KID_PREV = "mint-test-0";
export const DISCORD_HOST = "https://discord.test";

// --- CF Access ES256 JWT (auth testleri) --------------------------------------

export interface AccessSigner {
  jwks: string; // JSON {keys:[jwk]}
  makeJWT(claims: Record<string, unknown>, opts?: { kid?: string; alg?: string }): Promise<string>;
}

function b64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlStr(s: string): string {
  return b64url(utf8(s));
}

/** makeAccessSigner, bir ES256 keypair üretir; JWKS + JWT üretici döner. */
export async function makeAccessSigner(kid = "test-kid"): Promise<AccessSigner> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const jwk = { ...pubJwk, kid, alg: "ES256", use: "sig" };
  const jwks = JSON.stringify({ keys: [jwk] });
  return {
    jwks,
    async makeJWT(claims, o) {
      const header = { alg: o?.alg ?? "ES256", kid: o?.kid ?? kid, typ: "JWT" };
      const signingInput = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(claims))}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, utf8(signingInput)));
      return `${signingInput}.${b64url(sig)}`;
    },
  };
}

// --- fetchMock: JWKS + get-identity + Discord ---------------------------------

// fetchMock ile yakalanan Discord alert POST'ları.
export const discordCalls: { body: string }[] = [];

// get-identity davranışı (testler mutasyona uğratır; resetWorld sıfırlar):
//  - groupsByEmail: email → grup e-postaları (yanıt {email|name} obje dizisi şeklinde)
//  - identityMode: "ok" | "down" (500) | "badshape" (groups alanı bozuk)
export const groupsByEmail = new Map<string, string[]>();
export let identityMode: "ok" | "down" | "badshape" = "ok";
export function setIdentityMode(m: "ok" | "down" | "badshape"): void {
  identityMode = m;
}
// get-identity'ye düşen çağrı sayısı (KV cache hit doğrulaması).
export let identityCalls = 0;

function decodeJwtEmail(cookieHeader: string): string {
  // Cookie: CF_Authorization=<jwt> → payload.email (mock; imza doğrulaması Worker'da yapıldı).
  const m = /CF_Authorization=([^;]+)/.exec(cookieHeader);
  if (!m) return "";
  const parts = m[1].split(".");
  if (parts.length !== 3) return "";
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/") + "===".slice((parts[1].length + 3) % 4);
    const payload = JSON.parse(atob(b64)) as { email?: string };
    return payload.email ?? "";
  } catch {
    return "";
  }
}

let _signer: AccessSigner | null = null;
let _mocksReady = false;

/** ensureJwks, paylaşımlı ES256 signer'ı + JWKS + get-identity + Discord mock'larını kurar. */
export async function ensureJwks(): Promise<AccessSigner> {
  if (!_signer) _signer = await makeAccessSigner();
  if (!_mocksReady) {
    fetchMock.activate();
    fetchMock.disableNetConnect();
    fetchMock.get(`https://${TEAM_DOMAIN}`).intercept({ path: "/cdn-cgi/access/certs" }).reply(200, _signer.jwks).persist();
    // get-identity (§3.2): dinamik yanıt — identityMode + groupsByEmail'e göre.
    fetchMock
      .get(`https://${TEAM_DOMAIN}`)
      .intercept({ path: "/cdn-cgi/access/get-identity", method: "GET" })
      .reply((opts: { headers?: unknown }) => {
        identityCalls++;
        if (identityMode === "down") return { statusCode: 503, data: "upstream down" };
        const headers = (opts.headers ?? {}) as Record<string, string>;
        const cookie = headers.cookie ?? headers.Cookie ?? "";
        const email = decodeJwtEmail(String(cookie));
        if (identityMode === "badshape") {
          return { statusCode: 200, data: JSON.stringify({ email, groups: "not-an-array" }) };
        }
        const groups = (groupsByEmail.get(email) ?? []).map((g) => ({ email: g, name: g }));
        return { statusCode: 200, data: JSON.stringify({ email, groups }) };
      })
      .persist();
    // Discord webhook: her alert POST'unu kaydet + 204 dön.
    fetchMock
      .get(DISCORD_HOST)
      .intercept({ path: () => true, method: "POST" })
      .reply((opts: { body?: unknown }) => {
        discordCalls.push({ body: typeof opts.body === "string" ? opts.body : String(opts.body ?? "") });
        return { statusCode: 204, data: "" };
      })
      .persist();
    _mocksReady = true;
  }
  return _signer;
}

// --- Claim setleri --------------------------------------------------------------

/** validClaims, geçerli bir human read-AUD JWT claim seti üretir. */
export function validClaims(email = "writer@wapps.dev", extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_READ], email, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

/** validClaimsWrite, write-AUD (control-plane) human JWT claim seti. */
export function validClaimsWrite(email: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_WRITE], email, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

/** serviceTokenClaims, CF Access SERVICE-TOKEN şekilli JWT claim seti (common_name, email YOK). */
export function serviceTokenClaims(commonName: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: [AUD_READ], common_name: commonName, iat: now, nbf: now - 10, exp: now + 3600, ...extra };
}

// --- Policy seed -------------------------------------------------------------------

/** DEFAULT_RULES, testlerin çoğunun kullandığı temel kural seti. */
export function defaultRules(): PolicyRule[] {
  return [
    { group: "developers@wapps.co", projects: ["*"], keys: ["*", "!*_PROD_*"], verbs: ["read", "write", "rotate"] },
    { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*"] },
    { service: "svc-woodpecker", projects: ["vaulter"], keys: ["DEPLOY_*", "DB_*"], verbs: ["read"] },
  ];
}

/** seedPolicy, policy v1'i R2'ye doğrudan yazar (PUT rotası değil — fixture). */
export async function seedPolicy(rules: PolicyRule[], version = 1): Promise<void> {
  const doc = { schema: SCHEMA_POLICY, version, rules };
  const bytes = utf8(JSON.stringify(doc));
  await env.SECRETS_BUCKET.put(keyPolicyVersion(version), bytes);
  await env.SECRETS_BUCKET.put(keyPolicyCurrent(), utf8(JSON.stringify({ version, sha256: sha256Hex(bytes) })));
  __resetPolicyCache();
}

// --- Dünya sıfırlama ------------------------------------------------------------------

/** clearBucket, R2'deki tüm objeleri siler (isolatedStorage:false per-test temizlik). */
export async function clearBucket(): Promise<void> {
  let cursor: string | undefined;
  do {
    const l = await env.SECRETS_BUCKET.list({ cursor });
    for (const o of l.objects) await env.SECRETS_BUCKET.delete(o.key);
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
}

/**
 * resetWorld, testler arası TAM izolasyon: R2 + KV (RATE/JTI/IDENTITY_CACHE) +
 * D1 audit + AUDIT_LOG DO storage + izolat cache'leri (policy/kek) + mock durumu.
 */
export async function resetWorld(): Promise<void> {
  await clearBucket();
  for (const ns of [env.RATE, env.JTI_DENYLIST, env.IDENTITY_CACHE]) {
    let cursor: string | undefined;
    do {
      const l = await ns.list({ cursor });
      for (const k of l.keys) await ns.delete(k.name);
      cursor = l.list_complete ? undefined : l.cursor;
    } while (cursor);
  }
  try {
    await env.AUDIT_DB.prepare(`DELETE FROM audit`).run();
  } catch {
    /* şema henüz yok — ilk erişimde kurulur */
  }
  // Audit DO storage'ını DOĞRULAYARAK sıfırla: deleteAll transient invalidation'da
  // sessizce başarısız kalırsa eski `idem:<project>:<epoch>` marker'ları yaşar ve
  // (R2 wipe'ı epoch'ları 1'den başlattığı için) yeni testin outcome batch'i yanlış
  // DEDUP edilirdi — head==undefined görülene dek dene.
  const auditStub = () => env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME));
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      await runInDoRetry(auditStub(), (_i: unknown, state: DurableObjectState) => state.storage.deleteAll());
      const head = await runInDoRetry(auditStub(), (_i: unknown, state: DurableObjectState) => state.storage.get("head"));
      if (head === undefined) break; // doğrulandı: storage boş
    } catch (e) {
      if (attempt === 7 && !/invalidating|broken|please retry|code was updated|reset because/i.test(String(e))) throw e;
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  discordCalls.length = 0;
  groupsByEmail.clear();
  identityMode = "ok";
  identityCalls = 0;
  __resetPolicyCache();
  __resetKekCache();
}

/**
 * runInDoRetry, bir runInDurableObject çağrısını geçici DO invalidation'ında
 * (vitest-pool-workers modül reload) retry+backoff ile yeniden dener.
 */
export async function runInDoRetry<T>(stub: DurableObjectStub, fn: (instance: unknown, state: DurableObjectState) => T | Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await runInDurableObject(stub, fn as never);
    } catch (e) {
      if (attempt >= 10 || !/invalidating|broken|please retry/i.test(String(e))) throw e;
      await new Promise((r) => setTimeout(r, 5 * (attempt + 1)));
    }
  }
}

/**
 * callGate, Worker'ın fetch handler'ını doğrudan çağırır. envOverride ile secret/var
 * geçici ezilebilir (ör. MASTER_KEK rotasyonu, audit DO enjeksiyonu).
 */
export async function callGate(path: string, init: RequestInit, envOverride: Record<string, unknown> = {}): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`https://gate${path}`, init), { ...env, ...envOverride } as never, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

/** authHeader, bir JWT için Cf-Access-Jwt-Assertion header'ı üretir. */
export function authHeader(jwt: string, extra: Record<string, string> = {}): Record<string, string> {
  return { "Cf-Access-Jwt-Assertion": jwt, ...extra };
}

/** allAuditRows, D1 audit satırlarını seq sırasıyla döner. */
export interface AuditRowDb {
  seq: number;
  ts: string;
  principal: string;
  principal_type: string;
  project: string | null;
  key: string | null;
  verb: string;
  decision: string;
  intent: string | null;
  prev_hash: string;
  hash: string;
}
export async function allAuditRows(): Promise<AuditRowDb[]> {
  try {
    const r = await env.AUDIT_DB.prepare("SELECT * FROM audit ORDER BY seq ASC").all<AuditRowDb>();
    return r.results ?? [];
  } catch {
    return [];
  }
}

/**
 * settleAudit, audit satırlarını `ready` koşulu sağlanana dek bekler. Harness'ın
 * DO modül-invalidation'ı post-CAS outcome batch'ini pending-retry kuyruğuna
 * düşürebilir (ÜRÜN davranışı doğru: commit kalıcı, satır alarm'la drene edilir);
 * test, writer-DO alarm'ını tetikleyerek drenajı hızlandırır (üretimde 30 sn alarm).
 */
export async function settleAudit(project: string, ready: (rows: AuditRowDb[]) => boolean, tries = 20): Promise<AuditRowDb[]> {
  for (let i = 0; ; i++) {
    const rows = await allAuditRows();
    if (ready(rows) || i >= tries) return rows;
    try {
      const { runDurableObjectAlarm } = await import("cloudflare:test");
      await runDurableObjectAlarm(env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(project)));
    } catch {
      /* transient invalidation — sonraki turda tekrar */
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}
