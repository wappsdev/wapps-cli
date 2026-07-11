// secrets-gate Worker entrypoint — SERVER-DECRYPT v2 (SPEC §7.6 route table).
// Pivot (§0): zero-knowledge trust spine yerine CF Access kimliği + Google
// Workspace grup üyeliği (get-identity, §3) + policy.json (§4) + MASTER_KEK
// altında server-side zarf kriptosu (§2). Okumalar plaintext DÖNER (TLS + CF
// Access); yazmalar plaintext ALIR ve writer DO içinde mühürlenir (§2.7).
//
// Rota sınıfları: /v1/admin/* + /v1/policy = write-AUD (15 dk + WebAuthn app'i);
// kalan her şey read-AUD (§3.2/§7.6). Plaintext dönen okumalar SENKRON audit'lenir
// (§6.4 — ledger offboard rotate-oracle'ıdır); metadata okumaları async kalır.
// C2: hiçbir console.* çağrısına değer/DEK/KEK/MASTER_KEK verilmez.

import { Env, AuthFail, authenticate, loadAccessConfig, stripForgeableHeaders, Principal, resolveMachinePrincipal } from "./auth.js";
import { HTTP, jsonError, jsonOK } from "./errors.js";
import { sha256Hex, utf8 } from "./crypto/encoding.js";
import { MasterKey, loadMasterKeys, unwrapDEK, WrapError } from "./crypto/kek.js";
import { openValue, BlobError } from "./crypto/blob.js";
import {
  keyBlob,
  keyCurrent,
  keyManifest,
  getObject,
  validProject,
  validKeyName,
  deriveProjects,
  mapPool,
  BLOB_POOL,
  RESPONSE_MAX,
} from "./storage.js";
import { parseCurrentPointer, parseManifest, manifestObjectHash, DataManifest, ManifestEntry } from "./manifest.js";
import {
  AuthzPrincipal,
  LoadedPolicy,
  PolicyStoreError,
  PolicyVerb,
  Topology,
  authorize,
  filterReadableKeys,
  loadPolicy,
  rulesFor,
} from "./policy.js";
import { IdentityError, createGroupResolver } from "./identity.js";
import { ProjectWriterDO, WriteOp } from "./writer-do.js";
import { AuditLogDO } from "./audit-do.js";
import { scopeAllowsKey, scopeAllowsVerb } from "./mint.js";
import { checkRateLimit } from "./ratelimit.js";
import { auditReadAsync, auditAppendBatch, AuditRow, ipOf, rayOf, AUDIT_DO_NAME } from "./audit.js";
import { handleTokenMint } from "./token.js";
import { handleAdmin, AdminContext } from "./admin.js";
import { fireAlert, ALERT } from "./alerts.js";
import { doStubFetch } from "./do-util.js";
import { runGC, GCDeps } from "./gc.js";
import { escrowConfig, headObject, putObject, keyEscrowAuditAnchor } from "./escrow.js";

export { ProjectWriterDO, AuditLogDO };

// Topoloji (§3.2 PRIMARY / §3.3 FALLBACK): day-1 smoke test kararına kadar PRIMARY.
// FALLBACK seçilirse: burada "fallback" + get-identity'siz bir GroupResolver
// (aud→projects haritası) takılır; policy PUT validation'ı aud selector'lerini
// kabul etmeye başlar (§4.4). Rota/policy katmanı DEĞİŞMEZ.
export const TOPOLOGY: Topology = "primary";

const ACCESS_ASSERTION_HEADER = "Cf-Access-Jwt-Assertion";
const ROTATION_HEADER = "X-Wapps-Rotation"; // §6.4 rotate.step intent'i (bilgilendirici)
const INTENT_HEADER = "X-Wapps-Intent"; // "sync" → key.sync audit verb'ü

/** RequestCtx, bir isteğin çözülmüş kimlik + policy bağlamı. */
interface RequestCtx {
  principal: Principal;
  authz: AuthzPrincipal;
  policy: LoadedPolicy;
  adminEmails: string[];
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Fail-closed config (§3.1): ACCESS_* / MASTER_KEK / ADMIN_EMAILS eksik → 503 + A8.
    const cfg = loadAccessConfig(env);
    const masters = loadMasterKeys(env);
    const adminEmails = parseAdminEmails(env.ADMIN_EMAILS);
    if (!cfg || !masters || adminEmails.length === 0) {
      fireAlert(ctx, env, ALERT.A8, "SERVICE_MISCONFIGURED: access config / MASTER_KEK / ADMIN_EMAILS missing");
      return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "service configuration incomplete");
    }

    // Forgeable Access header'ı her istekten strip et (§3.4).
    request = stripForgeableHeaders(request);

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter((p) => p !== "");
    if (parts[0] !== "v1") return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");

    // Rota sınıfı → gereken AUD (§7.6): /v1/admin/* + /v1/policy = write.
    const isWriteApp = parts[1] === "admin" || parts[1] === "policy";
    const routeAud: "read" | "write" = isWriteApp ? "write" : "read";

    try {
      let principal = await authenticate(request, cfg, routeAud);

      // Rate limit: her authenticated principal 60/dk; 429 deny olarak audit'lenir.
      const rl = await checkRateLimit(env, principal.id);
      if (!rl.allowed) {
        auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal.id, ptypeOf(principal), "rate_limit", null, null, null));
        await countDenyBurst(ctx, env, principal.id);
        return new Response(JSON.stringify({ error: "RATE_LIMITED", message: "rate limit exceeded", retry_after: rl.retryAfter }), {
          status: HTTP.TOO_MANY,
          headers: { "content-type": "application/json", "Retry-After": String(rl.retryAfter) },
        });
      }

      // OPSİYONEL mint katmanı (§5.3): service principal Bearer minted-token
      // sunarsa scope-pinli machine principal'a daralır (asla genişlemez).
      // PRINCIPAL BINDING: minted sub, DIŞ CF-Access-doğrulanmış principal'a
      // eşit olmalı — başka principal'a mint'lenmiş token = privilege escalation
      // → TOKEN_PRINCIPAL_MISMATCH + deny audit (dış principal adına).
      if (principal.kind === "service" && (request.headers.get("authorization") ?? "").trim() !== "") {
        const outerId = principal.id;
        try {
          principal = await resolveMachinePrincipal(request, env, outerId);
        } catch (e) {
          if (e instanceof AuthFail && e.code === "TOKEN_PRINCIPAL_MISMATCH") {
            auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, outerId, "machine", "token.use", null, null, "TOKEN_PRINCIPAL_MISMATCH"));
            await countDenyBurst(ctx, env, outerId);
          }
          throw e;
        }
      }

      // Grup çözümü (§3.2): yalnızca human. Hata → 503 IDENTITY_UNAVAILABLE (fail-closed).
      let groups: string[] = [];
      if (principal.kind === "human") {
        const jwt = request.headers.get(ACCESS_ASSERTION_HEADER) ?? "";
        // Resolver istek-başına kurulur (ucuz closure): A10 alert'i BU isteğin
        // ExecutionContext'ine bağlanmalı (bayat ctx.waitUntil kullanılamaz).
        const resolver = createGroupResolver((env.ACCESS_TEAM_DOMAIN ?? "").trim(), env.IDENTITY_CACHE, (summary, detail) => {
          fireAlert(ctx, env, ALERT.A10, summary, detail);
        });
        groups = await resolver.resolve(jwt, principal.email);
      }
      const authz: AuthzPrincipal =
        principal.kind === "human"
          ? { kind: "human", id: principal.id, groups }
          : { kind: "service", id: principal.id, groups: [] };

      // Policy yükle (§4.1; izolat cache ≤60 s). Depo bozuksa fail-closed + A8.
      let policy: LoadedPolicy;
      try {
        policy = await loadPolicy(env.SECRETS_BUCKET, TOPOLOGY, adminEmails);
      } catch (e) {
        if (e instanceof PolicyStoreError) {
          fireAlert(ctx, env, ALERT.A8, "policy store integrity failure", { error: e.message });
          return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "policy store unreadable");
        }
        throw e;
      }
      const rctx: RequestCtx = { principal, authz, policy, adminEmails };

      // --- Control plane: /v1/policy + /v1/admin/* (write-AUD) ------------------
      if (isWriteApp) {
        const actx: AdminContext = { policy, authz, adminEmails, topology: TOPOLOGY };
        return await handleAdmin(request, env, ctx, parts, principal, actx);
      }

      // --- GET /v1/whoami --------------------------------------------------------
      if (parts[1] === "whoami" && parts.length === 2 && request.method === "GET") {
        return jsonOK({
          principal: authz.id,
          kind: principal.kind,
          ...(principal.kind === "human" ? { email: principal.email } : {}),
          ...(principal.kind === "service" ? { common_name: principal.commonName } : {}),
          groups,
          policy_version: policy.version,
          grants: rulesFor(policy.doc, authz),
          is_root_admin: principal.kind === "human" && adminEmails.includes(principal.email),
        });
      }

      // --- POST /v1/token (yalnızca service principal, §5.3) ----------------------
      if (parts[1] === "token" && parts.length === 2 && request.method === "POST") {
        if (principal.kind !== "service") return jsonError(HTTP.FORBIDDEN, "MACHINE_TOKEN_REQUIRED", "only service tokens may mint");
        return await handleTokenMint(request, env, ctx, principal.commonName, policy);
      }

      // --- projects/{p}/... --------------------------------------------------------
      if (parts[1] === "projects" && parts.length >= 4) {
        const project = parts[2];
        if (!validProject(project)) return jsonError(HTTP.UNPROCESSABLE, "PROJECT_MISMATCH", "invalid project segment");
        const kind = parts[3];

        if (kind === "keys" && parts.length === 4 && request.method === "GET") {
          return await handleKeysList(request, env, ctx, project, rctx, masters);
        }
        if (kind === "read" && parts.length === 4 && request.method === "POST") {
          return await handleRead(request, env, ctx, project, rctx, masters);
        }
        // MIGRATION_FREEZE (§7.5/§8.2) — BİLİNÇLİ ERTELEME: per-proje soak
        // write-freeze'i (set/import/sync/rotate → 409 MIGRATION_FREEZE) migration
        // fazının mekanizmasıdır (rollout adım 7; freeze migration kaydında deklare
        // edilir) ve `wapps migrate` tooling'iyle birlikte gelecektir. Worker
        // çekirdeğinde şimdilik YOKTUR — spec changelog rev 3'te not düşüldü.
        if (kind === "keys" && parts.length === 5 && request.method === "PUT") {
          return await handleSet(request, env, ctx, project, parts[4], rctx);
        }
        if (kind === "keys" && parts.length === 5 && request.method === "DELETE") {
          return await handleDelete(request, env, ctx, project, parts[4], rctx);
        }
        if (kind === "import" && parts.length === 4 && request.method === "POST") {
          return await handleImport(request, env, ctx, project, rctx);
        }
        if (kind === "manifests" && parts.length === 5 && request.method === "GET") {
          return await handleManifestRead(request, env, ctx, project, parts[4], rctx);
        }
      }
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");
    } catch (e) {
      if (e instanceof AuthFail) return e.toResponse();
      if (e instanceof IdentityError) {
        // §3.2 adım 5: fail-closed, retryable.
        return jsonError(HTTP.MISCONFIGURED, "IDENTITY_UNAVAILABLE", "identity/groups unresolvable; retry");
      }
      throw e;
    }
  },

  // scheduled — cron yüzeyi (§8.3 pinli küme): haftalık GC + NIGHTLY audit-head
  // çapası + escrow reconcile. event.cron ile dispatch (DO alarm'ı DEĞİL).
  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    if (event.cron === "0 3 * * 0") {
      ctx.waitUntil(runScheduledGC(env, ctx));
    }
    if (event.cron === "0 2 * * *") {
      ctx.waitUntil(runNightlyAnchor(env, ctx));
    }
  },
};

// --- Kimlik / yardımcılar -------------------------------------------------------

function parseAdminEmails(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

function ptypeOf(p: Principal): "human" | "machine" {
  return p.kind === "human" ? "human" : "machine";
}

function denyRow(
  request: Request,
  principalId: string,
  ptype: "human" | "machine",
  verb: string,
  project: string | null,
  key: string | null,
  intent: string | null,
): AuditRow {
  return { principal: principalId, principal_type: ptype, project, key, verb, decision: "deny", intent, ip: ipOf(request), cf_ray: rayOf(request) };
}

/**
 * can, data-plane authz (§4.3 + §5.3 minted-scope kesişimi): policy izin vermeli
 * VE (machine principal ise) minted scope da kapsamalı — scope asla genişletmez.
 */
function can(rctx: RequestCtx, project: string, key: string | null, verb: PolicyVerb): { allowed: boolean; reason?: string } {
  const p = rctx.principal;
  if (p.kind === "machine") {
    if (p.project !== project) return { allowed: false, reason: "token_project" };
    if (!scopeAllowsVerb(p.scope, verb)) return { allowed: false, reason: "token_verb" };
    if (key !== null && !scopeAllowsKey(p.scope, key)) return { allowed: false, reason: "token_key" };
  }
  const d = authorize(rctx.policy.doc, rctx.authz, project, key, verb);
  return d.allowed ? { allowed: true } : { allowed: false, reason: d.reason };
}

// --- A1/A2 burst detektörleri (KV pencere sayaçları) -------------------------------

/** countDenyBurst, A1 (deny spike): principal başına 5 dk penceresinde ≥10 deny. */
async function countDenyBurst(ctx: ExecutionContext, env: Env, principalId: string): Promise<void> {
  try {
    const window = Math.floor(Date.now() / 300_000);
    const key = `deny:${principalId}:${window}`;
    const n = (parseInt((await env.RATE.get(key)) ?? "0", 10) || 0) + 1;
    await env.RATE.put(key, String(n), { expirationTtl: 600 });
    if (n === 10) fireAlert(ctx, env, ALERT.A1, `denial spike by ${principalId}`, { principal: principalId, count: n });
  } catch {
    // sayaç best-effort; alert = tespit
  }
}

/** countReadBurst, A2 (value-read burst): principal başına 10 dk penceresinde ≥50 anahtar okuması. */
async function countReadBurst(ctx: ExecutionContext, env: Env, principalId: string, keys: number): Promise<void> {
  try {
    const window = Math.floor(Date.now() / 600_000);
    const key = `readburst:${principalId}:${window}`;
    const before = parseInt((await env.RATE.get(key)) ?? "0", 10) || 0;
    const after = before + keys;
    await env.RATE.put(key, String(after), { expirationTtl: 1200 });
    if (before < 50 && after >= 50) fireAlert(ctx, env, ALERT.A2, `value-read burst by ${principalId}`, { principal: principalId, count: after });
  } catch {
    // best-effort
  }
}

// --- Manifest yükleme (read path ortak) ---------------------------------------------

class ReadPathError extends Error {
  constructor(public status: number, public code: string, public detail?: Record<string, unknown>) {
    super(code);
  }
  toResponse(): Response {
    return jsonError(this.status, this.code, this.code, this.detail);
  }
}

/** loadCurrentManifest, current pointer + manifest'i zincir-bütünlük kontrolüyle yükler. */
async function loadCurrentManifest(env: Env, project: string): Promise<{ manifest: DataManifest; epoch: number; sha: string } | null> {
  const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
  if (!cur) return null;
  let ptr;
  try {
    ptr = parseCurrentPointer(cur.bytes);
  } catch {
    throw new ReadPathError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "current pointer malformed" });
  }
  const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, ptr.epoch));
  if (!man) throw new ReadPathError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "current manifest missing" });
  if (manifestObjectHash(man.bytes) !== ptr.manifestSha256) {
    throw new ReadPathError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "pointer/manifest hash mismatch" });
  }
  let m: DataManifest;
  try {
    m = parseManifest(man.bytes);
  } catch (e) {
    throw new ReadPathError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: (e as Error).message });
  }
  if (m.project !== project) throw new ReadPathError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", { reason: "manifest project mismatch" });
  return { manifest: m, epoch: ptr.epoch, sha: ptr.manifestSha256 };
}

function etagResponse(bodyStr: string, ifNoneMatch: string | null): Response | { etag: string } {
  const etag = `"${sha256Hex(utf8(bodyStr))}"`;
  if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "").trim() === etag) {
    return new Response(null, { status: HTTP.NOT_MODIFIED, headers: { ETag: etag } });
  }
  return { etag };
}

// --- GET /v1/projects/{p}/keys (metadata; liste FİLTRELİ, §4.3.3) --------------------

async function handleKeysList(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  project: string,
  rctx: RequestCtx,
  _masters: MasterKey[],
): Promise<Response> {
  // key=null proje-metadata op'u: bir kural principal+read+project'i eşlemeli (§4.3.3).
  const projectGate = can(rctx, project, null, "read");
  if (!projectGate.allowed) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "key.list", project, null, projectGate.reason ?? null));
    await countDenyBurst(ctx, env, rctx.authz.id);
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project", { dimension: projectGate.reason });
  }
  let loaded;
  try {
    loaded = await loadCurrentManifest(env, project);
  } catch (e) {
    if (e instanceof ReadPathError) return e.toResponse();
    throw e;
  }
  const allNames = loaded ? loaded.manifest.entries.map((e) => e.keyName) : [];
  // Liste OKUNABİLİR anahtarlara filtrelenir (§4.3.3) + minted scope kesişimi.
  const readable = filterReadableKeys(rctx.policy.doc, rctx.authz, project, allNames).filter(
    (k) => can(rctx, project, k, "read").allowed,
  );
  const entryByName = new Map<string, ManifestEntry>(loaded ? loaded.manifest.entries.map((e) => [e.keyName, e]) : []);
  const bodyStr = JSON.stringify({
    project,
    epoch: loaded?.epoch ?? 0,
    keys: readable.map((k) => ({ keyName: k, keyVersion: entryByName.get(k)?.keyVersion ?? 0 })),
  });
  const et = etagResponse(bodyStr, request.headers.get("if-none-match"));
  if (et instanceof Response) return et; // 304 → audit YOK (KEPT davranış)
  auditReadAsync(ctx, env.AUDIT_LOG, {
    principal: rctx.authz.id,
    principal_type: ptypeOf(rctx.principal),
    project,
    key: null,
    verb: "key.list",
    decision: "allow",
    ip: ipOf(request),
    cf_ray: rayOf(request),
  });
  return new Response(bodyStr, { status: HTTP.OK, headers: { "content-type": "application/json", ETag: et.etag } });
}

// --- GET /v1/projects/{p}/manifests/{current|epoch} (entries FİLTRELİ, §7.6) ---------

async function handleManifestRead(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  project: string,
  sel: string,
  rctx: RequestCtx,
): Promise<Response> {
  const projectGate = can(rctx, project, null, "read");
  if (!projectGate.allowed) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "manifest.read", project, null, projectGate.reason ?? null));
    await countDenyBurst(ctx, env, rctx.authz.id);
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project", { dimension: projectGate.reason });
  }
  let manifest: DataManifest | null = null;
  if (sel === "current") {
    let loaded;
    try {
      loaded = await loadCurrentManifest(env, project);
    } catch (e) {
      if (e instanceof ReadPathError) return e.toResponse();
      throw e;
    }
    if (!loaded) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "no current manifest");
    manifest = loaded.manifest;
  } else {
    const epoch = Number(sel);
    if (!Number.isInteger(epoch) || epoch < 1) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "bad epoch");
    const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, epoch));
    if (!man) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "manifest not found");
    try {
      manifest = parseManifest(man.bytes);
    } catch {
      return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "stored manifest unparsable");
    }
  }
  // entries, principal'ın OKUYABİLDİĞİ anahtarlara filtrelenir (§4.3.3/§7.6):
  // tek-anahtarlı bir principal projenin tam anahtar kümesini SAYAMAZ. Wrap'ler opak.
  const filtered = manifest.entries.filter((e) => can(rctx, project, e.keyName, "read").allowed);
  const bodyStr = JSON.stringify({ ...manifest, entries: filtered });
  const et = etagResponse(bodyStr, request.headers.get("if-none-match"));
  if (et instanceof Response) return et;
  auditReadAsync(ctx, env.AUDIT_LOG, {
    principal: rctx.authz.id,
    principal_type: ptypeOf(rctx.principal),
    project,
    key: null,
    verb: "manifest.read",
    decision: "allow",
    ip: ipOf(request),
    cf_ray: rayOf(request),
  });
  return new Response(bodyStr, { status: HTTP.OK, headers: { "content-type": "application/json", ETag: et.etag } });
}

// --- POST /v1/projects/{p}/read — PLAINTEXT bulk read (§7.4/§7.6) --------------------

async function handleRead(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  project: string,
  rctx: RequestCtx,
  masters: MasterKey[],
): Promise<Response> {
  let body: { keys?: unknown };
  try {
    body = (await request.json()) as { keys?: unknown };
  } catch {
    return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  if (!Array.isArray(body.keys) || body.keys.length === 0) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "keys required");
  const keys = [...new Set(body.keys.filter((k): k is string => typeof k === "string"))];
  if (keys.length !== body.keys.length) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "keys must be unique strings");
  for (const k of keys) {
    if (!validKeyName(k)) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", `invalid key name: ${k}`);
  }

  // ALL-OR-NOTHING policy (§7.6): reddedilen HERHANGİ bir anahtar tüm çağrıyı,
  // anahtarı adlandırarak düşürür.
  for (const k of keys) {
    const d = can(rctx, project, k, "read");
    if (!d.allowed) {
      auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "value.read", project, k, d.reason ?? null));
      await countDenyBurst(ctx, env, rctx.authz.id);
      return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "read denied", { key: k, dimension: d.reason });
    }
  }

  let loaded;
  try {
    loaded = await loadCurrentManifest(env, project);
  } catch (e) {
    if (e instanceof ReadPathError) return e.toResponse();
    throw e;
  }
  if (!loaded) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "project has no secrets");
  const byName = new Map(loaded.manifest.entries.map((e) => [e.keyName, e]));

  // Tüm anahtarlar manifest'te mi? (NOT_FOUND fail-fast, I/O'dan ÖNCE.)
  for (const k of keys) {
    if (!byName.get(k)) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "key not found", { key: k });
  }
  // Çöz: CHUNK'lar halinde (≤BLOB_POOL). Her chunk'ın blob'ları PARALEL getirilir (I/O
  // wall-time sink), sonra çözülüp ciphertext bırakılır → canlı ciphertext bir chunk ×
  // 64KB ile sınırlı (sıralı-tek-tek wall-time'ı aşıyordu; sınırsız Promise.all TÜM
  // ciphertext'i tutuyordu — codex P2). Toplam plaintext RESPONSE_MAX ile bantlanır.
  const values: Record<string, string> = {};
  let totalBytes = 0;
  for (let start = 0; start < keys.length; start += BLOB_POOL) {
    const chunk = keys.slice(start, start + BLOB_POOL);
    const blobs = await mapPool(chunk, BLOB_POOL, (k) => getObject(env.SECRETS_BUCKET, keyBlob(project, byName.get(k)!.blobHash)));
    for (let j = 0; j < chunk.length; j++) {
      const k = chunk[j];
      const entry = byName.get(k)!;
      const blob = blobs[j];
      if (!blob) {
        fireAlert(ctx, env, ALERT.A8, "referenced blob missing", { project, key: k });
        return jsonError(HTTP.MISCONFIGURED, "BLOB_MISSING", "referenced blob missing", { key: k });
      }
      if (sha256Hex(blob.bytes) !== entry.blobHash) {
        fireAlert(ctx, env, ALERT.A8, "blob content-address mismatch", { project, key: k });
        return jsonError(HTTP.MISCONFIGURED, "BLOB_HASH_MISMATCH", "blob bytes do not match address", { key: k });
      }
      let dek: Uint8Array;
      try {
        dek = unwrapDEK(masters, project, k, entry.keyVersion, entry.wrap);
      } catch (e) {
        if (e instanceof WrapError) {
          fireAlert(ctx, env, ALERT.A8, "DEK unwrap failed (tamper or key mismatch)", { project, key: k });
          return jsonError(HTTP.MISCONFIGURED, e.code === "ALG_UNSUPPORTED" ? "ALG_UNSUPPORTED" : "WRAP_INVALID", "wrap open failed", { key: k });
        }
        throw e;
      }
      try {
        const decoded = new TextDecoder().decode(openValue(dek, project, k, entry.keyVersion, blob.bytes));
        // SERİLEŞTİRİLMİŞ boyutu say (plaintext bayt DEĞİL): JSON.stringify kaçışları
        // (ör. NUL →   = 6 bayt) + anahtar adı gerçek yanıt/bellek maliyetidir (codex P3).
        totalBytes += JSON.stringify(decoded).length + k.length + 4; // +4 ≈ "":, çerçeve
        if (totalBytes > RESPONSE_MAX) return jsonError(HTTP.PAYLOAD_TOO_LARGE, "RESPONSE_TOO_LARGE", "read response exceeds the size cap; request fewer keys");
        values[k] = decoded;
      } catch (e) {
        if (e instanceof BlobError) {
          fireAlert(ctx, env, ALERT.A8, "blob open failed (tamper)", { project, key: k });
          return jsonError(HTTP.MISCONFIGURED, e.code, "blob open failed", { key: k });
        }
        throw e;
      } finally {
        dek.fill(0);
      }
    }
  }

  // SENKRON per-key audit (§6.4): DO ack'i plaintext'ten ÖNCE. Bulk = her anahtara
  // bir `value.read.bulk` satırı, TEK /append-batch ack'i. Audit down → 503, plaintext YOK.
  const verb = keys.length === 1 ? "value.read" : "value.read.bulk";
  const rows: AuditRow[] = keys.map((k) => ({
    principal: rctx.authz.id,
    principal_type: ptypeOf(rctx.principal),
    project,
    key: k,
    verb,
    decision: "allow",
    ip: ipOf(request),
    cf_ray: rayOf(request),
    token_jti: rctx.principal.kind === "machine" ? rctx.principal.jti : null,
  }));
  try {
    await auditAppendBatch(env.AUDIT_LOG, rows);
  } catch {
    fireAlert(ctx, env, ALERT.A8, "audit DO unavailable on plaintext read", { project });
    return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable — plaintext refused");
  }
  await countReadBurst(ctx, env, rctx.authz.id, keys.length);

  return jsonOK({ epoch: loaded.epoch, values });
}

// --- Write dispatch → PROJECT_WRITER DO (§7.6) ----------------------------------------

async function dispatchWrite(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  project: string,
  rctx: RequestCtx,
  op: WriteOp,
  auditVerb: string,
): Promise<Response> {
  const doHeaders: Record<string, string> = {
    "content-type": "application/json",
    "x-principal-id": rctx.authz.id,
    "x-principal-type": ptypeOf(rctx.principal),
    "x-token-jti": rctx.principal.kind === "machine" ? rctx.principal.jti : "",
    "x-intent": request.headers.get(INTENT_HEADER) ?? "",
    "x-audit-verb": auditVerb,
    "x-policy-version": String(rctx.policy.version),
    "x-cf-ip": ipOf(request) ?? "",
    "x-cf-ray": rayOf(request) ?? "",
  };
  const res = await doStubFetch(
    () => env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(project)),
    `https://do/commit?project=${encodeURIComponent(project)}`,
    { method: "POST", headers: doHeaders, body: JSON.stringify(op) },
  );
  if (res.status === HTTP.MISCONFIGURED) {
    const clone = res.clone();
    const j = (await clone.json().catch(() => ({}))) as { error?: string };
    if (j.error === "AUDIT_UNAVAILABLE") fireAlert(ctx, env, ALERT.A8, "audit DO unavailable on commit", { project });
  }
  return res;
}

/** writeAuditVerb, yazma outcome verb'ünü türetir (§6.4): rotation header →
 * rotate.step; sync intent → key.sync; yoksa temel verb. Header'lar bilgilendiricidir,
 * ASLA authz girdisi değildir — strip edilmiş header key.set'e düşer (oracle yine tam). */
function writeAuditVerb(request: Request, base: "key.set" | "key.import" | "key.delete"): string {
  if (base === "key.delete") return base;
  if ((request.headers.get(ROTATION_HEADER) ?? "").trim() !== "") return "rotate.step";
  if (base === "key.import" && (request.headers.get(INTENT_HEADER) ?? "").trim() === "sync") return "key.sync";
  return base;
}

async function handleSet(request: Request, env: Env, ctx: ExecutionContext, project: string, keyName: string, rctx: RequestCtx): Promise<Response> {
  if (!validKeyName(keyName)) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "invalid key name");
  const d = can(rctx, project, keyName, "write");
  if (!d.allowed) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "key.set", project, keyName, d.reason ?? null));
    await countDenyBurst(ctx, env, rctx.authz.id);
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "write denied", { key: keyName, dimension: d.reason });
  }
  let body: { value?: unknown; ifEpoch?: unknown };
  try {
    body = (await request.json()) as { value?: unknown; ifEpoch?: unknown };
  } catch {
    return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  if (typeof body.value !== "string") return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "value must be a string");
  const op: WriteOp = { op: "set", values: { [keyName]: body.value }, ifEpoch: typeof body.ifEpoch === "number" ? body.ifEpoch : undefined };
  return dispatchWrite(request, env, ctx, project, rctx, op, writeAuditVerb(request, "key.set"));
}

async function handleImport(request: Request, env: Env, ctx: ExecutionContext, project: string, rctx: RequestCtx): Promise<Response> {
  let body: { values?: unknown; ifEpoch?: unknown };
  try {
    body = (await request.json()) as { values?: unknown; ifEpoch?: unknown };
  } catch {
    return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  if (typeof body.values !== "object" || body.values === null || Array.isArray(body.values)) {
    return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "values must be an object");
  }
  const values = body.values as Record<string, unknown>;
  const names = Object.keys(values);
  if (names.length === 0) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "values empty");
  // Anahtar-SAYISI cap'i yok: import boyutu manifest 1 MB cap'iyle (MANIFEST_TOO_LARGE,
  // writer-DO) doğal olarak sınırlı → geçerli bir proje her zaman import edilebilir.
  for (const k of names) {
    if (!validKeyName(k)) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", `invalid key name: ${k}`);
    if (typeof values[k] !== "string") return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", `value for ${k} must be a string`);
  }
  // Policy: body'deki HER anahtar için write (§7.6).
  for (const k of names) {
    const d = can(rctx, project, k, "write");
    if (!d.allowed) {
      auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "key.import", project, k, d.reason ?? null));
      await countDenyBurst(ctx, env, rctx.authz.id);
      return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "write denied", { key: k, dimension: d.reason });
    }
  }
  const op: WriteOp = { op: "import", values: values as Record<string, string>, ifEpoch: typeof body.ifEpoch === "number" ? body.ifEpoch : undefined };
  return dispatchWrite(request, env, ctx, project, rctx, op, writeAuditVerb(request, "key.import"));
}

async function handleDelete(request: Request, env: Env, ctx: ExecutionContext, project: string, keyName: string, rctx: RequestCtx): Promise<Response> {
  if (!validKeyName(keyName)) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "invalid key name");
  const d = can(rctx, project, keyName, "write");
  if (!d.allowed) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, rctx.authz.id, ptypeOf(rctx.principal), "key.delete", project, keyName, d.reason ?? null));
    await countDenyBurst(ctx, env, rctx.authz.id);
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "write denied", { key: keyName, dimension: d.reason });
  }
  const op: WriteOp = { op: "delete", key: keyName };
  return dispatchWrite(request, env, ctx, project, rctx, op, "key.delete");
}

// --- Cron: GC + nightly audit-head anchor (§8.3) ---------------------------------------

/** runScheduledGC, haftalık GC cron'unu üretim bağımlılıklarıyla sürer. */
async function runScheduledGC(env: Env, ctx: ExecutionContext): Promise<void> {
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
    alert: (rule, summary, detail) => fireAlert(ctx, env, rule as typeof ALERT.A8, summary, detail),
  };
  await runGC(env.SECRETS_BUCKET, projects, deps);
}

/**
 * runNightlyAnchor, NIGHTLY cron'u (§8.3): D1 zincir head'ini ({last_seq,
 * last_hash, ts}) append-only B2'ye çapa olarak iter — CF-seviyesi bir ledger
 * yeniden-yazımı çapalara karşı tespit edilebilir. B2 yapılandırılmamışsa no-op.
 */
async function runNightlyAnchor(env: Env, ctx: ExecutionContext): Promise<void> {
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
    fireAlert(ctx, env, ALERT.A4, "nightly audit-head anchor push failed", { error: String(e) });
  }
}
