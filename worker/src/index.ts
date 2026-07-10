// secrets-gate Worker entrypoint (SPEC §6). Router + read endpoints (DO-free) +
// auth middleware + rate-limit + machine-token mint/verify + per-key authz +
// read-path async audit + freshness receipt + admin API + commit dispatch (DO).
//
// G6 çekirdeği (read/commit/blob + CF Access auth + M-of-N trust + semantik-diff
// authz) G7'de genişletildi: §6.1 rate-limit + minted-token, §6.3 per-key authz,
// §6.4 mint/revoke, §6.5 D1 hash-chained audit (attempt→outcome), §6.6 receipt,
// §6.9 admin API + pending-ops, §6.10 alerts. ERTELENDİ (G10): B2 escrow push,
// non-CF witness endpoint, GC cron.

import { Env, AuthFail, authenticate, loadAccessConfig, stripForgeableHeaders, Principal, resolveMachinePrincipal } from "./auth.js";
import { HTTP, jsonError } from "./errors.js";
import { sha256Hex } from "./crypto/verify.js";
import {
  keyBlob,
  keyCurrent,
  keyManifest,
  keyTrustCurrent,
  keyTrustManifest,
  getObject,
  validProject,
  validSha256Hex,
} from "./storage.js";
import { parseCurrentPointer, parseManifestBody } from "./manifest.js";
import { parseSignedObject } from "./crypto/verify.js";
import { loadTrustHead } from "./trust-loader.js";
import { hasVerbGrant, verbKeyAllowed, identityByID, TrustError, VerifiedEpoch } from "./trust.js";
import { ProjectWriterDO } from "./writer-do.js";
import { AuditLogDO } from "./audit-do.js";
import { AttestationDO } from "./attestation-do.js";
import { loadMintConfig, scopeAllowsKey, scopeAllowsVerb } from "./mint.js";
import { checkRateLimit } from "./ratelimit.js";
import { auditReadAsync, AuditRow, ipOf, rayOf } from "./audit.js";
import { handleTokenMint, revokeJti } from "./token.js";
import { handleAdmin } from "./admin.js";
import { issueReceipt } from "./receipt.js";
import { fireAlert, ALERT } from "./alerts.js";
import { ensureMirror } from "./grants-mirror.js";
import { doStubFetch } from "./do-util.js";

export { ProjectWriterDO, AuditLogDO, AttestationDO };

const BLOB_CAP = 65_536; // §5.7
const BLOB_OVERHEAD = 4 + 24 + 16; // magic + XChaCha nonce + Poly1305 tag (§3.5.4)

/** validFramingLength, depolanan blob uzunluğunun §3 padding-kova framing'ine uyduğunu doğrular. */
function validFramingLength(len: number): boolean {
  const bucket = len - BLOB_OVERHEAD;
  if (bucket === 256 || bucket === 1024) return true;
  const maxBucket = Math.floor((BLOB_CAP - BLOB_OVERHEAD) / 4096) * 4096; // 61440
  return bucket >= 4096 && bucket <= maxBucket && bucket % 4096 === 0;
}

function etagResponse(bytes: Uint8Array, etag: string, ifNoneMatch: string | null, contentType: string): Response {
  const quoted = `"${etag}"`;
  if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "").trim() === quoted) {
    return new Response(null, { status: HTTP.NOT_MODIFIED, headers: { ETag: quoted } });
  }
  return new Response(bytes, { status: HTTP.OK, headers: { "content-type": contentType, ETag: quoted } });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Fail-closed config (§6 intro): eksik → 503 tüm rotalarda.
    const cfg = loadAccessConfig(env);
    if (!cfg) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "access config missing");
    if (!(env.GENESIS_TRUST_SHA256 ?? "").trim()) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "genesis pin missing");
    if (!loadMintConfig(env)) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", "mint key missing/invalid");

    // Forgeable Access header'ı her istekten strip et (§6.1 step 8).
    request = stripForgeableHeaders(request);

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter((p) => p !== "");
    if (parts[0] !== "v1") return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");

    // Admin preflight (§6.9): CORS OPTIONS auth'tan ÖNCE (credential taşımaz).
    if (parts[1] === "admin" && request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "https://admin.meapps.dev",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
          "Access-Control-Allow-Headers": "content-type,authorization,cf-access-jwt-assertion",
          Vary: "Origin",
        },
      });
    }

    // Rota sınıfı → gereken AUD (§6 route table). Control-plane = write-AUD.
    const isAdmin = parts[1] === "admin";
    const isTokenRevoke = parts[1] === "token" && parts[2] === "revoke";
    const routeAud: "read" | "write" = isAdmin || isTokenRevoke ? "write" : "read";

    try {
      const principal = await authenticate(request, cfg, routeAud);

      // Rate limit (§6.1): her authenticated principal 60/dk. 304 poll'ları RATE'e
      // sayılır ama audit'lenmez; 429 ise deny olarak audit'lenir.
      const rl = await checkRateLimit(env, principal.id);
      if (!rl.allowed) {
        auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "rate_limit", null, null));
        return new Response(JSON.stringify({ error: "RATE_LIMITED", message: "rate limit exceeded", retry_after: rl.retryAfter }), {
          status: HTTP.TOO_MANY,
          headers: { "content-type": "application/json", "Retry-After": String(rl.retryAfter) },
        });
      }

      // POST /v1/token — TEK service-token kabul eden rota (§6.4).
      if (parts[1] === "token" && parts.length === 2 && request.method === "POST") {
        if (principal.kind !== "seed") return jsonError(HTTP.FORBIDDEN, "MACHINE_TOKEN_REQUIRED", "only service tokens may mint");
        const head = await trustHeadOr503(env);
        return await handleTokenMint(request, env, ctx, principal.commonName, head);
      }

      // POST /v1/token/revoke — admin (write-AUD).
      if (isTokenRevoke && request.method === "POST") {
        const head = await trustHeadOr503(env);
        if (principal.kind !== "human" || !head.manifest.admins.includes(principal.id)) {
          return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "revoke requires an admin");
        }
        let jti = "";
        try {
          jti = ((await request.json()) as { jti?: string }).jti ?? "";
        } catch {
          return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
        }
        if (!jti) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "jti required");
        try {
          await revokeJti(ctx, env, jti, principal.id, request);
        } catch {
          return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable");
        }
        return new Response(JSON.stringify({ jti, revoked: true }), { status: HTTP.OK, headers: { "content-type": "application/json" } });
      }

      // /v1/admin/* — control plane (§6.9).
      if (isAdmin) {
        const head = await trustHeadOr503(env);
        return await handleAdmin(request, env, ctx, parts, principal, head);
      }

      // Data-plane: seed → minted machine-token GEREKİR (§6.1 step 8).
      const dp: Principal = principal.kind === "seed" ? await resolveMachinePrincipal(request, env) : principal;

      // trust/current, trust/{epoch} (herhangi bir enrolled principal).
      if (parts[1] === "trust") {
        return await handleTrustRead(request, env, ctx, parts, dp);
      }

      // projects/{project}/...
      if (parts[1] === "projects" && parts.length >= 4) {
        const project = parts[2];
        if (!validProject(project)) return jsonError(HTTP.UNPROCESSABLE, "PROJECT_MISMATCH", "invalid project segment");
        const kind = parts[3];

        if (kind === "manifests" && request.method === "GET") {
          return await handleManifestRead(request, env, ctx, project, parts[4], dp);
        }
        if (kind === "receipt" && request.method === "GET") {
          return await handleReceipt(request, env, ctx, project, dp);
        }
        if (kind === "blobs" && parts.length === 5) {
          const sha = parts[4];
          if (!validSha256Hex(sha)) return jsonError(HTTP.BAD_REQUEST, "BLOB_HASH_MISMATCH", "invalid blob address");
          if (request.method === "GET") return await handleBlobRead(request, env, ctx, project, sha, dp);
          if (request.method === "PUT") return await handleBlobPut(request, env, project, sha, dp);
        }
        if (kind === "commit" && request.method === "POST") {
          return await handleCommit(request, env, ctx, project, dp);
        }
      }
      return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");
    } catch (e) {
      if (e instanceof AuthFail) return e.toResponse();
      if (e instanceof TrustError) return jsonError(HTTP.MISCONFIGURED, "SERVICE_MISCONFIGURED", e.message);
      throw e;
    }
  },
};

// --- Yardımcılar ------------------------------------------------------------

async function trustHeadOr503(env: Env): Promise<VerifiedEpoch> {
  return loadTrustHead(env.SECRETS_BUCKET, (env.GENESIS_TRUST_SHA256 ?? "").trim());
}

function ptypeOf(p: Principal): "human" | "machine" {
  return p.kind === "machine" ? "machine" : "human";
}
function allowRow(request: Request, p: Principal, verb: string, project: string | null, key: string | null): AuditRow {
  return { principal: p.id, principal_type: ptypeOf(p), project, key, verb, decision: "allow", ip: ipOf(request), cf_ray: rayOf(request), token_jti: p.kind === "machine" ? p.jti : null };
}
function denyRow(request: Request, p: Principal, verb: string, project: string | null, key: string | null): AuditRow {
  return { principal: p.id, principal_type: ptypeOf(p), project, key, verb, decision: "deny", ip: ipOf(request), cf_ray: rayOf(request), token_jti: p.kind === "machine" ? p.jti : null };
}

// Per-key / project authz (§6.3), makine principal'ları token scope ile SINIRLI.
function machineScopeOk(p: Principal, project: string, verb: string, key: string | null): boolean {
  if (p.kind !== "machine") return true;
  if (p.project !== project) return false;
  if (!scopeAllowsVerb(p.scope, verb)) return false;
  if (key !== null && !scopeAllowsKey(p.scope, key)) return false;
  return true;
}
function canProject(head: VerifiedEpoch, p: Principal, project: string, verb: string): boolean {
  return hasVerbGrant(head.manifest, p.id, project, verb) && machineScopeOk(p, project, verb, null);
}
function canKey(head: VerifiedEpoch, p: Principal, project: string, verb: string, key: string): boolean {
  return verbKeyAllowed(head.manifest, p.id, project, verb, key) && machineScopeOk(p, project, verb, key);
}

// --- Read handlers (DO-free, §5.5 rule 5; read-path audit ASENKRON, §6.5) ---

async function handleTrustRead(request: Request, env: Env, ctx: ExecutionContext, parts: string[], principal: Principal): Promise<Response> {
  const head = await trustHeadOr503(env);
  // Herhangi bir enrolled principal (§6 route table).
  if (!identityByID(head.manifest, principal.id)) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "trust.read", null, null));
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "not an enrolled identity");
  }
  const ifNoneMatch = request.headers.get("if-none-match");
  if (parts[2] === "current") {
    const o = await getObject(env.SECRETS_BUCKET, keyTrustCurrent());
    if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "trust/current not found");
    const res = etagResponse(o.bytes, sha256Hex(o.bytes), ifNoneMatch, "application/json");
    if (res.status !== HTTP.NOT_MODIFIED) auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "trust.read", null, null));
    return res;
  }
  const epoch = Number(parts[2]);
  if (!Number.isInteger(epoch) || epoch < 1) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "bad trust epoch");
  const o = await getObject(env.SECRETS_BUCKET, keyTrustManifest(epoch));
  if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "trust epoch not found");
  const res = etagResponse(o.bytes, sha256Hex(o.bytes), ifNoneMatch, "application/json");
  if (res.status !== HTTP.NOT_MODIFIED) auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "trust.read", null, null));
  return res;
}

async function handleManifestRead(request: Request, env: Env, ctx: ExecutionContext, project: string, sel: string, principal: Principal): Promise<Response> {
  const head = await trustHeadOr503(env);
  // Manifest read = proje-seviyesi read grant (anahtar ADLARI gizli değil, §6.3).
  if (!canProject(head, principal, project, "read")) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "read", project, null));
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project (or token scope)");
  }
  const ifNoneMatch = request.headers.get("if-none-match");

  if (sel === "current") {
    const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
    if (!cur) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "no current manifest");
    const ptr = parseCurrentPointer(cur.bytes);
    if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "").trim() === `"${ptr.manifestSha256}"`) {
      return new Response(null, { status: HTTP.NOT_MODIFIED, headers: { ETag: `"${ptr.manifestSha256}"` } });
    }
    const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, ptr.epoch));
    if (!man) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "current manifest object missing");
    auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "read", project, null));
    return etagResponse(man.bytes, ptr.manifestSha256, ifNoneMatch, "application/json");
  }

  const epoch = Number(sel);
  if (!Number.isInteger(epoch) || epoch < 1) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "bad epoch");
  const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, epoch));
  if (!man) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "manifest not found");
  const res = etagResponse(man.bytes, sha256Hex(man.bytes), ifNoneMatch, "application/json");
  if (res.status !== HTTP.NOT_MODIFIED) auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "read", project, null));
  return res;
}

async function handleBlobRead(request: Request, env: Env, ctx: ExecutionContext, project: string, sha: string, principal: Principal): Promise<Response> {
  const head = await trustHeadOr503(env);
  // Per-key authz (§6.3 blob read): blob hash → current manifest'teki anahtar(lar)a
  // eşle; principal en az birinde 'read' tutmalı (makine: grants ∩ token scope).
  const keyNames = await blobKeyNames(env, project, sha);
  let okKey: string | null = null;
  if (keyNames.length > 0) {
    const found = keyNames.find((k) => canKey(head, principal, project, "read", k));
    if (!found) {
      auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "blob.get", project, keyNames[0]));
      return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant on any key referencing this blob");
    }
    okKey = found;
  } else {
    // Current manifest'te referanslanmayan blob (orphan/historical). MAKİNE principal'ları
    // için kaba proje-read gate'ine DÜŞME (§6.3 per-key/token-key confinement): anahtar A'ya
    // scoped bir token, geçmiş epoch'tan hash ile anahtar-scope'unu aşan blob'u OKUYAMAMALI
    // → deny. İnsan principal'ları için proje-reader manifest'ten TÜM blobHash'leri zaten
    // görür (404 sızıntı değil), dolayısıyla kaba proje-read gate KORUNUR.
    if (principal.kind === "machine") {
      auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "blob.get", project, null));
      return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "machine token confined to its key scope; unreferenced/historical blob denied");
    }
    if (!canProject(head, principal, project, "read")) {
      auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "blob.get", project, null));
      return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project (or token scope)");
    }
  }
  const o = await getObject(env.SECRETS_BUCKET, keyBlob(project, sha));
  if (!o) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "blob not found");
  const ifNoneMatch = request.headers.get("if-none-match");
  const res = etagResponse(o.bytes, sha, ifNoneMatch, "application/octet-stream");
  if (res.status !== HTTP.NOT_MODIFIED) {
    auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "blob.get", project, okKey));
    // A2 (§6.10): tek principal 10dk'da ≥50 distinct blob → cache-harvest detektörü.
    await maybeBurstAlert(ctx, env, principal, project);
  }
  return res;
}

/** blobKeyNames, current manifest'te bu blob hash'ini referanslayan anahtar adları. */
async function blobKeyNames(env: Env, project: string, sha: string): Promise<string[]> {
  const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
  if (!cur) return [];
  const ptr = parseCurrentPointer(cur.bytes);
  const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, ptr.epoch));
  if (!man) return [];
  const signed = parseSignedObject(JSON.parse(new TextDecoder().decode(man.bytes)));
  const body = parseManifestBody(signed.bytes);
  return body.entries.filter((e) => e.blobHash === sha).map((e) => e.keyName);
}

// A2 blob-fetch burst detektörü (basit KV distinct-sayaç; RATE binding'i tekrar kullanır).
async function maybeBurstAlert(ctx: ExecutionContext, env: Env, principal: Principal, project: string): Promise<void> {
  const window = Math.floor(Date.now() / 600_000); // 10 dk
  const key = `burst:${principal.id}:${window}`;
  const n = (parseInt((await env.RATE.get(key)) ?? "0", 10) || 0) + 1;
  await env.RATE.put(key, String(n), { expirationTtl: 1200 });
  if (n === 50) fireAlert(ctx, env, ALERT.A2, `blob-fetch burst by ${principal.id}`, { principal: principal.id, project, count: n });
}

async function handleReceipt(request: Request, env: Env, ctx: ExecutionContext, project: string, principal: Principal): Promise<Response> {
  const head = await trustHeadOr503(env);
  if (!canProject(head, principal, project, "read")) {
    auditReadAsync(ctx, env.AUDIT_LOG, denyRow(request, principal, "receipt", project, null));
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no read grant in project");
  }
  const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
  if (!cur) return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "no current manifest");
  const ptr = parseCurrentPointer(cur.bytes);
  const receipt = await issueReceipt(env, ptr.manifestSha256, ptr.epoch);
  auditReadAsync(ctx, env.AUDIT_LOG, allowRow(request, principal, "receipt", project, null));
  return new Response(JSON.stringify(receipt), { status: HTTP.OK, headers: { "content-type": "application/json" } });
}

// --- Blob PUT (§6.2 blob upload) --------------------------------------------

async function handleBlobPut(request: Request, env: Env, project: string, sha: string, principal: Principal): Promise<Response> {
  const head = await trustHeadOr503(env);
  if (!canProject(head, principal, project, "write")) {
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "no write grant in project (or token scope)");
  }
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length > BLOB_CAP) return jsonError(HTTP.PAYLOAD_TOO_LARGE, "BLOB_TOO_LARGE", "blob exceeds 64 KB");
  if (!validFramingLength(body.length)) return jsonError(HTTP.BAD_REQUEST, "PADDING_INVALID", "blob length not a valid framing length");
  const got = sha256Hex(body);
  if (got !== sha) return jsonError(HTTP.BAD_REQUEST, "BLOB_HASH_MISMATCH", "bytes do not hash to path");
  const existing = await env.SECRETS_BUCKET.head(keyBlob(project, sha));
  if (!existing) await env.SECRETS_BUCKET.put(keyBlob(project, sha), body, { onlyIf: { etagDoesNotMatch: "*" } });
  return new Response(JSON.stringify({ sha256: sha }), { status: HTTP.OK, headers: { "content-type": "application/json" } });
}

// --- Commit dispatch → PROJECT_WRITER DO (§6.2) -----------------------------

async function handleCommit(request: Request, env: Env, ctx: ExecutionContext, project: string, principal: Principal): Promise<Response> {
  const rawWrapper = await request.text();
  // Mirror'ı doğrulanmış trust head'ine senkronla (audit forensics + admin metadata, §6.3).
  try {
    const head = await trustHeadOr503(env);
    await ensureMirror(env, head.manifest);
  } catch {
    // Mirror rebuild başarısızlığı commit'i düşürmez (authz DO'da manifest'ten yapılır).
  }
  const doHeaders: Record<string, string> = {
    "content-type": "application/json",
    "x-principal-id": principal.id,
    "x-principal-type": ptypeOf(principal),
    "x-token-jti": principal.kind === "machine" ? principal.jti : "",
    // Minted token'ın SCOPE'unu (verbs+keys) DO'ya taşı → yazma yolunda least-privilege
    // enforcement (§6.3 grants ∩ token scope; §6.2 step 8). İnsan principal'larının
    // (CF-Access JWT) token scope'u yoktur → boş. Client-forge riski yok: bu header
    // doğrulanmış principal.scope'tan türetilir, inbound header'dan DEĞİL.
    "x-token-scope": principal.kind === "machine" ? JSON.stringify(principal.scope) : "",
    "x-intent": request.headers.get("x-wapps-intent") ?? "",
    "x-genesis-pin": (env.GENESIS_TRUST_SHA256 ?? "").trim(),
    "x-cf-ip": ipOf(request) ?? "",
    "x-cf-ray": rayOf(request) ?? "",
  };
  const res = await doStubFetch(
    () => env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(project)),
    `https://do/commit?project=${encodeURIComponent(project)}`,
    { method: "POST", headers: doHeaders, body: rawWrapper },
  );
  if (res.status === HTTP.OK) {
    // 18. Yanıta taze liveness receipt ekle (§6.2 step 18 / §6.6).
    const body = (await res.json()) as { epoch: number; manifestSha256: string };
    let receipt: unknown = undefined;
    try {
      receipt = await issueReceipt(env, body.manifestSha256, body.epoch);
    } catch {
      // Receipt üretilemezse commit yine başarılı (freshness attestation best-effort).
    }
    return new Response(JSON.stringify({ ...body, receipt }), { status: HTTP.OK, headers: { "content-type": "application/json" } });
  }
  // A8 (§6.10): audit DO down → commit fail-closed 503 AUDIT_UNAVAILABLE → alert.
  if (res.status === HTTP.MISCONFIGURED) {
    const clone = res.clone();
    const j = (await clone.json().catch(() => ({}))) as { error?: string };
    if (j.error === "AUDIT_UNAVAILABLE") fireAlert(ctx, env, ALERT.A8, "audit DO unavailable on commit", { project });
  }
  return res;
}
