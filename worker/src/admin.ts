// Admin API + pending-operations kuyruğu (SPEC §6.9). Control-plane: write-AUD
// (15dk, WebAuthn) + email SIGNED trust manifest'te admin üyesi + strict CORS.
// KRİTİK model (seam #1): tarayıcılar donanım age kimliğini süremez / manifest
// imzalayamaz → admin API TRUST/GRANT/WRAP/VALUE'yu DOĞRUDAN MUTASYON ETMEZ. Panel
// ÖNERİR (pending-ops), enrolled makine CLI ceremony'si imzalar+commit'ler. Kuyruk
// girdileri SIFIR otorite taşır. Tüm admin çağrıları audit'lenir (admin.* / denials).

import { HTTP, jsonError } from "./errors.js";
import { Env, Principal } from "./auth.js";
import { VerifiedEpoch } from "./trust.js";
import { auditAppendSync, AuditRow, ipOf, rayOf } from "./audit.js";
import { revokeJti } from "./token.js";
import { attestationPubkey } from "./receipt.js";
import { activeMintKid } from "./mint.js";
import { ensureSchema } from "./schema.js";
import { uuidv7 } from "./jose.js";
import { keyCurrent, keyManifest, keyTrustManifest } from "./storage.js";
import { parseCurrentPointer, parseManifestBody } from "./manifest.js";
import { parseSignedObject } from "./crypto/verify.js";

const ADMIN_ORIGIN = "https://admin.meapps.dev"; // strict, wildcard YOK (§6.9)
const PENDING_TTL_DAYS = 7;
const PENDING_TYPES = new Set(["grant", "revoke", "offboard", "rotation", "token_policy", "machine_enroll", "token_revoke"]);

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": ADMIN_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "content-type,authorization,cf-access-jwt-assertion",
    Vary: "Origin",
  };
}
function withCors(res: Response): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(corsHeaders())) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}
function adminJson(body: unknown, status = 200): Response {
  return withCors(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}
function adminErr(status: number, code: string, message: string, detail?: Record<string, unknown>): Response {
  return withCors(jsonError(status, code, message, detail));
}

/** isAdmin, email'in SIGNED trust manifest'te admin üyesi olup olmadığı (§6.9). */
function isAdmin(head: VerifiedEpoch, principalId: string): boolean {
  return head.manifest.admins.includes(principalId);
}

async function auditAdmin(env: Env, principal: Principal, verb: string, decision: "allow" | "deny", request: Request, extra?: Partial<AuditRow>): Promise<void> {
  const row: AuditRow = {
    principal: principal.id,
    principal_type: "human",
    verb,
    decision,
    ip: ipOf(request),
    cf_ray: rayOf(request),
    ...extra,
  };
  // Control-plane: SENKRON audit. Audit DO down → çağıran 503'e çevirir.
  await auditAppendSync(env.AUDIT_LOG, row);
}

/**
 * handleAdmin, /v1/admin/* dispatcher. Çağıran ZATEN write-AUD ile authenticate etmiş
 * ve human principal'ı geçmiştir; burada admin üyeliği + CORS + rota kontrolü yapılır.
 */
export async function handleAdmin(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  parts: string[],
  principal: Principal,
  head: VerifiedEpoch,
): Promise<Response> {
  // Preflight (§6.9): non-GET için OPTIONS.
  if (request.method === "OPTIONS") return withCors(new Response(null, { status: 204 }));

  if (principal.kind !== "human") return adminErr(HTTP.FORBIDDEN, "AUD_MISMATCH", "admin requires a human session");
  if (!isAdmin(head, principal.id)) {
    try {
      await auditAdmin(env, principal, "admin.denied", "deny", request, { intent: "not_admin" });
    } catch {
      /* best-effort deny logging */
    }
    return adminErr(HTTP.FORBIDDEN, "GRANT_DENIED", "not an admin member of the signed trust manifest");
  }

  try {
    const sub = parts[2]; // v1 / admin / <sub>
    if (sub === "audit" && request.method === "GET") return await adminAuditQuery(request, env, principal);
    if (sub === "projects" && request.method === "GET") return await adminProjects(request, env, principal, parts);
    if (sub === "tokens" && parts.length === 3 && request.method === "GET") return await adminTokens(request, env, principal);
    if (sub === "tokens" && parts[3] === "revoke" && request.method === "POST") return await adminRevoke(request, env, ctx, principal);
    if (sub === "gc" && parts[3] === "run" && request.method === "POST") return await adminGcRun(request, env, principal);
    if (sub === "attestation" && request.method === "GET") return await adminAttestation(request, env, principal);
    if (sub === "pending-ops") return await adminPendingOps(request, env, principal, parts, head);
    return adminErr(HTTP.NOT_FOUND, "NOT_FOUND", "unknown admin route");
  } catch (e) {
    if (e instanceof AuditDown) return adminErr(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable");
    throw e;
  }
}

class AuditDown extends Error {}
async function auditAdminOr503(env: Env, principal: Principal, verb: string, decision: "allow" | "deny", request: Request, extra?: Partial<AuditRow>): Promise<void> {
  try {
    await auditAdmin(env, principal, verb, decision, request, extra);
  } catch {
    throw new AuditDown();
  }
}

// --- Audit query (§6.9) ----------------------------------------------------

async function adminAuditQuery(request: Request, env: Env, principal: Principal): Promise<Response> {
  await ensureSchema(env.AUDIT_DB);
  const u = new URL(request.url);
  const clauses: string[] = [];
  const binds: (string | number)[] = [];
  const eq = (col: string, param: string | null) => {
    if (param) {
      clauses.push(`${col} = ?`);
      binds.push(param);
    }
  };
  eq("principal", u.searchParams.get("principal"));
  eq("project", u.searchParams.get("project"));
  eq("key", u.searchParams.get("key"));
  eq("verb", u.searchParams.get("verb"));
  eq("decision", u.searchParams.get("decision"));
  eq("token_jti", u.searchParams.get("jti"));
  const from = u.searchParams.get("from");
  const to = u.searchParams.get("to");
  if (from) {
    clauses.push("ts >= ?");
    binds.push(from);
  }
  if (to) {
    clauses.push("ts <= ?");
    binds.push(to);
  }
  const limit = Math.min(1000, Math.max(1, parseInt(u.searchParams.get("limit") ?? "200", 10) || 200));
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await env.AUDIT_DB.prepare(`SELECT * FROM audit ${where} ORDER BY seq DESC LIMIT ?`)
    .bind(...binds, limit)
    .all();
  await auditAdminOr503(env, principal, "admin.audit.query", "allow", request);
  return adminJson({ rows: rows.results ?? [] });
}

// --- Metadata (§6.9) — NEVER values ----------------------------------------

async function adminProjects(request: Request, env: Env, principal: Principal, parts: string[]): Promise<Response> {
  // /v1/admin/projects   veya  /v1/admin/projects/{p}/keys
  if (parts.length >= 5 && parts[4] === "keys") {
    const project = parts[3];
    const cur = await env.SECRETS_BUCKET.get(keyCurrent(project));
    if (!cur) return adminErr(HTTP.NOT_FOUND, "NOT_FOUND", "no current manifest");
    const ptr = parseCurrentPointer(new Uint8Array(await cur.arrayBuffer()));
    const man = await env.SECRETS_BUCKET.get(keyManifest(project, ptr.epoch));
    if (!man) return adminErr(HTTP.NOT_FOUND, "NOT_FOUND", "manifest object missing");
    const signed = parseSignedObject(JSON.parse(new TextDecoder().decode(new Uint8Array(await man.arrayBuffer()))));
    const body = parseManifestBody(signed.bytes);
    const keys = body.entries.map((e) => ({ keyName: e.keyName, keyVersion: e.keyVersion, wrapSetSize: e.wraps.length, hasRotation: e.hasRotation }));
    await auditAdminOr503(env, principal, "admin.projects.keys", "allow", request, { project });
    return adminJson({ project, epoch: ptr.epoch, keys });
  }
  // Proje listesi: R2 prefix'inden benzersiz proje adları (metadata).
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const l = await env.SECRETS_BUCKET.list({ prefix: "secrets/", cursor, delimiter: "/" });
    for (const p of l.delimitedPrefixes ?? []) {
      const name = p.replace(/^secrets\//, "").replace(/\/$/, "");
      if (name) seen.add(name);
    }
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  await auditAdminOr503(env, principal, "admin.projects.list", "allow", request);
  return adminJson({ projects: [...seen] });
}

async function adminTokens(request: Request, env: Env, principal: Principal): Promise<Response> {
  await ensureSchema(env.AUDIT_DB);
  // Aktif mint'ler (audit token.mint) + deny-list durumu.
  const mints = await env.AUDIT_DB.prepare("SELECT ts, principal, project, token_jti, intent FROM audit WHERE verb = 'token.mint' AND decision = 'allow' ORDER BY seq DESC LIMIT 100").all();
  const revoked = await env.AUDIT_DB.prepare("SELECT token_jti, ts FROM audit WHERE verb = 'token.revoke' ORDER BY seq DESC LIMIT 100").all();
  await auditAdminOr503(env, principal, "admin.tokens.list", "allow", request);
  return adminJson({ active_mint_kid: activeMintKid(env), mints: mints.results ?? [], revoked: revoked.results ?? [] });
}

async function adminRevoke(request: Request, env: Env, ctx: ExecutionContext, principal: Principal): Promise<Response> {
  let jti = "";
  try {
    jti = ((await request.json()) as { jti?: string }).jti ?? "";
  } catch {
    return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  if (!jti) return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "jti required");
  try {
    await revokeJti(ctx, env, jti, principal.id, request);
  } catch {
    return adminErr(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable — revoke not recorded");
  }
  return adminJson({ jti, revoked: true });
}

async function adminGcRun(request: Request, env: Env, principal: Principal): Promise<Response> {
  // GC (§6.7) G10'a ERTELENDİ — bu rota şimdilik yalnızca audit + 202 döner (escrow
  // doğrulama koşulu G10'da). NOT: gerçek GC witness-verified snapshot gerektirir.
  await auditAdminOr503(env, principal, "admin.gc.run", "allow", request, { intent: "deferred_g10" });
  return adminJson({ status: "accepted", note: "GC deferred to G10 (escrow-verified deletion condition)" }, HTTP.ACCEPTED);
}

async function adminAttestation(request: Request, env: Env, principal: Principal): Promise<Response> {
  const pub = await attestationPubkey(env);
  await auditAdminOr503(env, principal, "admin.attestation.pubkey", "allow", request);
  return adminJson(pub);
}

// --- Pending-ops kuyruğu (§6.9) --------------------------------------------

async function adminPendingOps(request: Request, env: Env, principal: Principal, parts: string[], head: VerifiedEpoch): Promise<Response> {
  await ensureSchema(env.AUDIT_DB);
  // /v1/admin/pending-ops            POST propose | GET list
  // /v1/admin/pending-ops/{id}       GET
  // /v1/admin/pending-ops/{id}/withdraw   POST
  // /v1/admin/pending-ops/{id}/resolve    POST
  const id = parts[3];
  const action = parts[4];

  if (!id) {
    if (request.method === "POST") return await proposeOp(request, env, principal);
    if (request.method === "GET") return await listOps(request, env, principal);
    return adminErr(HTTP.NOT_FOUND, "NOT_FOUND", "bad pending-ops route");
  }
  if (!action && request.method === "GET") return await getOp(request, env, principal, id);
  if (action === "withdraw" && request.method === "POST") return await transitionOp(request, env, principal, id, "withdrawn");
  if (action === "resolve" && request.method === "POST") return await resolveOp(request, env, principal, id, head);
  return adminErr(HTTP.NOT_FOUND, "NOT_FOUND", "bad pending-ops route");
}

async function proposeOp(request: Request, env: Env, principal: Principal): Promise<Response> {
  let bodyObj: { type?: unknown; payload?: unknown };
  try {
    bodyObj = (await request.json()) as { type?: unknown; payload?: unknown };
  } catch {
    return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  const type = typeof bodyObj.type === "string" ? bodyObj.type : "";
  if (!PENDING_TYPES.has(type)) return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "invalid pending-op type");
  const payload = JSON.stringify(bodyObj.payload ?? {});
  const id = uuidv7();
  const now = new Date();
  const proposedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + PENDING_TTL_DAYS * 86400_000).toISOString();
  await env.AUDIT_DB.prepare(
    "INSERT INTO pending_ops (id, type, payload, proposed_by, proposed_at, status, expires_at) VALUES (?,?,?,?,?, 'proposed', ?)",
  )
    .bind(id, type, payload, principal.id, proposedAt, expiresAt)
    .run();
  await auditAdminOr503(env, principal, "admin.pending_op.propose", "allow", request, { intent: type });
  return adminJson({ id, type, status: "proposed", proposed_by: principal.id, proposed_at: proposedAt, expires_at: expiresAt }, HTTP.CREATED);
}

async function listOps(request: Request, env: Env, principal: Principal): Promise<Response> {
  const status = new URL(request.url).searchParams.get("status");
  const rows = status
    ? await env.AUDIT_DB.prepare("SELECT * FROM pending_ops WHERE status = ? ORDER BY proposed_at DESC").bind(status).all()
    : await env.AUDIT_DB.prepare("SELECT * FROM pending_ops ORDER BY proposed_at DESC").all();
  await auditAdminOr503(env, principal, "admin.pending_op.list", "allow", request);
  return adminJson({ ops: (rows.results ?? []).map(derivedExpiry) });
}

async function getOp(request: Request, env: Env, principal: Principal, id: string): Promise<Response> {
  const row = await env.AUDIT_DB.prepare("SELECT * FROM pending_ops WHERE id = ?").bind(id).first();
  if (!row) return adminErr(HTTP.NOT_FOUND, "PENDING_OP_NOT_FOUND", "no such pending op");
  await auditAdminOr503(env, principal, "admin.pending_op.get", "allow", request, { intent: id });
  return adminJson(derivedExpiry(row as Record<string, unknown>));
}

async function transitionOp(request: Request, env: Env, principal: Principal, id: string, to: "withdrawn"): Promise<Response> {
  const row = (await env.AUDIT_DB.prepare("SELECT * FROM pending_ops WHERE id = ?").bind(id).first()) as Record<string, unknown> | null;
  if (!row) return adminErr(HTTP.NOT_FOUND, "PENDING_OP_NOT_FOUND", "no such pending op");
  const cur = effectiveStatus(row);
  if (cur !== "proposed") return adminErr(HTTP.CONFLICT, "PENDING_OP_INVALID_STATE", `cannot ${to} from ${cur}`);
  await env.AUDIT_DB.prepare("UPDATE pending_ops SET status = ? WHERE id = ?").bind(to, id).run();
  await auditAdminOr503(env, principal, "admin.pending_op.withdraw", "allow", request, { intent: id });
  return adminJson({ id, status: to });
}

async function resolveOp(request: Request, env: Env, principal: Principal, id: string, head: VerifiedEpoch): Promise<Response> {
  void head;
  let bodyObj: { status?: unknown; committed_epoch?: unknown; resolution_note?: unknown };
  try {
    bodyObj = (await request.json()) as typeof bodyObj;
  } catch {
    return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
  const status = bodyObj.status === "committed" || bodyObj.status === "rejected" ? bodyObj.status : null;
  if (!status) return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "status must be committed|rejected");
  const row = (await env.AUDIT_DB.prepare("SELECT * FROM pending_ops WHERE id = ?").bind(id).first()) as Record<string, unknown> | null;
  if (!row) return adminErr(HTTP.NOT_FOUND, "PENDING_OP_NOT_FOUND", "no such pending op");
  const cur = effectiveStatus(row);
  if (cur === "expired") return adminErr(HTTP.CONFLICT, "PENDING_OP_EXPIRED", "pending op expired");
  if (cur !== "proposed") return adminErr(HTTP.CONFLICT, "PENDING_OP_INVALID_STATE", `cannot resolve from ${cur}`);

  const note = typeof bodyObj.resolution_note === "string" ? bodyObj.resolution_note : null;
  let committedEpoch: number | null = null;
  if (status === "committed") {
    committedEpoch = typeof bodyObj.committed_epoch === "number" ? bodyObj.committed_epoch : NaN;
    if (!Number.isInteger(committedEpoch)) return adminErr(HTTP.BAD_REQUEST, "BAD_REQUEST", "committed_epoch required for committed");
    // Cross-check (§6.9): committed çözümü, resolving principal'ın GERÇEKTEN committed_epoch'u
    // yazdığına dair kanıt gerektirir. "Principal'a ait HERHANGİ bir commit" YETMEZ (aksi hâlde
    // admin, yazmadığı rastgele bir epoch'a atıf yaparak op'u committed işaretleyebilir). İki
    // koşul, SPESİFİK committed_epoch'a bağlı:
    //   (a) committed_epoch'ta bir trust manifest R2'de VAR (epoch gerçekten yazıldı), VE
    //   (b) o epoch'a atıfta bulunan, principal.id'ye ait bir allow commit audit satırı var
    //       (trust-commit audit satırları enacted admin_epoch'u `intent`'te taşır).
    const manifestExists = await env.SECRETS_BUCKET.head(keyTrustManifest(committedEpoch));
    const proof = manifestExists
      ? await env.AUDIT_DB.prepare(
          "SELECT seq FROM audit WHERE principal = ? AND decision = 'allow' AND verb IN ('commit','trust.commit') AND intent = ? LIMIT 1",
        )
          .bind(principal.id, String(committedEpoch))
          .first()
      : null;
    if (!proof) return adminErr(HTTP.CONFLICT, "PENDING_OP_INVALID_STATE", "committed_epoch not written by this principal (audit cross-check)");
  }
  await env.AUDIT_DB.prepare("UPDATE pending_ops SET status = ?, committed_epoch = ?, committed_by = ?, resolution_note = ? WHERE id = ?")
    .bind(status, committedEpoch, principal.id, note, id)
    .run();
  await auditAdminOr503(env, principal, "admin.pending_op.resolve", "allow", request, { intent: `${id}:${status}` });
  return adminJson({ id, status, committed_epoch: committedEpoch });
}

/** effectiveStatus, DB status'ünü türev-expiry ile hesaplar (7 gün geçmiş proposed → expired). */
function effectiveStatus(row: Record<string, unknown>): string {
  const status = String(row.status);
  if (status === "proposed" && typeof row.expires_at === "string" && Date.parse(row.expires_at) < Date.now()) return "expired";
  return status;
}
function derivedExpiry(row: Record<string, unknown>): Record<string, unknown> {
  return { ...row, status: effectiveStatus(row) };
}
