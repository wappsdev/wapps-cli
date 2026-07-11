// Machine-token mint + revoke (SPEC §5.3 — OPSİYONEL confinement katmanı).
// v2 delta: service token'lar data-plane'e DOĞRUDAN kabul edilir (§5.1); mint artık
// zorunlu DEĞİL. Bir pipeline, uzun ömürlü service-token çiftini ≤10 dk'lık ES256
// scoped token'a exchange EDEBİLİR; scope kontrolleri silinen grants-mirror yerine
// policy.json'a karşı çalışır: istenen {project, keys[], verbs[]} ⊆ service satırları
// (minted scope policy satırını ASLA genişletmez — kesişir).

import { HTTP, jsonError, jsonOK } from "./errors.js";
import { Env } from "./auth.js";
import { authorize, LoadedPolicy, PolicyVerb } from "./policy.js";
import { validKeyName } from "./storage.js";
import { mintToken, TokenScope, TTL_MAX_SECONDS } from "./mint.js";
import { auditAppendSync, AuditRow, ipOf, rayOf } from "./audit.js";
import { fireAlert, ALERT } from "./alerts.js";

interface TokenRequest {
  project?: unknown;
  scope?: { verbs?: unknown; keys?: unknown };
  ttl_seconds?: unknown;
}

const MINTABLE_VERBS: PolicyVerb[] = ["read", "write", "rotate"];

/**
 * handleTokenMint, POST /v1/token: service principal'ı kısa-TTL scoped token'a
 * exchange eder (§5.3). Scope ⊆ policy satırları: her (verb, key) çifti için
 * policy authorize geçmeli; aşan istek TOKEN_SCOPE_EXCEEDED. Minted keys EXACT
 * anahtar adlarıdır (glob/joker yok — least-privilege confinement).
 */
export async function handleTokenMint(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
  serviceCommonName: string,
  policy: LoadedPolicy,
): Promise<Response> {
  let req: TokenRequest;
  try {
    req = (await request.json()) as TokenRequest;
  } catch {
    return jsonError(HTTP.BAD_REQUEST, "TOKEN_REQUEST_INVALID", "body not JSON");
  }
  const project = typeof req.project === "string" ? req.project : "";
  if (!project) return jsonError(HTTP.BAD_REQUEST, "TOKEN_REQUEST_INVALID", "project required");
  const verbs = Array.isArray(req.scope?.verbs) ? (req.scope!.verbs as unknown[]).filter((v): v is string => typeof v === "string") : [];
  const keys = Array.isArray(req.scope?.keys) ? (req.scope!.keys as unknown[]).filter((k): k is string => typeof k === "string") : [];
  if (verbs.length === 0 || keys.length === 0) return jsonError(HTTP.BAD_REQUEST, "TOKEN_REQUEST_INVALID", "scope.verbs and scope.keys required");
  const ttlReq = typeof req.ttl_seconds === "number" ? req.ttl_seconds : TTL_MAX_SECONDS;
  const principalId = `service:${serviceCommonName}`;

  // Minted scope EXACT anahtar adları + kapalı verb kümesiyle sınırlı.
  for (const v of verbs) {
    if (!(MINTABLE_VERBS as string[]).includes(v)) return jsonError(HTTP.BAD_REQUEST, "TOKEN_REQUEST_INVALID", `verb not mintable: ${v}`);
  }
  for (const k of keys) {
    if (!validKeyName(k)) return jsonError(HTTP.BAD_REQUEST, "TOKEN_REQUEST_INVALID", `scope keys must be exact key names: ${k}`);
  }

  // Requested scope ⊆ policy satırları (§5.3): her (verb, key) çifti izinli olmalı.
  const p = { kind: "service" as const, id: principalId, groups: [] };
  const offending: { verb: string; key: string }[] = [];
  for (const k of keys) {
    for (const v of verbs) {
      if (!authorize(policy.doc, p, project, k, v as PolicyVerb).allowed) offending.push({ verb: v, key: k });
    }
  }
  if (offending.length > 0) {
    await tryDenyAudit(env, principalId, project, "token.mint", `TOKEN_SCOPE_EXCEEDED:${offending[0].verb}:${offending[0].key}`, request);
    return jsonError(HTTP.FORBIDDEN, "TOKEN_SCOPE_EXCEEDED", "requested scope exceeds policy rows", { offending });
  }

  // ttl clamp ≤600 + mint. sub = MINT EDEN principal (CF Access common_name'den) —
  // data-plane'de principal binding bu alana karşı doğrulanır (auth.ts): minted
  // token yalnızca kendi ihraççısının scope'unu daraltabilir, başkasını taşıyamaz.
  const scope: TokenScope = { verbs, keys };
  const minted = await mintToken(env, { sub: principalId, project, scope, ttlSeconds: ttlReq });

  // Mint SENKRON audit'lenir (control-plane). Audit DO down → fail closed.
  const row: AuditRow = {
    principal: principalId,
    principal_type: "machine",
    project,
    verb: "token.mint",
    decision: "allow",
    ip: ipOf(request),
    cf_ray: rayOf(request),
    token_jti: minted.jti,
  };
  try {
    await auditAppendSync(env.AUDIT_LOG, row);
  } catch {
    return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable — mint refused");
  }

  return jsonOK({ token: minted.token, token_type: "Bearer", expires_in: minted.ttl, exp: minted.exp, jti: minted.jti, sub: principalId, scope });
}

/**
 * revokeJti, bir minted-token jti'sini KV deny-list'e yazar. TTL = maks token
 * ömrü (600s) + 60s lag; her minted-token kullanımında kontrol edilir.
 * Control-plane: yalnızca POST /v1/admin/token/revoke çağırır (§7.6).
 */
export async function revokeJti(
  ctx: ExecutionContext,
  env: Env,
  jti: string,
  revokedBy: string,
  request: Request,
): Promise<void> {
  await env.JTI_DENYLIST.put(jti, JSON.stringify({ revoked_at: new Date().toISOString(), by: revokedBy }), {
    expirationTtl: TTL_MAX_SECONDS + 60,
  });
  // token.revoke SENKRON audit (control-plane).
  await auditAppendSync(env.AUDIT_LOG, {
    principal: revokedBy,
    principal_type: revokedBy.startsWith("human:") ? "human" : "worker",
    verb: "token.revoke",
    decision: "allow",
    token_jti: jti,
    ip: ipOf(request),
    cf_ray: rayOf(request),
  });
  // Revoke = güvenlik olayı → alert.
  fireAlert(ctx, env, ALERT.A8, `token revoked jti=${jti}`, { jti, by: revokedBy });
}

/** tryDenyAudit, best-effort deny satırı (audit DO down ise yutulur). */
async function tryDenyAudit(env: Env, principal: string, project: string, verb: string, intent: string, request: Request): Promise<void> {
  try {
    await auditAppendSync(env.AUDIT_LOG, {
      principal,
      principal_type: "machine",
      project,
      verb,
      decision: "deny",
      intent,
      ip: ipOf(request),
      cf_ray: rayOf(request),
    });
  } catch {
    // best-effort
  }
}
