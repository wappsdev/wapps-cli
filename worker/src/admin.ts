// Admin/control-plane rotaları (SPEC §7.6 write-AUD path kümesi: /v1/admin/* +
// /v1/policy). ZK tasarımın pending-ops töre kuyruğu SİLİNDİ (§0.2) — policy
// düzenlemeleri DOĞRUDAN admin yazımlarıdır (§4.5). Rotalar:
//   GET  /v1/policy                 → aktif policy (admin verb)
//   PUT  /v1/policy                 → CAS'lı policy yazımı (§4.1/§4.4), audit + A9
//   GET  /v1/admin/rotate-plan      → audit ledger = rotate-set oracle (§6.3)
//   POST /v1/admin/token/revoke     → minted-token jti revoke (§5.3)
//   POST /v1/admin/rewrap-kek       → MASTER_KEK rotasyonu re-wrap turu (§2.5)
//
// `admin` verb'i GLOBAL op'ları kapsar (§4.2: policy edit, rotate-plan, token
// revoke, rewrap-kek) — bu yüzden admin kontrolü selector+verb üzerindendir
// (proje glob'ları global op'ta anlamsız); kök çapa ADMIN_EMAILS (§4.5). Tüm bu
// rotalar Access WRITE app'inin (15 dk + WebAuthn) arkasındadır (§3.2).

import { HTTP, jsonError, jsonOK } from "./errors.js";
import { Env, Principal } from "./auth.js";
import {
  AuthzPrincipal,
  LoadedPolicy,
  PolicyConflictError,
  PolicyDoc,
  PolicyValidationError,
  Topology,
  authorize,
  expandVerbs,
  putPolicy,
  rulesFor,
} from "./policy.js";
import { deriveProjects, getObject, keyCurrent, keyManifest } from "./storage.js";
import { parseCurrentPointer, parseManifest } from "./manifest.js";
import { ensureSchema } from "./schema.js";
import { auditAppendSync, auditReadAsync, AuditRow, ipOf, rayOf } from "./audit.js";
import { revokeJti } from "./token.js";
import { fireAlert, ALERT } from "./alerts.js";
import { doStubFetch } from "./do-util.js";

/** rotate-plan oracle verb kümesi (§6.3) — §6.4 sözlüğünün plaintext-bilen verb'leriyle
 * KİLİTLİ adım: buraya verb eklemeden §6.4'e plaintext-bilen verb eklemek gate 7c ihlalidir. */
export const ROTATE_PLAN_VERBS = ["value.read", "value.read.bulk", "key.set", "key.import", "key.sync", "rotate.step"] as const;

/** hasAdminVerb, principal'ın `admin` verb'ini tutup tutmadığı: kök çapa (ADMIN_EMAILS,
 * §4.5) VEYA selector'üne eşleşen herhangi bir kuralın verbs'ünde admin.
 *
 * NOT (bilinçli): eşleşen kuralın projects/keys kapsaması BURADA OKUNMAZ — `admin`
 * verb'i GLOBAL op'ları yetkilendirir (§4.2), proje/anahtar glob'ları admin op'unda
 * ölü kapsamdır. Proje-kapsamlı bir kurala admin/["*"] yazmak yanıltıcıdır; bunu
 * `wapps policy lint` kuralı (e) uyarır (§7.3). */
export function hasAdminVerb(policy: LoadedPolicy, p: AuthzPrincipal, principal: Principal, adminEmails: string[]): boolean {
  if (principal.kind === "human" && adminEmails.includes(principal.email)) return true;
  return rulesFor(policy.doc, p).some((r) => expandVerbs(r.verbs).has("admin"));
}

export interface AdminContext {
  policy: LoadedPolicy;
  authz: AuthzPrincipal;
  adminEmails: string[];
  topology: Topology;
}

/** handleAdmin, /v1/policy + /v1/admin/* rotalarını sürer. Çağıran write-AUD'u zaten doğruladı. */
export async function handleAdmin(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  parts: string[],
  principal: Principal,
  actx: AdminContext,
): Promise<Response> {
  const denyVerb = parts[1] === "policy" ? (request.method === "PUT" ? "policy.write" : "policy.read") : `admin.${parts[2] ?? ""}`;

  // Minted machine-token'lar admin rotalarında REDDEDİLİR (§5.3: minted scope,
  // service satırıyla KESİŞİR — asla genişletmez; MINTABLE_VERBS 'admin' içermez,
  // dolayısıyla hiçbir minted scope bir admin op'unu kapsayamaz). Aksi hâlde
  // read-scoped 10 dk'lık bir token, parent service satırı admin/["*"] veriyorsa
  // parent'ın TAM admin hakkına yükselirdi (scope-escalation, fail-closed red).
  if (principal.kind === "machine") {
    auditReadAsync(ctx, env.AUDIT_LOG, {
      principal: actx.authz.id,
      principal_type: "machine",
      verb: denyVerb,
      decision: "deny",
      intent: "minted_token",
      ip: ipOf(request),
      cf_ray: rayOf(request),
    });
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "minted machine tokens cannot use admin routes", { dimension: "verb" });
  }

  // Tüm admin rotaları `admin` verb'i gerektirir (§7.6 route table).
  if (!hasAdminVerb(actx.policy, actx.authz, principal, actx.adminEmails)) {
    auditReadAsync(ctx, env.AUDIT_LOG, {
      principal: actx.authz.id,
      principal_type: principal.kind === "human" ? "human" : "machine",
      verb: denyVerb,
      decision: "deny",
      intent: "verb",
      ip: ipOf(request),
      cf_ray: rayOf(request),
    });
    return jsonError(HTTP.FORBIDDEN, "GRANT_DENIED", "admin verb required", { dimension: "verb" });
  }

  // --- /v1/policy -------------------------------------------------------------
  if (parts[1] === "policy" && parts.length === 2) {
    if (request.method === "GET") {
      auditReadAsync(ctx, env.AUDIT_LOG, adminRow(actx.authz.id, principal, "policy.read", request));
      return jsonOK({ version: actx.policy.version, sha256: actx.policy.sha256, policy: actx.policy.doc });
    }
    if (request.method === "PUT") {
      let raw: unknown;
      try {
        raw = await request.json();
      } catch {
        return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
      }
      const oldVersion = actx.policy.version;
      const oldSha = actx.policy.sha256;
      let stored;
      try {
        stored = await putPolicy(env.SECRETS_BUCKET, raw as PolicyDoc, actx.topology, actx.adminEmails);
      } catch (e) {
        if (e instanceof PolicyValidationError) {
          return jsonError(HTTP.UNPROCESSABLE, "POLICY_INVALID", e.message, { rule_index: e.ruleIndex });
        }
        if (e instanceof PolicyConflictError) {
          return jsonError(HTTP.PRECONDITION_FAILED, "POLICY_CONFLICT", e.message, { current_version: oldVersion });
        }
        throw e;
      }
      // Policy değişimi SENKRON audit'lenir (eski/yeni versiyon + sha, §4.1) + A9.
      try {
        await auditAppendSync(env.AUDIT_LOG, {
          ...adminRow(actx.authz.id, principal, "policy.write", request),
          intent: `v${oldVersion}:${oldSha.slice(0, 12)}->v${stored.version}:${stored.sha256.slice(0, 12)}`,
        });
      } catch {
        return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "policy stored but audit unavailable — investigate", {
          version: stored.version,
        });
      }
      fireAlert(ctx, env, ALERT.A9, `policy updated v${oldVersion} -> v${stored.version} by ${actx.authz.id}`, {
        old_version: oldVersion,
        new_version: stored.version,
        sha256: stored.sha256,
      });
      return jsonOK({ version: stored.version, sha256: stored.sha256 });
    }
    return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown policy route");
  }

  // --- /v1/admin/* --------------------------------------------------------------
  if (parts[1] !== "admin") return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown route");

  // GET /v1/admin/rotate-plan?identity=<p>[&since=..][&assume_policy=1] (§6.3).
  if (parts[2] === "rotate-plan" && parts.length === 3 && request.method === "GET") {
    const url = new URL(request.url);
    const identity = url.searchParams.get("identity") ?? "";
    if (!identity) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "identity required");
    const since = url.searchParams.get("since");
    if (since && Number.isNaN(Date.parse(since))) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "since not RFC3339");
    const assumePolicy = url.searchParams.get("assume_policy") === "1";

    await ensureSchema(env.AUDIT_DB);
    const verbList = ROTATE_PLAN_VERBS.map((v) => `'${v}'`).join(",");
    const stmt = since
      ? env.AUDIT_DB.prepare(
          `SELECT project, key, MAX(ts) AS last_read, COUNT(*) AS reads FROM audit
           WHERE principal = ? AND decision = 'allow' AND key IS NOT NULL AND verb IN (${verbList}) AND ts >= ?
           GROUP BY project, key`,
        ).bind(identity, since)
      : env.AUDIT_DB.prepare(
          `SELECT project, key, MAX(ts) AS last_read, COUNT(*) AS reads FROM audit
           WHERE principal = ? AND decision = 'allow' AND key IS NOT NULL AND verb IN (${verbList})
           GROUP BY project, key`,
        ).bind(identity);
    const res = await stmt.all<{ project: string | null; key: string; last_read: string; reads: number }>();
    const items = (res.results ?? []).map((r) => ({ project: r.project ?? "", key: r.key, last_read: r.last_read, reads: r.reads }));

    // --assume-policy (§6.3): identity'nin kuralları altında OKUYABİLECEĞİ her
    // anahtarı da birleştir (paranoyak süperset). Human için gruplar offboard
    // sonrası bilinemez → TÜM group kuralları potansiyel sayılır (süperset yönü güvenli).
    if (assumePolicy) {
      const seen = new Set(items.map((i) => `${i.project} ${i.key}`));
      const candidateGroups = actx.policy.doc.rules.map((r) => r.group).filter((g): g is string => g !== undefined);
      const assumed: AuthzPrincipal = identity.startsWith("service:")
        ? { kind: "service", id: identity, groups: [] }
        : { kind: "human", id: identity, groups: candidateGroups };
      for (const project of await deriveProjects(env.SECRETS_BUCKET)) {
        const cur = await getObject(env.SECRETS_BUCKET, keyCurrent(project));
        if (!cur) continue;
        let names: string[];
        try {
          const ptr = parseCurrentPointer(cur.bytes);
          const man = await getObject(env.SECRETS_BUCKET, keyManifest(project, ptr.epoch));
          if (!man) continue;
          names = parseManifest(man.bytes).entries.map((e) => e.keyName);
        } catch {
          continue; // bozuk proje assume-policy taramasını düşürmez
        }
        for (const k of names) {
          if (!authorize(actx.policy.doc, assumed, project, k, "read").allowed) continue;
          const dedup = `${project} ${k}`;
          if (seen.has(dedup)) continue;
          seen.add(dedup);
          items.push({ project, key: k, last_read: "", reads: 0 });
        }
      }
    }

    // rotate-plan SENKRON audit (control-plane).
    try {
      await auditAppendSync(env.AUDIT_LOG, { ...adminRow(actx.authz.id, principal, "admin.rotate_plan", request), intent: identity });
    } catch {
      return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable");
    }
    return jsonOK({ identity, generated_at: new Date().toISOString(), items });
  }

  // POST /v1/admin/token/revoke (§7.6 — bare /v1/token/revoke READ app'e düşerdi).
  if (parts[2] === "token" && parts[3] === "revoke" && parts.length === 4 && request.method === "POST") {
    let jti = "";
    try {
      jti = ((await request.json()) as { jti?: string }).jti ?? "";
    } catch {
      return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
    }
    if (!jti) return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "jti required");
    try {
      await revokeJti(ctx, env, jti, actx.authz.id, request);
    } catch {
      return jsonError(HTTP.MISCONFIGURED, "AUDIT_UNAVAILABLE", "audit unavailable");
    }
    return jsonOK({ jti, revoked: true });
  }

  // POST /v1/admin/rewrap-kek (§2.5): her proje için writer DO'dan bir re-wrap epoch'u.
  if (parts[2] === "rewrap-kek" && parts.length === 3 && request.method === "POST") {
    const projects = await deriveProjects(env.SECRETS_BUCKET);
    const results: Record<string, unknown> = {};
    let failed = 0;
    for (const project of projects) {
      const res = await doStubFetch(
        () => env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName(project)),
        `https://do/commit?project=${encodeURIComponent(project)}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-principal-id": actx.authz.id,
            "x-principal-type": principal.kind === "human" ? "human" : "machine",
            "x-audit-verb": "admin.rewrap_kek",
            "x-policy-version": String(actx.policy.version),
            "x-cf-ip": ipOf(request) ?? "",
            "x-cf-ray": rayOf(request) ?? "",
          },
          body: JSON.stringify({ op: "rewrap" }),
        },
      );
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      results[project] = res.status === HTTP.OK ? body : { error: body.error ?? res.status };
      if (res.status !== HTTP.OK) failed++;
    }
    return jsonOK({ projects: results, failed });
  }

  return jsonError(HTTP.NOT_FOUND, "NOT_FOUND", "unknown admin route");
}

function adminRow(principalId: string, principal: Principal, verb: string, request: Request): AuditRow {
  return {
    principal: principalId,
    principal_type: principal.kind === "human" ? "human" : "machine",
    verb,
    decision: "allow",
    ip: ipOf(request),
    cf_ray: rayOf(request),
  };
}
