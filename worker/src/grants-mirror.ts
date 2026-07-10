// Grants mirror (SPEC §6.3). D1 `grants` = imzalı trust manifest'ten TÜRETİLMİŞ
// query index; ASLA source of truth değildir. TEK yazarı bu mirror-rebuild'dir
// (admin/API path'leri D1'e grant YAZMAZ). Authz KARARLARI otoritatif manifest'ten
// verilir (trust.ts); mirror mint-scope subset kontrolü + admin metadata için.
//
// Freshness (§6.3): Worker her istekte trust head'ini zaten yükler+doğrular
// (loadTrustHead), dolayısıyla ensureMirror'a verilen manifest = doğrulanmış
// trust/current'tır; mirror epoch ondan farklıysa senkron rebuild edilir.

import { ensureSchema } from "./schema.js";
import { TrustManifest } from "./trust.js";

interface MirrorEnv {
  AUDIT_DB: D1Database;
}

export interface MirrorGrant {
  principal: string;
  principalType: "human" | "machine";
  project: string;
  keyName: string;
  verb: string;
  rotateBy: string | null;
}

function principalTypeOf(principal: string): "human" | "machine" | null {
  if (principal.startsWith("human:")) return "human";
  if (principal.startsWith("machine:")) return "machine";
  return null; // escrow vb. grant öznesi olamaz
}

/** rotateByOf, bir makine kimliğinin rotate_by'ını manifest'ten çıkarır (varsa). */
function rotateByOf(m: TrustManifest, principal: string): string | null {
  const id = m.identities.find((i) => i.id === principal) as unknown as { rotate_by?: unknown } | undefined;
  return id && typeof id.rotate_by === "string" ? id.rotate_by : null;
}

/**
 * ensureMirror, mirror'ı doğrulanmış manifest epoch'una senkronlar. mirror_state
 * güncel değilse (veya hiç yoksa) grants tablosunu bu epoch için yeniden kurar ve
 * mirror_state'i atomik flip eder (§6.3 mirror rules).
 */
export async function ensureMirror(env: MirrorEnv, m: TrustManifest): Promise<void> {
  await ensureSchema(env.AUDIT_DB);
  const state = await env.AUDIT_DB.prepare("SELECT current_trust_epoch FROM mirror_state WHERE id = 1").first<{ current_trust_epoch: number }>();
  if (state && state.current_trust_epoch === m.admin_epoch) return; // güncel
  await rebuildMirror(env, m);
}

/** rebuildMirror, grants'ı manifest'ten yeniden kurar (DELETE + INSERT + flip). */
export async function rebuildMirror(env: MirrorEnv, m: TrustManifest): Promise<void> {
  await ensureSchema(env.AUDIT_DB);
  const stmts: D1PreparedStatement[] = [];
  stmts.push(env.AUDIT_DB.prepare("DELETE FROM grants"));
  for (const g of m.grants) {
    const ptype = principalTypeOf(g.principal);
    if (!ptype) continue;
    const rotateBy = ptype === "machine" ? rotateByOf(m, g.principal) : null;
    for (const key of g.keys) {
      for (const verb of g.verbs) {
        if (verb !== "read" && verb !== "write" && verb !== "rotate") continue;
        stmts.push(
          env.AUDIT_DB.prepare(
            "INSERT OR REPLACE INTO grants (trust_epoch, principal, principal_type, project, key_name, verb, rotate_by) VALUES (?,?,?,?,?,?,?)",
          ).bind(m.admin_epoch, g.principal, ptype, g.project, key, verb, rotateBy),
        );
      }
    }
  }
  // mirror_state'i son flip et (rebuild atomikliği — D1 batch tek transaction).
  stmts.push(env.AUDIT_DB.prepare("INSERT OR REPLACE INTO mirror_state (id, current_trust_epoch) VALUES (1, ?)").bind(m.admin_epoch));
  await env.AUDIT_DB.batch(stmts);
}

/** mirrorGrantsFor, mirror'dan bir (principal, project) için grant satırlarını okur. */
export async function mirrorGrantsFor(env: MirrorEnv, principal: string, project: string): Promise<MirrorGrant[]> {
  await ensureSchema(env.AUDIT_DB);
  const rows = await env.AUDIT_DB.prepare(
    "SELECT principal, principal_type, project, key_name, verb, rotate_by FROM grants WHERE principal = ? AND project = ?",
  )
    .bind(principal, project)
    .all<{ principal: string; principal_type: "human" | "machine"; project: string; key_name: string; verb: string; rotate_by: string | null }>();
  return (rows.results ?? []).map((r) => ({
    principal: r.principal,
    principalType: r.principal_type,
    project: r.project,
    keyName: r.key_name,
    verb: r.verb,
    rotateBy: r.rotate_by,
  }));
}
