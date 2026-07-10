// D1 şema tanımı (SPEC §6.3 grants + §6.5 audit + §6.9 pending-ops). Tablolar
// idempotent CREATE IF NOT EXISTS ile kurulur; canlıda Atlas/migrations, testte
// ilk erişimde lazily. `audit` tablosunun TEK yazarı AuditLogDO'dur (§6.5); grants
// yalnızca mirror-rebuild tarafından, pending_ops yalnızca admin API tarafından yazılır.

const DDL: string[] = [
  // --- audit ledger (§6.5): hash-zincirli, TEK global DO yazar --------------
  `CREATE TABLE IF NOT EXISTS audit (
     seq            INTEGER PRIMARY KEY AUTOINCREMENT,
     ts             TEXT NOT NULL,
     principal      TEXT NOT NULL,
     principal_type TEXT NOT NULL CHECK (principal_type IN ('human','machine','worker')),
     project        TEXT,
     key            TEXT,
     verb           TEXT NOT NULL,
     decision       TEXT NOT NULL CHECK (decision IN ('allow','deny')),
     intent         TEXT,
     ip             TEXT,
     cf_ray         TEXT,
     token_jti      TEXT,
     prev_hash      TEXT NOT NULL,
     hash           TEXT NOT NULL
   )`,
  `CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit(principal)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_project ON audit(project)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_verb ON audit(verb)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_jti ON audit(token_jti)`,

  // --- grants mirror (§6.3): imzalı trust manifest'ten TÜRETİLMİŞ query index -
  `CREATE TABLE IF NOT EXISTS grants (
     trust_epoch    INTEGER NOT NULL,
     principal      TEXT NOT NULL,
     principal_type TEXT NOT NULL CHECK (principal_type IN ('human','machine')),
     project        TEXT NOT NULL,
     key_name       TEXT NOT NULL,
     verb           TEXT NOT NULL CHECK (verb IN ('read','write','rotate')),
     rotate_by      TEXT,
     PRIMARY KEY (trust_epoch, principal, project, key_name, verb)
   )`,
  `CREATE TABLE IF NOT EXISTS mirror_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     current_trust_epoch INTEGER NOT NULL
   )`,

  // --- pending-ops kuyruğu (§6.9): panel ÖNERİR, CLI törenle imzalar+commit'ler
  `CREATE TABLE IF NOT EXISTS pending_ops (
     id              TEXT PRIMARY KEY,
     type            TEXT NOT NULL CHECK (type IN ('grant','revoke','offboard','rotation','token_policy','machine_enroll','token_revoke')),
     payload         TEXT NOT NULL,
     proposed_by     TEXT NOT NULL,
     proposed_at     TEXT NOT NULL,
     status          TEXT NOT NULL CHECK (status IN ('proposed','withdrawn','rejected','committed','expired')),
     expires_at      TEXT NOT NULL,
     committed_epoch INTEGER,
     committed_by    TEXT,
     resolution_note TEXT
   )`,
];

// İzolat başına tek-sefer flag; IF NOT EXISTS olsa da gereksiz round-trip'i keser.
let schemaReady: WeakSet<D1Database> | null = null;

/**
 * ensureSchema, tüm D1 tablolarını idempotent kurar. AuditLogDO ilk append'ten
 * önce, Worker ise grants/pending_ops erişiminden önce çağırır. IF NOT EXISTS
 * olduğu için tekrar çağrı zararsızdır; izolat-içi cache round-trip'i azaltır.
 */
export async function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaReady) schemaReady = new WeakSet();
  if (schemaReady.has(db)) return;
  for (const stmt of DDL) await db.prepare(stmt).run();
  schemaReady.add(db);
}

/** __resetSchemaCache, testler arası izolasyon (yeni izolat simülasyonu) içindir. */
export function __resetSchemaCache(): void {
  schemaReady = null;
}
