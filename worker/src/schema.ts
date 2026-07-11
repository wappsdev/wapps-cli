// D1 şema tanımı (SPEC §6.4 audit). v2 delta: grants/mirror_state/pending_ops/
// trust_pin tabloları trust-spine ile birlikte SİLİNDİ (§0.2) — authz kaynağı
// artık R2'deki policy.json'dır (§4). Kalan tek tablo hash-zincirli `audit`
// ledger'ıdır; TEK yazarı AuditLogDO'dur ve ASLA GC'lenmez. Bu ledger aynı
// zamanda offboard rotate-set oracle'ıdır (§6.3).

const DDL: string[] = [
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
];

// İzolat başına tek-sefer flag; IF NOT EXISTS olsa da gereksiz round-trip'i keser.
let schemaReady: WeakSet<D1Database> | null = null;

/**
 * ensureSchema, D1 audit tablosunu idempotent kurar. AuditLogDO ilk append'ten
 * önce çağırır; Worker rotate-plan sorgusundan önce çağırabilir.
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
