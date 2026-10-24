// D1 schema (SPEC §6.4 audit). v2 delta: the grants/mirror_state/pending_ops/
// trust_pin tables were DELETED together with the trust spine (§0.2); the authz
// source is now policy.json in R2 (§4). The only table left is the hash-chained
// `audit` ledger. Its ONLY writer is AuditLogDO, and it is NEVER garbage-collected.
// The ledger is also the offboard rotate-set oracle (§6.3).

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

// One-shot flag per isolate. IF NOT EXISTS is idempotent; this only saves round-trips.
let schemaReady: WeakSet<D1Database> | null = null;

/**
 * ensureSchema creates the D1 audit tables idempotently. AuditLogDO calls it before
 * its first append; the Worker may call it before the rotate-plan query.
 */
export async function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaReady) schemaReady = new WeakSet();
  if (schemaReady.has(db)) return;
  for (const stmt of DDL) await db.prepare(stmt).run();
  schemaReady.add(db);
}

/** __resetSchemaCache isolates tests from each other (it simulates a new isolate). */
export function __resetSchemaCache(): void {
  schemaReady = null;
}
