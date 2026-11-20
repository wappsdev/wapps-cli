// Policy engine testleri (SPEC §4, build gate 3): §4.3 semantiği table-driven —
// deny-glob kural-kapsamı, allow-birleşimi, rotate⊃write, null-key op'ları,
// service selector'ları, PRIMARY aud-reddi, liste filtreleme, validation.

import { afterEach, beforeEach, describe, it, expect } from "vitest";
import {
  AuthzPrincipal,
  PolicyDoc,
  PolicyValidationError,
  SCHEMA_POLICY,
  authorize,
  expandVerbs,
  filterReadableKeys,
  globMatch,
  grantsAdmin,
  putPolicy,
  validatePolicy,
  __resetPolicyCache,
} from "../src/policy.js";
import { keyPolicyCurrent } from "../src/storage.js";
import { env } from "cloudflare:test";
import { clearBucket } from "./helpers.js";

function doc(rules: PolicyDoc["rules"]): PolicyDoc {
  return { schema: SCHEMA_POLICY, version: 1, rules };
}
const dev: AuthzPrincipal = { kind: "human", id: "human:dev@wapps.co", groups: ["developers@wapps.co"] };
const admin: AuthzPrincipal = { kind: "human", id: "human:boss@wapps.co", groups: ["admins@wapps.co"] };
const svc: AuthzPrincipal = { kind: "service", id: "service:svc-woodpecker", groups: [] };

const BASE = doc([
  { group: "developers@wapps.co", projects: ["*"], keys: ["*", "!*_PROD_*"], verbs: ["read"] },
  { group: "developers@wapps.co", projects: ["*"], keys: ["*", "!*_PROD_*"], verbs: ["write", "rotate"] },
  { group: "contractors@wapps.co", projects: ["lumira"], keys: ["*", "!*_PROD_*"], verbs: ["read"] },
  { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*", "admin"] },
  { service: "svc-woodpecker", projects: ["vaulter"], keys: ["DEPLOY_*", "DB_*"], verbs: ["read"] },
]);

describe("glob (pinned §4.2)", () => {
  it("* / ? / literal, tam-string, case-sensitive", () => {
    expect(globMatch("*", "")).toBe(true);
    expect(globMatch("*", "ANYTHING")).toBe(true);
    expect(globMatch("DB_*", "DB_URL")).toBe(true);
    expect(globMatch("DB_*", "MYDB_URL")).toBe(false); // tam-string
    expect(globMatch("K?Y", "KEY")).toBe(true);
    expect(globMatch("K?Y", "KY")).toBe(false);
    expect(globMatch("key", "KEY")).toBe(false); // case-sensitive
    expect(globMatch("A.B", "AxB")).toBe(false); // '.' literal
    expect(globMatch("*_PROD_*", "DB_PROD_URL")).toBe(true);
  });

  it("çok yıldızlı pattern'ler doğru eşleşir (iki-işaretçili algoritma)", () => {
    expect(globMatch("*A*B*C*", "xxAyyBzzCww")).toBe(true);
    expect(globMatch("*A*B*C*", "xxAyyCzzBww")).toBe(false); // sıra korunur
    expect(globMatch("a*a*a", "aaa")).toBe(true); // '*' boş eşleşebilir
    expect(globMatch("a**b", "ab")).toBe(true); // ardışık '*' tek '*' gibi
    expect(globMatch("*?", "")).toBe(false); // '?' en az bir karakter ister
  });

  it("ReDoS-şekilli pattern (GLOB_MAX_LEN içinde) 128-char anahtarda HIZLI ve doğru döner", () => {
    // Eski regex çevirisinde ( [\s\S]* greedy ) bu pattern katastrofik
    // backtracking'le pratikte sonsuza asılırdı; lineer eşleştiricide µs sürer.
    const evil = "*a".repeat(120) + "*b"; // 242 char ≤ 256 (policy PUT kabul ederdi)
    const key = "a".repeat(128); // 'b' yok → eşleşmemeli
    const t0 = Date.now();
    expect(globMatch(evil, key)).toBe(false);
    expect(globMatch(evil, "a".repeat(127) + "b")).toBe(true); // pozitif kontrol
    expect(Date.now() - t0).toBeLessThan(500); // backtracking olsa saatler sürerdi
  });
});

describe("expandVerbs (§4.2)", () => {
  it("* = the data verbs (create included), never admin; rotate ⊃ write", () => {
    expect([...expandVerbs(["*"])].sort()).toEqual(["create", "delete", "read", "rotate", "write"]);
    const r = expandVerbs(["rotate"]);
    expect(r.has("rotate")).toBe(true);
    expect(r.has("write")).toBe(true); // rotate-only grant düz yazmaya DA izin verir (pinli)
    expect(r.has("read")).toBe(false);
  });

  // delete HİÇBİR verb tarafından ima edilmez: silme geri alınamaz, açık grant ister.
  it("delete ima EDİLMEZ — ne write ne rotate onu verir", () => {
    expect(expandVerbs(["write"]).has("delete")).toBe(false);
    expect(expandVerbs(["rotate"]).has("delete")).toBe(false);
    expect(expandVerbs(["admin"]).has("delete")).toBe(false);
    const d = expandVerbs(["delete"]);
    expect(d.has("delete")).toBe(true);
    expect(d.has("write")).toBe(false); // geri-grant yok
  });

  // `create` (E-M3) permits create-only writes and nothing else.
  it("create is its own verb: it grants neither write nor rotate, and a policy may name it", () => {
    const c = expandVerbs(["create"]);
    expect(c.has("create")).toBe(true);
    expect(c.has("write")).toBe(false);
    expect(c.has("rotate")).toBe(false);
    const p = doc([{ group: "creators@wapps.co", projects: ["*"], keys: ["*"], verbs: ["create"] }]);
    expect(validatePolicy(p, "primary", ["root@wapps.dev"]).rules[0].verbs).toEqual(["create"]);
  });
});

// E-M1 (security review 2026-11-19): `admin` is a GLOBAL verb. A rule scoped to some
// projects must never reach it, so "*" does not expand to admin, and admin counts only
// on a group rule whose projects are all-wildcard.
describe("admin verb scope (E-M1)", () => {
  const member = (g: string): AuthzPrincipal => ({ kind: "human", id: `human:${g}`, groups: [g] });
  const SCOPED = doc([
    { group: "lumira-owners@wapps.co", projects: ["lumira"], keys: ["*"], verbs: ["*"] },
    { group: "lumira-admin@wapps.co", projects: ["lumira"], keys: ["*"], verbs: ["admin"] },
    { group: "all-admin@wapps.co", projects: ["*"], keys: ["*"], verbs: ["admin"] },
    { group: "shared-admin@wapps.co", projects: ["*/*"], keys: ["*"], verbs: ["*", "admin"] },
    { group: "both-admin@wapps.co", projects: ["*", "*/*"], keys: ["*"], verbs: ["admin"] },
    { service: "svc-ops", projects: ["*"], keys: ["*"], verbs: ["*", "admin"] },
  ]);

  it('a project-scoped rule with verbs ["*"] gives no admin, but keeps its data verbs', () => {
    const d = authorize(SCOPED, member("lumira-owners@wapps.co"), "lumira", null, "admin");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("verb");
    for (const v of ["read", "write", "rotate", "delete"] as const) {
      expect(authorize(SCOPED, member("lumira-owners@wapps.co"), "lumira", "K", v).allowed, v).toBe(true);
    }
  });

  it("an explicit admin on a project-scoped group rule is not honoured", () => {
    expect(authorize(SCOPED, member("lumira-admin@wapps.co"), "lumira", null, "admin").allowed).toBe(false);
    expect(grantsAdmin(SCOPED.rules[1])).toBe(false);
  });

  it("a service rule never grants admin, even on all-wildcard projects", () => {
    const svcOps: AuthzPrincipal = { kind: "service", id: "service:svc-ops", groups: [] };
    expect(authorize(SCOPED, svcOps, "lumira", null, "admin").allowed).toBe(false);
    expect(grantsAdmin(SCOPED.rules[5])).toBe(false);
  });

  it('the all-wildcard group shapes ["*"], ["*/*"] and ["*", "*/*"] keep admin', () => {
    for (const g of ["all-admin@wapps.co", "shared-admin@wapps.co", "both-admin@wapps.co"]) {
      expect(authorize(SCOPED, member(g), "lumira", null, "admin").allowed, g).toBe(true);
    }
    expect(grantsAdmin(SCOPED.rules[2])).toBe(true);
    expect(grantsAdmin(SCOPED.rules[3])).toBe(true);
    expect(grantsAdmin(SCOPED.rules[4])).toBe(true);
  });

  it('an all-wildcard group rule with only "*" holds no admin ("*" is data verbs only)', () => {
    expect(grantsAdmin({ group: "g@x.co", projects: ["*"], keys: ["*"], verbs: ["*"] })).toBe(false);
  });
});

describe("authorize (§4.3 normatif)", () => {
  const cases: { name: string; p: AuthzPrincipal; project: string; key: string | null; verb: "read" | "write" | "rotate" | "admin"; want: boolean; reason?: string }[] = [
    { name: "dev okur", p: dev, project: "vaulter", key: "DATABASE_URL", verb: "read", want: true },
    { name: "deny-glob KENDİ kuralında kazanır", p: dev, project: "vaulter", key: "DB_PROD_URL", verb: "read", want: false, reason: "key_denied" },
    { name: "admin kuralı prod'u okur (kurallar-arası birleşim; dev'in deny'i admins'i vetolamaz)", p: admin, project: "vaulter", key: "DB_PROD_URL", verb: "read", want: true },
    { name: "rotate⊃write: dev rotate kuralıyla yazar", p: dev, project: "vaulter", key: "API_KEY", verb: "write", want: true },
    { name: "dev admin verb tutmaz", p: dev, project: "vaulter", key: null, verb: "admin", want: false, reason: "verb" },
    { name: "yanlış grup → no_rule", p: { kind: "human", id: "human:x@y.z", groups: ["strangers@wapps.co"] }, project: "vaulter", key: "K", verb: "read", want: false, reason: "no_rule" },
    { name: "service tam eşleşme + key-glob", p: svc, project: "vaulter", key: "DEPLOY_TOKEN", verb: "read", want: true },
    { name: "service proje dışı", p: svc, project: "lumira", key: "DEPLOY_TOKEN", verb: "read", want: false, reason: "project" },
    { name: "service key-glob dışı", p: svc, project: "vaulter", key: "OTHER_KEY", verb: "read", want: false, reason: "key_denied" },
    { name: "service yazamaz", p: svc, project: "vaulter", key: "DB_URL", verb: "write", want: false, reason: "verb" },
    { name: "null-key proje-metadata op'u (adım 4 atlanır)", p: dev, project: "vaulter", key: null, verb: "read", want: true },
    { name: "contractor yalnız lumira", p: { kind: "human", id: "human:c@x.co", groups: ["contractors@wapps.co"] }, project: "vaulter", key: "K", verb: "read", want: false, reason: "project" },
    { name: "deny-by-default (boş policy)", p: dev, project: "vaulter", key: "K", verb: "read", want: false, reason: "no_rule" },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const d = authorize(c.name.includes("boş policy") ? doc([]) : BASE, c.p, c.project, c.key, c.verb);
      expect(d.allowed).toBe(c.want);
      if (!c.want && c.reason) expect(d.reason).toBe(c.reason);
    });
  }

  it("group kuralı service principal'a ASLA eşleşmez (kind ayrımı)", () => {
    const impostor: AuthzPrincipal = { kind: "service", id: "service:x", groups: ["developers@wapps.co"] };
    expect(authorize(BASE, impostor, "vaulter", "K", "read").allowed).toBe(false);
  });

  it("DENY case-insensitive (fail-safe) / ALLOW case-sensitive (storage kimliği)", () => {
    // Deny fail-safe hardening: `!*_PROD_*` her case'i yakalar (fazladan eşleşme güvenli).
    expect(authorize(BASE, dev, "vaulter", "DB_PROD_URL", "read").allowed).toBe(false); // upper
    expect(authorize(BASE, dev, "vaulter", "db_prod_url", "read").allowed).toBe(false); // lower (fold)
    expect(authorize(BASE, dev, "vaulter", "Db_Prod_Url", "read").allowed).toBe(false); // karışık (fold)
    expect(authorize(BASE, dev, "vaulter", "database_url", "read").allowed).toBe(true); // prod yok → erişilebilir
    // Allow CASE-SENSITIVE: svc DEPLOY_* yalnız uppercase DEPLOY_ anahtarlarını kapsar
    // (adlar storage'da case-sensitive kimlik — over-grant yok).
    expect(authorize(BASE, svc, "vaulter", "DEPLOY_KEY", "read").allowed).toBe(true);
    expect(authorize(BASE, svc, "vaulter", "deploy_key", "read").allowed).toBe(false); // farklı kimlik
    expect(authorize(BASE, svc, "vaulter", "API_KEY", "read").allowed).toBe(false); // allow glob yok
  });
});

// Shared named secrets (design 2026-11-11): a project glob matches a shared id only
// if the glob holds exactly one `/`. `["*"]` never reaches a shared secret.
describe("project globs and shared ids", () => {
  const rel = (group: string): AuthzPrincipal => ({ kind: "human", id: `human:${group}`, groups: [group] });
  const SHARED = doc([
    { group: "tv@wapps.co", projects: ["wapps-tv-remote", "*"], keys: ["*"], verbs: ["read"] },
    { group: "apple-all@wapps.co", projects: ["apple/*"], keys: ["*"], verbs: ["read"] },
    { group: "all-shared@wapps.co", projects: ["*/*"], keys: ["*"], verbs: ["read"] },
    { group: "apple-other@wapps.co", projects: ["apple/other"], keys: ["*"], verbs: ["read"] },
    { group: "exact@wapps.co", projects: ["apple/asc"], keys: ["ASC_*"], verbs: ["read"] },
    { group: "odd@wapps.co", projects: ["apple?asc", "apple/asc/x", "*/*/*", "**"], keys: ["*"], verbs: ["read"] },
  ]);

  it("a principal granted a project and [\"*\"] is refused on apple/asc (dimension project)", () => {
    const d = authorize(SHARED, rel("tv@wapps.co"), "apple/asc", "ASC_KEY_ID", "read");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("project");
    expect(authorize(SHARED, rel("tv@wapps.co"), "apple/asc", null, "read").allowed).toBe(false);
    // The same rule still reaches every project.
    expect(authorize(SHARED, rel("tv@wapps.co"), "wapps-tv-remote", "K", "read").allowed).toBe(true);
    expect(authorize(SHARED, rel("tv@wapps.co"), "emlak-radar", "K", "read").allowed).toBe(true);
  });

  it("apple/* and */* match apple/asc; apple/other does not", () => {
    expect(authorize(SHARED, rel("apple-all@wapps.co"), "apple/asc", "ASC_KEY_ID", "read").allowed).toBe(true);
    expect(authorize(SHARED, rel("all-shared@wapps.co"), "apple/asc", "ASC_KEY_ID", "read").allowed).toBe(true);
    expect(authorize(SHARED, rel("all-shared@wapps.co"), "google/play", "K", "read").allowed).toBe(true);
    expect(authorize(SHARED, rel("apple-all@wapps.co"), "google/play", "K", "read").allowed).toBe(false);
    const d = authorize(SHARED, rel("apple-other@wapps.co"), "apple/asc", "ASC_KEY_ID", "read");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("project");
  });

  it("an exact shared id rule keeps its key globs", () => {
    expect(authorize(SHARED, rel("exact@wapps.co"), "apple/asc", "ASC_KEY_ID", "read").allowed).toBe(true);
    expect(authorize(SHARED, rel("exact@wapps.co"), "apple/asc", "OTHER", "read").allowed).toBe(false);
  });

  it("globs with a `/` never match a project name", () => {
    for (const g of ["apple-all@wapps.co", "all-shared@wapps.co", "exact@wapps.co"]) {
      expect(authorize(SHARED, rel(g), "apple", "K", "read").allowed, g).toBe(false);
      expect(authorize(SHARED, rel(g), "apple-asc", "K", "read").allowed, g).toBe(false);
    }
  });

  it("no slash-free glob and no glob with two `/` reaches a shared id", () => {
    // `?` and `**` would match the `/` under plain globMatch; the rule refuses them.
    expect(authorize(SHARED, rel("odd@wapps.co"), "apple/asc", "K", "read").allowed).toBe(false);
  });

  it("filterReadableKeys follows the same rule", () => {
    expect(filterReadableKeys(SHARED, rel("tv@wapps.co"), "apple/asc", ["ASC_KEY_ID"])).toEqual([]);
    expect(filterReadableKeys(SHARED, rel("apple-all@wapps.co"), "apple/asc", ["ASC_KEY_ID"])).toEqual(["ASC_KEY_ID"]);
  });
});

describe("filterReadableKeys (§4.3.3)", () => {
  it("liste okunabilir anahtarlara indirgenir", () => {
    const keys = ["DATABASE_URL", "DB_PROD_URL", "API_KEY"];
    expect(filterReadableKeys(BASE, dev, "vaulter", keys)).toEqual(["DATABASE_URL", "API_KEY"]);
    expect(filterReadableKeys(BASE, admin, "vaulter", keys)).toEqual(keys);
    expect(filterReadableKeys(BASE, svc, "vaulter", keys)).toEqual(["DB_PROD_URL"]); // yalnızca DB_* glob'u eşleşir
  });
});

describe("validatePolicy (§4.4)", () => {
  const ADMINS = ["admin@wapps.dev"];
  const ok = {
    schema: SCHEMA_POLICY,
    version: 1,
    rules: [{ group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read"] }],
  };

  it("geçerli doküman kabul", () => {
    expect(validatePolicy(ok, "primary", ADMINS).rules.length).toBe(1);
  });

  it("PRIMARY'de aud selector'ü REDDEDİLİR (dead-rule); FALLBACK'te kabul (§3.3/§4.4)", () => {
    const withAud = { ...ok, rules: [{ aud: "abc123", projects: ["*"], keys: ["*"], verbs: ["read"] }] };
    expect(() => validatePolicy(withAud, "primary", ADMINS)).toThrowError(PolicyValidationError);
    expect(validatePolicy(withAud, "fallback", ADMINS).rules.length).toBe(1);
  });

  it("kural index'i adlandırılır", () => {
    const bad = { ...ok, rules: [ok.rules[0], { group: "g@x.co", projects: ["*"], keys: ["!*"], verbs: ["read"] }] };
    try {
      validatePolicy(bad, "primary", ADMINS);
      expect.unreachable();
    } catch (e) {
      expect((e as PolicyValidationError).ruleIndex).toBe(1);
    }
  });

  const rejects: { name: string; mut: (r: Record<string, unknown>) => void }[] = [
    { name: "iki selector", mut: (r) => (r.service = "svc-x") },
    { name: "selector yok", mut: (r) => delete r.group },
    { name: "boş projects", mut: (r) => (r.projects = []) },
    { name: "pozitif key glob'u yok", mut: (r) => (r.keys = ["!SECRET_*"]) },
    { name: "bilinmeyen verb", mut: (r) => (r.verbs = ["decrypt"]) },
    { name: "bilinmeyen alan", mut: (r) => (r.extra = 1) },
    { name: "deny formu projects'te yok", mut: (r) => (r.projects = ["!lab"]) },
  ];
  for (const c of rejects) {
    it(`RED: ${c.name}`, () => {
      const rule: Record<string, unknown> = { group: "g@x.co", projects: ["*"], keys: ["*"], verbs: ["read"] };
      c.mut(rule);
      expect(() => validatePolicy({ ...ok, rules: [rule] }, "primary", ADMINS)).toThrowError(PolicyValidationError);
    });
  }

  it("lockout guard: admin group kuralı yok + ADMIN_EMAILS boş → red; ADMIN_EMAILS dolu → kabul", () => {
    expect(() => validatePolicy(ok, "primary", [])).toThrowError(PolicyValidationError);
    expect(validatePolicy(ok, "primary", ADMINS)).toBeTruthy();
    const withAdminGroup = { ...ok, rules: [...ok.rules, { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*", "admin"] }] };
    expect(validatePolicy(withAdminGroup, "primary", [])).toBeTruthy();
  });

  it('lockout guard: a group admin that is not honoured (scoped, or "*" only) is no admin path', () => {
    for (const r of [
      { group: "admins@wapps.co", projects: ["lumira"], keys: ["*"], verbs: ["admin"] },
      { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*"] },
    ]) {
      expect(() => validatePolicy({ ...ok, rules: [...ok.rules, r] }, "primary", [])).toThrowError(PolicyValidationError);
    }
  });
});

// E-M1: policy set refuses any rule that carries admin where admin is not honoured,
// naming the rule. The check is PUT-only (like dead project globs), so a stored policy
// that holds such a rule still loads; the rule just grants no admin.
describe("putPolicy refuses misplaced admin (E-M1)", () => {
  // Storage is shared across test files (vitest.config.ts): start and end clean.
  beforeEach(async () => {
    await clearBucket();
    __resetPolicyCache();
  });
  afterEach(async () => {
    await clearBucket();
    __resetPolicyCache();
  });
  const ADMINS = ["admin@wapps.dev"];
  const base = { group: "developers@wapps.co", projects: ["*"], keys: ["*"], verbs: ["read"] };
  const put = (rule: Record<string, unknown>, topology: "primary" | "fallback" = "primary") =>
    putPolicy(env.SECRETS_BUCKET, { schema: SCHEMA_POLICY, version: 1, rules: [base, rule] } as unknown as PolicyDoc, topology, ADMINS);

  const refused: { name: string; rule: Record<string, unknown>; topology?: "fallback" }[] = [
    { name: "service rule with admin", rule: { service: "svc-ops", projects: ["*"], keys: ["*"], verbs: ["admin"] } },
    { name: "aud rule with admin", rule: { aud: "aud-x", projects: ["*"], keys: ["*"], verbs: ["read", "admin"] }, topology: "fallback" },
    { name: "project-scoped group rule with admin", rule: { group: "g@x.co", projects: ["lumira"], keys: ["*"], verbs: ["admin"] } },
    { name: "group rule mixing a wildcard and a project", rule: { group: "g@x.co", projects: ["*", "lumira"], keys: ["*"], verbs: ["admin"] } },
    { name: "group rule on one shared namespace", rule: { group: "g@x.co", projects: ["apple/*"], keys: ["*"], verbs: ["admin"] } },
  ];
  for (const c of refused) {
    it(`refuses: ${c.name}, naming the rule`, async () => {
      let err: unknown = null;
      try {
        await put(c.rule, c.topology);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(PolicyValidationError);
      expect((err as PolicyValidationError).ruleIndex).toBe(1);
      expect((err as Error).message).toContain("admin");
      // Nothing was stored.
      expect(await env.SECRETS_BUCKET.head(keyPolicyCurrent())).toBeNull();
    });
  }

  it("accepts admin on an all-wildcard group rule", async () => {
    const r = await put({ group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*", "admin"] });
    expect(r.version).toBe(1);
  });
});
