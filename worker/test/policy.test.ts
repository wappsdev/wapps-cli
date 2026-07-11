// Policy engine testleri (SPEC §4, build gate 3): §4.3 semantiği table-driven —
// deny-glob kural-kapsamı, allow-birleşimi, rotate⊃write, null-key op'ları,
// service selector'ları, PRIMARY aud-reddi, liste filtreleme, validation.

import { describe, it, expect } from "vitest";
import {
  AuthzPrincipal,
  PolicyDoc,
  PolicyValidationError,
  SCHEMA_POLICY,
  authorize,
  expandVerbs,
  filterReadableKeys,
  globMatch,
  validatePolicy,
} from "../src/policy.js";

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
  { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*"] },
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
  it("* = dört verb; rotate ⊃ write", () => {
    expect([...expandVerbs(["*"])].sort()).toEqual(["admin", "read", "rotate", "write"]);
    const r = expandVerbs(["rotate"]);
    expect(r.has("rotate")).toBe(true);
    expect(r.has("write")).toBe(true); // rotate-only grant düz yazmaya DA izin verir (pinli)
    expect(r.has("read")).toBe(false);
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
    const withAdminGroup = { ...ok, rules: [...ok.rules, { group: "admins@wapps.co", projects: ["*"], keys: ["*"], verbs: ["*"] }] };
    expect(validatePolicy(withAdminGroup, "primary", [])).toBeTruthy();
  });
});
