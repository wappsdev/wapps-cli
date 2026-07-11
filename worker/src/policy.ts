// Yetkilendirme: policy.json (SPEC §4). Server-decrypt pivotunda authz kaynağı
// artık imzalı trust manifest'i DEĞİL, R2'de versiyonlanan tek bir kural dosyasıdır:
//   - Kural şekli: { group | service | aud (tam olarak biri), projects[], keys[]
//     (baş '!' = DENY glob), verbs[] } (§4.2).
//   - Değerlendirme (§4.3): kurallar-arası ALLOW BİRLEŞİMİ; deny-glob yalnızca
//     KENDİ kuralı içinde kazanır; deny-by-default; rotate ⊃ write; key=null
//     proje-metadata op'ları; liste yanıtları okunabilir anahtarlara FİLTRELENİR.
//   - Depolama (§4.1): policy/versions/<n>.json (immutable, onlyIf-absent) +
//     policy/current pointer (If-Match CAS). İzolat-içi parse cache ≤60 s.
//   - ADMIN_EMAILS (§4.5): kök admin çapası — policy.json'dan BAĞIMSIZ `admin` verb'i.

import { sha256Hex, utf8 } from "./crypto/encoding.js";
import { getObject, keyPolicyCurrent, keyPolicyVersion } from "./storage.js";

export const SCHEMA_POLICY = "wapps-secrets/policy/v1";
export const POLICY_VERBS = ["read", "write", "rotate", "admin"] as const;
export type PolicyVerb = (typeof POLICY_VERBS)[number];

/** PolicyRule, §4.2 kural şekli. Tam olarak bir selector (group|service|aud). */
export interface PolicyRule {
  group?: string;
  service?: string;
  aud?: string; // YALNIZCA FALLBACK topolojisi (§3.3); PRIMARY'de PUT reddedilir (§4.4)
  projects: string[];
  keys: string[];
  verbs: string[];
}

export interface PolicyDoc {
  schema: string;
  version: number;
  rules: PolicyRule[];
}

/** Topology, §3.2/§3.3 seçimi. PRIMARY'de `aud` selector'lü kural dead-rule → red. */
export type Topology = "primary" | "fallback";

// --- Glob (pinli sözdizimi, §4.2) --------------------------------------------
// `*` = herhangi bir karakter dizisi (boş dahil), `?` = tek karakter, gerisi
// literal, TAM-string eşleşme. Karakter sınıfı / `**` YOK.
//
// CASE SEMANTİĞİ: globMatch primitivi case-SENSITIVE'dir (aşağıdaki testler pinler)
// ve anahtar adları storage'da case-sensitive kimliktir (keyName AEAD AAD'ye bağlı) —
// allow/token/lookup HEP case-sensitive. TEK istisna DENY'dir: keyGlobMatch üstünden
// CASE-INSENSITIVE eşleşir (fail-safe hardening: bir `!*_PROD_*` deny'i `*_prod_*`
// varyantını da yakalasın; deny fazladan eşleşmesi güvenli yöndür).
//
// GÜVENLİK (ReDoS): regex TABANLI DEĞİL. Greedy `[\s\S]*` çevirisi, policy
// admin'inin PUT edebildiği `*A*A*...*B` şekilli bir pattern'de katastrofik
// backtracking'e (üstel süre) açıktı — authorize()/filterReadableKeys() üstünden
// tüm list/read/write/manifest yolları DoS edilebilirdi. Aşağıdaki eşleştirici
// klasik iki-işaretçili '*' geri-alma algoritmasıdır: backtracking regex YOK,
// en kötü durum O(|glob| × |s|) — 256×128 sınırlarıyla mikro-saniyeler.

/**
 * globMatch, pinli glob semantiğiyle tam-string eşleşme (§4.2). Lineer-zamanlı
 * iki-işaretçili algoritma: son görülen '*' konumu (star) + o yıldızın s'de
 * denenen başlangıcı (mark) tutulur; uyumsuzlukta yıldız bir karakter daha
 * "yutar" (mark++). '?' tek karakter (UTF-16 code unit — eski `[\s\S]`
 * semantiğiyle birebir), baştaki '!' deny formu ÇAĞIRANDA ele alınır.
 */
export function globMatch(glob: string, s: string): boolean {
  let gi = 0; // glob işaretçisi
  let si = 0; // s işaretçisi
  let star = -1; // son '*' index'i (yoksa -1)
  let mark = 0; // son '*' için s'de denenen eşleşme başlangıcı
  while (si < s.length) {
    if (gi < glob.length && (glob[gi] === "?" || glob[gi] === s[si])) {
      gi++;
      si++;
    } else if (gi < glob.length && glob[gi] === "*") {
      star = gi;
      gi++;
      mark = si; // '*' önce BOŞ eşleşmeyi dener
    } else if (star !== -1) {
      // Uyumsuzluk: son '*' bir karakter daha yutsun, kaldığı yerden devam.
      gi = star + 1;
      mark++;
      si = mark;
    } else {
      return false;
    }
  }
  // s tükendi: glob'un kalanı yalnızca '*' ise eşleşme tamdır.
  while (gi < glob.length && glob[gi] === "*") gi++;
  return gi === glob.length;
}

/**
 * keyGlobMatch, anahtar-ADI eşleşmesidir (§4.3) ve globMatch'i CASE-INSENSITIVE
 * uygular. Anahtar adları POSIX env-var olabildiğinden case-insensitive KİMLİKtir
 * (FOO ≡ foo — writer-DO farklı-case varyantı reddeder). Böylece bir `!*_PROD_*`
 * deny'i `*_prod_*` varyantını da yakalar VE allow tarafı simetrik kalır (asimetri
 * yok, over-match yok). globMatch'in kendisi §4.2 pinli case-SENSITIVE kalır.
 */
export function keyGlobMatch(glob: string, key: string): boolean {
  return globMatch(glob.toLowerCase(), key.toLowerCase());
}

// --- Verb genişletmesi (§4.2) --------------------------------------------------

/** expandVerbs, rule.verbs'i efektif verb kümesine açar: "*" = dördü; rotate ⊃ write. */
export function expandVerbs(verbs: string[]): Set<PolicyVerb> {
  const out = new Set<PolicyVerb>();
  for (const v of verbs) {
    if (v === "*") {
      for (const all of POLICY_VERBS) out.add(all);
      continue;
    }
    if ((POLICY_VERBS as readonly string[]).includes(v)) out.add(v as PolicyVerb);
    // rotate, data-plane yazma rotalarında write'ı DA kapsar (§4.2 pinli semantik).
    if (v === "rotate") out.add("write");
  }
  return out;
}

// --- Değerlendirme (§4.3, normatif algoritma) ----------------------------------

/** AuthzPrincipal, policy eşleşmesi için gereken principal görünümü. */
export interface AuthzPrincipal {
  kind: "human" | "service";
  id: string; // "human:<email>" | "service:<common_name>"
  groups: string[]; // yalnızca human (get-identity, §3.2); service için []
  aud?: string; // isteğin doğrulanmış aud'u (FALLBACK selector'ı için)
}

export type DenyDimension = "no_rule" | "verb" | "project" | "key_denied";

export interface AuthzDecision {
  allowed: boolean;
  // deny'de en İLERİ ulaşılan boyut (§4.3.4 audit alanı): selector'ü geçen kural
  // yoksa no_rule; verb'te takılan en iyi kural → verb; ...
  reason?: DenyDimension;
}

const DIM_ORDER: DenyDimension[] = ["no_rule", "verb", "project", "key_denied"];

/**
 * authorize, §4.3'ün birebir uygulamasıdır: herhangi TEK kural izin verirse allow
 * (kurallar-arası birleşim); deny-glob kural-KAPSAMLIDIR (başka kuralın allow'unu
 * veto etmez); hiçbir kural izin vermezse deny (deny-by-default). key=null →
 * proje-seviyesi metadata op'u (adım 4 atlanır).
 */
export function authorize(
  doc: PolicyDoc,
  p: AuthzPrincipal,
  project: string,
  key: string | null,
  verb: PolicyVerb,
): AuthzDecision {
  let furthest = 0; // DIM_ORDER index'i (deny nedeni raporu için)
  for (const rule of doc.rules) {
    // 1. principal selector
    if (rule.group !== undefined) {
      if (p.kind !== "human" || !p.groups.includes(rule.group)) continue;
    } else if (rule.service !== undefined) {
      if (p.id !== `service:${rule.service}`) continue;
    } else if (rule.aud !== undefined) {
      if (p.aud !== rule.aud) continue;
    } else {
      continue; // selector'süz kural (validation zaten reddeder) — asla eşleşmez
    }
    furthest = Math.max(furthest, 1);
    // 2. verb
    if (!expandVerbs(rule.verbs).has(verb)) continue;
    furthest = Math.max(furthest, 2);
    // 3. project
    if (!rule.projects.some((g) => globMatch(g, project))) continue;
    furthest = Math.max(furthest, 3);
    // 4. key (null → proje-metadata op'u; adım atlanır)
    if (key !== null) {
      // deny-glob KENDİ kuralı içinde kazanır (§4.3 pinli semantik 2).
      //  • DENY: keyGlobMatch (CASE-INSENSITIVE) — fail-safe hardening. `!*_PROD_*`
      //    `*_prod_*` varyantını da yakalar; deny fazladan eşleşmesi GÜVENLİ yöndür.
      //  • ALLOW: globMatch (case-SENSITIVE, §4.2 pinli) — anahtar adları storage'da
      //    case-sensitive kimliktir (keyName AEAD AAD'ye bağlı), allow bir case-
      //    varyantını istemeden GRANT'lamaz (over-grant yok, storage ile tutarlı).
      if (rule.keys.some((g) => g.startsWith("!") && keyGlobMatch(g.slice(1), key))) continue;
      if (!rule.keys.some((g) => !g.startsWith("!") && globMatch(g, key))) continue;
    }
    return { allowed: true };
  }
  return { allowed: false, reason: DIM_ORDER[Math.min(furthest, 3)] };
}

/** filterReadableKeys, bir anahtar-adı listesini principal'ın `read` tuttuğu alt kümeye indirger (§4.3.3). */
export function filterReadableKeys(doc: PolicyDoc, p: AuthzPrincipal, project: string, keys: string[]): string[] {
  return keys.filter((k) => authorize(doc, p, project, k, "read").allowed);
}

/** rulesFor, principal'ın selector'üne eşleşen kuralları döner (whoami efektif grant görünümü). */
export function rulesFor(doc: PolicyDoc, p: AuthzPrincipal): PolicyRule[] {
  return doc.rules.filter((rule) => {
    if (rule.group !== undefined) return p.kind === "human" && p.groups.includes(rule.group);
    if (rule.service !== undefined) return p.id === `service:${rule.service}`;
    if (rule.aud !== undefined) return p.aud === rule.aud;
    return false;
  });
}

// --- Validation (§4.4) ----------------------------------------------------------

const COMMON_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const GLOB_MAX_LEN = 256;

/** PolicyValidationError, kural index'ini adlandıran 422 POLICY_INVALID hatası. */
export class PolicyValidationError extends Error {
  constructor(public ruleIndex: number | null, msg: string) {
    super(msg);
    this.name = "PolicyValidationError";
  }
}

/**
 * validatePolicy, §4.4'ün Worker-side doğrulamasıdır (PUT'ta; kural index'i
 * adlandırılır). version-CAS kontrolü ÇAĞIRANDA (putPolicy) yapılır — burada
 * yalnızca doküman-içi tutarlılık.
 */
export function validatePolicy(doc: unknown, topology: Topology, adminEmails: string[]): PolicyDoc {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new PolicyValidationError(null, "policy not an object");
  const o = doc as Record<string, unknown>;
  if (o.schema !== SCHEMA_POLICY) throw new PolicyValidationError(null, `schema must be ${SCHEMA_POLICY}`);
  if (typeof o.version !== "number" || !Number.isInteger(o.version) || o.version < 1) throw new PolicyValidationError(null, "version must be a positive integer");
  if (!Array.isArray(o.rules)) throw new PolicyValidationError(null, "rules must be an array");

  let hasGroupAdmin = false;
  const rules: PolicyRule[] = o.rules.map((raw, i) => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new PolicyValidationError(i, `rule[${i}] not an object`);
    const r = raw as Record<string, unknown>;
    for (const k of Object.keys(r)) {
      if (!["group", "service", "aud", "projects", "keys", "verbs"].includes(k)) throw new PolicyValidationError(i, `rule[${i}]: unknown field ${k}`);
    }
    // Tam olarak bir selector (§4.2).
    const selectors = (["group", "service", "aud"] as const).filter((k) => r[k] !== undefined);
    if (selectors.length !== 1) throw new PolicyValidationError(i, `rule[${i}]: exactly one of group/service/aud required`);
    const sel = selectors[0];
    if (typeof r[sel] !== "string" || (r[sel] as string).trim() === "") throw new PolicyValidationError(i, `rule[${i}].${sel} must be a non-empty string`);
    if (sel === "aud" && topology === "primary") {
      // PRIMARY'de aud selector'ü sessizce hiç eşleşmeyen DEAD kural olurdu → red (§4.4).
      throw new PolicyValidationError(i, `rule[${i}]: aud selectors are FALLBACK-only (§3.3); rejected in PRIMARY topology`);
    }
    if (sel === "service" && !COMMON_NAME_RE.test(r.service as string)) throw new PolicyValidationError(i, `rule[${i}].service not a valid common_name`);

    // projects: boş olmayan glob listesi; deny formu YOK (§4.2).
    if (!Array.isArray(r.projects) || r.projects.length === 0) throw new PolicyValidationError(i, `rule[${i}].projects must be a non-empty array`);
    for (const g of r.projects) {
      if (typeof g !== "string" || g === "" || g.length > GLOB_MAX_LEN || g.startsWith("!")) throw new PolicyValidationError(i, `rule[${i}].projects: invalid glob`);
    }
    // keys: en az bir POZİTİF glob (§4.2).
    if (!Array.isArray(r.keys) || r.keys.length === 0) throw new PolicyValidationError(i, `rule[${i}].keys must be a non-empty array`);
    let positive = 0;
    for (const g of r.keys) {
      if (typeof g !== "string" || g === "" || g === "!" || g.length > GLOB_MAX_LEN) throw new PolicyValidationError(i, `rule[${i}].keys: invalid glob`);
      if (!g.startsWith("!")) positive++;
    }
    if (positive === 0) throw new PolicyValidationError(i, `rule[${i}].keys: at least one positive glob required`);
    // verbs: kapalı küme veya ["*"] (§4.2).
    if (!Array.isArray(r.verbs) || r.verbs.length === 0) throw new PolicyValidationError(i, `rule[${i}].verbs must be a non-empty array`);
    for (const v of r.verbs) {
      if (v !== "*" && !(POLICY_VERBS as readonly string[]).includes(v as string)) throw new PolicyValidationError(i, `rule[${i}].verbs: unknown verb ${String(v)}`);
    }
    if (sel === "group" && expandVerbs(r.verbs as string[]).has("admin")) hasGroupAdmin = true;

    return { group: r.group as string | undefined, service: r.service as string | undefined, aud: r.aud as string | undefined, projects: r.projects as string[], keys: r.keys as string[], verbs: r.verbs as string[] };
  });

  // Lockout guard (§4.4): admin verb'i veren bir group kuralı YA DA ADMIN_EMAILS dolu.
  if (!hasGroupAdmin && adminEmails.length === 0) throw new PolicyValidationError(null, "no admin path: no group rule grants admin and ADMIN_EMAILS is empty (lockout)");

  return { schema: SCHEMA_POLICY, version: o.version, rules };
}

// --- Depolama + versiyon zinciri (§4.1) ------------------------------------------

/** CurrentPolicyPointer, policy/current pointer objesi. */
interface CurrentPolicyPointer {
  version: number;
  sha256: string; // versiyon objesi baytlarının hex sha256'sı
}

/** LoadedPolicy, R2'den çözülmüş + doğrulanmış aktif policy. */
export interface LoadedPolicy {
  doc: PolicyDoc;
  version: number;
  sha256: string;
}

/** EMPTY_POLICY, first-boot (hiç policy PUT edilmemiş) durumu: yalnızca ADMIN_EMAILS çalışır (§4.5). */
export const EMPTY_POLICY: LoadedPolicy = { doc: { schema: SCHEMA_POLICY, version: 0, rules: [] }, version: 0, sha256: "" };

// İzolat-içi policy cache (§4.1): ≤60 s; policy PUT versiyonu bumplar, sonraki
// refresh yeni dokümanı alır (authz lag ≤60 s, kabul edilmiş).
const POLICY_CACHE_MS = 60_000;
let policyCache: { loaded: LoadedPolicy; at: number } | null = null;

/** __resetPolicyCache, testler arası izolasyon içindir. */
export function __resetPolicyCache(): void {
  policyCache = null;
}

/** PolicyStoreError, policy R2 durumu bozuksa (pointer/hash uyuşmazlığı) fırlar → 503. */
export class PolicyStoreError extends Error {}

/**
 * loadPolicy, aktif policy'yi R2'den yükler (izolat cache ≤60 s). policy/current
 * yoksa EMPTY_POLICY (first-boot, §4.5). Pointer'ın sha256'sı versiyon objesiyle
 * tutmazsa fail-closed PolicyStoreError (tamper/yarım yazım).
 */
export async function loadPolicy(bucket: R2Bucket, topology: Topology, adminEmails: string[]): Promise<LoadedPolicy> {
  if (policyCache && Date.now() - policyCache.at < POLICY_CACHE_MS) return policyCache.loaded;
  const cur = await getObject(bucket, keyPolicyCurrent());
  if (!cur) {
    policyCache = { loaded: EMPTY_POLICY, at: Date.now() };
    return EMPTY_POLICY;
  }
  let ptr: CurrentPolicyPointer;
  try {
    ptr = JSON.parse(new TextDecoder().decode(cur.bytes)) as CurrentPolicyPointer;
  } catch {
    throw new PolicyStoreError("policy/current not valid JSON");
  }
  if (typeof ptr.version !== "number" || typeof ptr.sha256 !== "string") throw new PolicyStoreError("policy/current malformed");
  const verObj = await getObject(bucket, keyPolicyVersion(ptr.version));
  if (!verObj) throw new PolicyStoreError(`policy version object ${ptr.version} missing`);
  if (sha256Hex(verObj.bytes) !== ptr.sha256) throw new PolicyStoreError("policy version object hash != pointer sha256");
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(verObj.bytes));
  } catch {
    throw new PolicyStoreError("policy version object not valid JSON");
  }
  let doc: PolicyDoc;
  try {
    doc = validatePolicy(raw, topology, adminEmails);
  } catch (e) {
    // Depodaki policy artık geçersizse (ör. topoloji değişimi) fail-closed.
    throw new PolicyStoreError(`stored policy invalid: ${(e as Error).message}`);
  }
  if (doc.version !== ptr.version) throw new PolicyStoreError("policy version field != pointer version");
  const loaded: LoadedPolicy = { doc, version: ptr.version, sha256: ptr.sha256 };
  policyCache = { loaded, at: Date.now() };
  return loaded;
}

/** PolicyConflictError, CAS kaybı (412 POLICY_CONFLICT) — çağıran refetch+retry eder. */
export class PolicyConflictError extends Error {}

/**
 * putPolicy, §4.1'in pinli PUT atomikliği: (1) versiyon objesi onlyIf-absent
 * (slot'u ilk yazan kazanır), (2) pointer If-Match CAS (ilk PUT'ta onlyIf-absent).
 * version === current+1 değilse veya herhangi bir conditional kaybederse
 * PolicyConflictError. Başarıda cache düşürülür. Dönen değer yeni pointer.
 */
export async function putPolicy(bucket: R2Bucket, doc: PolicyDoc, topology: Topology, adminEmails: string[]): Promise<LoadedPolicy> {
  // Doküman-içi doğrulama (fırlatırsa PolicyValidationError → 422).
  const valid = validatePolicy(doc, topology, adminEmails);

  const cur = await getObject(bucket, keyPolicyCurrent());
  const curVersion = cur ? (JSON.parse(new TextDecoder().decode(cur.bytes)) as CurrentPolicyPointer).version : 0;
  if (valid.version !== curVersion + 1) throw new PolicyConflictError(`version must be ${curVersion + 1} (current ${curVersion})`);

  const bytes = utf8(JSON.stringify(valid));
  const sha = sha256Hex(bytes);
  // (1) Versiyon slot'u: onlyIf-absent — iki eşzamanlı PUT'tan yalnızca biri kazanır.
  const wrote = await bucket.put(keyPolicyVersion(valid.version), bytes, { onlyIf: { etagDoesNotMatch: "*" } });
  if (wrote === null) {
    // Liveness kurtarması (wedge fix): önceki bir PUT, slot-yazımı ile pointer-CAS'i
    // ARASINDA düşmüşse (crash / CAS kaybı) slot n kalıcı yanmış olurdu — her sonraki
    // PUT version=current+1=n kullanmak zorunda ve hep burada takılırdı. Dolu slot'un
    // içeriği yazacağımızla BİREBİR aynıysa (sha256 eşit) bunu idempotent-DEVAM say:
    // pointer CAS'ine geç. Farklı içerik → gerçek versiyon yarışı → POLICY_CONFLICT.
    const existing = await getObject(bucket, keyPolicyVersion(valid.version));
    if (!existing || sha256Hex(existing.bytes) !== sha) throw new PolicyConflictError("version slot already written");
  }
  // (2) Pointer CAS: If-Match mevcut etag (ilk PUT'ta onlyIf-absent).
  const ptrBytes = utf8(JSON.stringify({ version: valid.version, sha256: sha }));
  const swapped = cur
    ? await bucket.put(keyPolicyCurrent(), ptrBytes, { onlyIf: { etagMatches: cur.etag } })
    : await bucket.put(keyPolicyCurrent(), ptrBytes, { onlyIf: { etagDoesNotMatch: "*" } });
  if (swapped === null) throw new PolicyConflictError("pointer CAS lost");
  policyCache = null; // sonraki istek taze policy'yi okur
  return { doc: valid, version: valid.version, sha256: sha };
}
