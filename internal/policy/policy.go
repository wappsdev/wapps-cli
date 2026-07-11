// Package policy, policy.json'un İSTEMCİ-TARAFI doğrulaması + lint'idir
// (SPEC §4.2/§4.4 şema kuralları; §7.3 lint kuralları a–e). Worker aynı şema
// doğrulamasını PUT'ta ZORLAR (authz kaynağı SUNUCUDUR); buradaki kopya yalnızca
// `wapps secrets policy lint/set`in hızlı, çevrimdışı ön-kontrolüdür.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/store"
)

// SchemaPolicy, §4.2 şema tanımlayıcısı.
const SchemaPolicy = "wapps-secrets/policy/v1"

// policyVerbs, kapalı verb kümesi (§4.2).
var policyVerbs = map[string]bool{"read": true, "write": true, "rotate": true, "admin": true}

var commonNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

const globMaxLen = 256

// --- Glob (pinli sözdizimi, §4.2): `*` = herhangi bir dizi (boş dahil), `?` =
// tek karakter, gerisi literal, case-sensitive, TAM-string eşleşme. -----------

// GlobMatch, pinli glob semantiğiyle tam-string eşleşme yapar (§4.2 case-SENSITIVE).
func GlobMatch(glob, s string) bool {
	return globMatchAt(glob, s)
}

// keyGlobMatch, anahtar-ADI eşleşmesidir: GlobMatch'i CASE-INSENSITIVE uygular.
// Anahtar adları POSIX env-var (karışık harf) olabildiğinden case-insensitive
// KİMLİKtir — Worker enforcement (authorize) ile aynı semantik. GlobMatch'in kendisi
// §4.2 pinli case-sensitive kalır.
func keyGlobMatch(glob, key string) bool {
	return GlobMatch(strings.ToLower(glob), strings.ToLower(key))
}

func globMatchAt(g, s string) bool {
	// Klasik geri-izlemeli glob eşleyici (yalnızca * ve ?).
	var gi, si int
	star, starSi := -1, 0
	for si < len(s) {
		switch {
		case gi < len(g) && (g[gi] == '?' || g[gi] == s[si]):
			gi++
			si++
		case gi < len(g) && g[gi] == '*':
			star, starSi = gi, si
			gi++
		case star != -1:
			gi = star + 1
			starSi++
			si = starSi
		default:
			return false
		}
	}
	for gi < len(g) && g[gi] == '*' {
		gi++
	}
	return gi == len(g)
}

// ExpandVerbs, rule.verbs'i efektif kümeye açar: "*" = dördü; rotate ⊃ write (§4.2).
func ExpandVerbs(verbs []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range verbs {
		if v == "*" {
			for pv := range policyVerbs {
				out[pv] = true
			}
			continue
		}
		if policyVerbs[v] {
			out[v] = true
		}
		if v == "rotate" {
			out["write"] = true
		}
	}
	return out
}

// Validate, §4.4 doküman-içi doğrulamasını uygular (Worker paritesi; version-CAS
// kontrolü sunucudadır). topology "primary" iken aud selector'lü kurallar
// reddedilir (dead rule, §3.3/§4.4). Hata mesajı kural index'ini adlandırır.
func Validate(doc store.PolicyDoc, topology string) error {
	if doc.Schema != SchemaPolicy {
		return fmt.Errorf("policy: schema must be %s", SchemaPolicy)
	}
	if doc.Version < 1 {
		return fmt.Errorf("policy: version must be a positive integer")
	}
	for i, r := range doc.Rules {
		selectors := 0
		if r.Group != "" {
			selectors++
		}
		if r.Service != "" {
			selectors++
		}
		if r.Aud != "" {
			selectors++
		}
		if selectors != 1 {
			return fmt.Errorf("policy: rule[%d]: exactly one of group/service/aud required", i)
		}
		if r.Aud != "" && topology == "primary" {
			return fmt.Errorf("policy: rule[%d]: aud selectors are FALLBACK-only (§3.3); rejected in PRIMARY topology", i)
		}
		if r.Service != "" && !commonNameRE.MatchString(r.Service) {
			return fmt.Errorf("policy: rule[%d].service not a valid common_name", i)
		}
		if len(r.Projects) == 0 {
			return fmt.Errorf("policy: rule[%d].projects must be a non-empty array", i)
		}
		for _, g := range r.Projects {
			if g == "" || len(g) > globMaxLen || strings.HasPrefix(g, "!") {
				return fmt.Errorf("policy: rule[%d].projects: invalid glob %q", i, g)
			}
		}
		if len(r.Keys) == 0 {
			return fmt.Errorf("policy: rule[%d].keys must be a non-empty array", i)
		}
		positive := 0
		for _, g := range r.Keys {
			if g == "" || g == "!" || len(g) > globMaxLen {
				return fmt.Errorf("policy: rule[%d].keys: invalid glob %q", i, g)
			}
			if !strings.HasPrefix(g, "!") {
				positive++
			}
		}
		if positive == 0 {
			return fmt.Errorf("policy: rule[%d].keys: at least one positive glob required", i)
		}
		if len(r.Verbs) == 0 {
			return fmt.Errorf("policy: rule[%d].verbs must be a non-empty array", i)
		}
		for _, v := range r.Verbs {
			if v != "*" && !policyVerbs[v] {
				return fmt.Errorf("policy: rule[%d].verbs: unknown verb %q", i, v)
			}
		}
	}
	return nil
}

// --- Lint (§7.3 kuralları a–e; UYARI üretir, bloklamaz) -------------------------

// Warning, bir lint bulgusudur.
type Warning struct {
	Rule    string // a|b|c|d|e
	Index   int    // ilgili kural index'i
	Message string
}

func (w Warning) String() string {
	return fmt.Sprintf("lint(%s) rule[%d]: %s", w.Rule, w.Index, w.Message)
}

// selectorOf, bir kuralın principal selector anahtarını döner.
func selectorOf(r store.Rule) string {
	switch {
	case r.Group != "":
		return "group:" + r.Group
	case r.Service != "":
		return "service:" + r.Service
	default:
		return "aud:" + r.Aud
	}
}

// globsIntersectHeuristic, iki glob'un kesişebileceğini SEZGİSEL tespit eder
// (tam glob-kesişimi kararsızlığa yakın pahalıdır; lint için yeterli): biri
// diğerinin ürettiği temsili dizeyi eşliyorsa kesişir sayılır. Temsilci =
// glob'da '*'→"" ve '?'→"x".
func globsIntersectHeuristic(a, b string) bool {
	// Anahtar-glob'ları CASE-INSENSITIVE kesişir (enforcement/keyGlobMatch ile
	// tutarlı): küçük-harf bir allow, karışık-harf bir deny'yi override edebilir.
	return keyGlobMatch(a, concretize(b)) || keyGlobMatch(b, concretize(a)) || strings.EqualFold(a, b)
}

func concretize(glob string) string {
	s := strings.ReplaceAll(glob, "*", "")
	return strings.ReplaceAll(s, "?", "x")
}

// prodProbe, (b) kuralının temsilî prod anahtarı: glob'un *_PROD_* desenli bir
// anahtarı eşleyip eşleyemeyeceğini yoklamak için '*'→"_PROD_" ikamesi denenir.
func canMatchProd(keyGlob string) bool {
	// Case-insensitive: anahtar adları POSIX env-var (karışık harf) olabilir ve
	// enforcement/keyGlobMatch case-insensitive eşleştiğinden, risky-prod tespiti de
	// küçük-harf üstünden yapılır — `*_prod_*` kaçmasın.
	if strings.Contains(strings.ToLower(keyGlob), "_prod_") {
		return true
	}
	probe := strings.ReplaceAll(keyGlob, "*", "_PROD_")
	probe = strings.ReplaceAll(probe, "?", "x")
	return keyGlobMatch(keyGlob, probe) && keyGlobMatch("*_prod_*", probe)
}

// deniedByRule, key'in kuralın deny glob'larından birine takıldığını döner. Deny
// CASE-INSENSITIVE eşleşir (keyGlobMatch, enforcement ile aynı §4.3): küçük-harf bir
// ad varyantı bir deny glob'unu atlatmasın.
func deniedByRule(r store.Rule, key string) bool {
	for _, g := range r.Keys {
		if strings.HasPrefix(g, "!") && keyGlobMatch(g[1:], key) {
			return true
		}
	}
	return false
}

// Lint, §7.3 lint kurallarını uygular:
//
//	(a) bir kuralda deny'lanan anahtar deseni, ÖRTÜŞEN bir principal kümesine
//	    başka bir kuralla allow ediliyor (deny kural-KAPSAMLI olduğundan yazarın
//	    görmesi gerekir, §4.3.2);
//	(b) *_PROD_* eşleyebilen anahtarlara admin-dışı GRUP kurallarıyla write/rotate
//	    VEYA plaintext read grant'i (read, server-decrypt modelde DAHA tehlikeli verb);
//	(c) erişilemez (tamamen gölgelenmiş / yinelenen) kurallar — sezgisel: aynı
//	    selector'lü bir kuralın verb+project+key yüzeyi bir başkasının alt kümesi;
//	(d) verbs ["*"] taşıyan service satırları;
//	(e) admin granting kurallarda proje/anahtar kapsaması (admin op'ları GLOBAL —
//	    kapsam ÖLÜdür ve yanıltır, §4.2/§7.3 rev3).
func Lint(doc store.PolicyDoc) []Warning {
	var out []Warning
	rules := doc.Rules

	for i, r := range rules {
		verbs := ExpandVerbs(r.Verbs)

		// (d) service + ["*"].
		if r.Service != "" {
			for _, v := range r.Verbs {
				if v == "*" {
					out = append(out, Warning{"d", i, fmt.Sprintf("service row %q grants verbs [\"*\"] — scope service tokens to the narrowest verb set", r.Service)})
				}
			}
		}

		// (e) admin + ölü proje/anahtar kapsaması.
		if verbs["admin"] {
			scoped := false
			for _, p := range r.Projects {
				if p != "*" {
					scoped = true
				}
			}
			for _, k := range r.Keys {
				if k != "*" {
					scoped = true
				}
			}
			if scoped {
				out = append(out, Warning{"e", i, "rule grants `admin` with project/key scoping — admin ops are GLOBAL (§4.2); the scoping is dead and misleads reviewers"})
			}
		}

		// (b) *_PROD_* anahtarlarına admin-dışı grup grant'i (read dahil).
		if r.Group != "" && !verbs["admin"] && (verbs["read"] || verbs["write"] || verbs["rotate"]) {
			for _, g := range r.Keys {
				if strings.HasPrefix(g, "!") {
					continue
				}
				if canMatchProd(g) && !deniedByRule(r, strings.ReplaceAll(strings.ReplaceAll(g, "*", "_PROD_"), "?", "x")) {
					out = append(out, Warning{"b", i, fmt.Sprintf("group %q can reach *_PROD_*-matching keys via %q — plaintext read is the MOST dangerous verb in a server-decrypt model; consider a \"!*_PROD_*\" deny glob", r.Group, g)})
					break
				}
			}
		}

		// (a) deny'lanan desen başka kuralda örtüşen principal'a allow.
		for _, g := range r.Keys {
			if !strings.HasPrefix(g, "!") {
				continue
			}
			denyPat := g[1:]
			for j, s := range rules {
				if j == i || selectorOf(s) != selectorOf(r) {
					continue
				}
				for _, ag := range s.Keys {
					if strings.HasPrefix(ag, "!") {
						continue
					}
					if globsIntersectHeuristic(denyPat, ag) {
						out = append(out, Warning{"a", i, fmt.Sprintf("deny glob %q is overridden for the same principal set by rule[%d]'s allow %q (deny is rule-scoped, §4.3.2)", g, j, ag)})
					}
				}
			}
		}
	}

	// (c) erişilemez/yinelenen kurallar (sezgisel alt-küme tespiti).
	for i, r := range rules {
		for j, s := range rules {
			if i == j || selectorOf(r) != selectorOf(s) {
				continue
			}
			if ruleSubsumes(s, r) && (j < i || !ruleSubsumes(r, s)) {
				out = append(out, Warning{"c", i, fmt.Sprintf("rule appears unreachable: rule[%d] already grants a superset for the same selector", j)})
				break
			}
		}
	}
	return out
}

// ruleSubsumes, a'nın b'yi kapsadığını SEZGİSEL döner: verb'ler ⊇, projeler ve
// anahtarlar glob-kapsama (b'nin her glob'u a'nın bir glob'u tarafından
// concretize edilerek eşleniyor) ve a deny taşımıyor.
func ruleSubsumes(a, b store.Rule) bool {
	av, bv := ExpandVerbs(a.Verbs), ExpandVerbs(b.Verbs)
	for v := range bv {
		if !av[v] {
			return false
		}
	}
	for _, g := range a.Keys {
		if strings.HasPrefix(g, "!") {
			return false
		}
	}
	covers := func(aGlobs, bGlobs []string) bool {
		for _, bg := range bGlobs {
			if strings.HasPrefix(bg, "!") {
				continue
			}
			ok := false
			for _, ag := range aGlobs {
				if ag == "*" || ag == bg || GlobMatch(ag, concretize(bg)) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	return covers(a.Projects, b.Projects) && covers(a.Keys, b.Keys)
}
