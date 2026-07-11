package policy

// İstemci-tarafı policy doğrulama + lint testleri (SPEC §4.2/§4.4 şema; §7.3 a–e).

import (
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/store"
)

// TestGlobMatch, pinli glob semantiği (§4.2): *, ?, tam-string, case-sensitive.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		glob, s string
		want    bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"DB_*", "DB_URL", true},
		{"DB_*", "db_url", false}, // case-sensitive
		{"*_PROD_*", "APP_PROD_KEY", true},
		{"*_PROD_*", "APP_PRODKEY", false},
		{"?", "a", true},
		{"?", "", false},
		{"A?C", "ABC", true},
		{"A?C", "AC", false},
		{"literal", "literal", true},
		{"literal", "literalx", false}, // tam-string
		{"a*b*c", "aXXbYYc", true},
	}
	for _, tc := range cases {
		if got := GlobMatch(tc.glob, tc.s); got != tc.want {
			t.Errorf("GlobMatch(%q,%q) = %v, want %v", tc.glob, tc.s, got, tc.want)
		}
	}
}

// TestExpandVerbs, "*" = dört verb; rotate ⊃ write (§4.2 pinli semantik).
func TestExpandVerbs(t *testing.T) {
	all := ExpandVerbs([]string{"*"})
	for _, v := range []string{"read", "write", "rotate", "admin"} {
		if !all[v] {
			t.Errorf("[\"*\"] must expand to %s", v)
		}
	}
	rot := ExpandVerbs([]string{"rotate"})
	if !rot["write"] {
		t.Error("rotate must ALSO grant write (rotate ⊃ write)")
	}
	if rot["admin"] || rot["read"] {
		t.Error("rotate must not grant admin/read")
	}
}

func validDoc(rules ...store.Rule) store.PolicyDoc {
	return store.PolicyDoc{Schema: SchemaPolicy, Version: 1, Rules: rules}
}

// TestValidate, §4.4 kuralları: selector tekliği, PRIMARY aud reddi, pozitif
// key glob zorunluluğu, kapalı verb kümesi.
func TestValidate(t *testing.T) {
	ok := validDoc(store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!*_PROD_*"}, Verbs: []string{"read"}})
	if err := Validate(ok, "primary"); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}

	cases := []struct {
		name string
		doc  store.PolicyDoc
		frag string
	}{
		{"bad schema", store.PolicyDoc{Schema: "nope", Version: 1}, "schema"},
		{"no selector", validDoc(store.Rule{Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}}), "exactly one"},
		{"two selectors", validDoc(store.Rule{Group: "g@x", Service: "svc", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}}), "exactly one"},
		{"aud in primary", validDoc(store.Rule{Aud: "aud1", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}}), "FALLBACK-only"},
		{"bad service name", validDoc(store.Rule{Service: "bad name!", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}}), "common_name"},
		{"deny-only keys", validDoc(store.Rule{Group: "g@x", Projects: []string{"*"}, Keys: []string{"!*"}, Verbs: []string{"read"}}), "positive"},
		{"deny project glob", validDoc(store.Rule{Group: "g@x", Projects: []string{"!x"}, Keys: []string{"*"}, Verbs: []string{"read"}}), "invalid glob"},
		{"unknown verb", validDoc(store.Rule{Group: "g@x", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"deploy"}}), "unknown verb"},
	}
	for _, tc := range cases {
		err := Validate(tc.doc, "primary")
		if err == nil || !strings.Contains(err.Error(), tc.frag) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.frag, err)
		}
	}

	// FALLBACK topolojisinde aud kuralı GEÇERLİDİR (§3.3).
	aud := validDoc(store.Rule{Aud: "aud1", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}})
	if err := Validate(aud, "fallback"); err != nil {
		t.Errorf("aud selector must be valid in FALLBACK: %v", err)
	}
}

// hasWarn, verilen kural sınıfından bir uyarı arar.
func hasWarn(warns []Warning, rule string) bool {
	for _, w := range warns {
		if w.Rule == rule {
			return true
		}
	}
	return false
}

// TestLintRules, §7.3 lint kuralları a–e.
func TestLintRules(t *testing.T) {
	// (a) aynı principal'a bir kuralda deny, diğerinde allow.
	a := validDoc(
		store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!SECRET_*"}, Verbs: []string{"read"}},
		store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"SECRET_API"}, Verbs: []string{"read"}},
	)
	if !hasWarn(Lint(a), "a") {
		t.Error("lint(a): overridden deny glob must warn")
	}

	// (b) admin-dışı gruba *_PROD_* erişimi (read dahil — server-decrypt'te en tehlikeli verb).
	b := validDoc(store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"read"}})
	if !hasWarn(Lint(b), "b") {
		t.Error("lint(b): non-admin group reaching *_PROD_* keys must warn")
	}
	// Deny glob'lu hali uyarmamalı.
	bOK := validDoc(store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!*_PROD_*"}, Verbs: []string{"read"}})
	if hasWarn(Lint(bOK), "b") {
		t.Error("lint(b): a \"!*_PROD_*\" deny must silence the warning")
	}

	// (c) erişilemez kural: aynı selector'ün süperset'i varken dar kural.
	c := validDoc(
		store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"*"}},
		store.Rule{Group: "dev@wapps.co", Projects: []string{"vaulter"}, Keys: []string{"DB_*"}, Verbs: []string{"read"}},
	)
	if !hasWarn(Lint(c), "c") {
		t.Error("lint(c): a fully-shadowed rule must warn")
	}

	// (d) service satırında ["*"].
	d := validDoc(store.Rule{Service: "svc-woodpecker", Projects: []string{"vaulter"}, Keys: []string{"DEPLOY_*"}, Verbs: []string{"*"}})
	if !hasWarn(Lint(d), "d") {
		t.Error("lint(d): service row with [\"*\"] verbs must warn")
	}

	// (e) admin + proje/anahtar kapsaması (ölü kapsam).
	e := validDoc(store.Rule{Group: "admins@wapps.co", Projects: []string{"vaulter"}, Keys: []string{"*"}, Verbs: []string{"admin"}})
	if !hasWarn(Lint(e), "e") {
		t.Error("lint(e): project-scoped admin grant must warn (admin ops are global)")
	}
	eOK := validDoc(store.Rule{Group: "admins@wapps.co", Projects: []string{"*"}, Keys: []string{"*"}, Verbs: []string{"*"}})
	if hasWarn(Lint(eOK), "e") {
		t.Error("lint(e): unscoped admin grant must not warn")
	}
}

func TestDenyCaseInsensitive(t *testing.T) {
	// Anahtar adları POSIX env-var (karışık harf). Deny savunma amaçlıdır →
	// case-insensitive: `!*_PROD_*` küçük/karışık harf prod adını da yakalar.
	r := store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!*_PROD_*"}, Verbs: []string{"read"}}
	for _, k := range []string{"DB_PROD_URL", "db_prod_url", "Db_Prod_Url", "vaulter_pg_prod_password"} {
		if !deniedByRule(r, k) {
			t.Errorf("deniedByRule(%q) = false, want denied (case-insensitive deny)", k)
		}
	}
	if deniedByRule(r, "database_url") {
		t.Error("deniedByRule(database_url) = true, want allowed (no prod token)")
	}
}

func TestLintProdCaseInsensitive(t *testing.T) {
	// (b) küçük-harf `*_prod_*` erişimi de uyarmalı (risky-prod tespiti case-insensitive).
	b := validDoc(store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*_prod_*"}, Verbs: []string{"read"}})
	if !hasWarn(Lint(b), "b") {
		t.Error("lint(b): lowercase *_prod_* reachability must warn")
	}
	// Küçük-harf deny de uyarıyı susturmalı (enforcement case-insensitive olduğundan).
	bOK := validDoc(store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!*_prod_*"}, Verbs: []string{"read"}})
	if hasWarn(Lint(bOK), "b") {
		t.Error("lint(b): a lowercase !*_prod_* deny must silence the warning")
	}
}

func TestKeyGlobMatchCaseInsensitive(t *testing.T) {
	// GlobMatch §4.2 pinli case-SENSITIVE kalır; keyGlobMatch (anahtar-adı) case-insensitive.
	if !GlobMatch("DB_*", "DB_URL") || GlobMatch("DB_*", "db_url") {
		t.Fatal("GlobMatch must stay case-sensitive (§4.2 pinned)")
	}
	if !keyGlobMatch("DB_*", "db_url") || !keyGlobMatch("db_*", "DB_URL") || !keyGlobMatch("*_PROD_*", "x_prod_y") {
		t.Error("keyGlobMatch must fold case (key names are case-insensitive identifiers)")
	}
	if keyGlobMatch("DB_*", "MYDB_URL") {
		t.Error("keyGlobMatch must still anchor (full-string) — case-fold only, not substring")
	}
}

func TestLintOverriddenDenyCaseInsensitive(t *testing.T) {
	// (a) küçük-harf deny, başka kuralda karışık-harf allow'la override ediliyor →
	// enforcement case-insensitive olduğundan lint(a) da yakalamalı (codex P3).
	a := validDoc(
		store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"*", "!secret_*"}, Verbs: []string{"read"}},
		store.Rule{Group: "dev@wapps.co", Projects: []string{"*"}, Keys: []string{"SECRET_API"}, Verbs: []string{"read"}},
	)
	if !hasWarn(Lint(a), "a") {
		t.Error("lint(a): a case-distinct override of a deny glob must still warn")
	}
}
