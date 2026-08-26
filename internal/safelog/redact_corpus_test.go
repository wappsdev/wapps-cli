package safelog

import (
	"encoding/json"
	"os"
	"testing"
)

// Bu dosya, RedactPatterns'ın Go ve Rust portu ARASINDA paylaşılan tek
// fikstürünü doğrular. Korpus dosyasının `want` alanları BU tarafın (Go'nun)
// çıktısıdır — Go ORACLE'dır. Rust tarafında aynı dosyayı okuyan ikinci bir
// test var (rust/crates/cli/tests/redaction.rs); iki taraf da aynı goldenlara
// bağlı olduğu için bir ayrışma tek bir dosyayı değiştirmeden gizlenemez.
//
// Go'nun davranışı değişirse BU test kırılır (golden bayat kalır); Rust'ınki
// değişirse ORADAKİ test kırılır. Golden'ı yeniden üretmek:
//
//	WAPPS_UPDATE_GOLDEN=1 go test ./internal/safelog
//
// GİZLİ DEĞER YOK: korpustaki her dize uydurma bir biçim örneğidir (AKIA…
// benzeri şekil, üç parçalı sahte bir JWT), gerçek bir anahtar değildir.
type corpusCase struct {
	Name string `json:"name"`
	In   string `json:"in"`
	Want string `json:"want"`
}

const corpusPath = "testdata/redact_corpus.json"

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cases) < 20 {
		t.Fatalf("corpus too small (%d cases); an empty corpus proves nothing", len(cases))
	}
	return cases
}

func TestRedactPatterns_Corpus(t *testing.T) {
	cases := loadCorpus(t)

	if os.Getenv("WAPPS_UPDATE_GOLDEN") == "1" {
		for i := range cases {
			cases[i].Want = RedactPatterns(cases[i].In)
		}
		raw, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatalf("encode corpus: %v", err)
		}
		if err := os.WriteFile(corpusPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("write corpus: %v", err)
		}
		t.Fatalf("golden regenerated — re-run without WAPPS_UPDATE_GOLDEN")
	}

	for _, c := range cases {
		got := RedactPatterns(c.In)
		if got != c.Want {
			t.Errorf("%s:\n in:   %q\n want: %q\n got:  %q", c.Name, c.In, c.Want, got)
		}
	}
}

// TestRedactPatterns_CorpusCoversBothPatterns, korpusun İKİ deseni de gerçekten
// tetiklediğini kanıtlar. Hiçbir şeyi redakte etmeyen bir korpus da "geçer".
func TestRedactPatterns_CorpusCoversBothPatterns(t *testing.T) {
	cases := loadCorpus(t)
	var jwt, token, untouched int
	for _, c := range cases {
		switch {
		case c.Want == c.In:
			untouched++
		default:
			// [REDACTED:N] uzunluk taşıyan token deseni; çıplak [REDACTED] JWT.
			if containsRedactedWithLength(c.Want) {
				token++
			} else {
				jwt++
			}
		}
	}
	if jwt == 0 || token == 0 || untouched == 0 {
		t.Fatalf("corpus does not exercise all three outcomes: jwt=%d token=%d untouched=%d", jwt, token, untouched)
	}
}

func containsRedactedWithLength(s string) bool {
	for i := 0; i+len("[REDACTED:") <= len(s); i++ {
		if s[i:i+len("[REDACTED:")] == "[REDACTED:" {
			return true
		}
	}
	return false
}
