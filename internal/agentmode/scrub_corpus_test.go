package agentmode

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Bu dosya, exec'in SIZINTI YÜZEYİNİ — FilterScrubbable + Scrubber — Go ve
// Rust portu ARASINDA paylaşılan tek fikstürle sabitler. Korpusun `want_*`
// alanları BU tarafın çıktısıdır: Go ORACLE'dır.
//
// Neden korpus, neden elle yeniden türetilmiş testler değil: Scrubber bir
// STREAMING eşleştirici ve asıl davranışı chunk SINIRLARINDA yaşıyor
// (maxLen-1 baytlık rolling buffer, en-erken/en-uzun eşleşme seçimi). Bu
// sınırlar iki dilde bağımsız yazılınca "ikisi de makul ama farklı" olur ve
// fark yalnızca gerçek bir sır bölünmüş bir okumada geldiğinde görünür —
// yani üretimde. Tek fikstür bunu imkânsız kılar.
//
// Rust tarafında aynı dosyayı okuyan ikinci bir test var
// (rust/crates/cli/tests/scrubber.rs). Go değişirse BU test kırılır, Rust
// ayrışırsa ORADAKİ kırılır.
//
// Golden'ı yeniden üretmek:
//
//	WAPPS_UPDATE_GOLDEN=1 go test ./internal/agentmode
//
// GİZLİ DEĞER YOK: korpustaki her dize uydurma bir test dizesidir.
type scrubCase struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
	Chunks []string `json:"chunks"`
	// WantFiltered: FilterScrubbable'ın seçtiği alt küme (scrubber'a verilen).
	WantFiltered []string `json:"want_filtered"`
	// WantNote: floor-altı atlanan gerçek-görünümlü değerler için uyarı satırı.
	WantNote string `json:"want_note"`
	// WantOut: chunk'lar sırayla yazılıp Flush edildikten sonraki TAM çıktı.
	WantOut string `json:"want_out"`
}

const scrubCorpusPath = "testdata/scrub_corpus.json"

// runScrubCase, ÜRETİM sırasını birebir tekrarlar (runWithInjectedEnv):
// önce FilterScrubbable, sonra onun sonucuyla NewScrubber.
func runScrubCase(c scrubCase) (filtered []string, note string, out string) {
	var noteBuf bytes.Buffer
	filtered = FilterScrubbable(c.Values, &noteBuf)
	var outBuf bytes.Buffer
	s := NewScrubber(&outBuf, filtered)
	for _, chunk := range c.Chunks {
		if _, err := s.Write([]byte(chunk)); err != nil {
			panic(err)
		}
	}
	if err := s.Flush(); err != nil {
		panic(err)
	}
	if filtered == nil {
		filtered = []string{}
	}
	return filtered, noteBuf.String(), outBuf.String()
}

func loadScrubCorpus(t *testing.T) []scrubCase {
	t.Helper()
	raw, err := os.ReadFile(scrubCorpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var cases []scrubCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cases) < 20 {
		t.Fatalf("corpus too small (%d cases); an empty corpus proves nothing", len(cases))
	}
	return cases
}

func TestScrubber_Corpus(t *testing.T) {
	cases := loadScrubCorpus(t)

	if os.Getenv("WAPPS_UPDATE_GOLDEN") == "1" {
		for i := range cases {
			f, n, o := runScrubCase(cases[i])
			cases[i].WantFiltered, cases[i].WantNote, cases[i].WantOut = f, n, o
		}
		raw, err := json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatalf("encode corpus: %v", err)
		}
		if err := os.WriteFile(scrubCorpusPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("write corpus: %v", err)
		}
		t.Fatalf("golden regenerated — re-run without WAPPS_UPDATE_GOLDEN")
	}

	for _, c := range cases {
		f, n, o := runScrubCase(c)
		if o != c.WantOut {
			t.Errorf("%s out:\n want: %q\n got:  %q", c.Name, c.WantOut, o)
		}
		if n != c.WantNote {
			t.Errorf("%s note:\n want: %q\n got:  %q", c.Name, c.WantNote, n)
		}
		if len(f) != len(c.WantFiltered) {
			t.Errorf("%s filtered: want %v got %v", c.Name, c.WantFiltered, f)
			continue
		}
		for i := range f {
			if f[i] != c.WantFiltered[i] {
				t.Errorf("%s filtered[%d]: want %q got %q", c.Name, i, c.WantFiltered[i], f[i])
			}
		}
	}
}

// TestScrubber_CorpusExercisesTheHardParts, korpusun GERÇEKTEN zor kolları
// gezdiğini kanıtlar. Hiçbir şeyi redakte etmeyen, hiç chunk bölmeyen bir
// korpus da "geçer" — ve hiçbir mutasyonu yakalamaz.
func TestScrubber_CorpusExercisesTheHardParts(t *testing.T) {
	cases := loadScrubCorpus(t)
	var redacted, untouched, multiChunk, noted, filteredOut int
	for _, c := range cases {
		if bytes.Contains([]byte(c.WantOut), []byte(Redaction)) {
			redacted++
		}
		joined := ""
		for _, ch := range c.Chunks {
			joined += ch
		}
		if c.WantOut == joined {
			untouched++
		}
		if len(c.Chunks) > 1 {
			multiChunk++
		}
		if c.WantNote != "" {
			noted++
		}
		if len(c.WantFiltered) < len(c.Values) {
			filteredOut++
		}
	}
	if redacted == 0 || untouched == 0 || multiChunk == 0 || noted == 0 || filteredOut == 0 {
		t.Fatalf("corpus misses a branch: redacted=%d untouched=%d multiChunk=%d noted=%d filteredOut=%d",
			redacted, untouched, multiChunk, noted, filteredOut)
	}
}
