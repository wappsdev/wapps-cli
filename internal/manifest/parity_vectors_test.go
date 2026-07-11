package manifest

// CROSS-LANGUAGE PARITY ORACLE (Go tarafı — data manifest).
//
// Bu test, Go `ParseManifestBody` ile TS `parseManifestBody`'nin HER crafted JSON
// gövdesinde AYNI accept/reject kararını verdiğini kanıtlar. Vektörler
// `worker/test/parity-vectors.json` dosyasında TEK KAYNAK olarak tutulur ve AYNI
// dosya TS tarafında (worker/test/parity-vectors.test.ts) da okunur → iki tablo
// LİTERAL olarak aynı girdileri sürer. Bir vektörün Go verdict'i beklenenle
// uyuşmazsa (veya TS ile ayrışırsa) bu bir CONSENSUS DIVERGENCE'tır ve testi
// gevşeterek DEĞİL, parser'ı hizalayarak çözülmelidir.
//
// Yol: paket dizini internal/manifest → ../../worker/test/parity-vectors.json.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// parityVector, paylaşılan fixture dosyasının bir satırıdır (Go+TS ortak şema).
type parityVector struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // "manifest" | "trust"
	Verdict string `json:"verdict"` // "accept" | "reject"
	Body    string `json:"body"`    // parser'a AYNEN verilen JSON gövde metni
}

// loadParityVectors, paylaşılan cross-language fixture listesini okur (aynı dosya
// TS tarafında import edilir → literal-aynı girdiler).
func loadParityVectors(t *testing.T) []parityVector {
	t.Helper()
	path := filepath.Join("..", "..", "worker", "test", "parity-vectors.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "shared parity fixture must be readable at %s", path)
	var vecs []parityVector
	require.NoError(t, json.Unmarshal(raw, &vecs))
	require.NotEmpty(t, vecs)
	return vecs
}

// TestParityVectors_Manifest, paylaşılan vektör listesinin "manifest" satırlarını
// gerçek ParseManifestBody'ye sürer ve beklenen accept/reject'i doğrular.
func TestParityVectors_Manifest(t *testing.T) {
	var ran int
	for _, v := range loadParityVectors(t) {
		if v.Kind != "manifest" {
			continue
		}
		ran++
		t.Run(v.Name, func(t *testing.T) {
			_, err := ParseManifestBody([]byte(v.Body))
			switch v.Verdict {
			case "accept":
				require.NoError(t, err, "vector %q must be ACCEPTED (Go) but was rejected; body=%s", v.Name, v.Body)
			case "reject":
				require.Error(t, err, "vector %q must be REJECTED (Go) but was accepted; body=%s", v.Name, v.Body)
			default:
				t.Fatalf("vector %q has unknown verdict %q", v.Name, v.Verdict)
			}
		})
	}
	require.Positive(t, ran, "no manifest parity vectors were exercised")
}
