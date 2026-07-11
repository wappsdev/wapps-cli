package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// manifestBodyWithRotation, key "A" için verilen rotation JSON'unu taşıyan minimal
// bir data-manifest body'si kurar. rotation ham JSON passthrough olarak parse edilir
// (json.RawMessage boşlukları AYNEN korur).
func manifestBodyWithRotation(rotation string) string {
	return `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,` +
		`"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-11T00:00:00Z",` +
		`"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab",` +
		`"wraps":[{"recipient":"sha256:ff","wrap":"//8="}],"rotation":` + rotation + `}]}`
}

// TestWinnerTouched_RotationWhitespaceDetected (FIX #3): rotation metadata BYTE-EXACT
// karşılaştırılır (RotationMeta ham json.RawMessage). YALNIZCA boşlukla (whitespace)
// farklılaşan bir rotation değişikliği bile "touched" olarak algılanmalı — böylece
// yetkisiz bir yazarın blobHash/keyVersion/wrap'i sabit tutup rotation'ı boşlukla
// mutasyona uğrattığı bir yazım, read-yolu yazar-yetkisi kontrolünü ATLAYAMAZ. Bu,
// TS byte-exact rotation fix'iyle (JSON.stringify-of-reparsed DEĞİL, ham baytlar)
// hemfikirdir; iki taraf aynı değişiklik-kümesini görür.
func TestWinnerTouched_RotationWhitespaceDetected(t *testing.T) {
	base, err := manifest.ParseManifestBody([]byte(manifestBodyWithRotation(`{"reason":"x"}`)))
	require.NoError(t, err)

	// Yalnızca boşluk farkı: {"reason":"x"} → {"reason": "x"} (aynı anlam, farklı bayt).
	changed, err := manifest.ParseManifestBody([]byte(manifestBodyWithRotation(`{"reason": "x"}`)))
	require.NoError(t, err)

	touched := winnerTouched(base.Entries, changed.Entries)
	require.True(t, touched["A"], "whitespace-only rotation change on key A must be detected as touched")

	// Kontrol: rotation baytları AYNI ise touched OLMAMALI (yanlış pozitif yok).
	same, err := manifest.ParseManifestBody([]byte(manifestBodyWithRotation(`{"reason":"x"}`)))
	require.NoError(t, err)
	touchedSame := winnerTouched(base.Entries, same.Entries)
	require.False(t, touchedSame["A"], "byte-identical rotation must NOT be touched")
}
