package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// TestFetch_WrapSetExpansionRejected (FIX #3): compromised bir Worker, düşük-yetkili
// bir yazar imzasıyla, AYNI blobHash+keyVersion'ı koruyan ama wrap-set'i GENİŞLETEN
// (yeni bir alıcı ekleyen) bir manifest sunarsa — imzalayanın o anahtar için yazma
// grant'ı OLMASA bile — istemcinin okuma-yolu yazar-yetkisi kontrolü bunu YAKALAMALI
// (WRITER_NOT_ALLOWED). Eski winnerTouched yalnızca blobHash/keyVersion'a baktığı için
// bu mutasyonu ATLARDI; tam-girdi karşılaştırması (wraps + rotation) onu zorlar.
func TestFetch_WrapSetExpansionRejected(t *testing.T) {
	f := newFixture(t)
	f.seed(t) // epoch1: A, DB (insan daily-imzalı)

	// machine:limited YALNIZCA "B"yi yazabilir. "A"nın wrap-set'ini genişleten
	// (blobHash/keyVersion DEĞİŞMEDEN) bir epoch2 imzalar → yazar-yetkisi taşması.
	tampered := mkWrapExpansionSignedBy(t, f, "A", f.limitedWriter)
	f.server.mu.Lock()
	f.server.installCurrent(2, tampered)
	f.server.mu.Unlock()

	fresh := f.freshStore(t)
	_, err := fresh.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.WriterNotAllowed),
		"wrap-set expansion by an unauthorized writer must be rejected on the client read path: %v", err)
}

// mkWrapExpansionSignedBy, epoch1 tabanı üzerine changeKey'in wrap-set'ine YENİ bir
// alıcı ekleyen (blobHash + keyVersion AYNI) bir epoch2 manifest'i kurar ve verilen
// anahtarla imzalar.
func mkWrapExpansionSignedBy(t *testing.T, f *fixture, changeKey string, signer cryptoid.SigningKey) []byte {
	t.Helper()
	f.server.mu.Lock()
	cur := f.server.projManifests[1]
	f.server.mu.Unlock()
	obj, err := manifest.ParseSignedObject(cur)
	require.NoError(t, err)
	m, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)

	// Taze, wrap-set'te OLMAYAN bir alıcı üret (yeni bir device gibi eklendiğini simüle).
	extra, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)

	entries := append([]manifest.KeyEntry(nil), m.Entries...)
	found := false
	for i := range entries {
		if entries[i].KeyName == changeKey {
			// blobHash + keyVersion AYNI; yalnızca wrap-set genişliyor.
			wraps := append([]manifest.DEKWrap(nil), entries[i].Wraps...)
			wraps = append(wraps, manifest.DEKWrap{
				Recipient: extra.Fingerprint(),
				Wrap:      []byte("forged-extra-wrap-bytes"),
			})
			entries[i].Wraps = wraps
			found = true
		}
	}
	require.True(t, found, "changeKey must exist in epoch1")

	wm := &manifest.DataManifest{
		Schema: manifest.SchemaDataManifest, Project: testProject, Epoch: 2,
		PrevManifestSha256: manifest.ManifestObjectHash(cur), TrustEpoch: 1,
		CreatedAt: fixTime, Entries: entries,
	}
	wobj, _, err := manifest.SignManifest(wm, signer)
	require.NoError(t, err)
	raw, err := manifest.MarshalSignedObject(wobj)
	require.NoError(t, err)
	return raw
}
