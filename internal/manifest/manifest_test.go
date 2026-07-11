package manifest

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

func sampleManifest() *DataManifest {
	return &DataManifest{
		Schema:             SchemaDataManifest,
		Project:            "vaulter",
		Epoch:              1,
		PrevManifestSha256: "",
		TrustEpoch:         7,
		CreatedAt:          time.Date(2026, 7, 9, 12, 34, 56, 0, time.UTC),
		Entries: []KeyEntry{
			{KeyName: "DATABASE_URL", KeyVersion: 3, BlobHash: "aa", Wraps: []DEKWrap{{Recipient: "sha256:ff", Wrap: []byte("w1")}}},
			{KeyName: "API_KEY", KeyVersion: 1, BlobHash: "bb", Wraps: []DEKWrap{{Recipient: "sha256:ff", Wrap: []byte("w2")}}},
		},
	}
}

func ringFor(t *testing.T, key cryptoid.SigningKey) WriterKeyring {
	t.Helper()
	vk, err := cryptoid.NewVerifierKey(key.Alg(), key.PublicKeyBytes())
	require.NoError(t, err)
	return WriterKeyring{vk.KeyID(): vk}
}

// TestSignVerify_Roundtrip, Ed25519 ve ECDSA yazarlarla imzala/doğrula
// round-trip'ini test eder.
func TestSignVerify_Roundtrip(t *testing.T) {
	keys := map[string]func() (cryptoid.SigningKey, error){
		"ed25519": func() (cryptoid.SigningKey, error) { return cryptoid.GenerateEd25519() },
		"ecdsa":   func() (cryptoid.SigningKey, error) { return cryptoid.GenerateECDSAP256() },
	}
	for name, gen := range keys {
		t.Run(name, func(t *testing.T) {
			key, err := gen()
			require.NoError(t, err)
			obj, body, err := SignManifest(sampleManifest(), key)
			require.NoError(t, err)
			require.Len(t, obj.Sigs, 1)
			// obj.Bytes artık cryptoid.B64Strict (KATİ KANONİK base64); imzalanan
			// kanonik body ile bayt-bayt aynı olmalı ([]byte'a çevirerek karşılaştır).
			assert.Equal(t, body, []byte(obj.Bytes))

			got, err := VerifyDataManifest(obj, ringFor(t, key))
			require.NoError(t, err)
			assert.Equal(t, "vaulter", got.Project)
			assert.Len(t, got.Entries, 2)
		})
	}
}

// TestVerify_TamperBytes, depolanan baytların tek baytı bozulursa doğrulamanın
// SIG_INVALID ile başarısız olduğunu doğrular (sign-over-exact-bytes).
func TestVerify_TamperBytes(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	obj, _, err := SignManifest(sampleManifest(), key)
	require.NoError(t, err)
	ring := ringFor(t, key)

	// Sağlam doğrulanmalı.
	_, err = VerifyDataManifest(obj, ring)
	require.NoError(t, err)

	// Her bayt konumunu boz — hepsi reddedilmeli.
	for i := 0; i < len(obj.Bytes); i++ {
		tampered := SignedObject{Bytes: bytes.Clone(obj.Bytes), Sigs: obj.Sigs}
		tampered.Bytes[i] ^= 0x01
		_, err := VerifyDataManifest(tampered, ring)
		assert.ErrorIs(t, err, cryptoid.ErrSigInvalid, "flipped byte %d must fail verify", i)
	}
}

// TestVerify_BadSignatureCount, sigs != 1 durumunu test eder (SPEC §5.4.1).
func TestVerify_BadSignatureCount(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	obj, _, err := SignManifest(sampleManifest(), key)
	require.NoError(t, err)
	ring := ringFor(t, key)

	zero := SignedObject{Bytes: obj.Bytes, Sigs: nil}
	_, err = VerifyDataManifest(zero, ring)
	assert.ErrorIs(t, err, ErrBadSignatureCount)

	two := SignedObject{Bytes: obj.Bytes, Sigs: []Signature{obj.Sigs[0], obj.Sigs[0]}}
	_, err = VerifyDataManifest(two, ring)
	assert.ErrorIs(t, err, ErrBadSignatureCount)
}

// TestVerify_WriterUnknown, key_id roster'da yoksa reddedildiğini test eder.
func TestVerify_WriterUnknown(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	obj, _, err := SignManifest(sampleManifest(), key)
	require.NoError(t, err)

	_, err = VerifyDataManifest(obj, WriterKeyring{}) // boş roster
	assert.ErrorIs(t, err, ErrWriterUnknown)
}

// TestMarshalCanonical_Deterministic, girdi sırasından bağımsız olarak aynı
// baytların üretildiğini doğrular (girdiler KeyName'e göre sıralanır).
func TestMarshalCanonical_Deterministic(t *testing.T) {
	m1 := sampleManifest() // DATABASE_URL, API_KEY sırası
	m2 := sampleManifest()
	// m2'nin girdi sırasını ters çevir.
	m2.Entries[0], m2.Entries[1] = m2.Entries[1], m2.Entries[0]

	b1, err := m1.MarshalCanonical()
	require.NoError(t, err)
	b2, err := m2.MarshalCanonical()
	require.NoError(t, err)
	assert.Equal(t, b1, b2, "canonical bytes must be order-independent")

	// Ve gerçekten sıralı (API_KEY, DATABASE_URL).
	parsed, err := ParseManifestBody(b1)
	require.NoError(t, err)
	assert.Equal(t, "API_KEY", parsed.Entries[0].KeyName)
	assert.Equal(t, "DATABASE_URL", parsed.Entries[1].KeyName)
}

// TestSignedObject_MarshalRoundtrip, sarmalayıcının R2 baytlarına serileşip
// geri okunmasını ve doğrulanmasını test eder.
func TestSignedObject_MarshalRoundtrip(t *testing.T) {
	key, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	obj, _, err := SignManifest(sampleManifest(), key)
	require.NoError(t, err)

	raw, err := MarshalSignedObject(obj)
	require.NoError(t, err)
	back, err := ParseSignedObject(raw)
	require.NoError(t, err)
	assert.Equal(t, obj.Bytes, back.Bytes)

	_, err = VerifyDataManifest(back, ringFor(t, key))
	require.NoError(t, err)
}

// TestEpochChain, genesis + zincir bağı kurallarını test eder (SPEC §5.5).
func TestEpochChain(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)

	// Genesis (epoch 1).
	gen := sampleManifest()
	require.NoError(t, VerifyGenesis(gen))
	genObj, _, err := SignManifest(gen, key)
	require.NoError(t, err)
	genRaw, err := MarshalSignedObject(genObj)
	require.NoError(t, err)

	// Epoch 2, prevManifestSha256 = genesis obje baytlarının hash'i.
	next := sampleManifest()
	next.Epoch = 2
	next.PrevManifestSha256 = ManifestObjectHash(genRaw)
	assert.NoError(t, VerifyChainLink(genRaw, 1, next))

	// Yanlış epoch → EPOCH_CONFLICT.
	badEpoch := sampleManifest()
	badEpoch.Epoch = 3
	badEpoch.PrevManifestSha256 = ManifestObjectHash(genRaw)
	assert.ErrorIs(t, VerifyChainLink(genRaw, 1, badEpoch), ErrEpochConflict)

	// Yanlış prev hash → EPOCH_CONFLICT.
	badPrev := sampleManifest()
	badPrev.Epoch = 2
	badPrev.PrevManifestSha256 = "00"
	assert.ErrorIs(t, VerifyChainLink(genRaw, 1, badPrev), ErrEpochConflict)

	// Genesis kuralları: epoch != 1 veya prev != "" → hata.
	bg := sampleManifest()
	bg.Epoch = 2
	assert.ErrorIs(t, VerifyGenesis(bg), ErrEpochConflict)
	bg2 := sampleManifest()
	bg2.PrevManifestSha256 = "ab"
	assert.ErrorIs(t, VerifyGenesis(bg2), ErrEpochConflict)
}

// TestCheckProjectAndEscrow, project ve escrow-wrap kontrollerini test eder.
func TestCheckProjectAndEscrow(t *testing.T) {
	m := sampleManifest()
	assert.NoError(t, CheckProject(m, "vaulter"))
	assert.ErrorIs(t, CheckProject(m, "other"), ErrProjectMismatch)

	const escrowFP = "sha256:escrow"
	// Escrow wrap'i her girdiye ekle → geçmeli.
	for i := range m.Entries {
		m.Entries[i].Wraps = append(m.Entries[i].Wraps, DEKWrap{Recipient: escrowFP, Wrap: []byte("e")})
	}
	assert.NoError(t, CheckEscrowWraps(m, escrowFP))

	// Bir girdiden escrow wrap'i çıkar → ESCROW_WRAP_MISSING.
	m.Entries[0].Wraps = m.Entries[0].Wraps[:1]
	assert.ErrorIs(t, CheckEscrowWraps(m, escrowFP), cryptoid.ErrEscrowWrapMissing)
}

// TestRotationMeta_Passthrough, rotation ham JSON'unun byte-exact korunduğunu
// doğrular (SPEC §5.4.3 rule 5: Worker asla yorumlamaz).
func TestRotationMeta_Passthrough(t *testing.T) {
	raw := json.RawMessage(`{"recipe":"rotate-db","doneCriterion":"smoke-ok","nested":{"a":1}}`)
	m := sampleManifest()
	m.Entries[0].Rotation = NewRotationMeta(raw)

	body, err := m.MarshalCanonical()
	require.NoError(t, err)
	parsed, err := ParseManifestBody(body)
	require.NoError(t, err)

	var rot *RotationMeta
	for _, e := range parsed.Entries {
		if e.KeyName == "DATABASE_URL" {
			rot = e.Rotation
		}
	}
	require.NotNil(t, rot)
	assert.JSONEq(t, string(raw), string(rot.Raw()))
}

// TestParseManifestBody_TrailingContent, imzalı body'den SONRA fazladan içerik
// (geçerli JSON VEYA çöp) reddedildiğini doğrular (COORD c). Go json.Decoder
// io.EOF kontrol edilmeden bu içeriği sessizce kabul ederdi; Worker JSON.parse ise
// reddeder — bu kontrol iki tarafı hizalar.
func TestParseManifestBody_TrailingContent(t *testing.T) {
	body, err := sampleManifest().MarshalCanonical()
	require.NoError(t, err)

	// Temiz body parse edilmeli.
	_, err = ParseManifestBody(body)
	require.NoError(t, err)

	// Sonda geçerli bir JSON değeri → red.
	trailingJSON := append(append([]byte(nil), body...), []byte("\n{}")...)
	_, err = ParseManifestBody(trailingJSON)
	assert.ErrorIs(t, err, ErrTrailingContent)

	// Sonda çöp → red.
	trailingGarbage := append(append([]byte(nil), body...), []byte(" not-json")...)
	_, err = ParseManifestBody(trailingGarbage)
	assert.ErrorIs(t, err, ErrTrailingContent)
}

// TestParseManifestBody_IntegerDomain, epoch/trustEpoch/keyVersion alanlarının
// JS güvenli-tamsayı alanıyla [0, 2^53-1] sınırlı olduğunu doğrular (COORD a):
// 2^53-1 kabul, 2^53 red.
func TestParseManifestBody_IntegerDomain(t *testing.T) {
	const maxSafe = uint64(1<<53 - 1)

	// Sınır değeri (2^53-1) her üç alanda da kabul edilmeli.
	ok := sampleManifest()
	ok.Epoch = maxSafe
	ok.TrustEpoch = maxSafe
	ok.Entries[0].KeyVersion = maxSafe
	okBody, err := ok.MarshalCanonical()
	require.NoError(t, err)
	_, err = ParseManifestBody(okBody)
	require.NoError(t, err)

	// 2^53 her alan için ayrı ayrı reddedilmeli.
	over := map[string]func(m *DataManifest){
		"epoch":      func(m *DataManifest) { m.Epoch = 1 << 53 },
		"trustEpoch": func(m *DataManifest) { m.TrustEpoch = 1 << 53 },
		"keyVersion": func(m *DataManifest) { m.Entries[0].KeyVersion = 1 << 53 },
	}
	for name, mutate := range over {
		t.Run(name, func(t *testing.T) {
			m := sampleManifest()
			mutate(m)
			body, err := m.MarshalCanonical()
			require.NoError(t, err)
			_, err = ParseManifestBody(body)
			assert.ErrorIs(t, err, ErrIntegerOutOfRange)
		})
	}
}

// TestCurrentPointer, current pointer round-trip + bütünlük kontrolünü test eder.
func TestCurrentPointer(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	obj, _, err := SignManifest(sampleManifest(), key)
	require.NoError(t, err)
	raw, err := MarshalSignedObject(obj)
	require.NoError(t, err)

	ptr := NewCurrentPointer("vaulter", 1, raw)
	assert.Equal(t, SchemaCurrentPointer, ptr.Schema)
	assert.Equal(t, ManifestObjectHash(raw), ptr.ManifestSha256)

	pb, err := ptr.Marshal()
	require.NoError(t, err)
	back, err := ParseCurrentPointer(pb)
	require.NoError(t, err)
	assert.Equal(t, ptr, back)

	// Bütünlük: doğru baytlar geçer, bozuk baytlar reddedilir.
	assert.NoError(t, back.VerifyManifestBytes(raw))
	bad := bytes.Clone(raw)
	bad[5] ^= 0x01
	assert.ErrorIs(t, back.VerifyManifestBytes(bad), ErrEpochConflict)
}

// TestEndToEnd_SealSignVerifyUnwrapOpen, iki paketin BİRLİKTE çalıştığı tam
// bir yaşam döngüsünü test eder: değeri blob'a mühürle, DEK'i alıcıya wrap'le,
// manifest'i imzala/doğrula, wrap'i unwrap et, blob'u aç.
func TestEndToEnd_SealSignVerifyUnwrapOpen(t *testing.T) {
	// Alıcı kimliği (okuyucu) + escrow alıcısı.
	reader, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	escrow, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	writer, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)

	project, keyName := "vaulter", "DATABASE_URL"
	var keyVersion uint64 = 3
	slot := cryptoid.Slot{Project: project, KeyName: keyName, KeyVersion: keyVersion}
	plaintext := []byte("postgres://u:p@h/db")

	dek, err := cryptoid.NewDEK()
	require.NoError(t, err)
	blob, err := cryptoid.SealBlob(plaintext, dek, slot)
	require.NoError(t, err)
	blobHash := cryptoid.BlobHash(blob)

	// Wrap'leri kur (okuyucu + escrow) ve zorunlu öz-kontrolü yap.
	wraps := []DEKWrap{}
	for _, rec := range []*cryptoid.X25519Recipient{reader.Recipient(), escrow.Recipient()} {
		w, err := cryptoid.SealDEK(dek, rec, slot)
		require.NoError(t, err)
		require.NoError(t, cryptoid.WrapVerify(dek, rec, slot, w)) // WRAP_SELFCHECK
		wraps = append(wraps, DEKWrap{Recipient: rec.Fingerprint(), Wrap: w})
	}

	m := &DataManifest{
		Schema: SchemaDataManifest, Project: project, Epoch: 1, TrustEpoch: 1,
		CreatedAt: time.Now().UTC(),
		Entries: []KeyEntry{
			{KeyName: keyName, KeyVersion: keyVersion, BlobHash: blobHash, Wraps: wraps},
		},
	}
	require.NoError(t, CheckEscrowWraps(m, escrow.Recipient().Fingerprint()))

	obj, _, err := SignManifest(m, writer)
	require.NoError(t, err)
	raw, err := MarshalSignedObject(obj)
	require.NoError(t, err)

	// --- Okuma yolu ---
	back, err := ParseSignedObject(raw)
	require.NoError(t, err)
	verified, err := VerifyDataManifest(back, ringFor(t, writer))
	require.NoError(t, err)

	entry := verified.Entries[0]
	// Blob hash doğrula (parse/decrypt öncesi).
	require.NoError(t, cryptoid.VerifyBlobHash(blob, entry.BlobHash))

	// Okuyucunun wrap'ini bul, DEK'i çöz, blob'u aç.
	var myWrap []byte
	for _, w := range entry.Wraps {
		if w.Recipient == reader.Recipient().Fingerprint() {
			myWrap = w.Wrap
		}
	}
	require.NotNil(t, myWrap)
	gotDEK, err := cryptoid.UnsealDEK(myWrap, reader)
	require.NoError(t, err)

	readSlot := cryptoid.Slot{Project: verified.Project, KeyName: entry.KeyName, KeyVersion: entry.KeyVersion}
	got, err := cryptoid.OpenBlob(blob, gotDEK, readSlot)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// Escrow de aynı DEK'i çözebilmeli (wrap-at-write, §3.3.4).
	var escrowWrap []byte
	for _, w := range entry.Wraps {
		if w.Recipient == escrow.Recipient().Fingerprint() {
			escrowWrap = w.Wrap
		}
	}
	require.NotNil(t, escrowWrap)
	escrowDEK, err := cryptoid.UnsealDEK(escrowWrap, escrow)
	require.NoError(t, err)
	assert.Equal(t, dek, escrowDEK)
}
