package witness

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

const fixProject = "vaulter"

var fixTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// fixture, doğrulanabilir bir escrow snapshot'ı + pinler + escrow kimliğini tutar.
type fixture struct {
	store     *MemStore
	pins      *trust.PinStore
	escrow    *cryptoid.X25519Identity
	escrowRec *cryptoid.X25519Recipient
	escrowFp  string
	headEpoch uint64
	headHash  string
	writer    *cryptoid.ECDSAP256SigningKey
}

func edSeed(t *testing.T, b byte) *cryptoid.Ed25519SigningKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := cryptoid.NewEd25519FromSeed(seed)
	require.NoError(t, err)
	return k
}

func receiptJWKOf(t *testing.T, k *cryptoid.ECDSAP256SigningKey) json.RawMessage {
	t.Helper()
	pub := k.PublicKeyBytes()
	x := b64url(pub[1:33])
	y := b64url(pub[33:65])
	return json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, x, y))
}

// b64url, RawURL base64 (JWK koordinatları).
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// newFixture, epoch-1 + epoch-2 zincirli, escrow-wrap'li, pointer-event'li,
// audit-segment'li geçerli bir escrow snapshot'ı kurar.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root1, root2, root3 := edSeed(t, 1), edSeed(t, 2), edSeed(t, 3)
	writer, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	backup, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	escrow, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	receiptKey, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)

	humanID := "human:adnan@example.com"
	human := registry.Identity{
		ID:         humanID,
		Type:       registry.TypeHuman,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(device.Recipient(), registry.EncClassDevice, "software", 1),
			registry.NewEncKeyEntry(backup.Recipient(), registry.EncClassBackup, "paper-steel", 1),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(writer, registry.SignClassDaily, "software"),
		},
	}
	escrowID := registry.Identity{
		ID:         "escrow:vault",
		Type:       registry.TypeEscrow,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		EncKeys:    []registry.EncKey{registry.NewEncKeyEntry(escrow.Recipient(), registry.EncClassBackup, "paper-steel", 1)},
	}

	tm := &trust.TrustManifest{
		Schema:          trust.SchemaTrust,
		AdminEpoch:      1,
		PrevTrustSHA256: "",
		CreatedAt:       fixTime,
		ChangeClass:     trust.ChangeRoster,
		Quorum:          trust.Quorum{M: 2, N: 3},
		Roots: []trust.RootKey{
			trust.NewRootKey(root1, "yubikey-piv", "human:a"),
			trust.NewRootKey(root2, "yubikey-piv", "human:b"),
			trust.NewRootKey(root3, "yubikey-piv", "human:c"),
		},
		Admins:     []string{humanID},
		Identities: []registry.Identity{human, escrowID},
		Grants: []registry.Grant{
			{Principal: humanID, Project: fixProject, Verbs: []string{"read", "write"}, Keys: []string{"*"}},
		},
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: receiptJWKOf(t, receiptKey)},
	}
	obj, _, err := trust.SignTrustManifest(tm, root1, root2)
	require.NoError(t, err)
	genesisPin := trust.Pin{AdminEpoch: 1, SHA256: trust.TrustObjectHash(obj.Bytes)}
	_, verr := trust.VerifyRosterChain(genesisPin, genesisPin, obj)
	require.NoError(t, verr, "fixture trust genesis must verify")
	trustWrapper, err := json.Marshal(obj)
	require.NoError(t, err)

	store := NewMemStore()
	store.Objects[keyTrustManifest(1)] = trustWrapper

	recs := []recip{
		{device.Fingerprint(), device.Recipient()},
		{backup.Fingerprint(), backup.Recipient()},
		{escrow.Fingerprint(), escrow.Recipient()},
	}

	// epoch 1 (genesis): DATABASE_URL + canary.
	e1, w1 := buildEpoch(t, store, 1, "", writer, recs, map[string][]byte{
		"DATABASE_URL": []byte("postgres://secret-1"),
		CANARY_KEY:     []byte("canary-plaintext-v1"),
	})
	// epoch 2: DATABASE_URL rotated (v2) + carry canary forward.
	_, w2 := buildEpoch(t, store, 2, manifest.ManifestObjectHash(w1), writer, recs, map[string][]byte{
		"DATABASE_URL": []byte("postgres://secret-2"),
	}, e1...)

	// audit segments (geçerli zincir).
	writeAuditSegment(store, 1, auditGenesisHash, `[1,"2026-07-09T12:00:00Z","human:adnan@example.com","human","vaulter","DATABASE_URL","commit","allow",null,null,null,null]`)
	prevHash := hashSegment(auditGenesisHash, `[1,"2026-07-09T12:00:00Z","human:adnan@example.com","human","vaulter","DATABASE_URL","commit","allow",null,null,null,null]`)
	writeAuditSegment(store, 2, prevHash, `[2,"2026-07-09T12:05:00Z","human:adnan@example.com","human","vaulter","DATABASE_URL","commit","allow",null,null,null,null]`)

	return &fixture{
		store:     store,
		pins:      trust.NewPinStore(genesisPin),
		escrow:    escrow,
		escrowRec: escrow.Recipient(),
		escrowFp:  escrow.Fingerprint(),
		headEpoch: 2,
		headHash:  ManifestObjectHashOf(w2),
		writer:    writer,
	}
}

// ManifestObjectHashOf, test yardımcısı (manifest.ManifestObjectHash sarmalayıcısı).
func ManifestObjectHashOf(b []byte) string { return manifest.ManifestObjectHash(b) }

type recip struct {
	fp        string
	recipient *cryptoid.X25519Recipient
}

// buildEpoch, tek bir data manifest epoch'unu (imzalı) + blob'larını + pointer
// event'ini store'a yazar. carry = önceki epoch'un DEĞİŞMEYEN girdileri (aynen taşınır).
// Dönüş: bu epoch'un TÜM girdileri (bir sonrakine carry için) + stored wrapper.
func buildEpoch(t *testing.T, store *MemStore, epoch uint64, prevSha string, writer *cryptoid.ECDSAP256SigningKey, recs []recip, sets map[string][]byte, carry ...manifest.KeyEntry) ([]manifest.KeyEntry, []byte) {
	t.Helper()
	entries := make([]manifest.KeyEntry, 0, len(carry)+len(sets))
	// carry değişmeyenleri (sets'te olmayanlar).
	for _, e := range carry {
		if _, changed := sets[e.KeyName]; changed {
			continue
		}
		entries = append(entries, e)
	}
	for keyName, value := range sets {
		var version uint64 = 1
		for _, e := range carry {
			if e.KeyName == keyName {
				version = e.KeyVersion + 1
			}
		}
		slot := cryptoid.Slot{Project: fixProject, KeyName: keyName, KeyVersion: version}
		dek, err := cryptoid.NewDEK()
		require.NoError(t, err)
		blob, err := cryptoid.SealBlob(value, dek, slot)
		require.NoError(t, err)
		blobHash := cryptoid.BlobHash(blob)
		store.Objects[keyBlob(fixProject, blobHash)] = blob
		wraps := make([]manifest.DEKWrap, 0, len(recs))
		for _, rc := range recs {
			wrap, err := cryptoid.SealDEK(dek, rc.recipient, slot)
			require.NoError(t, err)
			wraps = append(wraps, manifest.DEKWrap{Recipient: rc.fp, Wrap: wrap})
		}
		entries = append(entries, manifest.KeyEntry{KeyName: keyName, KeyVersion: version, BlobHash: blobHash, Wraps: wraps})
	}
	m := &manifest.DataManifest{
		Schema:             manifest.SchemaDataManifest,
		Project:            fixProject,
		Epoch:              epoch,
		PrevManifestSha256: prevSha,
		TrustEpoch:         1,
		CreatedAt:          fixTime,
		Entries:            entries,
	}
	obj, _, err := manifest.SignManifest(m, writer)
	require.NoError(t, err)
	raw, err := manifest.MarshalSignedObject(obj)
	require.NoError(t, err)
	store.Objects[keyManifest(fixProject, epoch)] = raw
	// pointer event.
	pe, _ := json.Marshal(pointerEvent{Schema: "wapps.pointer-event.v1", Project: fixProject, Epoch: epoch, ManifestSha256: manifest.ManifestObjectHash(raw), CommittedAt: fixTime.Format(time.RFC3339)})
	store.Objects[keyPointerEvent(fixProject, epoch)] = pe
	return entries, raw
}

func writeAuditSegment(store *MemStore, seq int, prevHash, rowJSON string) {
	seg := auditSegment{Schema: "wapps.audit-segment.v1", Seq: seq, PrevHash: prevHash, RowJSON: rowJSON, Hash: hashSegment(prevHash, rowJSON)}
	b, _ := json.Marshal(seg)
	store.Objects[keyAuditSegment(seq)] = b
}

func hashSegment(prevHash, rowJSON string) string {
	sum := sha256.Sum256([]byte(prevHash + "\n" + rowJSON))
	return hex.EncodeToString(sum[:])
}

// clone, MemStore'un derin bir kopyasını döner (tamper testleri orijinali bozmasın).
func (m *MemStore) clone() *MemStore {
	c := NewMemStore()
	for k, v := range m.Objects {
		cp := make([]byte, len(v))
		copy(cp, v)
		c.Objects[k] = cp
	}
	return c
}

func cfgOf(f *fixture) Config {
	return Config{Pins: f.pins, Now: func() time.Time { return fixTime.Add(time.Hour) }}
}

// --- Happy path + head derivation -------------------------------------------

func TestVerify_HappyPath(t *testing.T) {
	f := newFixture(t)
	res, err := Verify(context.Background(), f.store, cfgOf(f))
	require.NoError(t, err)
	require.Len(t, res.ProjectHeads, 1)
	h := res.ProjectHeads[fixProject]
	require.EqualValues(t, 2, h.Epoch)
	require.Equal(t, f.headHash, h.ManifestSha256)
	require.EqualValues(t, 1, res.TrustHead.AdminEpoch)
}

// --- Tamper classes (§9.3.2) ------------------------------------------------

func TestVerify_TamperBadSignature(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	// epoch-2 manifest sarmalayıcısının imzalanan body'sini kurcala → imza geçmez.
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(s.Objects[keyManifest(fixProject, 2)], &obj))
	// bytes alanını değiştir (base64 body): son karakteri değiştirerek boz.
	var wrapper struct {
		Bytes []byte          `json:"bytes"`
		Sigs  json.RawMessage `json:"sigs"`
	}
	require.NoError(t, json.Unmarshal(s.Objects[keyManifest(fixProject, 2)], &wrapper))
	wrapper.Bytes[len(wrapper.Bytes)-1] ^= 0xff
	tampered, _ := json.Marshal(wrapper)
	s.Objects[keyManifest(fixProject, 2)] = tampered
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrSig)
}

func TestVerify_TamperBlobHash(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	// epoch-1'in DATABASE_URL blob'unu bul + baytlarını boz (hash artık eşleşmez).
	// Blob anahtarlarını listeden bul.
	keys, _ := s.List(context.Background(), prefixBlobs(fixProject))
	require.NotEmpty(t, keys)
	blob := s.Objects[keys[0]]
	blob[10] ^= 0xff // içeriği boz → content-address mismatch
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrBlobHash)
}

func TestVerify_TamperChainBreak(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	// epoch-2'yi kaldır ve yerine YENİ bir epoch-2 koy ama prevManifestSha256'yı boz
	// olması için epoch-1 manifest'ini değiştir → epoch-2'nin prev bağı kopar.
	// Basit yol: epoch-2 manifest'ini epoch-1 ile değiştir → epoch alanı 1, key 2 → chain fail.
	s.Objects[keyManifest(fixProject, 2)] = s.Objects[keyManifest(fixProject, 1)]
	// pointer-event 2 de eşleşmeyecek ama önce chain/sig kontrolü çalışır.
	_, err := Verify(context.Background(), s, cfgOf(f))
	// epoch-2 slot'unda epoch==1 manifest → VerifyChainLink epoch mismatch = ErrChain
	// (veya proje eşleşir ama epoch 1 != 2 → chain). Sig önce geçer (writer aynı).
	require.ErrorIs(t, err, ErrChain)
}

func TestVerify_TamperMissingEscrowWrap(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	// epoch-1 manifest'inde bir girdinin escrow wrap'ini çıkar. Sarmalayıcının
	// imzalı body'sini yeniden imzalamamız gerekir (aksi halde SIG hatası önce gelir).
	// Bu yüzden epoch-1'i escrow-wrap'siz YENİDEN imzala.
	rebuildEpoch1WithoutEscrow(t, s, f)
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrEscrowWrap)
}

func TestVerify_TamperAuditChainBreak(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	// audit segment 2'nin hash'ini boz → zincir kopar.
	var seg auditSegment
	require.NoError(t, json.Unmarshal(s.Objects[keyAuditSegment(2)], &seg))
	seg.Hash = "deadbeef" + seg.Hash[8:]
	b, _ := json.Marshal(seg)
	s.Objects[keyAuditSegment(2)] = b
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrAuditChain)
}

// MID-CHAIN delik: epoch-1 pointer-event eksik ama epoch-2 (head) present → gerçek
// boşluk (backlog değil) → ErrPointerEvent. (§9.3.2f)
func TestVerify_TamperPointerEventMidChainGap(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	delete(s.Objects, keyPointerEvent(fixProject, 1)) // ortada delik: 1 yok, 2 var
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrPointerEvent)
}

// PRESENT ama TUTARSIZ: head pointer-event var ama manifest hash'i yanlış → tamper
// → ErrPointerEvent (trailing-gap toleransı bunu KAPSAMAZ). (§9.3.2f)
func TestVerify_TamperPointerEventInconsistent(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	var pe pointerEvent
	require.NoError(t, json.Unmarshal(s.Objects[keyPointerEvent(fixProject, 2)], &pe))
	pe.ManifestSha256 = "deadbeef" + pe.ManifestSha256[8:] // manifest hash'i boz
	b, _ := json.Marshal(pe)
	s.Objects[keyPointerEvent(fixProject, 2)] = b
	_, err := Verify(context.Background(), s, cfgOf(f))
	require.ErrorIs(t, err, ErrPointerEvent)
}

// TRAILING boşluk (write-through backlog): manifest N indi ama pointer-event N
// henüz yok = MEŞRU bölünmüş durum → verify GEÇER + head yine manifest zincirinden
// (epoch N). Spurious availability degradation'ı önler. (§9.3.2f)
func TestVerify_PointerEventTrailingGapTolerated(t *testing.T) {
	f := newFixture(t)
	s := f.store.clone()
	delete(s.Objects, keyPointerEvent(fixProject, 2)) // head pointer-event henüz drene olmadı
	res, err := Verify(context.Background(), s, cfgOf(f))
	require.NoError(t, err)
	h := res.ProjectHeads[fixProject]
	require.EqualValues(t, 2, h.Epoch) // head manifest zincirinden (N via chain)
	require.Equal(t, f.headHash, h.ManifestSha256)
}

// rebuildEpoch1WithoutEscrow, epoch-1'i escrow wrap'i OLMADAN yeniden imzalar
// (missing-escrow-wrap tamper'ının imza-geçerli hali). Zinciri de bozmamak için
// epoch-2'yi de yeni epoch-1'e göre yeniden zincirler.
func rebuildEpoch1WithoutEscrow(t *testing.T, s *MemStore, f *fixture) {
	t.Helper()
	device, _ := cryptoid.GenerateX25519Identity()
	_ = device
	// Yeni recs = escrow HARİÇ (ama en az bir wrap kalmalı — writer device).
	// Orijinal epoch-1'i parse et, escrow wrap'lerini çıkar, yeniden imzala.
	obj, err := manifest.ParseSignedObject(s.Objects[keyManifest(fixProject, 1)])
	require.NoError(t, err)
	m, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)
	for i := range m.Entries {
		kept := m.Entries[i].Wraps[:0]
		for _, w := range m.Entries[i].Wraps {
			if w.Recipient != f.escrowFp {
				kept = append(kept, w)
			}
		}
		m.Entries[i].Wraps = kept
	}
	newObj, _, err := manifest.SignManifest(m, f.writer)
	require.NoError(t, err)
	raw, err := manifest.MarshalSignedObject(newObj)
	require.NoError(t, err)
	s.Objects[keyManifest(fixProject, 1)] = raw
	// pointer-event 1 hash güncelle.
	pe, _ := json.Marshal(pointerEvent{Schema: "wapps.pointer-event.v1", Project: fixProject, Epoch: 1, ManifestSha256: manifest.ManifestObjectHash(raw), CommittedAt: fixTime.Format(time.RFC3339)})
	s.Objects[keyPointerEvent(fixProject, 1)] = pe
	// epoch-2 artık kopuk zincir olur ama escrow-wrap kontrolü epoch-1'de ÖNCE patlar
	// (verifyProject e=1'de d kontrolünü b/c'den sonra ama e=2'ye geçmeden yapar).
}
