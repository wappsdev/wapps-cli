package registry

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

var testTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// humanIdentity, tam bir insan kimliği kurar (device+backup enc, admin+daily
// signing). Anahtar nesnelerini de döner ki testler imzalayabilsin.
func humanIdentity(t *testing.T, email string) (Identity, *cryptoid.ECDSAP256SigningKey) {
	t.Helper()
	admin, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	daily, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	backup, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	id := Identity{
		ID: "human:" + email, Type: TypeHuman, Status: StatusActive, EnrolledAt: testTime,
		EncKeys: []EncKey{
			NewEncKeyEntry(device.Recipient(), EncClassDevice, "secure-enclave", 1),
			NewEncKeyEntry(backup.Recipient(), EncClassBackup, "paper-steel", 1),
		},
		SigningKeys: []SigningKey{
			NewSigningKeyEntry(admin, SignClassAdmin, "secure-enclave"),
			NewSigningKeyEntry(daily, SignClassDaily, "secure-enclave"),
		},
	}
	return id, admin
}

func machineIdentity(t *testing.T, name string) Identity {
	t.Helper()
	enc, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	auto, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	rotate := testTime.Add(90 * 24 * time.Hour)
	return Identity{
		ID: "machine:" + name, Type: TypeMachine, Status: StatusActive, EnrolledAt: testTime,
		RotateBy: &rotate,
		EncKeys:  []EncKey{NewEncKeyEntry(enc.Recipient(), EncClassDevice, "software", 1)},
		SigningKeys: []SigningKey{
			NewSigningKeyEntry(auto, SignClassAutomation, "woodpecker"),
		},
	}
}

func escrowIdentity(t *testing.T) Identity {
	t.Helper()
	enc, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	return Identity{
		ID: "escrow:primary", Type: TypeEscrow, Status: StatusActive, EnrolledAt: testTime,
		EncKeys: []EncKey{NewEncKeyEntry(enc.Recipient(), EncClassDevice, "paper-steel", 1)},
	}
}

// TestGrantLookups, verb/key/writer allowlist çözümlemesini test eder.
func TestGrantLookups(t *testing.T) {
	s := &Snapshot{
		Schema: SchemaRegistry,
		Grants: []Grant{
			{Principal: "human:a@x", Project: "vaulter", Verbs: []string{"get", "exec"}, Keys: []string{"*"}},
			{Principal: "human:a@x", Project: "lab", Verbs: []string{"get"}, Keys: []string{"API_KEY", "DB_URL"}},
		},
		WriterAllowlists: []WriterAllow{
			{Principal: "machine:tofu-sync", Project: "vaulter", Keys: []string{"TF_OUT_DB"}},
		},
	}

	assert.True(t, s.VerbAllowed("human:a@x", "vaulter", "get"))
	assert.True(t, s.VerbAllowed("human:a@x", "vaulter", "exec"))
	assert.False(t, s.VerbAllowed("human:a@x", "vaulter", "set"))
	assert.False(t, s.VerbAllowed("human:a@x", "other", "get"))

	assert.True(t, s.KeyAllowed("human:a@x", "vaulter", "ANYTHING")) // "*"
	assert.True(t, s.KeyAllowed("human:a@x", "lab", "API_KEY"))
	assert.False(t, s.KeyAllowed("human:a@x", "lab", "SECRET_X"))

	assert.True(t, s.WriterKeyAllowed("machine:tofu-sync", "vaulter", "TF_OUT_DB"))
	assert.False(t, s.WriterKeyAllowed("machine:tofu-sync", "vaulter", "OTHER"))
	assert.False(t, s.WriterKeyAllowed("machine:tofu-sync", "lab", "TF_OUT_DB"))

	assert.Len(t, s.GrantsFor("human:a@x", "vaulter"), 1)
	assert.Empty(t, s.GrantsFor("nobody", "vaulter"))
}

// TestValidate_Happy, geçerli bir kaydın (insan+makine+escrow+grant) geçtiğini
// test eder.
func TestValidate_Happy(t *testing.T) {
	human, _ := humanIdentity(t, "adnan@wapps.dev")
	s := &Snapshot{
		Schema:     SchemaRegistry,
		Identities: []Identity{human, machineIdentity(t, "tofu-sync"), escrowIdentity(t)},
		Grants: []Grant{
			{Principal: human.ID, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}},
		},
		WriterAllowlists: []WriterAllow{
			{Principal: "machine:tofu-sync", Project: "vaulter", Keys: []string{"TF_OUT"}},
		},
	}
	require.NoError(t, s.Validate())
}

// TestValidate_Failures, yapısal/anlamsal değişmez ihlallerini tablo-güdümlü
// test eder.
func TestValidate_Failures(t *testing.T) {
	base := func(t *testing.T) Identity { id, _ := humanIdentity(t, "adnan@wapps.dev"); return id }

	t.Run("human without backup enc", func(t *testing.T) {
		h := base(t)
		h.EncKeys = h.EncKeys[:1] // sadece device
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("human without daily signing", func(t *testing.T) {
		h := base(t)
		h.SigningKeys = h.SigningKeys[:1] // sadece admin
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("machine without rotate_by", func(t *testing.T) {
		m := machineIdentity(t, "x")
		m.RotateBy = nil
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{m}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("escrow with signing key", func(t *testing.T) {
		e := escrowIdentity(t)
		auto, _ := cryptoid.GenerateEd25519()
		e.SigningKeys = []SigningKey{NewSigningKeyEntry(auto, SignClassAutomation, "sw")}
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{e}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("duplicate identity id", func(t *testing.T) {
		h := base(t)
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h, h}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("grant names unknown principal", func(t *testing.T) {
		h := base(t)
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}, Grants: []Grant{
			{Principal: "human:ghost@x", Project: "p", Verbs: []string{"get"}},
		}}
		assert.ErrorIs(t, s.Validate(), ErrIdentityNotEnrolled)
	})
	t.Run("enc key_id mismatch", func(t *testing.T) {
		h := base(t)
		h.EncKeys[0].KeyID = "sha256:wrong"
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}}
		assert.ErrorIs(t, s.Validate(), ErrKeyIDMismatch)
	})
	t.Run("signing key_id mismatch", func(t *testing.T) {
		h := base(t)
		h.SigningKeys[0].KeyID = "sha256:wrong"
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}}
		assert.ErrorIs(t, s.Validate(), ErrKeyIDMismatch)
	})
	t.Run("writer allowlist unknown principal", func(t *testing.T) {
		h := base(t)
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}, WriterAllowlists: []WriterAllow{
			{Principal: "machine:ghost", Project: "p", Keys: []string{"*"}},
		}}
		assert.ErrorIs(t, s.Validate(), ErrIdentityNotEnrolled)
	})
	// P3-a: makine prensipleri joker ("*") anahtar yetkisi taşıyamaz — açık allowlist zorunlu.
	t.Run("machine grant with wildcard keys rejected", func(t *testing.T) {
		m := machineIdentity(t, "tofu-sync")
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{m}, Grants: []Grant{
			{Principal: m.ID, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}},
		}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	t.Run("machine writer allowlist with wildcard keys rejected", func(t *testing.T) {
		m := machineIdentity(t, "tofu-sync")
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{m}, WriterAllowlists: []WriterAllow{
			{Principal: m.ID, Project: "vaulter", Keys: []string{"*"}},
		}}
		assert.ErrorIs(t, s.Validate(), ErrRegistryInvalid)
	})
	// Kontrol: İNSAN prensibi joker grant TAŞIYABİLİR (kısıt yalnızca makinelere).
	t.Run("human grant with wildcard keys allowed", func(t *testing.T) {
		h := base(t)
		s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h}, Grants: []Grant{
			{Principal: h.ID, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}},
		}}
		require.NoError(t, s.Validate())
	})
}

// TestSnapshotSignVerify_Roundtrip, admin-imzalı kayıt anlık görüntüsünün
// imzala/doğrula round-trip'ini + eşik + tamper + yabancı-anahtar yollarını test
// eder.
func TestSnapshotSignVerify_Roundtrip(t *testing.T) {
	human, adminKey := humanIdentity(t, "adnan@wapps.dev")
	s := &Snapshot{
		Schema:     SchemaRegistry,
		Identities: []Identity{human},
		Grants:     []Grant{{Principal: human.ID, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}},
	}

	obj, body, err := SignSnapshot(s, adminKey)
	require.NoError(t, err)
	assert.Equal(t, body, obj.Bytes)

	ring := map[string]cryptoid.VerifierKey{}
	vk, err := cryptoid.NewVerifierKey(adminKey.Alg(), adminKey.PublicKeyBytes())
	require.NoError(t, err)
	ring[vk.KeyID()] = vk

	got, err := VerifySnapshot(obj, ring, 1)
	require.NoError(t, err)
	assert.Len(t, got.Identities, 1)
	assert.True(t, got.VerbAllowed(human.ID, "vaulter", "get"))

	// Eşik 2, tek imza → BAD_SIGNATURE_COUNT.
	_, err = VerifySnapshot(obj, ring, 2)
	assert.ErrorIs(t, err, ErrBadSignatureCount)

	// Yabancı anahtar ring'i → sayılmaz.
	foreign, _ := cryptoid.GenerateECDSAP256()
	fvk, _ := cryptoid.NewVerifierKey(foreign.Alg(), foreign.PublicKeyBytes())
	_, err = VerifySnapshot(obj, map[string]cryptoid.VerifierKey{fvk.KeyID(): fvk}, 1)
	assert.ErrorIs(t, err, ErrBadSignatureCount)

	// Payload tamper → imza geçmez → BAD_SIGNATURE_COUNT (parse edilmeden).
	tampered := cryptoid.SignedObject{Bytes: bytes.Clone(obj.Bytes), Sigs: obj.Sigs}
	tampered.Bytes[len(tampered.Bytes)/2] ^= 0x01
	_, err = VerifySnapshot(tampered, ring, 1)
	assert.ErrorIs(t, err, ErrBadSignatureCount)
}

// TestSnapshot_MultiSign, iki admin imzasıyla 2-of-N eşiğini test eder.
func TestSnapshot_MultiSign(t *testing.T) {
	h1, k1 := humanIdentity(t, "a@x")
	h2, k2 := humanIdentity(t, "b@x")
	s := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h1, h2}}

	obj, _, err := SignSnapshot(s, k1, k2)
	require.NoError(t, err)

	ring := map[string]cryptoid.VerifierKey{}
	for _, k := range []*cryptoid.ECDSAP256SigningKey{k1, k2} {
		vk, err := cryptoid.NewVerifierKey(k.Alg(), k.PublicKeyBytes())
		require.NoError(t, err)
		ring[vk.KeyID()] = vk
	}
	_, err = VerifySnapshot(obj, ring, 2)
	require.NoError(t, err)
}

// TestSignSnapshot_NoKeys, imza anahtarı verilmezse hata döner.
func TestSignSnapshot_NoKeys(t *testing.T) {
	s := &Snapshot{Schema: SchemaRegistry}
	_, _, err := SignSnapshot(s)
	assert.ErrorIs(t, err, ErrBadSignatureCount)
}

// TestMarshalCanonical_Deterministic, kimlik/grant sırasından bağımsız olarak
// aynı baytların üretildiğini doğrular.
func TestMarshalCanonical_Deterministic(t *testing.T) {
	h1, _ := humanIdentity(t, "a@x")
	h2, _ := humanIdentity(t, "b@x")
	s1 := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h1, h2}}
	s2 := &Snapshot{Schema: SchemaRegistry, Identities: []Identity{h2, h1}} // ters sıra

	b1, err := s1.MarshalCanonical()
	require.NoError(t, err)
	b2, err := s2.MarshalCanonical()
	require.NoError(t, err)
	assert.Equal(t, b1, b2, "canonical bytes must be order-independent")
}

// TestParseSnapshotBody_UnknownField, bilinmeyen alanın reddedildiğini test eder.
func TestParseSnapshotBody_UnknownField(t *testing.T) {
	_, err := ParseSnapshotBody([]byte(`{"schema":"wapps-registry/v1","bogus":1}`))
	assert.Error(t, err)
	_, err = ParseSnapshotBody([]byte(`{"schema":"other/v1"}`))
	assert.ErrorIs(t, err, ErrUnsupportedSchema)
}
