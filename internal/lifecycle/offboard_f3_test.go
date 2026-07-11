package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// TestAdminIdentityForSigningKey_DerivedFingerprint (F3 part-2): imzalayan kimliği,
// girdinin BEYAN ETTİĞİ sk.KeyID ile DEĞİL, pubkey'den TÜRETİLEN parmak izi
// (sk.Fingerprint) ile çözülür. Beyan edilen key_id spoofed/mismatched olsa bile
// çözümleme türetilmiş fp üzerinden yapılır → ayrılan bir admin mismatched declared
// key_id ile offboard'ı kendi kendine yetkilendiremez.
func TestAdminIdentityForSigningKey_DerivedFingerprint(t *testing.T) {
	h := newTHuman(t, "admin@wapps.dev")
	id := h.identity()
	derived := h.admin.KeyID() // admin-sınıfı imzalama anahtarının TÜRETİLMİŞ fp'si

	// Admin-sınıfı signing key'in BEYAN edilen key_id'sini spoofed bir değere boz.
	const spoof = "sha256:spoofed-declared-key-id"
	for i := range id.SigningKeys {
		if id.SigningKeys[i].Class == registry.SignClassAdmin {
			id.SigningKeys[i].KeyID = spoof
		}
	}
	tm := &trust.TrustManifest{
		Admins:     []string{h.id},
		Identities: []registry.Identity{id},
	}

	// TÜRETİLMİŞ fp ile çözülür (beyan edilen spoofed string DEĞİL).
	got, ok := adminIdentityForSigningKey(tm, derived)
	require.True(t, ok, "derived fingerprint must resolve the admin identity")
	require.Equal(t, h.id, got)

	// Spoofed BEYAN edilen key_id ile ÇÖZÜLMEZ (declared string'e güvenilmez).
	_, ok = adminIdentityForSigningKey(tm, spoof)
	require.False(t, ok, "declared/spoofed key_id must not resolve an identity")
}

// TestAdminIdentityForSigningKey_AmbiguousFailClosed (codex round-7, F3-komşusu):
// aynı TÜRETİLMİŞ imzalama parmak izi >1 aktif admin kimliğinde görünürse çözüm
// belirsizdir → fail-closed (ok=false). İlk-eşleşeni dönmek roster-sırasına bağlı
// yanlış-attribution'a ve assertRunner'daki departing-runner kontrolünün atlanmasına
// yol açardı: ayrılan bir admin'in anahtarı başka bir aktif kimlik altında da
// listeliyse offboard'ı kendi kendine sürebilirdi.
func TestAdminIdentityForSigningKey_AmbiguousFailClosed(t *testing.T) {
	h := newTHuman(t, "admin@wapps.dev")
	id1 := h.identity()
	id2 := h.identity() // AYNI h.admin imzalama anahtarı → AYNI türetilmiş fp
	id2.ID = "human:admin2@wapps.dev"
	tm := &trust.TrustManifest{
		Admins:     []string{id1.ID, id2.ID},
		Identities: []registry.Identity{id1, id2},
	}
	// İki farklı aktif admin kimliği aynı fp'yi taşıyor → belirsiz → çözülmez.
	_, ok := adminIdentityForSigningKey(tm, h.admin.KeyID())
	require.False(t, ok, "duplicate signing fingerprint across identities must fail closed")

	// Sağlık kontrolü: tek kimlikte kalınca aynı fp normal çözülür.
	tmSingle := &trust.TrustManifest{Admins: []string{id1.ID}, Identities: []registry.Identity{id1}}
	got, ok := adminIdentityForSigningKey(tmSingle, h.admin.KeyID())
	require.True(t, ok, "single owner must resolve")
	require.Equal(t, id1.ID, got)
}

// TestAdminIdentityForSigningKey_CrossClassReuse (codex round-8 P1-2): ayrılan bir
// admin'in DAILY-sınıf anahtarı, başka bir aktif admin'in ADMIN-sınıf anahtarıyla AYNI
// pubkey ise (aynı türetilmiş fp), yalnızca admin-sınıfa bakan attribution imzayı diğer
// admin'e atfederdi → departing-runner bypass. Sınıf-agnostik kimlik-bazlı sayım bunu
// belirsiz sayar → fail-closed.
func TestAdminIdentityForSigningKey_CrossClassReuse(t *testing.T) {
	ha := newTHuman(t, "admin-a@wapps.dev")
	admin := ha.identity() // ha.admin ADMIN-sınıf
	// Ayrılan kimlik: AYNI ha.admin anahtarını DAILY sınıfında listeler.
	departing := ha.identity()
	departing.ID = "human:departing@wapps.dev"
	departing.SigningKeys = []registry.SigningKey{
		registry.NewSigningKeyEntry(ha.admin, registry.SignClassDaily, "software"),
	}
	tm := &trust.TrustManifest{
		Admins:     []string{admin.ID, departing.ID},
		Identities: []registry.Identity{admin, departing},
	}
	// fp iki kimlikte (admin-sınıf + daily-sınıf) → belirsiz → çözülmez.
	_, ok := adminIdentityForSigningKey(tm, ha.admin.KeyID())
	require.False(t, ok, "cross-class fingerprint reuse must fail closed")
}
