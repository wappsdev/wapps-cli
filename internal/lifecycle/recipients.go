package lifecycle

import (
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Recipient, gerekli bir alıcının parmak izi + native X25519 recipient'ıdır
// (rewrap wrap-set kurulumu için).
type Recipient struct {
	Fingerprint string
	Recipient   *cryptoid.X25519Recipient
}

// RequiredRecipients, bir (project, keyName) için OTORİTATİF wrap-set alıcı
// kümesini doğrulanmış trust head'inden türetir — internal/store.requiredRecipients
// ile AYNI kural (§6.2 step 9): read-grant'lı her insanın device+backup enc
// anahtarları ∪ read-grant'lı her makinenin device enc anahtarı ∪ aktif escrow.
// Bu, rewrap motorunun "yeni alıcı kümesi"nin tek gerçek kaynağıdır; ADD/REMOVE
// bu kümeye göre otomatik saptanır. Native olmayan (donanım/plugin) alıcılar
// deterministik wrap üretemez → ErrHardwareNotWired (donanım yolu motor kapsamı
// DIŞINDA — §8.1.1 yazılım fallback'i CI/test yoludur).
func RequiredRecipients(tm *trust.TrustManifest, project, keyName string) ([]Recipient, error) {
	snap := tm.Registry()
	seen := map[string]bool{}
	var out []Recipient
	add := func(ek registry.EncKey) error {
		fp := ek.KeyID
		if fp == "" {
			fp = ek.Fingerprint()
		}
		if seen[fp] {
			return nil
		}
		rec, err := cryptoid.ParseX25519Recipient(ek.Pubkey)
		if err != nil {
			return ErrHardwareNotWired
		}
		seen[fp] = true
		out = append(out, Recipient{Fingerprint: fp, Recipient: rec})
		return nil
	}
	for _, id := range tm.Identities {
		if id.Status == registry.StatusRevoked {
			continue
		}
		if id.Type != registry.TypeHuman && id.Type != registry.TypeMachine {
			continue
		}
		if !snap.KeyAllowed(id.ID, project, keyName) || !snap.VerbAllowed(id.ID, project, "read") {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			if id.Type == registry.TypeHuman && ek.Class != registry.EncClassDevice && ek.Class != registry.EncClassBackup {
				continue
			}
			if id.Type == registry.TypeMachine && ek.Class != registry.EncClassDevice {
				continue
			}
			if err := add(ek); err != nil {
				return nil, err
			}
		}
	}
	// Escrow alıcıları (§9.1: her wrap-set'in ZORUNLU üyesi).
	for _, id := range tm.Identities {
		if id.Type != registry.TypeEscrow || id.Status == registry.StatusRevoked {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			if err := add(ek); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// escrowFingerprints, aktif escrow enc-key parmak izleri kümesini döner
// (client-enforced escrow değişmezi §9.1 için).
func escrowFingerprints(tm *trust.TrustManifest) map[string]bool {
	out := map[string]bool{}
	for _, id := range tm.Identities {
		if id.Type != registry.TypeEscrow || id.Status == registry.StatusRevoked {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			fp := ek.KeyID
			if fp == "" {
				fp = ek.Fingerprint()
			}
			out[fp] = true
		}
	}
	return out
}

// buildWriterKeyring, doğrulanmış trust head'inden data-manifest yazar-doğrulama
// keyring'ini kurar (internal/store.dataWriterKeyring ile AYNI): her AKTİF
// kimliğin her AKTİF imzalama anahtarı → VerifierKey. Rewrap'in ürettiği
// manifest'i imzadan sonra öz-doğrulamak için kullanılır.
func buildWriterKeyring(tm *trust.TrustManifest) manifest.WriterKeyring {
	ring := manifest.WriterKeyring{}
	for _, id := range tm.Identities {
		if id.Status == registry.StatusRevoked {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Status != registry.StatusActive {
				continue
			}
			raw, err := sk.DecodePubkey() // KATİ KANONİK base64 (Worker b64ToBytes paritesi)
			if err != nil {
				continue
			}
			vk, err := cryptoid.NewVerifierKey(sk.Alg, raw)
			if err != nil {
				continue
			}
			ring[vk.KeyID()] = vk
		}
	}
	return ring
}

// wrapFingerprints, bir manifest girdisinin mevcut wrap-set parmak izleri kümesi.
func wrapFingerprints(e manifest.KeyEntry) map[string]bool {
	out := make(map[string]bool, len(e.Wraps))
	for _, w := range e.Wraps {
		out[w.Recipient] = true
	}
	return out
}

// fingerprintSet, bir Recipient diliminin parmak izi kümesi.
func fingerprintSet(rs []Recipient) map[string]bool {
	out := make(map[string]bool, len(rs))
	for _, r := range rs {
		out[r.Fingerprint] = true
	}
	return out
}
