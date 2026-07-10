// Package store, wapps-secrets istemcisinin TEK okuma/yazma soyutlamasıdır
// (SPEC §7.3.1): verb'ler asla R2/Worker/dosya detayı bilmez. WorkerStore,
// secrets-gate Worker'ın (§6) HTTP sözleşmesi üzerinden çalışır.
//
// İstemci Worker'a ASLA GÜVENMEZ: her okumada trust roster'ı PİNLENMİŞ genesis +
// last-verified'e karşı doğrular (internal/trust), data-manifest yazar imzasını
// doğrular, her blob hash'ini içerik-adresine karşı doğrular, SONRA per-key DEK'i
// yerel X25519 kimlikle Unseal edip zarfı açar (Worker'ın AKSİNE — Worker çözmez).
//
// Doğrulama SIRASI ve exact-bytes disiplini frozen TCB'dendir (§3.6.3): imza,
// depolanan TAM baytların SHA-256'sı üzerinedir; body imza geçene kadar PARSE
// EDİLMEZ ve asla yeniden serileştirilmez.
package store

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Store, tek okuma/yazma soyutlamasıdır (SPEC §7.3.1). Verb çağrı yerleri
// doğrudan os.ReadFile + ageutil.Decrypt yerine BUNU kullanır.
type Store interface {
	// Fetch, çevrimiçi-first conditional GET yapar; doğrulanmış bir anlık
	// görüntü (manifest + istenen anahtarların blob'ları) döner.
	Fetch(ctx context.Context, project string, opts FetchOpts) (*VerifiedSnapshot, error)
	// Commit, epoch+1 CAS yazımı yapar; 412'de disjoint anahtarlar için
	// auto-rebase (max 3, jittered).
	Commit(ctx context.Context, project string, delta ManifestDelta) (*CommitResult, error)
}

// FetchOpts, bir okumanın kapsamını ve tazelik politikasını taşır (SPEC §7.3.1).
type FetchOpts struct {
	// Intent, "dev" (default) veya "deploy" (fresh-or-fail).
	Intent intent.Intent
	// Profile, boşsa tüm granted anahtarlar (kabul edilmiş risk §2); doluysa
	// yalnızca profildeki anahtarların blob'ları çekilir/cache'lenir.
	Profile string
	// Keys, sadece bu anahtarların blob'ları çekilir (blast-radius min §7.3.3).
	// Boşsa manifest'teki TÜM anahtarlar (identity'nin granted kümesi).
	Keys []string
	// Identity, deploy-intent receipt doğrulaması için gerekmez; okuma yolunda
	// blob çözme SNAPSHOT üzerinde ayrıca yapılır (kimlik burada tutulmaz).
}

// ManifestDelta, bir yazımın anahtar-düzeyi değişiklikleridir (SPEC §7.3.1).
//
// NOT (spec sözleşmesi uyarlaması): SPEC §7.3.1 imzayı ayrı bir parametre olarak
// listeler; ancak imza, rebase'ten SONRAKİ epoch+1 manifest baytları üzerinedir
// ve önceden-imzalı ayrık bir imza rebase'i geçemez. Bu yüzden imzalama CAS/
// rebase döngüsünün İÇİNDE, Writer anahtarıyla yapılır (aşağıda write.go).
type ManifestDelta struct {
	// Sets, keyName → yeni düz metin değer. Her set fresh DEK + re-wrap + re-key.
	Sets map[string][]byte
	// Writer, epoch+1 manifest'i imzalayan hardware daily (veya automation) anahtarı.
	Writer cryptoid.SigningKey
	// WriterID, Writer'ın sahibi principal id (x-principal-id header, §6.2 step 5).
	WriterID string
	// SelfDevice, yazarın KENDİ cihaz kimliği (varsa) — wrap roundtrip öz-kontrolü.
	SelfDevice *cryptoid.X25519Identity
	// Intent, x-wapps-intent header'ı ("dev"|"deploy").
	Intent intent.Intent
}

// CommitResult, bir yazımın sonucudur (SPEC §7.3.1).
type CommitResult struct {
	EpochBefore uint64
	EpochAfter  uint64
	Rebased     int // uygulanan auto-rebase sayısı (0..3)
}

// VerifiedSnapshot, YALNIZCA doğrulama boru hattı tarafından kurulur (SPEC
// §7.3.1): imza-over-exact-bytes, epoch monotonluğu (pin), blob-hash bağı. Hiçbir
// verb doğrulanmamış bayt tüketemez. Blobs ciphertext'tir; düz metin decrypt
// SNAPSHOT.Decrypt ile bellek-içi kimlik kullanılarak yapılır (§7.1: CLI çözer).
type VerifiedSnapshot struct {
	Project string
	Epoch   uint64
	ETag    string // manifest obje hash'i (manifests/current ETag'ı)

	Manifest *manifest.DataManifest
	Trust    *trust.VerifiedEpoch

	// wrapperBytes, imzalı manifest sarmalayıcısının TAM depolanan baytları.
	wrapperBytes []byte
	// blobs, hash → ciphertext blob (yalnızca istenen anahtarlar).
	blobs map[string][]byte

	Receipt   *intent.Receipt
	FetchedAt time.Time
	FromCache bool // çevrimdışı önbellekten servis edildi

	// Warnings, verb'lerin stderr'e basması için insan-okunur uyarılardır
	// (SADECE anahtar-sayısı + yaş; ASLA değer). Örn. çevrimdışı-bayat okuma.
	Warnings []string
}

// Keys, manifest'teki anahtar adlarını döner (asla değer).
func (s *VerifiedSnapshot) Keys() []string {
	out := make([]string, 0, len(s.Manifest.Entries))
	for _, e := range s.Manifest.Entries {
		out = append(out, e.KeyName)
	}
	return out
}

// entry, bir anahtar adının manifest girdisini döner.
func (s *VerifiedSnapshot) entry(keyName string) (*manifest.KeyEntry, bool) {
	for i := range s.Manifest.Entries {
		if s.Manifest.Entries[i].KeyName == keyName {
			return &s.Manifest.Entries[i], true
		}
	}
	return nil, false
}

// Decrypt, tek bir anahtarı yerel X25519 kimlikle çözer (SPEC §7.1 CLI-decrypts):
// kimliğin parmak izine karşılık gelen wrap'i bulur, DEK'i Unseal eder, blob
// hash'ini içerik-adresine karşı doğrular ve zarfı açar. Blob getirilmemişse
// (kapsam dışı) hata. Herhangi bir bütünlük ihlali BLOB_HASH_MISMATCH/SIG_INVALID.
func (s *VerifiedSnapshot) Decrypt(id *cryptoid.X25519Identity, keyName string) ([]byte, error) {
	if id == nil {
		return nil, clierr.New(clierr.IdentityMissing, "no local decryption identity")
	}
	e, ok := s.entry(keyName)
	if !ok {
		return nil, clierr.Newf(clierr.GrantDenied, "key %q not in manifest", keyName)
	}
	fp := id.Fingerprint()
	var wrap []byte
	for _, w := range e.Wraps {
		if w.Recipient == fp {
			wrap = w.Wrap
			break
		}
	}
	if wrap == nil {
		return nil, clierr.Newf(clierr.GrantDenied, "no DEK wrap for this identity on key %q", keyName)
	}
	blob, ok := s.blobs[e.BlobHash]
	if !ok {
		return nil, clierr.Newf(clierr.Internal, "blob for key %q not fetched (out of scope)", keyName)
	}
	// Bütünlük: blob hash'i imzalı manifest girdisiyle eşleşmeli (decrypt ÖNCESİ).
	if err := cryptoid.VerifyBlobHash(blob, e.BlobHash); err != nil {
		return nil, clierr.Wrapf(clierr.BlobHashMismatch, err, "blob hash mismatch for key %q", keyName)
	}
	dek, err := cryptoid.UnsealDEK(wrap, id)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "DEK unseal failed for key %q", keyName)
	}
	slot := cryptoid.Slot{Project: s.Project, KeyName: e.KeyName, KeyVersion: e.KeyVersion}
	pt, err := cryptoid.OpenBlob(blob, dek, slot)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "blob open failed for key %q", keyName)
	}
	return pt, nil
}

// DecryptAll, verilen anahtarları (boşsa manifest'teki tümünü) çözer. Bir anahtar
// bu kimlik için wrap taşımıyorsa (grant yok) SESSİZCE atlanır — çağıran profil∩
// grant kesişimini enjekte eder (§7.6). İlk gerçek bütünlük hatası döndürülür.
func (s *VerifiedSnapshot) DecryptAll(id *cryptoid.X25519Identity, keys []string) (map[string][]byte, error) {
	if len(keys) == 0 {
		keys = s.Keys()
	}
	out := make(map[string][]byte, len(keys))
	fp := ""
	if id != nil {
		fp = id.Fingerprint()
	}
	for _, k := range keys {
		e, ok := s.entry(k)
		if !ok {
			continue
		}
		// Bu kimliğin bu anahtarda wrap'i yoksa grant yok → sessizce atla.
		has := false
		for _, w := range e.Wraps {
			if w.Recipient == fp {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		pt, err := s.Decrypt(id, k)
		if err != nil {
			return nil, err
		}
		out[k] = pt
	}
	return out, nil
}

// dataWriterKeyring, doğrulanmış trust head'inden data-manifest yazar-doğrulama
// keyring'ini kurar: her AKTİF kimliğin her AKTİF imzalama anahtarı → VerifierKey.
// Worker'ın dataWriterKeyring'iyle AYNI (§5.4.1/§6.2).
func dataWriterKeyring(m *trust.TrustManifest) manifest.WriterKeyring {
	ring := manifest.WriterKeyring{}
	for _, id := range m.Identities {
		if id.Status == registry.StatusRevoked {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Status != registry.StatusActive {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(sk.Pubkey)
			if err != nil {
				continue
			}
			vk, err := cryptoid.NewVerifierKey(sk.Alg, raw)
			if err != nil {
				continue // kapalı-küme dışı / bozuk → keyring'e alınmaz (fail-closed)
			}
			ring[vk.KeyID()] = vk
		}
	}
	return ring
}

// ensure interface compliance.
var _ Store = (*WorkerStore)(nil)

// httpDoer, enjekte edilebilir HTTP taşımasıdır (üretimde *http.Client; testte
// httptest sunucusu).
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
