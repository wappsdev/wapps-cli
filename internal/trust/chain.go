package trust

import (
	"fmt"
	"reflect"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// VerifiedEpoch, tam doğrulanmış bir güven epoch'unun sonucudur: ayrıştırılmış
// manifest + İMZALANAN (payload) baytların hex SHA-256'sı. Pin (§4.4) bu
// hash'ten türetilir.
type VerifiedEpoch struct {
	Manifest    *TrustManifest
	BytesSHA256 string // TrustObjectHash(Raw.Bytes)
	Raw         cryptoid.SignedObject
	view        signerView // bir SONRAKİ epoch'u doğrulamak için imzalayan görünümü
}

// Pin, bu epoch'un {admin_epoch, sha256} yüksek-su-işaretidir (§4.4).
func (v *VerifiedEpoch) Pin() Pin {
	return Pin{AdminEpoch: v.Manifest.AdminEpoch, SHA256: v.BytesSHA256}
}

// adminKeyInfo, bir admin presence anahtarını sahibi insan kimliğiyle eşler
// (prod grant'ta FARKLI insan sayımı için, §4.5 step 4).
type adminKeyInfo struct {
	vk      cryptoid.VerifierKey
	humanID string
}

// signerView, doğrulanmış bir epoch'tan türetilen imzalayan keyring'leri + katman
// (tier) girdileridir. Bir SONRAKİ epoch bu görünüme karşı doğrulanır — asla
// kendi materyaline karşı (SPEC §4.5 step 4: "never epoch E+1's").
type signerView struct {
	rootKeys      map[string]cryptoid.VerifierKey // aktif kök Ed25519 anahtarları
	adminKeys     map[string]adminKeyInfo         // aktif admin-class presence anahtarları
	m, n          int
	bootstrapSolo bool
	nAdminHumans  int
}

// buildSignerView, bir manifest'ten imzalayan görünümünü türetir. Kökler
// Ed25519 olmalıdır (aksi halde TRUST_CHAIN_BROKEN); admin anahtarları
// admins[] listesindeki aktif kimliklerin aktif, ECDSA-P256 admin-class
// imzalama anahtarlarıdır. daily/automation anahtarları ASLA dahil edilmez.
func (m *TrustManifest) buildSignerView() (signerView, error) {
	v := signerView{
		rootKeys:      map[string]cryptoid.VerifierKey{},
		adminKeys:     map[string]adminKeyInfo{},
		m:             m.Quorum.M,
		n:             m.Quorum.N,
		bootstrapSolo: m.BootstrapSolo,
	}
	for _, r := range m.Roots {
		if r.Status != statusActive {
			continue
		}
		if r.Alg != cryptoid.AlgEd25519 {
			return signerView{}, fmt.Errorf("trust.buildSignerView: root %q must be ed25519: %w", r.KeyID, ErrTrustChainBroken)
		}
		vk, err := cryptoid.NewVerifierKey(r.Alg, r.Pubkey)
		if err != nil {
			return signerView{}, fmt.Errorf("trust.buildSignerView: root %q: %w", r.KeyID, ErrTrustChainBroken)
		}
		if r.KeyID != "" && r.KeyID != vk.KeyID() {
			return signerView{}, fmt.Errorf("trust.buildSignerView: root key_id mismatch: %w", ErrTrustChainBroken)
		}
		v.rootKeys[vk.KeyID()] = vk
	}

	adminSet := map[string]bool{}
	for _, a := range m.Admins {
		adminSet[a] = true
	}
	humans := map[string]bool{}
	for _, id := range m.Identities {
		if !adminSet[id.ID] || id.Status != statusActive {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Class != adminSigningClass || sk.Status != statusActive {
				continue
			}
			if sk.Alg != cryptoid.AlgECDSAP256SHA256 {
				continue // admin presence anahtarları P-256'dır (§4.1)
			}
			raw, err := sk.DecodePubkey() // KATİ KANONİK base64 (Worker b64ToBytes paritesi)
			if err != nil {
				return signerView{}, fmt.Errorf("trust.buildSignerView: admin key decode: %w", ErrTrustChainBroken)
			}
			vk, err := cryptoid.NewVerifierKey(sk.Alg, raw)
			if err != nil {
				return signerView{}, fmt.Errorf("trust.buildSignerView: admin key: %w", ErrTrustChainBroken)
			}
			if sk.KeyID != "" && sk.KeyID != vk.KeyID() {
				return signerView{}, fmt.Errorf("trust.buildSignerView: admin key_id mismatch: %w", ErrTrustChainBroken)
			}
			v.adminKeys[vk.KeyID()] = adminKeyInfo{vk: vk, humanID: id.ID}
			humans[id.ID] = true
		}
	}
	v.nAdminHumans = len(humans)
	return v, nil
}

// adminSigningClass, registry'deki admin-class imzalama anahtarı etiketi.
const adminSigningClass = "admin"

// verifyQuorum, childBytes (TAM depolanan payload) üzerindeki imza kümesinin
// gereken katmanı karşıladığını, PARENT'ın imzalayan görünümüne karşı doğrular
// (SPEC §4.5 step 4). Yalnızca gereken sınıftaki (root/admin) BİLİNEN anahtarlar
// sayılır — daily/automation/yabancı anahtarlar ve geçersiz imzalar sayılmaz
// (fail-closed). Tamper edilmiş payload → gerçek imzalar artık geçmez → eşik
// altına düşer → reddedilir.
func verifyQuorum(childBytes []byte, sigs []cryptoid.Signature, req Requirement, parent signerView) error {
	seen := map[string]bool{}
	humans := map[string]bool{}
	count := 0
	for _, s := range sigs {
		var vk cryptoid.VerifierKey
		var human string
		switch req.Class {
		case ClassRoot:
			k, ok := parent.rootKeys[s.KeyID]
			if !ok {
				continue
			}
			vk = k
		case ClassAdmin:
			info, ok := parent.adminKeys[s.KeyID]
			if !ok {
				continue
			}
			vk = info.vk
			human = info.humanID
		default:
			return fmt.Errorf("trust.verifyQuorum: unknown signer class %q: %w", req.Class, ErrTrustChainBroken)
		}
		if seen[s.KeyID] {
			continue // aynı anahtar iki kez sayılmaz
		}
		if err := cryptoid.VerifySignatureEnvelope(childBytes, s, vk); err != nil {
			continue // geçersiz imza sayılmaz (tamper → eşik altı → red)
		}
		seen[s.KeyID] = true
		count++
		if human != "" {
			humans[human] = true
		}
	}
	got := count
	if req.DistinctHuman {
		got = len(humans)
	}
	if got < req.Threshold {
		return fmt.Errorf("trust.verifyQuorum: have %d, need %d %s signatures: %w", got, req.Threshold, req.Class, ErrTrustQuorumUnmet)
	}
	return nil
}

// validateEmbeddedRegistry, doğrulanmış bir epoch'un GÖMÜLÜ kayıt görünümünün
// (§4.3) TOKEN-MINT açısından kritik anlamsal alt kümesini denetler. Quorum +
// hash-link + roster değişmezleri geçse BİLE bu denetim geçmezse epoch GEÇERSİZDİR:
//   - MAKİNE prensiplerinin joker ("*") grant/writer-allowlist'i YASAK; aksi halde
//     tek sızmış otomasyon anahtarı projedeki HER değere erişir ve Worker bir wildcard
//     token BASARDI (fix 3).
//   - Her anahtar (enc + signing) girdisinin declared key_id'si (boş değilse) pubkey
//     parmak izine (§3.7) UYMALI (COORD b / fix 4): kök + admin anahtarları zaten ayrı
//     kontrol edilir; bu çağrı daily/automation ve admin-dışı kimliklerin anahtarlarını
//     da kapsar — Worker'ın artık uyguladığı türetme-ve-reddet kuralıyla eşleşir.
//
// KASITLI OLARAK Validate()'in TAMAMINI değil, YALNIZCA bu consensus alt kümesini
// (ValidateSignerSemantics) çalıştırır: rotate_by / insan-enrollment gibi tam kayıt
// bütünlüğü Worker'ın token-mint yolunda YAPTIRILMADIĞI için, tam Validate() Go'yu
// Worker'dan KATI yapıp YENİ bir Go↔TS divergence yaratırdı.
//
// Kayıt görünümü, imza kümesi TAM baytlar üzerinde geçtikten SONRA otoritatif
// kabul edilen aynı imzalı payload'dan gelir (SPEC §3.6.3); tamper edilmiş bir
// grant zaten imzayı bozardı.
func validateEmbeddedRegistry(cand *TrustManifest) error {
	if err := cand.Registry().ValidateSignerSemantics(); err != nil {
		return fmt.Errorf("trust: embedded registry invalid: %w", err)
	}
	return nil
}

// maxHolderShare, tek bir insanın (holder) elindeki AKTİF kök anahtar sayısının
// maksimumudur. bootstrap_solo değişmezi bu değerle tanımlanır.
func maxHolderShare(roots []RootKey) int {
	byHolder := map[string]int{}
	max := 0
	for _, r := range roots {
		if r.Status != statusActive {
			continue
		}
		byHolder[r.Holder]++
		if byHolder[r.Holder] > max {
			max = byHolder[r.Holder]
		}
	}
	return max
}

// validateRosterInvariants, bir manifest'in §4.2.2 kök/quorum kurallarını ve
// §4.7 bootstrap_solo değişmezini denetler. Pinli bugün: m≥2, n = aktif kök
// sayısı, m≤n, tüm kökler Ed25519.
//
// bootstrap_solo değişmezi (SPEC §4.7): tek bir insan quorum'u TEK BAŞINA
// karşılayabiliyorsa (maxHolderShare ≥ m) solo TRUE olmalı; karşılayamıyorsa
// (custody gerçekten çok-insanlı) solo FALSE olmalı. Yani:
//
//	bootstrap_solo == (maxHolderShare >= quorum.m)
//
// solo=false'u bir insan hâlâ ≥M kök tutarken kurmak (§4.7 step 3) ve solo=true'yu
// artık kimse ≥M tutmazken bırakmak, her ikisi de TRUST_CHAIN_BROKEN'dır.
func validateRosterInvariants(m *TrustManifest) error {
	if m.Quorum.M < 2 {
		return fmt.Errorf("trust.validateRosterInvariants: quorum.m %d must be >= 2: %w", m.Quorum.M, ErrTrustChainBroken)
	}
	active := 0
	for _, r := range m.Roots {
		if r.Status != statusActive {
			continue
		}
		active++
		if r.Alg != cryptoid.AlgEd25519 {
			return fmt.Errorf("trust.validateRosterInvariants: root %q must be ed25519: %w", r.KeyID, ErrTrustChainBroken)
		}
		if len(r.Pubkey) != 32 {
			return fmt.Errorf("trust.validateRosterInvariants: root %q pubkey must be 32 bytes: %w", r.KeyID, ErrTrustChainBroken)
		}
		if r.KeyID != "" && r.KeyID != cryptoid.Fingerprint(r.Pubkey) {
			return fmt.Errorf("trust.validateRosterInvariants: root key_id mismatch: %w", ErrTrustChainBroken)
		}
	}
	if active != m.Quorum.N {
		return fmt.Errorf("trust.validateRosterInvariants: active roots %d != quorum.n %d: %w", active, m.Quorum.N, ErrTrustChainBroken)
	}
	if m.Quorum.M > m.Quorum.N {
		return fmt.Errorf("trust.validateRosterInvariants: quorum.m %d > quorum.n %d: %w", m.Quorum.M, m.Quorum.N, ErrTrustChainBroken)
	}
	wantSolo := maxHolderShare(m.Roots) >= m.Quorum.M
	if m.BootstrapSolo != wantSolo {
		return fmt.Errorf("trust.validateRosterInvariants: bootstrap_solo=%v but max holder share vs m=%d requires %v: %w",
			m.BootstrapSolo, m.Quorum.M, wantSolo, ErrTrustChainBroken)
	}
	return nil
}

// compareUnchanged, roster/epoch_reset OLMAYAN bir epoch'un kök/quorum/admins/
// bootstrap_solo/worker_receipt_pubkey/worker_mint_pubkeys alanlarını
// DEĞİŞTİRMEDİĞİNİ doğrular (SPEC §4.5 step 5). Herhangi bir değişiklik
// TRUST_CHAIN_BROKEN'dır. worker_mint_pubkeys (token-mint / audit-head ES256
// anahtarları) yüksek-değerli bir anahtar sınıfıdır → yalnızca roster M-of-N
// epoch'u döndürebilir; 1-admin (registry/policy/lab-grant) epoch'u ASLA.
func compareUnchanged(parent, cur *TrustManifest) error {
	// COORD (a): array-şekilli KİLİTLİ alanlar (roots/admins/worker_mint_pubkeys)
	// için JSON null / yokluk / [] hepsi "girdi yok" demektir ve EŞDEĞER sayılır.
	// reflect.DeepEqual nil ve boş dilimi AYIRDIĞINDAN (nil != []) burada
	// eqArrayNilAsEmpty ile normalize edilir; aksi halde null<->[] değişimi Go'da
	// reddedilir ama Worker'da (null→[] indirger) kabul edilirdi → desync.
	if !eqArrayNilAsEmpty(parent.Roots, cur.Roots) {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies roots: %w", ErrTrustChainBroken)
	}
	if parent.Quorum != cur.Quorum {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies quorum: %w", ErrTrustChainBroken)
	}
	if !eqArrayNilAsEmpty(parent.Admins, cur.Admins) {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies admins: %w", ErrTrustChainBroken)
	}
	if parent.BootstrapSolo != cur.BootstrapSolo {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies bootstrap_solo: %w", ErrTrustChainBroken)
	}
	if !reflect.DeepEqual(parent.WorkerReceiptPub, cur.WorkerReceiptPub) {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies worker_receipt_pubkey: %w", ErrTrustChainBroken)
	}
	if !eqArrayNilAsEmpty(parent.WorkerMintPubs, cur.WorkerMintPubs) {
		return fmt.Errorf("trust.compareUnchanged: non-roster epoch modifies worker_mint_pubkeys: %w", ErrTrustChainBroken)
	}
	return nil
}

// eqArrayNilAsEmpty, iki dilimi karşılaştırırken nil ve boş dilimi EŞDEĞER sayar
// (COORD a): imzalı array-şekilli kilitli alanlarda JSON null/yokluk/[] hepsi
// "girdi yok" anlamına gelir ve Worker de bunları []'ye indirger. İki taraf da
// boşsa (len==0) her zaman eşit; aksi halde eleman-bazlı reflect.DeepEqual.
func eqArrayNilAsEmpty[T any](a, b []T) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// grantTargetClass, bir grant epoch'unun parent'a göre EKLENEN/DEĞİŞEN
// grant'larının en katı proje sınıfını döndürür (herhangi biri prod ise prod).
// classifier nil ise güvenli varsayılan olarak prod (en katı) döner.
func grantTargetClass(parent, cur *TrustManifest, classifier ProjectClassifier) ProjectClass {
	if classifier == nil {
		return ProjectProd
	}
	sawProd, sawLab := false, false
	for _, g := range cur.Grants {
		changed := true
		for _, pg := range parent.Grants {
			if reflect.DeepEqual(g, pg) {
				changed = false
				break
			}
		}
		if !changed {
			continue
		}
		switch classifier(g.Project) {
		case ProjectProd:
			sawProd = true
		case ProjectLab:
			sawLab = true
		}
	}
	switch {
	case sawProd:
		return ProjectProd
	case sawLab:
		return ProjectLab
	default:
		return ProjectProd // değişiklik saptanamadı → strict-safe
	}
}

// VerifyGenesis, genesis güven epoch'unu (admin_epoch = pin) doğrular. Genesis
// zincirin PİNLENMİŞ anchor'ıdır: önce ham (payload) baytların hash'i pinlenmiş
// genesis hash'iyle EŞLEŞMELİ (parse ÖNCESİ), sonra roster olduğu, prev'in boş
// olduğu ve kendi kökleriyle ≥M imzalandığı doğrulanır (§4.4, §4.5 istisnası).
func VerifyGenesis(pinnedGenesis Pin, obj cryptoid.SignedObject) (*VerifiedEpoch, error) {
	if pinnedGenesis.SHA256 == "" {
		return nil, fmt.Errorf("trust.VerifyGenesis: no genesis pin: %w", ErrTrustPinMissing)
	}
	hash := TrustObjectHash(obj.Bytes)
	if hash != pinnedGenesis.SHA256 {
		return nil, fmt.Errorf("trust.VerifyGenesis: genesis hash does not match pin: %w", ErrTrustChainBroken)
	}
	cand, err := ParseTrustBody(obj.Bytes)
	if err != nil {
		return nil, err
	}
	if cand.AdminEpoch != pinnedGenesis.AdminEpoch {
		return nil, fmt.Errorf("trust.VerifyGenesis: admin_epoch %d != pinned %d: %w", cand.AdminEpoch, pinnedGenesis.AdminEpoch, ErrTrustChainBroken)
	}
	if cand.PrevTrustSHA256 != "" {
		return nil, fmt.Errorf("trust.VerifyGenesis: genesis prev_trust_sha256 must be empty: %w", ErrTrustChainBroken)
	}
	if cand.ChangeClass != ChangeRoster {
		return nil, fmt.Errorf("trust.VerifyGenesis: genesis must be a roster epoch: %w", ErrTrustChainBroken)
	}
	if err := validateRosterInvariants(cand); err != nil {
		return nil, err
	}
	view, err := cand.buildSignerView()
	if err != nil {
		return nil, err
	}
	// Genesis kendi kökleriyle ≥M imzalanır — pin ile anchor'landığı için
	// bu bir öz-imza değil, bütünlük doğrulamasıdır.
	req := Requirement{Class: ClassRoot, Threshold: cand.Quorum.M}
	if err := verifyQuorum(obj.Bytes, obj.Sigs, req, view); err != nil {
		return nil, err
	}
	// Gömülü kayıt anlamsal denetimi (makine-wildcard + key_id tutarlılığı).
	if err := validateEmbeddedRegistry(cand); err != nil {
		return nil, err
	}
	return &VerifiedEpoch{Manifest: cand, BytesSHA256: hash, Raw: obj, view: view}, nil
}

// VerifyNext, doğrulanmış parent epoch'un halefi (E+1) olan obj'yi doğrular
// (SPEC §4.5). classifier grant epoch'larının prod/lab katmanını belirlemek
// için kullanılır (grant dışında yok sayılır; nil = strict prod).
//
// pinnedLast ve witnessBound, istemcinin last_verified pin'i ve tanık sınırıdır;
// zincir-içi bir epoch_reset epoch'unda §4.8 rollback/downgrade ve tanık
// yaptırımlarını beslemek için verifyResetInternal'a AYNEN aktarılır (güvenlik:
// aksi halde reset yolu bu korumaları SIFIRLAR → geçmiş bir epoch'un ≥M kök
// imzasıyla rollback aklanabilir).
//
// DOĞRULAMA SIRASI NOTU (§3.6.3): body, change_class ve grant-diff'i okumak
// için ayrıştırılır; ancak HİÇBİR payload alanı, imza kümesi TAM baytlar
// üzerinde katmanı geçene kadar GÜVENİLMEZ. Sahte bir change_class baytları
// değiştirir → gerçek imzalar geçmez → red.
func VerifyNext(parent *VerifiedEpoch, obj cryptoid.SignedObject, classifier ProjectClassifier, pinnedLast Pin, witnessBound uint64) (*VerifiedEpoch, error) {
	if parent == nil {
		return nil, fmt.Errorf("trust.VerifyNext: nil parent: %w", ErrTrustChainBroken)
	}
	hash := TrustObjectHash(obj.Bytes)
	cand, err := ParseTrustBody(obj.Bytes)
	if err != nil {
		return nil, err
	}

	// Epoch-reset ayrı bir yolla (gevşetilmiş epoch kuralı) doğrulanır. İstemcinin
	// GERÇEK pin'i ve tanık sınırı aktarılır — böylece downgrade/rollback koruması
	// (§4.8) zincir-içi reset'te de yaptırılır.
	if cand.ChangeClass == ChangeEpochReset {
		return verifyResetInternal(obj, cand, hash, parent.view, parent.BytesSHA256, parent.Manifest.AdminEpoch, pinnedLast, witnessBound, true)
	}

	// (2) Hash-link: prev_trust_sha256 == parent'ın payload hash'i (§4.5 step 2).
	if cand.PrevTrustSHA256 != parent.BytesSHA256 {
		return nil, fmt.Errorf("trust.VerifyNext: prev_trust_sha256 does not link to parent: %w", ErrTrustChainBroken)
	}
	// (3) Monotonik, tam +1 (§4.5 step 3): boşluk/tekrar yok.
	if cand.AdminEpoch != parent.Manifest.AdminEpoch+1 {
		return nil, fmt.Errorf("trust.VerifyNext: admin_epoch %d != %d+1: %w", cand.AdminEpoch, parent.Manifest.AdminEpoch, ErrTrustChainBroken)
	}

	// (4) Katman gereksinimi — parent'ın durumundan (§4.5 step 4, §4.7).
	projClass := ProjectNone
	if cand.ChangeClass == ChangeGrant {
		projClass = grantTargetClass(parent.Manifest, cand, classifier)
	}
	req, err := RequiredSigners(cand.ChangeClass, projClass, parent.view.m, parent.view.bootstrapSolo, parent.view.nAdminHumans)
	if err != nil {
		return nil, err
	}
	// İmzalar PARENT'ın anahtar materyaline karşı doğrulanır.
	if err := verifyQuorum(obj.Bytes, obj.Sigs, req, parent.view); err != nil {
		return nil, err
	}

	// (5) Anlamsal değişmezler.
	if err := validateRosterInvariants(cand); err != nil {
		return nil, err
	}
	if cand.ChangeClass != ChangeRoster {
		if err := compareUnchanged(parent.Manifest, cand); err != nil {
			return nil, err
		}
	}
	// Gömülü kayıt anlamsal denetimi (§4.3): makine-wildcard grant/allowlist ve
	// key_id ↔ pubkey tutarsızlığı burada reddedilir — aksi halde imzalı ama geçersiz
	// bir kayıt Worker'da wildcard/yanlış-anahtar token'a çevrilirdi.
	if err := validateEmbeddedRegistry(cand); err != nil {
		return nil, err
	}

	view, err := cand.buildSignerView()
	if err != nil {
		return nil, err
	}
	return &VerifiedEpoch{Manifest: cand, BytesSHA256: hash, Raw: obj, view: view}, nil
}

// VerifyRosterChain, güven epoch'ları zincirini PİNLENMİŞ genesis'ten yukarı
// doğru yürütür ve yeni head'i döner (SPEC §4.4/§4.5). newChain[0] pinlenmiş
// genesis olmalıdır; her ardıl epoch bir öncekinin imzalayan görünümüne karşı
// doğrulanır. Downgrade (head, last-verified pin'in altında) ve pin-fork (aynı
// epoch'ta farklı hash) HARD FAIL'dir.
//
// Grant epoch'ları için strict-safe varsayılan sınıflandırıcı (tümü prod)
// kullanılır; lab grant'ları test/araç için VerifyRosterChainWithClassifier ile.
func VerifyRosterChain(pinnedGenesis, pinnedLast Pin, newChain ...cryptoid.SignedObject) (*VerifiedEpoch, error) {
	return VerifyRosterChainWithClassifier(defaultClassifier, pinnedGenesis, pinnedLast, newChain...)
}

// defaultClassifier, sınıflandırıcı verilmediğinde her projeyi prod (en katı)
// sayar — güvenli varsayılan.
func defaultClassifier(string) ProjectClass { return ProjectProd }

// VerifyRosterChainWithClassifier, VerifyRosterChain'in açık ProjectClassifier
// alan biçimidir (lab grant katmanını test etmek için).
func VerifyRosterChainWithClassifier(classifier ProjectClassifier, pinnedGenesis, pinnedLast Pin, newChain ...cryptoid.SignedObject) (*VerifiedEpoch, error) {
	if pinnedGenesis.SHA256 == "" {
		return nil, fmt.Errorf("trust.VerifyRosterChain: no genesis pin: %w", ErrTrustPinMissing)
	}
	if len(newChain) == 0 {
		return nil, fmt.Errorf("trust.VerifyRosterChain: empty chain: %w", ErrTrustChainBroken)
	}
	head, err := VerifyGenesis(pinnedGenesis, newChain[0])
	if err != nil {
		return nil, err
	}
	if err := checkPinPassthrough(head, pinnedLast); err != nil {
		return nil, err
	}
	// witnessBound = istemcinin last_verified epoch'u: zincir-içi bir reset bu
	// sınırdan KATİ büyük olmalı (§4.8 tanık monotonluğu). pinnedLast ile birlikte
	// VerifyNext'e aktarılır; grant/roster/registry yollarında yok sayılır.
	witnessBound := pinnedLast.AdminEpoch
	for i := 1; i < len(newChain); i++ {
		next, err := VerifyNext(head, newChain[i], classifier, pinnedLast, witnessBound)
		if err != nil {
			return nil, err
		}
		if err := checkPinPassthrough(next, pinnedLast); err != nil {
			return nil, err
		}
		head = next
	}
	// Sunulan head, daha önce doğrulanmış pin'in ALTINDA olamaz (§4.5 downgrade).
	if head.Manifest.AdminEpoch < pinnedLast.AdminEpoch {
		return nil, fmt.Errorf("trust.VerifyRosterChain: head epoch %d below last-verified %d: %w",
			head.Manifest.AdminEpoch, pinnedLast.AdminEpoch, ErrTrustDowngrade)
	}
	return head, nil
}

// checkPinPassthrough, zincir last-verified pin'in epoch'undan geçerken AYNI
// baytları taşıdığını doğrular: pin'in altında/eşitinde forklayan (farklı hash)
// bir zincir bir saldırıdır, staleness değil (§4.5 downgrade). pinnedLast boşsa
// (genesis'te) kontrol atlanır.
func checkPinPassthrough(ep *VerifiedEpoch, pinnedLast Pin) error {
	if pinnedLast.SHA256 == "" {
		return nil
	}
	if ep.Manifest.AdminEpoch == pinnedLast.AdminEpoch && ep.BytesSHA256 != pinnedLast.SHA256 {
		return fmt.Errorf("trust.checkPinPassthrough: epoch %d forks from last-verified pin: %w", pinnedLast.AdminEpoch, ErrTrustDowngrade)
	}
	return nil
}
