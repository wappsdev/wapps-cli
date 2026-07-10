package witness

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Tamper sınıfları (§9.3.2). Verify İLK ihlalde fail-closed döner; her sınıf bir
// sentinel ile ayrılır (errors.Is ile test edilir).
var (
	ErrSig          = errors.New("witness: writer/roster signature invalid")        // 9.3.2a
	ErrBlobHash     = errors.New("witness: blob hash mismatch")                     // 9.3.2b
	ErrBlobMissing  = errors.New("witness: referenced blob missing from escrow")    // 9.3.2b
	ErrChain        = errors.New("witness: manifest epoch chain broken")            // 9.3.2c
	ErrEscrowWrap   = errors.New("witness: escrow wrap missing")                    // 9.3.2d
	ErrAuditChain   = errors.New("witness: audit chain broken")                     // 9.3.2e
	ErrPointerEvent = errors.New("witness: pointer-event density/consistency fail") // 9.3.2f
	ErrCanaryForged = errors.New("witness: escrow canary wrap forged")              // 9.3.2g
	ErrNoTrust      = errors.New("witness: no verifiable trust chain in escrow")
)

// CANARY_KEY, her projenin rezerve escrow-canary anahtar adı (§3.5.5 F8).
const CANARY_KEY = "WAPPS_ESCROW_CANARY"

// Head, bir projenin doğrulanmış escrow head'idir (append-only temsilden türetilir).
type Head struct {
	Project        string `json:"project"`
	Epoch          uint64 `json:"epoch"`
	ManifestSha256 string `json:"manifestSha256"`
}

// TrustHead, doğrulanmış son trust head'idir (§4.8 epoch-reset issuance bound).
type TrustHead struct {
	AdminEpoch  uint64 `json:"admin_epoch"`
	TrustSha256 string `json:"trust_sha256"`
}

// Result, başarılı bir doğrulamanın çıktısı: per-proje head'ler + trust head.
type Result struct {
	ProjectHeads map[string]Head
	TrustHead    TrustHead
	VerifiedAt   time.Time
	// Head manifest'lerin doğrulanmış tam sarmalayıcı baytları (DR restore için).
	headWrapper map[string][]byte
}

// Config, doğrulayıcının bağımlılıklarıdır.
type Config struct {
	Pins *trust.PinStore
	// Projects, taranacak projeler; boşsa reader'dan türetilir.
	Projects []string
	// RequireCanary true ise her projenin head manifest'inde WAPPS_ESCROW_CANARY
	// girdisinin YAPISAL varlığı zorunludur (§9.3.2g presence). Actual byte-compare
	// (yayınlanmış DEK'ten re-derive) + DECRYPT DR seremonisidir (escrow.go
	// VerifyCanary) — bu hourly verifier structural presence yapar (task).
	RequireCanary bool
	Now           func() time.Time
}

var projectRe = regexp.MustCompile(`^secrets/([^/]+)/`)

// Verify, escrow snapshot'ının §9.3.2 kontrol paketini çalıştırır (a–g). İLK
// tamper'da fail-closed (sınıf sentinel'ini sarar). Başarıda per-proje head'ler +
// trust head döner. Yalnızca YEREL pinlere dayanır — Cloudflare'den çekilen hiçbir
// şeye güvenmez (§9.3.1).
func Verify(ctx context.Context, r Reader, cfg Config) (*Result, error) {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	if cfg.Pins == nil {
		return nil, fmt.Errorf("witness.Verify: nil pins")
	}

	// (a) Trust zinciri — pinlere karşı doğrula.
	head, err := verifyTrustChain(ctx, r, cfg.Pins)
	if err != nil {
		return nil, err
	}
	ring := writerKeyring(head.Manifest)
	escrowFps := escrowFingerprints(head.Manifest)
	if len(escrowFps) == 0 {
		return nil, fmt.Errorf("witness.Verify: trust roster has no active escrow recipient")
	}

	// (e) Audit zinciri (proje-bağımsız, global segmentler).
	if err := verifyAuditChain(ctx, r); err != nil {
		return nil, err
	}

	projects := cfg.Projects
	if len(projects) == 0 {
		projects, err = discoverProjects(ctx, r)
		if err != nil {
			return nil, err
		}
	}

	res := &Result{ProjectHeads: map[string]Head{}, TrustHead: TrustHead{AdminEpoch: head.Manifest.AdminEpoch, TrustSha256: head.BytesSHA256}, VerifiedAt: now().UTC(), headWrapper: map[string][]byte{}}

	for _, project := range projects {
		h, wrapper, err := verifyProject(ctx, r, project, ring, escrowFps, cfg.RequireCanary)
		if err != nil {
			return nil, err
		}
		res.ProjectHeads[project] = h
		res.headWrapper[project] = wrapper
	}
	return res, nil
}

// verifyTrustChain, escrow'daki trust manifest zincirini (trust/manifests/<e>.json)
// pinlere karşı doğrular (§9.3.2a). Mutable trust/current escrow'da YOKTUR (F2);
// head zincirden türetilir (istemci gibi, pinlere dayanır).
func verifyTrustChain(ctx context.Context, r Reader, pins *trust.PinStore) (*trust.VerifiedEpoch, error) {
	var chain []cryptoid.SignedObject
	for e := uint64(1); ; e++ {
		raw, err := r.Get(ctx, keyTrustManifest(e))
		if errors.Is(err, ErrNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
		obj, perr := manifest.ParseSignedObject(raw)
		if perr != nil {
			return nil, fmt.Errorf("%w: trust epoch %d malformed: %v", ErrSig, e, perr)
		}
		chain = append(chain, obj)
	}
	if len(chain) == 0 {
		return nil, ErrNoTrust
	}
	head, err := trust.VerifyRosterChain(pins.Genesis, pins.LastVerified, chain...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSig, err)
	}
	return head, nil
}

// verifyProject, tek bir projenin manifest zincirini (b/c/d/f/g) doğrular ve
// head'i (append-only temsilden) türetir.
func verifyProject(ctx context.Context, r Reader, project string, ring manifest.WriterKeyring, escrowFps []string, requireCanary bool) (Head, []byte, error) {
	var prevWrapper []byte
	var headEpoch uint64
	var headHash string
	var headWrapper []byte
	var headMan *manifest.DataManifest
	// chainHashes, doğrulanmış manifest zincirinin her epoch'unun obje hash'i —
	// pointer-event'lerin tutarlılığını (§9.3.2f) epoch bazında kontrol etmek için.
	chainHashes := map[uint64]string{}

	for e := uint64(1); ; e++ {
		raw, err := r.Get(ctx, keyManifest(project, e))
		if errors.Is(err, ErrNotExist) {
			break
		}
		if err != nil {
			return Head{}, nil, err
		}
		obj, perr := manifest.ParseSignedObject(raw)
		if perr != nil {
			return Head{}, nil, fmt.Errorf("%w: %s epoch %d malformed: %v", ErrSig, project, e, perr)
		}
		// (a) yazar imzası pinlenmiş ring'e karşı.
		man, verr := manifest.VerifyDataManifest(obj, ring)
		if verr != nil {
			return Head{}, nil, fmt.Errorf("%w: %s epoch %d: %v", ErrSig, project, e, verr)
		}
		if perr := manifest.CheckProject(man, project); perr != nil {
			return Head{}, nil, fmt.Errorf("%w: %v", ErrSig, perr)
		}
		// (c) epoch zinciri sürekli + monotonik.
		if e == 1 {
			if gerr := manifest.VerifyGenesis(man); gerr != nil {
				return Head{}, nil, fmt.Errorf("%w: %v", ErrChain, gerr)
			}
		} else {
			if lerr := manifest.VerifyChainLink(prevWrapper, e-1, man); lerr != nil {
				return Head{}, nil, fmt.Errorf("%w: %s epoch %d: %v", ErrChain, project, e, lerr)
			}
		}
		// (d) her aktif escrow alıcısı her girdinin wrap-set'inde.
		for _, fp := range escrowFps {
			if werr := manifest.CheckEscrowWraps(man, fp); werr != nil {
				return Head{}, nil, fmt.Errorf("%w: %s epoch %d: %v", ErrEscrowWrap, project, e, werr)
			}
		}
		// (b) her blob hash içerik-adresine + manifest bağına karşı.
		if berr := verifyBlobs(ctx, r, project, man); berr != nil {
			return Head{}, nil, berr
		}
		h := manifest.ManifestObjectHash(raw)
		prevWrapper = raw
		headEpoch = e
		headHash = h
		headWrapper = raw
		headMan = man
		chainHashes[e] = h
	}
	if headEpoch == 0 {
		return Head{}, nil, fmt.Errorf("witness: project %q has no manifests in escrow", project)
	}

	// (g) escrow-canary YAPISAL varlığı (head manifest'te). Byte-compare + DECRYPT
	// escrow.go VerifyCanary / DR seremonisidir.
	if requireCanary && !hasCanaryEntry(headMan) {
		return Head{}, nil, fmt.Errorf("%w: %s head manifest lacks a %s entry", ErrCanaryForged, project, CANARY_KEY)
	}

	// (f) pointer-event density/consistency — MANİFEST zinciri head'i otoritatif;
	// pointer-event'ler bağımsız çapraz kontrol. Write-through backlog trailing
	// boşluğu tolere edilir; mid-chain delik / tutarsız-present event reddedilir.
	if perr := verifyPointerEvents(ctx, r, project, headEpoch, chainHashes); perr != nil {
		return Head{}, nil, perr
	}
	return Head{Project: project, Epoch: headEpoch, ManifestSha256: headHash}, headWrapper, nil
}

// hasCanaryEntry, manifest'te WAPPS_ESCROW_CANARY girdisi olup olmadığını döner.
func hasCanaryEntry(m *manifest.DataManifest) bool {
	if m == nil {
		return false
	}
	for _, e := range m.Entries {
		if e.KeyName == CANARY_KEY {
			return true
		}
	}
	return false
}

// verifyBlobs, bir manifest'in her benzersiz blob'unu escrow'dan okur ve
// içerik-adresine karşı doğrular (§9.3.2b).
func verifyBlobs(ctx context.Context, r Reader, project string, man *manifest.DataManifest) error {
	seen := map[string]bool{}
	for _, e := range man.Entries {
		if seen[e.BlobHash] {
			continue
		}
		seen[e.BlobHash] = true
		blob, err := r.Get(ctx, keyBlob(project, e.BlobHash))
		if errors.Is(err, ErrNotExist) {
			return fmt.Errorf("%w: %s/%s (key %s)", ErrBlobMissing, project, e.BlobHash, e.KeyName)
		}
		if err != nil {
			return err
		}
		if verr := cryptoid.VerifyBlobHash(blob, e.BlobHash); verr != nil {
			return fmt.Errorf("%w: %s/%s: %v", ErrBlobHash, project, e.BlobHash, verr)
		}
	}
	return nil
}

// pointerEvent, escrow pointer-event objesinin şeklidir (Worker writer-do.ts).
type pointerEvent struct {
	Schema         string `json:"schema"`
	Project        string `json:"project"`
	Epoch          uint64 `json:"epoch"`
	ManifestSha256 string `json:"manifestSha256"`
	CommittedAt    string `json:"committed_at"`
}

// pointerEventBacklogWindow, pointer-event akışının manifest zincir head'inin ne
// kadar GERİSİNDE kalmasına izin verildiğidir (§9.3.2f write-through backlog).
// Escrow drenajı manifest→pointer-event→blob'ları AYRI objeler olarak PUT ettiğinden,
// "manifest N indi ama pointer-event N henüz değil" MEŞRU bir bölünmüş durumdur;
// head zaten manifest zincirinden re-derive edilebilir. KESİNTİSİZ prefix üstünde
// bu kadar epoch'luk TAM BOŞ trailing boşluk tolere edilir; daha fazlası akışın
// tamamen durduğuna işaret eder → reddet. Mid-chain delik her zaman reddedilir.
const pointerEventBacklogWindow uint64 = 8

// verifyPointerEvents, append-only pointer-event akışını doğrular (§9.3.2f).
// MANİFEST zinciri head'i OTORİTATİFTİR (chainHeadEpoch/chainHashes); pointer-event'ler
// bağımsız bir çapraz kontroldür. Semantik:
//   - KESİNTİSİZ prefix [1..contig] içindeki HER pointer-event kendi manifest'iyle
//     tutarlı olmalı (epoch alanı + manifest hash), aksi halde GERÇEK tamper.
//   - contig üstünde PRESENT bir event = MID-CHAIN delik (backlog değil) → reddet.
//   - contig ile chainHeadEpoch arasındaki (bounded) TAM BOŞ trailing boşluk = meşru
//     write-through backlog → tolere edilir (head yine manifest zincirinden gelir).
func verifyPointerEvents(ctx context.Context, r Reader, project string, chainHeadEpoch uint64, chainHashes map[uint64]string) error {
	// (1) epoch 1'den itibaren KESİNTİSİZ pointer-event prefix'ini yürü.
	var contig uint64 // en yüksek kesintisiz pointer-event epoch'u (0 = hiç yok)
	for e := uint64(1); e <= chainHeadEpoch; e++ {
		raw, err := r.Get(ctx, keyPointerEvent(project, e))
		if errors.Is(err, ErrNotExist) {
			break // ilk boşluk → prefix bitti; trailing mi mid-chain mi aşağıda ayrılır.
		}
		if err != nil {
			return err
		}
		var pe pointerEvent
		if jerr := json.Unmarshal(raw, &pe); jerr != nil {
			return fmt.Errorf("%w: %s epoch %d malformed: %v", ErrPointerEvent, project, e, jerr)
		}
		// PRESENT ama TUTARSIZ = gerçek tamper: epoch alanı + manifest hash eşleşmeli.
		if pe.Epoch != e {
			return fmt.Errorf("%w: %s epoch field %d != key %d", ErrPointerEvent, project, pe.Epoch, e)
		}
		if want := chainHashes[e]; pe.ManifestSha256 != want {
			return fmt.Errorf("%w: %s epoch %d pointer-event manifest %s != chain manifest %s",
				ErrPointerEvent, project, e, pe.ManifestSha256, want)
		}
		contig = e
	}
	// (2) contig üstünde HERHANGİ bir pointer-event VARSA = MID-CHAIN delik (gerçek
	// boşluk, backlog değil) → reddet.
	for e := contig + 1; e <= chainHeadEpoch; e++ {
		_, err := r.Get(ctx, keyPointerEvent(project, e))
		if errors.Is(err, ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %s pointer-event present at epoch %d above contiguous head %d (mid-chain gap)",
			ErrPointerEvent, project, e, contig)
	}
	// (3) [1..contig] kesintisiz+tutarlı, (contig..chainHead] TAM boş = write-through
	// backlog trailing boşluğu. Bounded tut: akış tamamen durmuş olmasın.
	if gap := chainHeadEpoch - contig; gap > pointerEventBacklogWindow {
		return fmt.Errorf("%w: %s pointer-event stream lags chain head by %d epoch(s) (> %d backlog window; contiguous head %d, chain head %d)",
			ErrPointerEvent, project, gap, pointerEventBacklogWindow, contig, chainHeadEpoch)
	}
	return nil
}

// auditSegment, escrow audit segment objesinin şeklidir (Worker audit-do.ts).
type auditSegment struct {
	Schema   string `json:"schema"`
	Seq      int    `json:"seq"`
	PrevHash string `json:"prev_hash"`
	RowJSON  string `json:"row_json"`
	Hash     string `json:"hash"`
}

const auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// verifyAuditChain, escrow'daki audit segment zincirinin sürekliliğini doğrular
// (§9.3.2e): hash = hex(SHA-256(prev_hash ‖ 0x0A ‖ row_json)), prev bağları
// sağlam, seq monotonik. Genesis prev = 64 sıfır.
func verifyAuditChain(ctx context.Context, r Reader) error {
	prev := auditGenesisHash
	for seq := 1; ; seq++ {
		raw, err := r.Get(ctx, keyAuditSegment(seq))
		if errors.Is(err, ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		var seg auditSegment
		if jerr := json.Unmarshal(raw, &seg); jerr != nil {
			return fmt.Errorf("%w: segment %d malformed: %v", ErrAuditChain, seq, jerr)
		}
		if seg.Seq != seq {
			return fmt.Errorf("%w: segment seq %d != key %d", ErrAuditChain, seg.Seq, seq)
		}
		if seg.PrevHash != prev {
			return fmt.Errorf("%w: segment %d prev_hash break", ErrAuditChain, seq)
		}
		sum := sha256.Sum256([]byte(seg.PrevHash + "\n" + seg.RowJSON))
		got := hex.EncodeToString(sum[:])
		if got != seg.Hash {
			return fmt.Errorf("%w: segment %d hash mismatch", ErrAuditChain, seq)
		}
		prev = seg.Hash
	}
	return nil
}

// discoverProjects, escrow'daki `secrets/<project>/` öneklerinden proje adlarını çıkarır.
func discoverProjects(ctx context.Context, r Reader) ([]string, error) {
	keys, err := r.List(ctx, "secrets/")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		m := projectRe.FindStringSubmatch(k)
		if m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out, nil
}

// writerKeyring, doğrulanmış trust head'inden data-manifest yazar keyring'ini kurar
// (store.dataWriterKeyring ile AYNI; her aktif kimliğin her aktif imzalama anahtarı).
func writerKeyring(m *trust.TrustManifest) manifest.WriterKeyring {
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
				continue
			}
			ring[vk.KeyID()] = vk
		}
	}
	return ring
}

// escrowFingerprints, aktif escrow enc-key parmak izlerini döner.
func escrowFingerprints(m *trust.TrustManifest) []string {
	var out []string
	for _, id := range m.Identities {
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
			out = append(out, fp)
		}
	}
	sort.Strings(out)
	return out
}
