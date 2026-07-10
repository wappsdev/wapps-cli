package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

const testProject = "testproj"

var fixTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// --- İnsan + escrow kimlik fixture'ları -------------------------------------

type human struct {
	id     string
	daily  *cryptoid.ECDSAP256SigningKey
	admin  *cryptoid.ECDSAP256SigningKey
	device *cryptoid.X25519Identity
	backup *cryptoid.X25519Identity
}

func newHuman(t *testing.T, email string) human {
	t.Helper()
	daily, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	admin, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	backup, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	return human{id: "human:" + email, daily: daily, admin: admin, device: device, backup: backup}
}

func (h human) identity() registry.Identity {
	return registry.Identity{
		ID:         h.id,
		Type:       registry.TypeHuman,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(h.device.Recipient(), registry.EncClassDevice, "software", 1),
			registry.NewEncKeyEntry(h.backup.Recipient(), registry.EncClassBackup, "paper-steel", 1),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(h.admin, registry.SignClassAdmin, "software"),
			registry.NewSigningKeyEntry(h.daily, registry.SignClassDaily, "software"),
		},
	}
}

func escrowIdentity(t *testing.T) (registry.Identity, *cryptoid.X25519Identity) {
	t.Helper()
	esc, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	id := registry.Identity{
		ID:         "escrow:vault",
		Type:       registry.TypeEscrow,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(esc.Recipient(), registry.EncClassBackup, "paper-steel", 1),
		},
	}
	return id, esc
}

func edFromSeed(t *testing.T, b byte) *cryptoid.Ed25519SigningKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := cryptoid.NewEd25519FromSeed(seed)
	require.NoError(t, err)
	return k
}

// receiptJWKOf, bir P-256 anahtarından ES256 JWK ({kty,crv,x,y}) üretir.
func receiptJWKOf(t *testing.T, k *cryptoid.ECDSAP256SigningKey) json.RawMessage {
	t.Helper()
	pub := k.PublicKeyBytes() // 65B SEC1 0x04||X||Y
	require.Len(t, pub, 65)
	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:65])
	return json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, x, y))
}

// fixture, tam bir test dünyası kurar: doğrulanabilir trust genesis + fakeWorker.
type fixture struct {
	server     *fakeWorker
	human      human
	escrow     *cryptoid.X25519Identity
	genesisPin trust.Pin
	receiptKey *cryptoid.ECDSAP256SigningKey
	// limitedWriter, roster'da yalnızca "B" anahtarı için writer_allowlist'e sahip
	// bir otomasyon (machine:limited) yazarıdır — yazar-yetkisi taşma testi için.
	limitedWriter *cryptoid.Ed25519SigningKey
	dirCache      string // paylaşılan pin/cache/epoch dizini (offline testleri için)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	h := newHuman(t, "adnan@example.com")
	escID, escIdentity := escrowIdentity(t)

	root1 := edFromSeed(t, 1)
	root2 := edFromSeed(t, 2)
	root3 := edFromSeed(t, 3)

	receiptKey, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)

	// Sınırlı otomasyon yazarı: writer_allowlist YALNIZCA "B"; başka anahtarlara
	// yazmaya yetkisi yok (yazar-yetkisi taşma testi için).
	limitedWriter := edFromSeed(t, 9)
	limitedMachine := registry.Identity{
		ID:         "machine:limited",
		Type:       registry.TypeMachine,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(limitedWriter, registry.SignClassAutomation, "software"),
		},
	}

	tm := &trust.TrustManifest{
		Schema:          trust.SchemaTrust,
		AdminEpoch:      1,
		PrevTrustSHA256: "",
		CreatedAt:       fixTime,
		ChangeClass:     trust.ChangeRoster,
		BootstrapSolo:   false, // 3 ayrı holder → maxHolderShare 1 < M 2
		Quorum:          trust.Quorum{M: 2, N: 3},
		Roots: []trust.RootKey{
			trust.NewRootKey(root1, "yubikey-piv", "human:a"),
			trust.NewRootKey(root2, "yubikey-piv", "human:b"),
			trust.NewRootKey(root3, "yubikey-piv", "human:c"),
		},
		Admins:     []string{h.id},
		Identities: []registry.Identity{h.identity(), escID, limitedMachine},
		Grants: []registry.Grant{
			{Principal: h.id, Project: testProject, Verbs: []string{"read", "write", "set", "exec", "apply"}, Keys: []string{"*"}},
		},
		WriterAllowlists: []registry.WriterAllow{
			{Principal: limitedMachine.ID, Project: testProject, Keys: []string{"B"}},
		},
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: receiptJWKOf(t, receiptKey)},
	}
	// ≥M=2 kök imzasıyla imzala.
	obj, _, err := trust.SignTrustManifest(tm, root1, root2)
	require.NoError(t, err)
	genesisPin := trust.Pin{AdminEpoch: 1, SHA256: trust.TrustObjectHash(obj.Bytes)}

	// Doğrulanabilirlik kontrolü (fixture'ın kendisi geçerli olsun).
	_, verr := trust.VerifyRosterChain(genesisPin, genesisPin, obj)
	require.NoError(t, verr, "fixture trust genesis must verify")

	trustWrapper, err := json.Marshal(obj)
	require.NoError(t, err)

	fw := newFakeWorker(t, receiptKey)
	fw.trustManifests[1] = trustWrapper
	cur, _ := json.Marshal(map[string]any{"admin_epoch": 1, "trustSha256": genesisPin.SHA256})
	fw.trustCurrent = cur

	return &fixture{server: fw, human: h, escrow: escIdentity, genesisPin: genesisPin, receiptKey: receiptKey, limitedWriter: limitedWriter}
}

// writeDelta, bir set delta'sı kurar (dev intent).
func (f *fixture) delta(sets map[string][]byte) ManifestDelta {
	return ManifestDelta{
		Sets:       sets,
		Writer:     f.human.daily,
		WriterID:   f.human.id,
		SelfDevice: f.human.device,
		Intent:     intent.Dev,
	}
}

// --- fakeWorker: secrets-gate Worker sözleşmesinin durumlu bir taklidi --------
//
// GERÇEK Worker'ın (worker/src/index.ts) route/header/status-code sözleşmesini
// uygular: conditional GET (ETag/304), içerik-adresli blob PUT/GET, epoch+1 CAS
// commit (412 EPOCH_CONFLICT), liveness receipt. Auth/authz + blob-varlık
// doğrulaması (gerçek Worker'da var) İSTEMCİ testinin kapsamı dışı olduğu için
// burada kasıtlı olarak atlanır — bu taklit İSTEMCİ doğrulama boru hattını sürer.
type fakeWorker struct {
	srv *httptest.Server
	mu  sync.Mutex

	trustManifests map[uint64][]byte
	trustCurrent   []byte

	projManifests map[uint64][]byte
	projCurrent   []byte // CurrentPointer JSON, boşsa henüz current yok
	blobs         map[string][]byte

	receiptKey *cryptoid.ECDSAP256SigningKey

	// injectQueue, bir sonraki commit CAS'ından ÖNCE current'a kurulacak
	// "kazanan" manifest'lerdir (yarış simülasyonu).
	injectQueue [][]byte

	// receiptIAT, verilecek receipt'in iat'ı (0 → time now). Bayat-receipt testi için.
	receiptIAT int64

	// commitEpochOverride, >0 ise commit yanıtındaki "epoch" alanını bu değerle
	// değiştirir (yalan söyleyen Worker simülasyonu — P2-a epoch-echo tampering).
	commitEpochOverride uint64

	// sayaçlar.
	notModified int
	blobGets    int

	clock time.Time
}

func newFakeWorker(t *testing.T, receiptKey *cryptoid.ECDSAP256SigningKey) *fakeWorker {
	t.Helper()
	fw := &fakeWorker{
		trustManifests: map[uint64][]byte{},
		projManifests:  map[uint64][]byte{},
		blobs:          map[string][]byte{},
		receiptKey:     receiptKey,
		clock:          fixTime,
	}
	fw.srv = httptest.NewServer(http.HandlerFunc(fw.handle))
	t.Cleanup(fw.srv.Close)
	return fw
}

func (fw *fakeWorker) now() time.Time { return fw.clock }

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func etagResp(w http.ResponseWriter, r *http.Request, body []byte, etag, contentType string) {
	inm := trimETag(r.Header.Get("If-None-Match"))
	if inm != "" && inm == etag {
		w.Header().Set("ETag", `"`+etag+`"`)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (fw *fakeWorker) handle(w http.ResponseWriter, r *http.Request) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /v1/...
	if len(parts) < 2 || parts[0] != "v1" {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}

	// /v1/trust/current | /v1/trust/{epoch}
	if parts[1] == "trust" && len(parts) == 3 && r.Method == http.MethodGet {
		if parts[2] == "current" {
			etagResp(w, r, fw.trustCurrent, sha256Hex(fw.trustCurrent), "application/json")
			return
		}
		var e uint64
		fmt.Sscanf(parts[2], "%d", &e)
		body, ok := fw.trustManifests[e]
		if !ok {
			http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
			return
		}
		etagResp(w, r, body, sha256Hex(body), "application/json")
		return
	}

	// /v1/projects/{project}/...
	if parts[1] == "projects" && len(parts) >= 4 {
		project := parts[2]
		if project != testProject {
			http.Error(w, `{"error":"PROJECT_MISMATCH"}`, http.StatusUnprocessableEntity)
			return
		}
		kind := parts[3]
		switch {
		case kind == "manifests" && r.Method == http.MethodGet:
			fw.handleManifestGet(w, r, parts)
			return
		case kind == "blobs" && len(parts) == 5 && r.Method == http.MethodGet:
			fw.handleBlobGet(w, r, parts[4])
			return
		case kind == "blobs" && len(parts) == 5 && r.Method == http.MethodPut:
			fw.handleBlobPut(w, r, parts[4])
			return
		case kind == "commit" && r.Method == http.MethodPost:
			fw.handleCommit(w, r)
			return
		case kind == "receipt" && r.Method == http.MethodGet:
			fw.handleReceipt(w, r)
			return
		}
	}
	http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
}

func (fw *fakeWorker) handleManifestGet(w http.ResponseWriter, r *http.Request, parts []string) {
	sel := ""
	if len(parts) >= 5 {
		sel = parts[4]
	}
	if sel == "current" || sel == "" {
		if len(fw.projCurrent) == 0 {
			http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
			return
		}
		ptr, err := manifest.ParseCurrentPointer(fw.projCurrent)
		if err != nil {
			http.Error(w, `{"error":"SERVICE_MISCONFIGURED"}`, http.StatusServiceUnavailable)
			return
		}
		body := fw.projManifests[ptr.Epoch]
		// ETag = manifest obje hash'i (pointer'daki).
		inm := trimETag(r.Header.Get("If-None-Match"))
		if inm != "" && inm == ptr.ManifestSha256 {
			fw.notModified++
			w.Header().Set("ETag", `"`+ptr.ManifestSha256+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		etagResp(w, r, body, ptr.ManifestSha256, "application/json")
		return
	}
	var e uint64
	fmt.Sscanf(sel, "%d", &e)
	body, ok := fw.projManifests[e]
	if !ok {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}
	etagResp(w, r, body, sha256Hex(body), "application/json")
}

func (fw *fakeWorker) handleBlobGet(w http.ResponseWriter, r *http.Request, sha string) {
	body, ok := fw.blobs[sha]
	if !ok {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}
	fw.blobGets++
	etagResp(w, r, body, sha, "application/octet-stream")
}

func (fw *fakeWorker) handleBlobPut(w http.ResponseWriter, r *http.Request, sha string) {
	body := readAll(r)
	got := sha256Hex(body)
	if got != sha {
		http.Error(w, `{"error":"BLOB_HASH_MISMATCH"}`, http.StatusBadRequest)
		return
	}
	fw.blobs[sha] = body
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"sha256":%q}`, sha)
}

func (fw *fakeWorker) currentEpochHash() (uint64, string) {
	if len(fw.projCurrent) == 0 {
		return 0, ""
	}
	ptr, err := manifest.ParseCurrentPointer(fw.projCurrent)
	if err != nil {
		return 0, ""
	}
	return ptr.Epoch, ptr.ManifestSha256
}

func (fw *fakeWorker) installCurrent(epoch uint64, wrapper []byte) {
	fw.projManifests[epoch] = wrapper
	ptr := manifest.NewCurrentPointer(testProject, epoch, wrapper)
	b, _ := ptr.Marshal()
	fw.projCurrent = b
}

func (fw *fakeWorker) handleCommit(w http.ResponseWriter, r *http.Request) {
	body := readAll(r)

	// Yarış simülasyonu: kuyrukta bir kazanan varsa CAS'tan ÖNCE current'a kur.
	if len(fw.injectQueue) > 0 {
		winner := fw.injectQueue[0]
		fw.injectQueue = fw.injectQueue[1:]
		obj, _ := manifest.ParseSignedObject(winner)
		m, _ := manifest.ParseManifestBody(obj.Bytes)
		fw.installCurrent(m.Epoch, winner)
	}

	obj, err := manifest.ParseSignedObject(body)
	if err != nil {
		http.Error(w, `{"error":"MANIFEST_MALFORMED"}`, http.StatusUnprocessableEntity)
		return
	}
	m, err := manifest.ParseManifestBody(obj.Bytes)
	if err != nil {
		http.Error(w, `{"error":"MANIFEST_MALFORMED"}`, http.StatusUnprocessableEntity)
		return
	}
	curEpoch, curHash := fw.currentEpochHash()
	ok := false
	if curEpoch == 0 {
		ok = m.Epoch == 1 && m.PrevManifestSha256 == ""
	} else {
		ok = m.Epoch == curEpoch+1 && m.PrevManifestSha256 == curHash
	}
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = fmt.Fprintf(w, `{"error":"EPOCH_CONFLICT","current_epoch":%d,"current_manifest_sha256":%q}`, curEpoch, curHash)
		return
	}
	fw.installCurrent(m.Epoch, body)
	newHash := manifest.ManifestObjectHash(body)
	rec := fw.issueReceipt(newHash, m.Epoch)
	respEpoch := m.Epoch
	if fw.commitEpochOverride != 0 {
		respEpoch = fw.commitEpochOverride // yalan Worker: şişirilmiş epoch echo'su
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(map[string]any{"epoch": respEpoch, "manifestSha256": newHash, "receipt": rec})
	_, _ = w.Write(out)
}

func (fw *fakeWorker) handleReceipt(w http.ResponseWriter, r *http.Request) {
	curEpoch, curHash := fw.currentEpochHash()
	if curEpoch == 0 {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}
	rec := fw.issueReceipt(curHash, curEpoch)
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(rec)
	_, _ = w.Write(out)
}

// issueReceipt, liveness receipt'i ES256 receipt anahtarıyla imzalar (§6.6).
func (fw *fakeWorker) issueReceipt(manifestSha string, epoch uint64) intent.Receipt {
	iat := fw.clock.Unix()
	if fw.receiptIAT != 0 {
		iat = fw.receiptIAT
	}
	payload, _ := json.Marshal(map[string]any{
		"schema": intent.ReceiptSchema, "manifestSha256": manifestSha, "epoch": epoch, "iat": iat,
	})
	sig, _ := fw.receiptKey.Sign(payload)
	return intent.Receipt{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Kid:     "att-1",
		Sig:     base64.StdEncoding.EncodeToString(sig.Sig),
	}
}

func readAll(r *http.Request) []byte {
	defer r.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	var out []byte
	for {
		n, err := r.Body.Read(b)
		if n > 0 {
			out = append(out, b[:n]...)
		}
		if err != nil {
			break
		}
	}
	_ = buf
	return out
}
