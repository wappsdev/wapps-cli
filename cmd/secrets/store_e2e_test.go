package secrets

// store_e2e_test.go, backend:store yolunun YAZILIM (CI/test) kimliği için UÇTAN UCA
// round-trippable olduğunu KANITLAR — canlı CF hesabı OLMADAN:
//
//  1. `wapps secrets enroll --software` yerel bir 0600 kimlik yazar (identity.json);
//  2. localDecryptIdentity/localSigningKey onu yükler;
//  3. out-of-band bir oturum token'ı (WAPPS_SESSION_TOKEN) gate'e bearer sunar;
//  4. httptest bir FAKE Worker, o kimliğe SEALED GERÇEK per-key DEK zarfları servis eder
//     (seed = GERÇEK WorkerStore.Commit → gerçek wrap/seal/imza yolu);
//  5. `exec -- <child>` değeri çözer, child env'ine enjekte eder VE stdout'u scrub eder
//     (agent-safety); ayrı bir set→fetch round-trip Commit'i sonra Fetch'in aynı değeri
//     çözdüğünü gösterir.
//
// Bu, "never-trust-Worker" store yolunun uçtan uca çalıştığını kanıtlar. GERÇEK
// interaktif `wapps login` (cloudflared) canlı CF Access hesabı gerektiren TEK insan
// adımıdır ve BİLEREK bir stub olarak kalır — bu test onu out-of-band token ile atlar.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/store"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

const e2eProject = "e2eproj"

var e2eFixedTime = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

// --- enroll yardımcısı (ürün yolu: runEnroll identity.json'ı yazar) ----------

// enrollForTest, enroll flag'lerini ayarlar ve runEnroll'u çağırır (identity.json'ı
// XDG altında yazar). Flag'ler temizlikte geri alınır.
func enrollForTest(t *testing.T, id, typ string, admin bool) {
	t.Helper()
	pID, pType, pDev, pAdmin, pJSON, pSW := enrollID, enrollType, enrollDevice, enrollAdmin, enrollJSON, enrollSoftware
	t.Cleanup(func() {
		enrollID, enrollType, enrollDevice, enrollAdmin, enrollJSON, enrollSoftware = pID, pType, pDev, pAdmin, pJSON, pSW
	})
	enrollID, enrollType, enrollDevice, enrollAdmin, enrollJSON, enrollSoftware = id, typ, "ci-device", admin, false, true
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	require.NoError(t, runEnroll(cmd, nil), "enroll must succeed and persist a software identity")
}

// --- enroll persistence birim testi ------------------------------------------

// TestEnrollPersistsLoadableSoftwareIdentity, enroll'ün yüklenebilir bir YAZILIM
// kimliği (X25519 enc + P-256 daily) yazdığını + backup GİZLİsinin ASLA persist
// edilmediğini + 0600 zorlamasını kanıtlar.
func TestEnrollPersistsLoadableSoftwareIdentity(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")

	enrollForTest(t, "human:alice@example.com", "human", true /*admin*/)

	// identity.json var + 0600.
	p, err := identityPath()
	require.NoError(t, err)
	info, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "identity file must be 0600")

	// enc kimliği yüklenir.
	dev, err := localDecryptIdentity()
	require.NoError(t, err)
	require.NotNil(t, dev, "device enc identity must load")

	// writer (insan daily) yüklenir, P-256'dır ve imzalayabilir.
	wr, err := localSigningKey()
	require.NoError(t, err)
	require.NotNil(t, wr)
	require.Equal(t, cryptoid.AlgECDSAP256SHA256, wr.Alg(), "human daily writer is P-256")
	_, serr := wr.Sign([]byte("proof-of-signing"))
	require.NoError(t, serr)

	// GİZLİ HİJYEN: dosyada TAM BİR AGE-SECRET-KEY olmalı (device enc). Backup GİZLİsi
	// asla yazılmaz (yalnızca public backup_recipient). Yazar gizli materyali base64'tür.
	raw, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(raw), "AGE-SECRET-KEY"),
		"only the device enc secret may be persisted; the backup secret must never be written")
	require.Contains(t, string(raw), "backup_recipient", "the PUBLIC backup recipient is fine to persist")

	// 0600'den gevşek izin → yükleyici NET reddeder (sessiz absent DEĞİL).
	require.NoError(t, os.Chmod(p, 0o644))
	_, lerr := localDecryptIdentity()
	require.Error(t, lerr, "loose perms must be rejected, not treated as absent")
}

// --- E2E round-trip: fake Worker + enrolled software identity ----------------

// storeE2E, uçtan-uca bir test dünyasıdır: enrolled makine kimliği + o kimliğe grant'lı
// doğrulanabilir trust genesis + fake Worker + yazılmış pin'ler + oturum token'ı + cwd.
type storeE2E struct {
	worker     *e2eWorker
	dev        *cryptoid.X25519Identity
	writer     cryptoid.SigningKey
	id         string
	genesisPin trust.Pin
	receiptKey *cryptoid.ECDSAP256SigningKey
}

// setupStoreE2E, bir E2E dünyasını kurar. keys, makinenin okuma+yazma allowlist'idir
// (makineler joker "*" grant TAŞIYAMAZ, §4.3 → açık liste).
func setupStoreE2E(t *testing.T, keys []string) *storeE2E {
	t.Helper()
	// İzole XDG: enroll + pin'ler buraya yazılır; store yolu (openWorkerStore) da
	// buradan okur (default pin/cache/epoch yolları XDG onurlandırır).
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// 1) enroll (ürün yolu) → identity.json.
	enrollForTest(t, "machine:ci-runner", "machine", false)
	dev, err := localDecryptIdentity()
	require.NoError(t, err)
	require.NotNil(t, dev)
	writer, err := localSigningKey()
	require.NoError(t, err)
	require.NotNil(t, writer)
	require.Equal(t, cryptoid.AlgEd25519, writer.Alg(), "machine automation writer is Ed25519")
	id := "machine:ci-runner"

	// 2) enrolled kimliği içeren doğrulanabilir trust genesis kur (roster: makine device
	//    enc + automation signing; grant read + writer_allowlist AÇIK anahtarlarla).
	root1, root2, root3 := edSeed(t, 1), edSeed(t, 2), edSeed(t, 3)
	receiptKey, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)

	rotateBy := e2eFixedTime.Add(90 * 24 * time.Hour)
	machine := registry.Identity{
		ID:         id,
		Type:       registry.TypeMachine,
		Status:     registry.StatusActive,
		EnrolledAt: e2eFixedTime,
		RotateBy:   &rotateBy, // makine ZORUNLU (§4.3)
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(dev.Recipient(), registry.EncClassDevice, "software", 1),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(writer, registry.SignClassAutomation, "software"),
		},
	}
	tm := &trust.TrustManifest{
		Schema:        trust.SchemaTrust,
		AdminEpoch:    1,
		CreatedAt:     e2eFixedTime,
		ChangeClass:   trust.ChangeRoster,
		BootstrapSolo: false, // 3 ayrı holder → maxHolderShare 1 < M 2
		Quorum:        trust.Quorum{M: 2, N: 3},
		Roots: []trust.RootKey{
			trust.NewRootKey(root1, "yubikey-piv", "human:a"),
			trust.NewRootKey(root2, "yubikey-piv", "human:b"),
			trust.NewRootKey(root3, "yubikey-piv", "human:c"),
		},
		Identities: []registry.Identity{machine},
		Grants: []registry.Grant{
			{Principal: id, Project: e2eProject, Verbs: []string{"read", "exec", "apply", "env", "get"}, Keys: keys},
		},
		WriterAllowlists: []registry.WriterAllow{
			{Principal: id, Project: e2eProject, Keys: keys},
		},
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: receiptJWK(t, receiptKey)},
	}
	// Roster spec-geçerli olmalı (makine RotateBy + açık-anahtar allowlist).
	require.NoError(t, tm.Registry().Validate(), "e2e roster must be spec-valid")

	obj, _, err := trust.SignTrustManifest(tm, root1, root2) // ≥M=2 kök imzası
	require.NoError(t, err)
	genesisPin := trust.Pin{AdminEpoch: 1, SHA256: trust.TrustObjectHash(obj.Bytes)}
	_, verr := trust.VerifyRosterChain(genesisPin, genesisPin, obj)
	require.NoError(t, verr, "e2e trust genesis must verify")

	// 3) pin store (XDG/wapps/roots.json) — hem seed hem exec buradan okur.
	pinPath, err := trust.DefaultPinPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(pinPath), 0o700))
	require.NoError(t, trust.NewPinStore(genesisPin).Save(pinPath))

	// 4) fake Worker + trust zinciri.
	fw := newE2EWorker(t, receiptKey)
	trustWrapper, err := json.Marshal(obj)
	require.NoError(t, err)
	fw.trust[1] = trustWrapper
	cur, err := json.Marshal(map[string]any{"admin_epoch": 1, "trustSha256": genesisPin.SHA256})
	require.NoError(t, err)
	fw.trustCurrent = cur

	// 5) çevre: gate URL + out-of-band oturum bearer (canlı CF login YOK).
	t.Setenv("WAPPS_SECRETS_GATE", fw.srv.URL)
	t.Setenv("WAPPS_SESSION_TOKEN", "ci-out-of-band-bearer")

	// 6) cwd + backend:store .wapps.yaml.
	work := t.TempDir()
	t.Chdir(work)
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })
	yaml := "version: 2\nbackend: store\nproject: " + e2eProject + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(work, ".wapps.yaml"), []byte(yaml), 0o644))

	return &storeE2E{worker: fw, dev: dev, writer: writer, id: id, genesisPin: genesisPin, receiptKey: receiptKey}
}

// seedViaCommit, GERÇEK WorkerStore.Commit ile verilen değerleri seed'ler (gerçek
// DEK üretimi + enrolled device'a wrap/seal + imza). Seed'in cache/epoch'u AYRIDIR ki
// exec TEMİZ bir online 200 fetch + tam yazar-yetkisi doğrulaması yapsın.
func (h *storeE2E) seedViaCommit(t *testing.T, sets map[string][]byte) {
	t.Helper()
	seed := store.New(store.Config{
		BaseURL:      h.worker.srv.URL,
		Doer:         h.worker.srv.Client(),
		CacheDir:     t.TempDir(),
		EpochPinPath: filepath.Join(t.TempDir(), "epochs.json"),
		Witness:      intent.NoWitness{},
		Now:          func() time.Time { return e2eFixedTime },
		// PinPath boş → XDG default (genesis pin'i buraya yazdık).
	})
	_, err := seed.Commit(context.Background(), e2eProject, store.ManifestDelta{
		Sets:     sets,
		Writer:   h.writer,
		WriterID: h.id,
		Intent:   intent.Dev,
	})
	require.NoError(t, err, "seed commit must succeed (real wrap/seal/sign path)")
}

// TestStore_E2E_ExecInjectsAndScrubs, TAM store yolunu sürer: enrolled kimlikle çöz,
// child env'ine enjekte et (dosyaya yazılan düz metinle KANITLA) ve child stdout'unu
// *** ile scrub et (transcript'e sızmaz). Bu, never-trust-Worker store yolunun
// agent-safe uçtan uca çalıştığının kanıtıdır.
func TestStore_E2E_ExecInjectsAndScrubs(t *testing.T) {
	const secretVal = "postgres://ci:sup3r-s3cr3t-p4ss@db.internal:5432/app"
	h := setupStoreE2E(t, []string{"DBURL"})
	h.seedViaCommit(t, map[string][]byte{"DBURL": []byte(secretVal)})

	// Child, enjekte edilen değeri (a) bir dosyaya (scrubber'ı BYPASS eder → düz metin
	// enjeksiyonu kanıtlar) ve (b) stdout'a (scrubber tarafından *** yapılır) yazar.
	captureFile := filepath.Join(t.TempDir(), "captured.txt")
	t.Setenv("CAPTURE_FILE", captureFile)
	script := `printenv TF_VAR_DBURL > "$CAPTURE_FILE"; printenv TF_VAR_DBURL`

	var stdout bytes.Buffer
	err := runExec([]string{"sh", "-c", script}, "TF_VAR_", "dev",
		false /*breakGlass*/, false /*isAgent*/, &stdout, io.Discard, defaultExecRunner)
	require.NoError(t, err, "store exec must run the child with decrypted env")

	// Enjeksiyon kanıtı: child, düz metin değeri env'inde GÖRDÜ (dosyaya yazdı).
	captured, err := os.ReadFile(captureFile)
	require.NoError(t, err)
	require.Equal(t, secretVal, strings.TrimRight(string(captured), "\n"),
		"child must see the DECRYPTED value in its env")

	// Scrub kanıtı: child stdout'una echo'ladığı değer transcript'te *** olur.
	require.Contains(t, stdout.String(), "***", "child output must be scrubbed to ***")
	require.NotContains(t, stdout.String(), secretVal, "the plaintext value must never reach the captured stdout")
}

// TestStore_E2E_SetThenGetRoundtrip, set→fetch round-trip'i kanıtlar: runSet GERÇEK
// Commit (enrolled writer imzası) yapar; runGet Fetch AYNI değeri çözer.
func TestStore_E2E_SetThenGetRoundtrip(t *testing.T) {
	const secretVal = "topsecret-api-token-9f3a2b"
	h := setupStoreE2E(t, []string{"API_TOKEN"})
	_ = h // worker + kimlik setup'ta kuruldu; runSet/runGet default openWorkerStore'u sürer

	valFile := filepath.Join(t.TempDir(), "val")
	require.NoError(t, os.WriteFile(valFile, []byte(secretVal+"\n"), 0o600))

	// set → GERÇEK Commit (localSigningKey writer'ı imzalar).
	require.NoError(t, runSet("API_TOKEN", setOptions{fromFile: valFile}),
		"store set must commit through the enrolled writer")

	// get → Fetch + enrolled device ile çözme; AYNI değer.
	var out bytes.Buffer
	require.NoError(t, runGet("API_TOKEN", &out), "store get must fetch + decrypt")
	require.Equal(t, secretVal, strings.TrimSpace(out.String()),
		"fetch must decrypt the exact value that was committed (never-trust-Worker round-trip)")
}

// --- fake Worker (secrets-gate HTTP sözleşmesinin kompakt, durumlu taklidi) ----
//
// GERÇEK Worker'ın route/ETag/CAS sözleşmesinin İSTEMCİ doğrulama boru hattını süren
// asgari bir taklidi (internal/store fake-Worker harness DESENİNİ yeniden kullanır).
// Auth/authz + blob-varlık kontrolü (gerçek Worker'da var) İSTEMCİ testi kapsamı dışı
// olduğu için kasıtlı atlanır — bu taklit istemcinin never-trust doğrulamasını sürer.
type e2eWorker struct {
	srv *httptest.Server
	mu  sync.Mutex

	trust        map[uint64][]byte
	trustCurrent []byte

	projManifests map[uint64][]byte
	projCurrent   []byte
	blobs         map[string][]byte

	receiptKey *cryptoid.ECDSAP256SigningKey
	clock      time.Time
}

func newE2EWorker(t *testing.T, receiptKey *cryptoid.ECDSAP256SigningKey) *e2eWorker {
	t.Helper()
	fw := &e2eWorker{
		trust:         map[uint64][]byte{},
		projManifests: map[uint64][]byte{},
		blobs:         map[string][]byte{},
		receiptKey:    receiptKey,
		clock:         e2eFixedTime,
	}
	fw.srv = httptest.NewServer(http.HandlerFunc(fw.handle))
	t.Cleanup(fw.srv.Close)
	return fw
}

func (fw *e2eWorker) handle(w http.ResponseWriter, r *http.Request) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "v1" {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}

	// /v1/trust/current | /v1/trust/{epoch}
	if parts[1] == "trust" && len(parts) == 3 && r.Method == http.MethodGet {
		if parts[2] == "current" {
			e2eEtagResp(w, r, fw.trustCurrent, e2eSHA(fw.trustCurrent))
			return
		}
		body, ok := fw.trust[e2eParseEpoch(parts[2])]
		if !ok {
			http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
			return
		}
		e2eEtagResp(w, r, body, e2eSHA(body))
		return
	}

	// /v1/projects/{project}/...
	if parts[1] == "projects" && len(parts) >= 4 {
		if parts[2] != e2eProject {
			http.Error(w, `{"error":"PROJECT_MISMATCH"}`, http.StatusUnprocessableEntity)
			return
		}
		switch kind := parts[3]; {
		case kind == "manifests" && r.Method == http.MethodGet:
			fw.handleManifestGet(w, r, parts)
			return
		case kind == "blobs" && len(parts) == 5 && r.Method == http.MethodGet:
			body, ok := fw.blobs[parts[4]]
			if !ok {
				http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
				return
			}
			e2eEtagResp(w, r, body, parts[4])
			return
		case kind == "blobs" && len(parts) == 5 && r.Method == http.MethodPut:
			body := e2eReadAll(r)
			if e2eSHA(body) != parts[4] {
				http.Error(w, `{"error":"BLOB_HASH_MISMATCH"}`, http.StatusBadRequest)
				return
			}
			fw.blobs[parts[4]] = body
			_, _ = fmt.Fprintf(w, `{"sha256":%q}`, parts[4])
			return
		case kind == "commit" && r.Method == http.MethodPost:
			fw.handleCommit(w, r)
			return
		case kind == "receipt" && r.Method == http.MethodGet:
			epoch, hash := fw.currentEpochHash()
			if epoch == 0 {
				http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
				return
			}
			rec := fw.issueReceipt(hash, epoch)
			_ = json.NewEncoder(w).Encode(rec)
			return
		}
	}
	http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
}

func (fw *e2eWorker) handleManifestGet(w http.ResponseWriter, r *http.Request, parts []string) {
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
		e2eEtagResp(w, r, fw.projManifests[ptr.Epoch], ptr.ManifestSha256)
		return
	}
	body, ok := fw.projManifests[e2eParseEpoch(sel)]
	if !ok {
		http.Error(w, `{"error":"NOT_FOUND"}`, http.StatusNotFound)
		return
	}
	e2eEtagResp(w, r, body, e2eSHA(body))
}

func (fw *e2eWorker) currentEpochHash() (uint64, string) {
	if len(fw.projCurrent) == 0 {
		return 0, ""
	}
	ptr, err := manifest.ParseCurrentPointer(fw.projCurrent)
	if err != nil {
		return 0, ""
	}
	return ptr.Epoch, ptr.ManifestSha256
}

func (fw *e2eWorker) installCurrent(epoch uint64, wrapper []byte) {
	fw.projManifests[epoch] = wrapper
	ptr := manifest.NewCurrentPointer(e2eProject, epoch, wrapper)
	b, _ := ptr.Marshal()
	fw.projCurrent = b
}

func (fw *e2eWorker) handleCommit(w http.ResponseWriter, r *http.Request) {
	body := e2eReadAll(r)
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
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = fmt.Fprintf(w, `{"error":"EPOCH_CONFLICT","current_epoch":%d,"current_manifest_sha256":%q}`, curEpoch, curHash)
		return
	}
	fw.installCurrent(m.Epoch, body)
	newHash := manifest.ManifestObjectHash(body)
	rec := fw.issueReceipt(newHash, m.Epoch)
	out, _ := json.Marshal(map[string]any{"epoch": m.Epoch, "manifestSha256": newHash, "receipt": rec})
	_, _ = w.Write(out)
}

func (fw *e2eWorker) issueReceipt(manifestSha string, epoch uint64) intent.Receipt {
	payload, _ := json.Marshal(map[string]any{
		"schema": intent.ReceiptSchema, "manifestSha256": manifestSha, "epoch": epoch, "iat": fw.clock.Unix(),
	})
	sig, _ := fw.receiptKey.Sign(payload)
	return intent.Receipt{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Kid:     "att-1",
		Sig:     base64.StdEncoding.EncodeToString(sig.Sig),
	}
}

// --- küçük test yardımcıları -------------------------------------------------

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

func receiptJWK(t *testing.T, k *cryptoid.ECDSAP256SigningKey) json.RawMessage {
	t.Helper()
	pub := k.PublicKeyBytes() // 65B SEC1 0x04||X||Y
	require.Len(t, pub, 65)
	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:65])
	return json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, x, y))
}

func e2eSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func e2eTrimETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func e2eEtagResp(w http.ResponseWriter, r *http.Request, body []byte, etag string) {
	if inm := e2eTrimETag(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
		w.Header().Set("ETag", `"`+etag+`"`)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func e2eReadAll(r *http.Request) []byte {
	defer func() { _ = r.Body.Close() }()
	out, _ := io.ReadAll(r.Body)
	return out
}

// e2eParseEpoch, bir epoch segmentini uint64'e çözer (hatalı → 0, çağıran 404'e düşer).
func e2eParseEpoch(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}
