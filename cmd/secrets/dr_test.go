package secrets

// dr verify + dr restore uçtan-uca testleri (SPEC §8.4): sentetik bir B2
// snapshot'ı (current → manifest → blob zinciri, WKW1 wrap'li) + 2-of-3 Shamir
// payı → 0600 env dosyası. Değerler asla stdout'a yazılmaz.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// buildSnapshot, tek projeli bir v2 replika snapshot'ı üretir; master'ı döner.
func buildSnapshot(t *testing.T, dir, project string, values map[string]string) []byte {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	kid, err := cryptoid.KekKid(master)
	if err != nil {
		t.Fatal(err)
	}

	blobDir := filepath.Join(dir, "secrets", project, "blobs")
	manDir := filepath.Join(dir, "secrets", project, "manifests")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(manDir, 0o755); err != nil {
		t.Fatal(err)
	}

	entries := []map[string]any{}
	for k, v := range values {
		slot := cryptoid.Slot{Project: project, KeyName: k, KeyVersion: 1}
		dek, err := cryptoid.NewDEK()
		if err != nil {
			t.Fatal(err)
		}
		blob, err := cryptoid.SealBlob([]byte(v), dek, slot)
		if err != nil {
			t.Fatal(err)
		}
		hash := cryptoid.BlobHash(blob)
		if err := os.WriteFile(filepath.Join(blobDir, hash), blob, 0o644); err != nil {
			t.Fatal(err)
		}
		wrap, err := cryptoid.WrapDEKForKEK(master, project, slot, dek, nil)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]any{
			"keyName": k, "keyVersion": 1, "blobHash": hash,
			"wrap": map[string]any{"recipient": cryptoid.WrapRecipient, "kid": kid, "wrap": base64.StdEncoding.EncodeToString(wrap)},
		})
	}
	man := map[string]any{
		"schema": "wapps-secrets/data-manifest/v2", "project": project, "epoch": 1,
		"prevManifestSha256": "", "policyVersion": 1, "writer": "human:test",
		"createdAt": "2026-07-11T00:00:00Z", "entries": entries,
	}
	manBytes, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manDir, "1.json"), manBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manBytes)
	ptr := map[string]any{"schema": "wapps-secrets/current/v1", "project": project, "epoch": 1, "manifestSha256": hex.EncodeToString(sum[:])}
	ptrBytes, _ := json.Marshal(ptr)
	if err := os.WriteFile(filepath.Join(dir, "secrets", project, "current"), ptrBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return master
}

func TestDrVerify_SnapshotChain(t *testing.T) {
	dir := t.TempDir()
	buildSnapshot(t, dir, "vaulter", map[string]string{"DB_URL": "postgres://x", "API_KEY": "k"})

	drSnapshotDir = dir
	t.Cleanup(func() { drSnapshotDir = "" })
	out := new(bytes.Buffer)
	drVerifyCmd.SetOut(out)
	if err := runDrVerify(drVerifyCmd, nil); err != nil {
		t.Fatalf("dr verify: %v", err)
	}
	if !strings.Contains(out.String(), "vaulter") || !strings.Contains(out.String(), "keys=2") {
		t.Errorf("verify output: %q", out.String())
	}

	// Tamper: blob baytlarını boz → içerik-adres uyuşmazlığı fail-closed.
	blobDir := filepath.Join(dir, "secrets", "vaulter", "blobs")
	des, _ := os.ReadDir(blobDir)
	p := filepath.Join(blobDir, des[0].Name())
	raw, _ := os.ReadFile(p)
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(p, raw, 0o644)
	if err := runDrVerify(drVerifyCmd, nil); err == nil {
		t.Fatal("tampered blob must fail dr verify")
	}
}

func TestDrRestore_SharesToEnvFile(t *testing.T) {
	dir := t.TempDir()
	master := buildSnapshot(t, dir, "vaulter", map[string]string{
		"DB_URL":  "postgres://user:pw@host/db",
		"API_KEY": "sk-123",
	})

	shares, err := cryptoid.ShamirSplit(master, 3, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shareDir := t.TempDir()
	var sharePaths []string
	for i, s := range shares[:2] {
		p := filepath.Join(shareDir, fmt.Sprintf("share%d.hex", i))
		if err := os.WriteFile(p, []byte(hex.EncodeToString(s)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sharePaths = append(sharePaths, p)
	}

	outFile := filepath.Join(t.TempDir(), "restored.env")
	drSnapshotDir, drRestoreProject, drRestoreOut = dir, "vaulter", outFile
	drRestoreShares, drRestoreConfirm = sharePaths, true
	t.Cleanup(func() {
		drSnapshotDir, drRestoreProject, drRestoreOut = "", "", ""
		drRestoreShares, drRestoreConfirm = nil, false
	})

	// Ajan modunda TTY-only seremoni reddedilmeli.
	t.Setenv("CLAUDECODE", "1")
	stdout := new(bytes.Buffer)
	drRestoreCmd.SetOut(stdout)
	if err := runDrRestore(drRestoreCmd, nil); err == nil {
		t.Fatal("dr restore must be REFUSED under agent mode")
	}
	t.Setenv("CLAUDECODE", "")

	// Test ortamı non-TTY olduğundan guard'lı runDrRestore yerine seremoni
	// çekirdeği doğrudan sürülür (guard yukarıda ayrıca kanıtlandı).
	if err := restoreProjectFromSnapshot(stdout, dir, "vaulter", sharePaths, outFile); err != nil {
		t.Fatalf("dr restore core: %v", err)
	}
	// Değerler stdout'a ASLA yazılmaz.
	if strings.Contains(stdout.String(), "postgres://user:pw@host/db") || strings.Contains(stdout.String(), "sk-123") {
		t.Error("restored values must never reach stdout")
	}
	fi, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("restored env file mode = %o, want 0600", fi.Mode().Perm())
	}
	body, _ := os.ReadFile(outFile)
	got := string(body)
	if !strings.Contains(got, "DB_URL=postgres://user:pw@host/db") || !strings.Contains(got, "API_KEY=sk-123") {
		t.Errorf("restored env content: %q", got)
	}
}
