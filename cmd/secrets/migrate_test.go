package secrets

// migrate import/export testleri (SPEC §8.2 Path B): fake store + geçici legacy
// arşiv. Kanıtlanan eksenler: (1) import arşivi çözer, TEK atomik Import çağrısı
// yapar ve round-trip verify eder; (2) verify başarısızlığı FAIL LOUD; (3)
// tombstone'lu arşiv ARCHIVE_MIGRATED ile reddedilir; (4) export store değerlerini
// arşive yazar + doğrular, --confirm'siz reddedilir, tombstone'u ASLA ezmez.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/rotation"
)

// migrateTestSetup, geçici bir cwd'de (config yok → legacy varsayılan yol)
// passphrase env'ini kurar ve istenirse legacy arşivi tohumlar.
func migrateTestSetup(t *testing.T, archive map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })
	pp := "migrate-test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)
	if err := os.MkdirAll("secrets", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if archive != nil {
		envelope := make(map[string]json.RawMessage, len(archive))
		for k, v := range archive {
			b, _ := json.Marshal(map[string]string{"value": v})
			envelope[k] = b
		}
		raw, _ := json.Marshal(envelope)
		enc, err := ageutil.Encrypt(raw, pp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if err := os.WriteFile("secrets/all.enc.age", enc, 0o600); err != nil {
			t.Fatalf("seed archive: %v", err)
		}
	}
	return pp
}

func TestMigrateImport_ImportsAndRoundtripVerifies(t *testing.T) {
	migrateTestSetup(t, map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_KEY":     "abc123",
	})
	f := installFakeStore(t)

	var out bytes.Buffer
	if err := runMigrateImport("vaulter", &out); err != nil {
		t.Fatalf("runMigrateImport: %v", err)
	}
	if len(f.importCalls) != 1 {
		t.Fatalf("Import must be called exactly once (one atomic epoch), got %d", len(f.importCalls))
	}
	c := f.importCalls[0]
	if c.project != "vaulter" {
		t.Errorf("Import project: got %q", c.project)
	}
	if c.values["DB_PASSWORD"] != "hunter2" || c.values["API_KEY"] != "abc123" {
		t.Errorf("Import values wrong: %v", c.values)
	}
	// Round-trip verify: import edilen anahtarlar geri OKUNMUŞ olmalı.
	if len(f.readCalls) != 1 {
		t.Fatalf("verify Read must run exactly once, got %d", len(f.readCalls))
	}
	if len(f.readCalls[0].keys) != 2 {
		t.Errorf("verify Read must scope to the imported keys, got %v", f.readCalls[0].keys)
	}
	if !strings.Contains(out.String(), "Imported 2 keys") || !strings.Contains(out.String(), "Round-trip verified 2 keys") {
		t.Errorf("import output: %q", out.String())
	}
	// Değerler stdout'a ASLA sızmamalı.
	if strings.Contains(out.String(), "hunter2") || strings.Contains(out.String(), "abc123") {
		t.Error("import output leaked a secret value")
	}
}

func TestMigrateImport_VerifyFailureFailsLoud(t *testing.T) {
	migrateTestSetup(t, map[string]string{"DB_PASSWORD": "hunter2"})
	f := installFakeStore(t)
	f.importNoop = true // Import kaydeder ama store durumunu güncellemez → verify boş okur

	err := runMigrateImport("vaulter", io.Discard)
	if err == nil {
		t.Fatal("expected round-trip verify failure")
	}
	if !strings.Contains(err.Error(), "round-trip verify FAILED") {
		t.Fatalf("wrong error: %v", err)
	}
	// Hata mesajı yalnızca anahtar ADI içerebilir, değer ASLA.
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("verify error leaked a secret value")
	}
}

func TestMigrateImport_TombstonedArchiveRefused(t *testing.T) {
	pp := migrateTestSetup(t, nil)
	pt, err := rotation.BuildTombstonePlaintext("vaulter", "2026-07-11")
	if err != nil {
		t.Fatalf("build tombstone: %v", err)
	}
	enc, err := ageutil.Encrypt(pt, pp)
	if err != nil {
		t.Fatalf("encrypt tombstone: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", enc, 0o600); err != nil {
		t.Fatalf("seed tombstone: %v", err)
	}
	f := installFakeStore(t)

	err = runMigrateImport("vaulter", io.Discard)
	if !clierr.Is(err, clierr.ArchiveMigrated) {
		t.Fatalf("want ARCHIVE_MIGRATED, got: %v", err)
	}
	if len(f.importCalls) != 0 {
		t.Error("a tombstoned archive must never reach the store")
	}
}

func TestMigrateImport_MissingPassphraseFails(t *testing.T) {
	migrateTestSetup(t, map[string]string{"K": "v"})
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "")
	installFakeStore(t)

	if err := runMigrateImport("vaulter", io.Discard); err == nil ||
		!strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Fatalf("want passphrase error, got: %v", err)
	}
}

func TestMigrateExport_WritesVerifiedArchive(t *testing.T) {
	pp := migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "rotated-in-store"
	f.values["API_KEY"] = "fresh-key"

	var out bytes.Buffer
	if err := runMigrateExport("vaulter", true, &out); err != nil {
		t.Fatalf("runMigrateExport: %v", err)
	}
	// Yazılan arşiv legacy passphrase ile çözülmeli ve store değerlerini taşımalı.
	enc, err := os.ReadFile("secrets/all.enc.age")
	if err != nil {
		t.Fatalf("read exported archive: %v", err)
	}
	vals, err := rotation.LegacyArchiveFromBytes(enc).Values(pp)
	if err != nil {
		t.Fatalf("decrypt exported archive: %v", err)
	}
	if string(vals["DB_PASSWORD"]) != "rotated-in-store" || string(vals["API_KEY"]) != "fresh-key" {
		t.Errorf("exported archive values wrong (keys: %d)", len(vals))
	}
	if !strings.Contains(out.String(), "Exported 2 keys") {
		t.Errorf("export output: %q", out.String())
	}
	if strings.Contains(out.String(), "rotated-in-store") {
		t.Error("export output leaked a secret value")
	}
}

func TestMigrateExport_RequiresConfirm(t *testing.T) {
	migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["K"] = "v"

	err := runMigrateExport("vaulter", false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("want --confirm refusal, got: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Error("no store read may happen before --confirm")
	}
	if _, statErr := os.Stat("secrets/all.enc.age"); !os.IsNotExist(statErr) {
		t.Error("archive must not be written without --confirm")
	}
}

func TestMigrateExport_RefusesTombstonedArchive(t *testing.T) {
	pp := migrateTestSetup(t, nil)
	pt, err := rotation.BuildTombstonePlaintext("vaulter", "2026-07-11")
	if err != nil {
		t.Fatalf("build tombstone: %v", err)
	}
	enc, err := ageutil.Encrypt(pt, pp)
	if err != nil {
		t.Fatalf("encrypt tombstone: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", enc, 0o600); err != nil {
		t.Fatalf("seed tombstone: %v", err)
	}
	f := installFakeStore(t)
	f.values["K"] = "v"

	err = runMigrateExport("vaulter", true, io.Discard)
	if !clierr.Is(err, clierr.ArchiveMigrated) {
		t.Fatalf("want ARCHIVE_MIGRATED, got: %v", err)
	}
	// Tombstone dosyası DEĞİŞMEMİŞ olmalı.
	after, _ := os.ReadFile("secrets/all.enc.age")
	if !bytes.Equal(enc, after) {
		t.Error("tombstoned archive must never be rewritten")
	}
}
