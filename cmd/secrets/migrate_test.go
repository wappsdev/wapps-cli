package secrets

// migrate import/export testleri (SPEC §8.2 Path B): fake store + geçici legacy
// arşiv. Kanıtlanan eksenler: (1) import arşivi çözer, TEK atomik Import çağrısı
// yapar ve round-trip verify eder (per-key rapor); (2) verify başarısızlığı FAIL
// LOUD; (3) tombstone'lu arşiv ARCHIVE_MIGRATED ile reddedilir; (4) --dry-run
// HİÇBİR yazma/değer-okuma yapmaz; (5) değerleri zaten eşleşen ikinci koşu
// idempotent no-op'tur (yeni epoch yok); (6) export store değerlerini --out
// arşivine yazar + doğrular, --confirm'siz reddedilir, tombstone'u ASLA ezmez;
// (7) store'daki FARKLI değerleri ezen import --confirm ister; (8) export
// rollback-TAMLIK ister: çözülemeyen mevcut --out reddedilir, önceki arşivde
// olup okumada olmayan anahtar fail LOUD, proje-geneli read grant'i kanıtsız
// principal reddedilir; (9) migrate ailesi ajan modunda fail-closed REFUSED.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/rotation"
	"github.com/wappsdev/wapps-cli/internal/store"
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
	if err := runMigrateImport("vaulter", false, false, &out); err != nil {
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
	// Round-trip verify: import edilen anahtarlar geri OKUNMUŞ olmalı (boş store'da
	// idempotency ön-okuması atlanır → tek Read = verify).
	if len(f.readCalls) != 1 {
		t.Fatalf("verify Read must run exactly once, got %d", len(f.readCalls))
	}
	if len(f.readCalls[0].keys) != 2 {
		t.Errorf("verify Read must scope to the imported keys, got %v", f.readCalls[0].keys)
	}
	if !strings.Contains(out.String(), "Imported 2 keys") || !strings.Contains(out.String(), "Round-trip verified 2 keys") {
		t.Errorf("import output: %q", out.String())
	}
	// Per-key rapor: her anahtar adıyla + durumla listelenir.
	if !strings.Contains(out.String(), "+ DB_PASSWORD (new, verified)") || !strings.Contains(out.String(), "+ API_KEY (new, verified)") {
		t.Errorf("per-key report missing: %q", out.String())
	}
	// Değerler stdout'a ASLA sızmamalı.
	if strings.Contains(out.String(), "hunter2") || strings.Contains(out.String(), "abc123") {
		t.Error("import output leaked a secret value")
	}
}

func TestMigrateImport_DryRunMakesNoStoreWrites(t *testing.T) {
	migrateTestSetup(t, map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_KEY":     "abc123",
	})
	f := installFakeStore(t)
	f.values["API_KEY"] = "old-value" // store'da zaten var → "already in store" işareti

	var out bytes.Buffer
	if err := runMigrateImport("vaulter", true, false, &out); err != nil {
		t.Fatalf("runMigrateImport dry-run: %v", err)
	}
	if len(f.importCalls) != 0 || len(f.setCalls) != 0 {
		t.Error("dry-run must not write to the store")
	}
	if len(f.readCalls) != 0 {
		t.Error("dry-run must not read plaintext values (metadata Keys only)")
	}
	s := out.String()
	if !strings.Contains(s, "DRY RUN") || !strings.Contains(s, "No writes performed") {
		t.Errorf("dry-run output: %q", s)
	}
	if !strings.Contains(s, "DB_PASSWORD (new)") || !strings.Contains(s, "API_KEY (already in store") {
		t.Errorf("dry-run per-key markers missing: %q", s)
	}
	if strings.Contains(s, "hunter2") || strings.Contains(s, "abc123") || strings.Contains(s, "old-value") {
		t.Error("dry-run output leaked a secret value")
	}
}

func TestMigrateImport_RerunWithMatchingValuesIsIdempotentNoop(t *testing.T) {
	migrateTestSetup(t, map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_KEY":     "abc123",
	})
	f := installFakeStore(t)
	// Store zaten arşivle birebir aynı → import no-op olmalı (yeni epoch YOK).
	f.values["DB_PASSWORD"] = "hunter2"
	f.values["API_KEY"] = "abc123"

	var out bytes.Buffer
	if err := runMigrateImport("vaulter", false, false, &out); err != nil {
		t.Fatalf("runMigrateImport rerun: %v", err)
	}
	if len(f.importCalls) != 0 {
		t.Errorf("matching re-run must not open a new epoch, got %d Import calls", len(f.importCalls))
	}
	if !strings.Contains(out.String(), "idempotent no-op") ||
		!strings.Contains(out.String(), "= DB_PASSWORD (unchanged)") {
		t.Errorf("idempotent no-op output: %q", out.String())
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Error("no-op output leaked a secret value")
	}
}

func TestMigrateImport_PartialDriftReimportsAtomically(t *testing.T) {
	migrateTestSetup(t, map[string]string{
		"DB_PASSWORD": "hunter2",
		"API_KEY":     "abc123",
	})
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "hunter2"    // eşleşiyor
	f.values["API_KEY"] = "stale-in-store" // farklı → tam import gerekir (--confirm ile)

	var out bytes.Buffer
	if err := runMigrateImport("vaulter", false, true, &out); err != nil {
		t.Fatalf("runMigrateImport partial: %v", err)
	}
	if len(f.importCalls) != 1 {
		t.Fatalf("partial drift must import in ONE atomic epoch, got %d", len(f.importCalls))
	}
	if len(f.importCalls[0].values) != 2 {
		t.Errorf("atomic import must carry ALL archive keys, got %d", len(f.importCalls[0].values))
	}
	if !strings.Contains(out.String(), "~ API_KEY (updated, verified)") ||
		!strings.Contains(out.String(), "= DB_PASSWORD (unchanged, verified)") {
		t.Errorf("partial-drift per-key report: %q", out.String())
	}
}

func TestMigrateImport_VerifyFailureFailsLoud(t *testing.T) {
	migrateTestSetup(t, map[string]string{"DB_PASSWORD": "hunter2"})
	f := installFakeStore(t)
	f.importNoop = true // Import kaydeder ama store durumunu güncellemez → verify boş okur

	err := runMigrateImport("vaulter", false, false, io.Discard)
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

	err = runMigrateImport("vaulter", false, false, io.Discard)
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

	if err := runMigrateImport("vaulter", false, false, io.Discard); err == nil ||
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
	if err := runMigrateExport("vaulter", "secrets/all.enc.age", true, &out); err != nil {
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

func TestMigrateExport_WritesToCustomOutPath(t *testing.T) {
	pp := migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "rotated-in-store"

	// --out başka bir yolu işaret edebilir (rollback yedeği); üst dizin yoksa açılır.
	if err := runMigrateExport("vaulter", "backup/rollback.enc.age", true, io.Discard); err != nil {
		t.Fatalf("runMigrateExport --out: %v", err)
	}
	enc, err := os.ReadFile("backup/rollback.enc.age")
	if err != nil {
		t.Fatalf("read --out archive: %v", err)
	}
	vals, err := rotation.LegacyArchiveFromBytes(enc).Values(pp)
	if err != nil {
		t.Fatalf("decrypt --out archive: %v", err)
	}
	if string(vals["DB_PASSWORD"]) != "rotated-in-store" {
		t.Error("--out archive value wrong")
	}
	// Değer taşıyan arşiv world-readable OLMAMALI (0600).
	if info, serr := os.Stat("backup/rollback.enc.age"); serr == nil && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("exported archive must be 0600, got %v", info.Mode().Perm())
	}
}

func TestMigrateExport_RequiresOutPath(t *testing.T) {
	migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["K"] = "v"

	err := runMigrateExport("vaulter", "", true, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("want --out refusal, got: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Error("no store read may happen without --out")
	}
}

func TestMigrateExport_RequiresConfirm(t *testing.T) {
	migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["K"] = "v"

	err := runMigrateExport("vaulter", "secrets/all.enc.age", false, io.Discard)
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

	err = runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard)
	if !clierr.Is(err, clierr.ArchiveMigrated) {
		t.Fatalf("want ARCHIVE_MIGRATED, got: %v", err)
	}
	// Tombstone dosyası DEĞİŞMEMİŞ olmalı.
	after, _ := os.ReadFile("secrets/all.enc.age")
	if !bytes.Equal(enc, after) {
		t.Error("tombstoned archive must never be rewritten")
	}
}

// Store'da FARKLI değer tutan mevcut anahtarları ezen import --confirm ister
// (soak sırasında store'a düşmüş DAHA YENİ değerlerin sessizce arşivin bayat
// değerlerine geri döndürülmesi engellenir); --confirm ile aynı koşu geçer.
func TestMigrateImport_DifferingStoreValuesRequireConfirm(t *testing.T) {
	migrateTestSetup(t, map[string]string{"API_KEY": "abc123"})
	f := installFakeStore(t)
	f.values["API_KEY"] = "newer-in-store" // soak sonrası store'a düşen daha yeni değer

	err := runMigrateImport("vaulter", false, false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("want --confirm refusal for differing store values, got: %v", err)
	}
	if !strings.Contains(err.Error(), "API_KEY") {
		t.Errorf("refusal must name the conflicting keys: %v", err)
	}
	if len(f.importCalls) != 0 {
		t.Fatal("no import may run without --confirm when store values differ")
	}
	if strings.Contains(err.Error(), "newer-in-store") || strings.Contains(err.Error(), "abc123") {
		t.Error("refusal leaked a secret value")
	}

	// --confirm ile bilinçli geri-dönüş serbesttir ve arşiv değeri store'a yazılır.
	var out bytes.Buffer
	if err := runMigrateImport("vaulter", false, true, &out); err != nil {
		t.Fatalf("runMigrateImport --confirm: %v", err)
	}
	if len(f.importCalls) != 1 {
		t.Fatalf("confirmed import must run exactly once, got %d", len(f.importCalls))
	}
	if f.values["API_KEY"] != "abc123" {
		t.Error("confirmed import must write the archive value to the store")
	}
	if !strings.Contains(out.String(), "~ API_KEY (updated, verified)") {
		t.Errorf("confirmed import per-key report: %q", out.String())
	}
}

// Mevcut --out HİÇ çözülemiyorsa export fail LOUD olur: yanlış passphrase'le
// tombstone guard'ı sessizce delinip yabancı/tombstone'lu bir arşiv ezilemez.
func TestMigrateExport_RefusesUndecryptableExistingOut(t *testing.T) {
	migrateTestSetup(t, nil)
	garbage := []byte("not-an-age-file")
	if err := os.WriteFile("secrets/all.enc.age", garbage, 0o600); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	f := installFakeStore(t)
	f.values["K"] = "v"

	err := runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Fatalf("want undecryptable-out refusal, got: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Error("no store read may happen when the existing --out is uninspectable")
	}
	after, _ := os.ReadFile("secrets/all.enc.age")
	if !bytes.Equal(garbage, after) {
		t.Error("an uninspectable --out must never be rewritten")
	}
}

// Rollback-TAMLIK çapraz kontrolü: önceki arşivde olup store okumasında OLMAYAN
// anahtar (policy-filtreli okuma ya da store silmesi) export'u FAIL LOUD durdurur
// ve mevcut arşive DOKUNULMAZ — eksik rollback arşivi sessizce üretilmez.
func TestMigrateExport_FailsWhenPreviousArchiveKeysMissingFromStore(t *testing.T) {
	migrateTestSetup(t, map[string]string{
		"DB_PASSWORD": "old-db",
		"API_KEY":     "old-api",
	})
	before, err := os.ReadFile("secrets/all.enc.age")
	if err != nil {
		t.Fatalf("read seeded archive: %v", err)
	}
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "rotated" // API_KEY okuma kümesinde YOK

	err = runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "NOT rollback-complete") {
		t.Fatalf("want rollback-completeness failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "API_KEY") {
		t.Errorf("failure must name the missing keys: %v", err)
	}
	if strings.Contains(err.Error(), "old-api") || strings.Contains(err.Error(), "rotated") {
		t.Error("completeness failure leaked a secret value")
	}
	after, _ := os.ReadFile("secrets/all.enc.age")
	if !bytes.Equal(before, after) {
		t.Error("archive must be untouched when the export is not rollback-complete")
	}
}

// Okuma-tamlığı KANITSIZ principal (root admin değil + proje-geneli "*" read
// grant'i yok) export'u başlatamaz: Worker GET /keys'i grant'e filtrelediği için
// kısmi okuma sessizce eksik arşiv üretirdi. Grant genişleyince koşu serbesttir.
func TestMigrateExport_RequiresCompleteReadGrant(t *testing.T) {
	migrateTestSetup(t, nil)
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "v1"
	f.whoami = &store.WhoamiResult{
		Principal:   "svc:partial",
		IsRootAdmin: false,
		Grants: []store.Rule{
			{Projects: []string{"vaulter"}, Keys: []string{"DB_*"}, Verbs: []string{"read"}},
		},
	}

	err := runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "PROJECT-WIDE read grant") {
		t.Fatalf("want incomplete-read-grant refusal, got: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Error("no bulk read may happen without a completeness proof")
	}
	if _, statErr := os.Stat("secrets/all.enc.age"); !os.IsNotExist(statErr) {
		t.Error("no archive may be written without a completeness proof")
	}

	// Deny-glob'lu "*" grant'i de KANIT DEĞİLDİR (kural-içi dışlama).
	f.whoami.Grants = []store.Rule{
		{Projects: []string{"vaulter"}, Keys: []string{"*", "!DB_*"}, Verbs: []string{"read"}},
	}
	if err := runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard); err == nil {
		t.Fatal("a deny-glob grant must not count as a completeness proof")
	}

	// Proje-geneli temiz "*" read grant'i → export serbest.
	f.whoami.Grants = []store.Rule{
		{Projects: []string{"vaulter"}, Keys: []string{"*"}, Verbs: []string{"read"}},
	}
	if err := runMigrateExport("vaulter", "secrets/all.enc.age", true, io.Discard); err != nil {
		t.Fatalf("project-wide read grant must allow export: %v", err)
	}
	if _, statErr := os.Stat("secrets/all.enc.age"); statErr != nil {
		t.Errorf("archive must exist after a proven-complete export: %v", statErr)
	}
}

// TestAgentGate_MigrateFamilyIsRefused, migrate ailesinin ajan modunda
// fail-closed REFUSED kaldığını PreRun üzerinden kanıtlar: "migrate" gateKey'i
// agentPolicy'de bilinçli olarak YOK (insan-eli admin op'ları) →
// AGENT_MODE_REFUSED. TestAgentGate_PolicyFamilyIsControlPlane'in eşleniği.
func TestAgentGate_MigrateFamilyIsRefused(t *testing.T) {
	t.Setenv("CLAUDECODE", "1") // ajan modu
	if !agentmode.IsAgent() {
		t.Skip("agent-mode detection unavailable in this environment")
	}
	for _, cmd := range []*cobra.Command{migrateImportCmd, migrateExportCmd, migrateTombstoneCmd} {
		if key := gateKey(cmd); key != "migrate" {
			t.Fatalf("gateKey(%s) = %q, want migrate", cmd.Name(), key)
		}
		err := secretsPreRunE(cmd, nil)
		if !clierr.Is(err, clierr.AgentModeRefused) {
			t.Fatalf("migrate %s under agent mode: want AGENT_MODE_REFUSED, got %v", cmd.Name(), err)
		}
	}
}
