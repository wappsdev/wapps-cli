package secrets

// import_env_test.go, `wapps secrets import-env <file>` sözleşmesini pinler:
// env dosyası parse edilir ve anahtarlar TEK atomik import'la store'a yazılır;
// mevcut anahtarlar KORUNUR (merge, replace değil) ve üzerine yazılanlar adıyla
// bildirilir.

import (
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

func TestRunImportEnv_HappyPath(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	// Mevcut bir anahtar: import MERGE etmeli, replace ETMEMELİ.
	f.values["EXISTING"] = "keep"

	input := []byte(`
# comment lines are skipped
STRIPE_KEY=sk_test_xyz
export QUOTED="with spaces"
`)
	if err := os.WriteFile("in.env", input, 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := runImportEnv("in.env", os.Getenv); err != nil {
		t.Fatalf("runImportEnv: %v", err)
	}

	if len(f.importCalls) != 1 {
		t.Fatalf("import must be ONE atomic call, got %d", len(f.importCalls))
	}
	got := f.importCalls[0].values
	if got["STRIPE_KEY"] != "sk_test_xyz" {
		t.Errorf("STRIPE_KEY: got %q", got["STRIPE_KEY"])
	}
	if got["QUOTED"] != "with spaces" {
		t.Errorf("QUOTED: got %q", got["QUOTED"])
	}
	if _, sent := got["EXISTING"]; sent {
		t.Error("import must only send the file's keys, not re-send untouched ones")
	}
	// Merge: dokunulmayan anahtar store'da kalır.
	if f.values["EXISTING"] != "keep" {
		t.Error("import must not drop existing keys")
	}
}

func TestRunImportEnv_RequiresWappsYAML(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })

	if err := os.WriteFile("in.env", []byte("A=1\n"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	err := runImportEnv("in.env", os.Getenv)
	if err == nil || !strings.Contains(err.Error(), ".wapps.yaml") {
		t.Fatalf("missing config must be named in the error, got %v", err)
	}
}

func TestRunImportEnv_MissingFile(t *testing.T) {
	setupStoreProject(t, "")
	installFakeStore(t)

	err := runImportEnv("nope.env", os.Getenv)
	if err == nil || !strings.Contains(err.Error(), "nope.env") {
		t.Fatalf("missing input file must be named in the error, got %v", err)
	}
}

// Boş/yalnız-yorum dosya: hata DEĞİL, ama store'a da hiçbir şey yazılmaz.
func TestRunImportEnv_EmptyFileNoOpButNoError(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	if err := os.WriteFile("empty.env", []byte("# only a comment\n\n"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := runImportEnv("empty.env", os.Getenv); err != nil {
		t.Fatalf("empty input must not error: %v", err)
	}
	if len(f.importCalls) != 0 {
		t.Errorf("empty input must not write to the store, got %+v", f.importCalls)
	}
}

// TestRunImportEnv_RefusesAnEpochDowngradeAndWritesNothing, bir ROLLBACK
// karşısında `import-env`in reddettiğini VE store'a yazmadığını ölçer.
//
// Neden bu test var: `checkAndAdvanceEpochPin` bir rollback saldırısını
// durduran TEK kontrol, ve yalnızca Keys + Read içinden çağrılıyor — Import
// onu HİÇ çağırmıyor. `import-env` Keys'i çağırıyordu ama hatasını BİLEREK
// yutuyordu (`if kr, kerr := ...; kerr == nil`), çünkü o çağrı bir kolaylık
// (hangi adların üzerine yazılacağını önceden söylemek). Yan etkisi:
// EPOCH_DOWNGRADE o yutulan hatanın içinde geliyordu ve sessizce atılıyordu.
// Sonuç: aynı geri sarılmış store'a karşı `list` ve `env` REDDEDERKEN, toplu
// YAZAN fiil sessizce yazıp 0 ile çıkıyordu.
//
// Testin İKİNCİ YARISI zorunlu: "reddetti" yetmez. Bir rollback'e karşı
// yazmanın kendisi zarardır, o yüzden Import'un HİÇ çağrılmadığı da ölçülüyor.
func TestRunImportEnv_RefusesAnEpochDowngradeAndWritesNothing(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.keysErr = clierr.Newf(clierr.EpochDowngrade, "served epoch %d < pinned %d for %q", 7, 9, "testproj")

	if err := os.WriteFile("in.env", []byte("ALPHA=test-string\n"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	err := runImportEnv("in.env", func(string) string { return "" })

	if err == nil {
		t.Fatal("import-env against a rolled-back store: want refusal, got nil")
	}
	if !clierr.Is(err, clierr.EpochDowngrade) {
		t.Errorf("error code = %v, want EPOCH_DOWNGRADE", err)
	}
	// İKİNCİ YARI: reddetmek yetmez, YAZMAMIŞ da olmalı.
	if len(f.importCalls) != 0 {
		t.Errorf("import-env wrote to a rolled-back store: %d Import call(s), want 0", len(f.importCalls))
	}
}

// TestRunImportEnv_StillSwallowsAnUnrelatedKeysError, ayrımın DAR olduğunu
// ölçer: yutmanın ilk yazılma sebebi (Keys başka bir sebeple patlarsa
// `import-env` kullanılamaz olmasın) korunuyor. Yalnızca EPOCH_DOWNGRADE bir
// kapı; geri kalan her şey hâlâ bir kolaylık hatası.
func TestRunImportEnv_StillSwallowsAnUnrelatedKeysError(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.keysErr = clierr.New(clierr.Internal, "keys listing is having a bad day")

	if err := os.WriteFile("in.env", []byte("ALPHA=test-string\n"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := runImportEnv("in.env", func(string) string { return "" }); err != nil {
		t.Fatalf("an unrelated Keys error must stay swallowed, got: %v", err)
	}
	if len(f.importCalls) != 1 {
		t.Errorf("Import call(s) = %d, want 1 (the write must still happen)", len(f.importCalls))
	}
}
