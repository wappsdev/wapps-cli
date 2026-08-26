package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envSetup, store fake'ini verilen değerlerle doldurur ve proje dizinini döner.
// (Eskiden bir age arşivi tohumluyordu; arşiv kalkınca gövde değişti, testler
// aynen kaldı — sınadıkları şey env BİÇİMLENDİRMESİ, değerin nereden geldiği değil.)
func envSetup(t *testing.T, values map[string]string) string {
	t.Helper()
	tmp := setupStoreProject(t, "")
	f := installFakeStore(t)
	for k, v := range values {
		f.values[k] = v
	}
	return tmp
}

func TestRunEnv_DefaultStdout(t *testing.T) {
	envSetup(t, map[string]string{"DB_PASSWORD": "secret"})

	var buf bytes.Buffer
	if err := runEnv("", "TF_VAR_", &buf); err != nil {
		t.Fatalf("runEnv: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "export TF_VAR_DB_PASSWORD='secret'") {
		t.Errorf("default prefix not applied:\n%s", got)
	}
}

func TestRunEnv_CustomPrefix(t *testing.T) {
	envSetup(t, map[string]string{"STRIPE_KEY": "sk_test"})

	var buf bytes.Buffer
	if err := runEnv("", "MY_PREFIX_", &buf); err != nil {
		t.Fatalf("runEnv: %v", err)
	}
	if !strings.Contains(buf.String(), "export MY_PREFIX_STRIPE_KEY='sk_test'") {
		t.Errorf("custom prefix not applied:\n%s", buf.String())
	}
}

func TestRunEnv_EmptyPrefixForFileSourceRepos(t *testing.T) {
	envSetup(t, map[string]string{"STRIPE_KEY": "sk_test", "DB_PASSWORD": "hunter2"})

	var buf bytes.Buffer
	if err := runEnv("", "", &buf); err != nil {
		t.Fatalf("runEnv: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "export STRIPE_KEY='sk_test'") {
		t.Errorf("empty prefix should produce plain export, got:\n%s", got)
	}
	if strings.Contains(got, "TF_VAR_") {
		t.Errorf("empty prefix should NOT include TF_VAR_:\n%s", got)
	}
}

func TestRunEnv_WritePath_FileGetsContent_StdoutSilent(t *testing.T) {
	tmp := envSetup(t, map[string]string{"FOO": "bar", "BAZ": "qux"})
	outPath := filepath.Join(tmp, ".env.local")

	var stdout bytes.Buffer
	if err := runEnv(outPath, "TF_VAR_", &stdout); err != nil {
		t.Fatalf("runEnv: %v", err)
	}

	// CRITICAL: stdout receives nothing — AI-safe contract (P4 revised).
	if stdout.Len() != 0 {
		t.Errorf("--write path must produce zero stdout (AI-safe contract), got: %q", stdout.String())
	}

	// File should contain the env lines.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"export TF_VAR_FOO='bar'",
		"export TF_VAR_BAZ='qux'",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("written file missing %q:\n%s", want, content)
		}
	}
}

func TestRunEnv_WriteFileMode0600(t *testing.T) {
	tmp := envSetup(t, map[string]string{"FOO": "bar"})
	outPath := filepath.Join(tmp, ".env.local")

	if err := runEnv(outPath, "TF_VAR_", &bytes.Buffer{}); err != nil {
		t.Fatalf("runEnv: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf(".env.local mode = %o, want 0600 (secrets file)", mode)
	}
}

func TestRunEnv_WriteAtomic_NoTempLeftover(t *testing.T) {
	tmp := envSetup(t, map[string]string{"FOO": "bar"})
	outPath := filepath.Join(tmp, ".env.local")

	if err := runEnv(outPath, "TF_VAR_", &bytes.Buffer{}); err != nil {
		t.Fatalf("runEnv: %v", err)
	}
	if _, err := os.Stat(outPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file should not persist after successful write")
	}
}

// Bug 1 regression: writeTofuOutputsAsEnv used to force all values to string
// at unmarshal time, crashing on non-string Tofu outputs like
// vaulter_traefik_cert_paths (a []string). After the fix, any JSON type
// round-trips via TF_VAR_<name>='<json>'.
func TestWriteTofuOutputsAsEnv_HandlesMixedValueTypes(t *testing.T) {
	input := []byte(`{
		"pg_password": {"value": "s3cr3t"},
		"vaulter_traefik_cert_paths": {"value": ["a.crt", "b.crt"]},
		"meta": {"value": {"version": 2, "ready": true}},
		"replicas": {"value": 3},
		"enabled": {"value": true},
		"optional": {"value": null}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, "TF_VAR_", &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: unexpected error: %v", err)
	}

	got := buf.String()
	// String: emit unquoted value
	if !strings.Contains(got, "export TF_VAR_pg_password='s3cr3t'\n") {
		t.Errorf("string output missing or wrong:\n%s", got)
	}
	// List: emit JSON-string (the bug 1 regression case)
	if !strings.Contains(got, `export TF_VAR_vaulter_traefik_cert_paths='["a.crt","b.crt"]'`) {
		t.Errorf("list output (Bug 1 regression) missing or wrong:\n%s", got)
	}
	// Map: emit JSON-string
	if !strings.Contains(got, `export TF_VAR_meta='{"version":2,"ready":true}'`) {
		t.Errorf("map output missing or wrong:\n%s", got)
	}
	// Number: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_replicas='3'\n") {
		t.Errorf("number output missing or wrong:\n%s", got)
	}
	// Bool: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_enabled='true'\n") {
		t.Errorf("bool output missing or wrong:\n%s", got)
	}
	// Null: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_optional='null'\n") {
		t.Errorf("null output missing or wrong:\n%s", got)
	}
}

func TestWriteTofuOutputsAsEnv_EscapesSingleQuotes(t *testing.T) {
	input := []byte(`{
		"tricky": {"value": "it's a 'value'"}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, "TF_VAR_", &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: %v", err)
	}

	// Single quotes inside the value must be escaped as '\'' (close-escape-open).
	want := `export TF_VAR_tricky='it'\''s a '\''value'\'''` + "\n"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("single-quote escape wrong.\nwant substring: %q\ngot: %q", want, buf.String())
	}
}

func TestWriteTofuOutputsAsEnv_DeterministicOrder(t *testing.T) {
	input := []byte(`{
		"zebra": {"value": "z"},
		"alpha": {"value": "a"},
		"mango": {"value": "m"}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, "TF_VAR_", &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: %v", err)
	}

	got := buf.String()
	alphaIdx := strings.Index(got, "TF_VAR_alpha")
	mangoIdx := strings.Index(got, "TF_VAR_mango")
	zebraIdx := strings.Index(got, "TF_VAR_zebra")

	if alphaIdx == -1 || mangoIdx == -1 || zebraIdx == -1 {
		t.Fatalf("expected all keys in output, got:\n%s", got)
	}
	if !(alphaIdx < mangoIdx && mangoIdx < zebraIdx) {
		t.Errorf("expected alphabetical order, got:\n%s", got)
	}
}

func TestWriteTofuOutputsAsEnv_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv([]byte(`{}`), "TF_VAR_", &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv on empty: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output on empty input, got: %q", buf.String())
	}
}

func TestWriteTofuOutputsAsEnv_MalformedJSON(t *testing.T) {
	var buf bytes.Buffer
	err := writeTofuOutputsAsEnv([]byte(`not json`), "TF_VAR_", &buf)
	if err == nil {
		t.Fatal("expected error on malformed JSON input, got nil")
	}
	if !strings.Contains(err.Error(), "parse values") {
		t.Errorf("expected error to mention 'parse values', got: %v", err)
	}
}

// TestRunEnv_WriteCannotInheritAWideTempMode, ÖNCEDEN DURAN dünya-okunur bir
// `<hedef>.tmp`in düz metin sırrı 0644 ile diske bırakamadığını ölçer.
//
// open(2): "the mode argument shall be ignored if the file exists". Eski
// yazıcı O_EXCL'siz O_CREATE|O_TRUNC kullanıyordu, yani istenen 0600 var olan
// bir dosyada HİÇ uygulanmıyordu. Bu bir İDDİA testidir, bir karşılaştırma
// değil: differential iki ikilinin PAYLAŞTIĞI bir kusuru göremez ve bu kusur
// iki taraftada birden canlıydı.
func TestRunEnv_WriteCannotInheritAWideTempMode(t *testing.T) {
	tmp := envSetup(t, map[string]string{"FOO": "bar"})
	outPath := filepath.Join(tmp, ".env.local")

	stale := outPath + ".tmp"
	if err := os.WriteFile(stale, []byte("stale"), 0600); err != nil {
		t.Fatalf("seed stale temp: %v", err)
	}
	// WriteFile umask'a tabidir; modu AÇIKÇA kur.
	if err := os.Chmod(stale, 0644); err != nil {
		t.Fatalf("chmod stale temp: %v", err)
	}

	if err := runEnv(outPath, "TF_VAR_", &bytes.Buffer{}); err != nil {
		t.Fatalf("runEnv: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("a stale 0644 %s widened the secret: mode = %o, want 0600", filepath.Base(stale), mode)
	}
}

// TestWriteEnvFileAtomic_ErrorNamesTheTargetNotTheTemp, hata cümlesinin
// RASTGELE geçici dosya adını TAŞIMADIĞINI ölçer.
//
// Neden bir test: temp adı artık rastgele, yani adı metne koyan bir yazıcı
// aynı hata için iki koşuda iki FARKLI cümle üretir. Bu, pty differential'ını
// deterministik olmayan bir vakayla kırar ve kullanıcıya tanımadığı bir yol
// gösterir. Cümle Go ikilisinden ÖLÇÜLDÜ; Rust karşılığı
// an_unwritable_target_names_the_target_with_the_go_sentence.
func TestWriteEnvFileAtomic_ErrorNamesTheTargetNotTheTemp(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nodir", "out.env")

	err := writeEnvFileAtomic(target, []byte(`{"A":{"value":"x"}}`), "")
	if err == nil {
		t.Fatal("writeEnvFileAtomic into a missing dir: want error, got nil")
	}
	want := "env: write " + target + ": no such file or directory"
	if err.Error() != want {
		t.Errorf("error text =\n  %q\nwant\n  %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), ".tmp") {
		t.Errorf("error text carries the random temp name (non-deterministic): %q", err.Error())
	}
}
