package secrets

// configroot_test.go, "başka bir dizinden çağırabilme" sözleşmesini pinler:
// cwd projeyle İLGİSİZ bir dizinken --config/--project ile verb'ler doğru
// projeye gider ve yazdıkları dosyalar configRoot altına düşer — operatörün
// bulunduğu rastgele dizine DEĞİL.
//
// (Eskiden bu dosya age-arşiv yolunun cwd bağımsızlığını sınıyordu; arşiv
// kalkınca konu aynı kaldı, mekanizma store'a taşındı.)

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupForeignProject, bir proje dizini kurar, cwd'yi İLGİSİZ bir dizine
// taşır ve paket config override'ını projenin .wapps.yaml'ına bağlar (root'un
// PersistentPreRunE'unda --config/--project'in yaptığının aynısı). Store fake'i
// verilen değerlerle doldurulur. Döndürdüğü şey proje dizinidir.
func setupForeignProject(t *testing.T, values map[string]string, yamlExtra string) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("CF_ACCESS_CLIENT_ID", "")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "")

	projDir := t.TempDir()
	otherDir := t.TempDir()

	yaml := "version: 2\nbackend: store\nproject: testproj\n" + yamlExtra
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	t.Chdir(otherDir) // cwd BİLEREK proje dizini değil
	SetConfigPath(filepath.Join(projDir, ".wapps.yaml"))
	t.Cleanup(func() { SetConfigPath("") })

	f := installFakeStore(t)
	for k, v := range values {
		f.values[k] = v
	}
	return projDir
}

// Kabul #1: yabancı bir cwd'den list → adlar gelir.
func TestList_ConfigRootDifferentCwd(t *testing.T) {
	setupForeignProject(t, map[string]string{"alpha": "1", "beta": "2"}, "")

	var buf bytes.Buffer
	if err := runList(&buf); err != nil {
		t.Fatalf("runList: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"alpha", "beta"} {
		if !strings.Contains(got, want) {
			t.Errorf("key %q missing from foreign-cwd list:\n%s", want, got)
		}
	}
}

// Kabul #2: yabancı bir cwd'den get → doğru değer.
func TestGet_ConfigRootDifferentCwd(t *testing.T) {
	setupForeignProject(t, map[string]string{"DB_PASSWORD": "hunter2"}, "")

	var buf bytes.Buffer
	if err := runGet("DB_PASSWORD", &buf); err != nil {
		t.Fatalf("runGet: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "hunter2" {
		t.Errorf("value: got %q, want hunter2", buf.String())
	}
}

// Kabul #3: yabancı bir cwd'den exec → alt sürece env enjekte edilir.
func TestExec_ConfigRootInjectsEnv(t *testing.T) {
	setupForeignProject(t, map[string]string{"API_KEY": "sk_live"}, "")

	r := &fakeRunner{returnCode: 0}
	if err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	found := false
	for _, e := range r.gotEnv {
		if e == "TF_VAR_API_KEY=sk_live" {
			found = true
		}
	}
	if !found {
		t.Errorf("foreign-cwd exec must inject the project's secrets; env=%v", r.gotEnv)
	}
}

// Kabul #4 (en önemlisi): apply, target'ı CONFIGROOT altına yazar — operatörün
// içinde bulunduğu rastgele dizine düz metin sır dosyası saçılmaz.
func TestApply_TargetWrittenUnderConfigRoot(t *testing.T) {
	projDir := setupForeignProject(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")

	if err := runApply(io.Discard); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	underProject := filepath.Join(projDir, ".env.local")
	if _, err := os.Stat(underProject); err != nil {
		t.Fatalf("target must be written under configRoot: %v", err)
	}
	cwd, _ := os.Getwd()
	if _, err := os.Stat(filepath.Join(cwd, ".env.local")); err == nil {
		t.Error("target leaked into cwd — plaintext secrets must never scatter outside the project")
	}
}
