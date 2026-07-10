package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// execTestSetup writes an encrypted archive into ./secrets/all.enc.age in
// a temp cwd and seeds WAPPS_SECRETS_PASSPHRASE. Returns the passphrase
// so the test can decrypt the archive in assertions if needed.
func execTestSetup(t *testing.T, archive map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "exec-test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	enc, err := ageutil.Encrypt(raw, pp)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", enc, 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return pp
}

// fakeRunner captures the call arguments so tests can assert env contents
// without spawning a real subprocess.
type fakeRunner struct {
	gotName    string
	gotArgs    []string
	gotEnv     []string
	returnCode int
	returnErr  error
}

func (f *fakeRunner) runner(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
	f.gotName = name
	f.gotArgs = args
	f.gotEnv = env
	return f.returnCode, f.returnErr
}

// execCall wraps runExec with the non-agent, discard-output defaults so the
// existing env-injection tests stay concise.
func execCall(args []string, prefix string, runner execRunner) error {
	return runExec(args, prefix, false, false, io.Discard, io.Discard, runner)
}

func TestRunExec_InjectsSecretsAsEnvVars(t *testing.T) {
	execTestSetup(t, map[string]string{
		"DB_PASSWORD": "hunter2",
		"STRIPE_KEY":  "sk_test_xyz",
	})

	r := &fakeRunner{returnCode: 0}
	err := execCall([]string{"printenv"}, "TF_VAR_", r.runner)
	if err != nil {
		t.Fatalf("runExec: %v", err)
	}

	// Confirm injection happened — env slice should contain TF_VAR_DB_PASSWORD=hunter2.
	want := map[string]string{
		"TF_VAR_DB_PASSWORD": "hunter2",
		"TF_VAR_STRIPE_KEY":  "sk_test_xyz",
	}
	for k, v := range want {
		found := false
		for _, entry := range r.gotEnv {
			if entry == k+"="+v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("env missing %s=%s\nfull env: %v", k, v, r.gotEnv)
		}
	}
}

func TestRunExec_EmptyPrefix(t *testing.T) {
	execTestSetup(t, map[string]string{"STRIPE_KEY": "sk_test"})

	r := &fakeRunner{returnCode: 0}
	if err := execCall([]string{"true"}, "", r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}

	for _, entry := range r.gotEnv {
		if strings.HasPrefix(entry, "TF_VAR_") {
			t.Errorf("empty prefix should not produce TF_VAR_ entries, got: %s", entry)
		}
	}
	found := false
	for _, entry := range r.gotEnv {
		if entry == "STRIPE_KEY=sk_test" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected plain STRIPE_KEY=sk_test in env, got: %v", r.gotEnv)
	}
}

func TestRunExec_PassesCommandArgsVerbatim(t *testing.T) {
	execTestSetup(t, nil)

	r := &fakeRunner{returnCode: 0}
	args := []string{"pnpm", "dev", "--port", "8080"}
	if err := execCall(args, "TF_VAR_", r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}

	if r.gotName != "pnpm" {
		t.Errorf("command name: got %q, want pnpm", r.gotName)
	}
	wantArgs := []string{"dev", "--port", "8080"}
	if len(r.gotArgs) != len(wantArgs) {
		t.Fatalf("args length: got %d, want %d", len(r.gotArgs), len(wantArgs))
	}
	for i, a := range wantArgs {
		if r.gotArgs[i] != a {
			t.Errorf("args[%d]: got %q, want %q", i, r.gotArgs[i], a)
		}
	}
}

func TestRunExec_InheritsParentEnv(t *testing.T) {
	execTestSetup(t, map[string]string{"INJECTED": "from-archive"})
	t.Setenv("PARENT_VAR", "from-parent")

	r := &fakeRunner{returnCode: 0}
	if err := execCall([]string{"true"}, "TF_VAR_", r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}

	gotParent := false
	gotInjected := false
	for _, entry := range r.gotEnv {
		if entry == "PARENT_VAR=from-parent" {
			gotParent = true
		}
		if entry == "TF_VAR_INJECTED=from-archive" {
			gotInjected = true
		}
	}
	if !gotParent {
		t.Errorf("parent env var lost: %v", r.gotEnv)
	}
	if !gotInjected {
		t.Errorf("archive var missing: %v", r.gotEnv)
	}
}

func TestRunExec_InjectedOverridesInheritedEnvOnCollision(t *testing.T) {
	// Archive's DB_PASSWORD must shadow shell's DB_PASSWORD. Test: shell sets
	// DB_PASSWORD=from-shell; archive supplies DB_PASSWORD=from-archive.
	// The env passed to the subprocess should have the archive value LAST
	// (so when the OS resolves duplicates, the last wins on most platforms,
	// or the runner uses the operator-intended value).
	execTestSetup(t, map[string]string{"DB_PASSWORD": "from-archive"})
	t.Setenv("TF_VAR_DB_PASSWORD", "from-shell")

	r := &fakeRunner{returnCode: 0}
	if err := execCall([]string{"true"}, "TF_VAR_", r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}

	// Find both entries — archive's must appear AFTER shell's.
	shellIdx := -1
	archiveIdx := -1
	for i, entry := range r.gotEnv {
		if entry == "TF_VAR_DB_PASSWORD=from-shell" {
			shellIdx = i
		}
		if entry == "TF_VAR_DB_PASSWORD=from-archive" {
			archiveIdx = i
		}
	}
	if archiveIdx == -1 {
		t.Fatalf("archive entry missing from env")
	}
	if shellIdx >= 0 && archiveIdx <= shellIdx {
		t.Errorf("archive entry should come AFTER shell entry (last-wins semantics): shell=%d archive=%d", shellIdx, archiveIdx)
	}
}

func TestRunExec_NoPassphraseErrors(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	os.Unsetenv("WAPPS_SECRETS_PASSPHRASE")

	err := execCall([]string{"true"}, "TF_VAR_", (&fakeRunner{}).runner)
	if err == nil {
		t.Fatal("expected error: passphrase required")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var, got: %v", err)
	}
}

func TestRunExec_EmptyArgsErrors(t *testing.T) {
	err := execCall(nil, "TF_VAR_", (&fakeRunner{}).runner)
	if err == nil {
		t.Fatal("expected error: empty args")
	}
}

func TestRunExec_RunnerErrorPropagates(t *testing.T) {
	execTestSetup(t, nil)

	r := &fakeRunner{returnErr: errors.New("command not found: nonexistent-binary")}
	err := execCall([]string{"nonexistent-binary"}, "TF_VAR_", r.runner)
	if err == nil {
		t.Fatal("expected error when runner fails")
	}
	if !strings.Contains(err.Error(), "command not found") {
		t.Errorf("runner error should propagate, got: %v", err)
	}
}

// TestRunExec_ScrubsInjectedValueFromChildOutput, VERB-seviyesi agent-safety
// kanıtı (§7.4.3): enjekte edilen bir değeri echo'layan bir alt-süreç, o değeri
// yakalanan stdout'a ASLA sızdıramaz — scrubber onu *** yapar.
func TestRunExec_ScrubsInjectedValueFromChildOutput(t *testing.T) {
	secret := "sk_live_supersecretvalue_1234567890"
	execTestSetup(t, map[string]string{"STRIPE_KEY": secret})

	var out bytes.Buffer
	leaky := func(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
		var val string
		for _, e := range env {
			if strings.HasPrefix(e, "TF_VAR_STRIPE_KEY=") {
				val = strings.TrimPrefix(e, "TF_VAR_STRIPE_KEY=")
			}
		}
		// Sızdıran bir araç gibi değeri stdout'a bas — hatta parçalı.
		_, _ = stdout.Write([]byte("connecting with " + val))
		_, _ = stdout.Write([]byte(" ... done\n"))
		return 0, nil
	}

	if err := runExec([]string{"leak"}, "TF_VAR_", false, false, &out, io.Discard, leaky); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("SECRET LEAKED into transcript: %q", out.String())
	}
	if !strings.Contains(out.String(), "***") {
		t.Fatalf("expected redaction ***, got: %q", out.String())
	}
}

// TestRunExec_BreakGlassRefusedInAgentMode, --break-glass ajan modunda HARD-REFUSED.
func TestRunExec_BreakGlassRefusedInAgentMode(t *testing.T) {
	execTestSetup(t, nil)
	err := runExec([]string{"true"}, "TF_VAR_", true /*breakGlass*/, true /*isAgent*/, io.Discard, io.Discard, (&fakeRunner{}).runner)
	if err == nil {
		t.Fatal("expected BREAK_GLASS_REFUSED")
	}
	if !clierr.Is(err, clierr.BreakGlassRefused) {
		t.Fatalf("wrong code: %v", err)
	}
}

func TestBuildExecEnv_StringValue(t *testing.T) {
	archive := []byte(`{"FOO":{"value":"bar"}}`)
	env, err := buildExecEnv(archive, "TF_VAR_")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	if len(env) != 1 || env[0] != "TF_VAR_FOO=bar" {
		t.Errorf("got %v, want [TF_VAR_FOO=bar]", env)
	}
}

// A mixed archive (Tofu outputs stored bare + file-source secrets carried in
// already TF_VAR_-prefixed) must NOT double-prefix the prefixed ones.
func TestBuildExecEnv_IdempotentPrefix(t *testing.T) {
	archive := []byte(`{"coolify_uuid":{"value":"u1"},"TF_VAR_gemini_api_key":{"value":"g"}}`)
	env, err := buildExecEnv(archive, "TF_VAR_")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	got := map[string]bool{}
	for _, e := range env {
		got[e] = true
	}
	if !got["TF_VAR_coolify_uuid=u1"] {
		t.Errorf("bare key should gain the prefix; got %v", env)
	}
	if !got["TF_VAR_gemini_api_key=g"] {
		t.Errorf("already-prefixed key should be verbatim; got %v", env)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "TF_VAR_TF_VAR_") {
			t.Errorf("double-prefixed: %q", e)
		}
	}
}

func TestEnvName_Idempotent(t *testing.T) {
	cases := []struct{ prefix, key, want string }{
		{"TF_VAR_", "coolify_uuid", "TF_VAR_coolify_uuid"},
		{"TF_VAR_", "TF_VAR_gemini_api_key", "TF_VAR_gemini_api_key"},
		{"", "anything", "anything"},
		{"TF_VAR_", "TF_VAR_", "TF_VAR_"},
	}
	for _, c := range cases {
		if got := envName(c.prefix, c.key); got != c.want {
			t.Errorf("envName(%q,%q)=%q, want %q", c.prefix, c.key, got, c.want)
		}
	}
}

func TestBuildExecEnv_ListValueEmitsCompactJSON(t *testing.T) {
	archive := []byte(`{"PATHS":{"value":["a","b","c"]}}`)
	env, err := buildExecEnv(archive, "")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	want := `PATHS=["a","b","c"]`
	if len(env) != 1 || env[0] != want {
		t.Errorf("got %v, want [%s]", env, want)
	}
}

func TestBuildExecEnv_NullValueEmitsLiteralNull(t *testing.T) {
	archive := []byte(`{"OPTIONAL":{"value":null}}`)
	env, err := buildExecEnv(archive, "TF_VAR_")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	if len(env) != 1 || env[0] != "TF_VAR_OPTIONAL=null" {
		t.Errorf("got %v, want [TF_VAR_OPTIONAL=null]", env)
	}
}

func TestBuildExecEnv_SortedOrder(t *testing.T) {
	archive := []byte(`{"Z":{"value":"z"},"A":{"value":"a"},"M":{"value":"m"}}`)
	env, err := buildExecEnv(archive, "")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	want := []string{"A=a", "M=m", "Z=z"}
	if len(env) != 3 {
		t.Fatalf("got %d entries, want 3", len(env))
	}
	for i, w := range want {
		if env[i] != w {
			t.Errorf("env[%d] = %q, want %q", i, env[i], w)
		}
	}
}

func TestBuildExecEnv_MalformedJSONErrors(t *testing.T) {
	_, err := buildExecEnv([]byte(`not json`), "TF_VAR_")
	if err == nil {
		t.Fatal("expected error on malformed archive")
	}
	if !strings.Contains(err.Error(), "parse archive") {
		t.Errorf("error should mention parse, got: %v", err)
	}
}
