package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// diffSetup writes the current archive to disk and returns a closure that
// produces "ref" archive bytes from an arbitrary key→value map. Tests inject
// the closure as gitShowFn to avoid needing a real git history.
func diffSetup(t *testing.T, current map[string]string) (gitShowFn, func(map[string]string)) {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "diff-test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	encrypt := func(m map[string]string) []byte {
		envelope := make(map[string]json.RawMessage)
		for k, v := range m {
			b, _ := json.Marshal(map[string]string{"value": v})
			envelope[k] = b
		}
		raw, _ := json.Marshal(envelope)
		enc, err := ageutil.Encrypt(raw, pp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return enc
	}

	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", encrypt(current), 0600); err != nil {
		t.Fatalf("write current: %v", err)
	}

	var refArchive []byte
	gitShow := func(ref, path string) ([]byte, error) {
		if refArchive == nil {
			return nil, fmt.Errorf("ref %s not staged in test", ref)
		}
		return refArchive, nil
	}
	stageRef := func(m map[string]string) {
		refArchive = encrypt(m)
	}
	return gitShow, stageRef
}

func TestRunDiff_AddedKey(t *testing.T) {
	gitShow, stageRef := diffSetup(t,
		map[string]string{"FOO": "1", "NEW_KEY": "x"})
	stageRef(map[string]string{"FOO": "1"})

	var buf bytes.Buffer
	if err := runDiff("HEAD~1", gitShow, &buf); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "+ NEW_KEY") {
		t.Errorf("output should mark NEW_KEY added, got:\n%s", got)
	}
	if !strings.Contains(got, "1 unchanged") {
		t.Errorf("output should report unchanged count, got:\n%s", got)
	}
}

func TestRunDiff_RemovedKey(t *testing.T) {
	gitShow, stageRef := diffSetup(t, map[string]string{"KEPT": "y"})
	stageRef(map[string]string{"KEPT": "y", "GONE": "x"})

	var buf bytes.Buffer
	if err := runDiff("HEAD~1", gitShow, &buf); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "- GONE") {
		t.Errorf("output should mark GONE removed, got:\n%s", buf.String())
	}
}

func TestRunDiff_ChangedKey(t *testing.T) {
	gitShow, stageRef := diffSetup(t, map[string]string{"K": "new"})
	stageRef(map[string]string{"K": "old"})

	var buf bytes.Buffer
	if err := runDiff("HEAD~1", gitShow, &buf); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "~ K") {
		t.Errorf("output should mark K changed, got:\n%s", buf.String())
	}
}

func TestRunDiff_NoChanges(t *testing.T) {
	gitShow, stageRef := diffSetup(t, map[string]string{"A": "1", "B": "2"})
	stageRef(map[string]string{"A": "1", "B": "2"})

	var buf bytes.Buffer
	if err := runDiff("HEAD~1", gitShow, &buf); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes") {
		t.Errorf("output should report no changes, got:\n%s", buf.String())
	}
}

func TestRunDiff_NeverPrintsValues(t *testing.T) {
	// AI-safety contract: values must never reach stdout, even for changed keys.
	secret := "P@ssw0rd-shouldnt-leak"
	gitShow, stageRef := diffSetup(t, map[string]string{"SECRET": secret})
	stageRef(map[string]string{"SECRET": "old-value-also-shouldnt-leak"})

	var buf bytes.Buffer
	if err := runDiff("HEAD~1", gitShow, &buf); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Errorf("new value leaked to stdout: %q", buf.String())
	}
	if strings.Contains(buf.String(), "old-value-also-shouldnt-leak") {
		t.Errorf("old value leaked to stdout: %q", buf.String())
	}
}

func TestRunDiff_RotationDetected(t *testing.T) {
	// Stage ref archive encrypted with a DIFFERENT passphrase to simulate
	// rotation between ref and current. Decrypt fails → friendly error.
	tmp := t.TempDir()
	t.Chdir(tmp)
	currentPP := "current-pp"
	otherPP := "rotated-from-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", currentPP)

	mkArchive := func(pp string, m map[string]string) []byte {
		envelope := make(map[string]json.RawMessage)
		for k, v := range m {
			b, _ := json.Marshal(map[string]string{"value": v})
			envelope[k] = b
		}
		raw, _ := json.Marshal(envelope)
		enc, _ := ageutil.Encrypt(raw, pp)
		return enc
	}

	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", mkArchive(currentPP, map[string]string{"A": "1"}), 0600); err != nil {
		t.Fatalf("write current: %v", err)
	}
	refArchive := mkArchive(otherPP, map[string]string{"A": "0"})
	gitShow := func(ref, path string) ([]byte, error) { return refArchive, nil }

	err := runDiff("HEAD~1", gitShow, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected decrypt error across rotation")
	}
	if !strings.Contains(err.Error(), "rotation") {
		t.Errorf("error should hint at rotation, got: %v", err)
	}
}

func TestRunDiff_NoPassphrase_Errors(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	os.Unsetenv("WAPPS_SECRETS_PASSPHRASE")

	err := runDiff("HEAD~1", nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when passphrase missing")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var: %v", err)
	}
	_ = tmp
}

func TestRunDiff_GitShowFailure_Propagates(t *testing.T) {
	gitShow, _ := diffSetup(t, map[string]string{"FOO": "1"})
	// Don't stage ref → gitShow returns "ref not staged" error.
	_ = gitShow

	failingGitShow := func(ref, path string) ([]byte, error) {
		return nil, fmt.Errorf("fatal: bad revision 'noexist'")
	}

	err := runDiff("noexist", failingGitShow, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when ref doesn't exist")
	}
	if !strings.Contains(err.Error(), "fetch archive at noexist") {
		t.Errorf("error should mention fetch failure, got: %v", err)
	}
}

func TestParseArchiveValueHashes_NormalizesWhitespace(t *testing.T) {
	// Same value with different whitespace should hash equal.
	a, err := parseArchiveValueHashes([]byte(`{"K":{"value":"hello"}}`))
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	b, err := parseArchiveValueHashes([]byte(`{"K":{"value":  "hello"  }}`))
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if a["K"] != b["K"] {
		t.Errorf("whitespace-different but value-equal should hash equal: %q vs %q", a["K"], b["K"])
	}
}

func TestParseArchiveValueHashes_DifferentValuesHashDifferent(t *testing.T) {
	a, _ := parseArchiveValueHashes([]byte(`{"K":{"value":"a"}}`))
	b, _ := parseArchiveValueHashes([]byte(`{"K":{"value":"b"}}`))
	if a["K"] == b["K"] {
		t.Error("different values must produce different hashes")
	}
}

// TestGitShowRunner_RefusesFlagShapedRef closes argv-injection vectors where
// `ref` is "--upload-pack=evil" or similar — git would otherwise treat it as
// an option flag. The dash-prefix rejection matches git-check-ref-format(1)
// which forbids leading '-' in legitimate ref names.
func TestGitShowRunner_RefusesFlagShapedRef(t *testing.T) {
	for _, badRef := range []string{
		"-foo",
		"--upload-pack=/bin/sh",
		"--config=core.sshCommand=evil",
	} {
		t.Run(badRef, func(t *testing.T) {
			_, err := gitShowRunner(badRef, "secrets/all.enc.age")
			if err == nil {
				t.Fatalf("gitShowRunner should refuse ref %q", badRef)
			}
			if !strings.Contains(err.Error(), "starts with '-'") {
				t.Errorf("error should explain dash-prefix rejection, got: %v", err)
			}
		})
	}
}
