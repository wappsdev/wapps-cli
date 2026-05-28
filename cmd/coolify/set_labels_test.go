package coolify

import (
	"strings"
	"testing"
)

// TestSetLabels_RefusesEmptyLabels is the regression for the silent
// data-loss bug where set-labels with no --label flag would PATCH
// custom_labels="" and wipe every existing label on the application.
// Coolify treats empty custom_labels as "clear", not "no-op", so the CLI
// has to refuse the request before it reaches the wire.
func TestSetLabels_RefusesEmptyLabels(t *testing.T) {
	// Save and restore module-level flag state — cobra writes into package
	// vars and the test parallels this.
	prevLabels := slLabels
	prevApp := slAppUUID
	prevStrip := slStripCert
	t.Cleanup(func() {
		slLabels = prevLabels
		slAppUUID = prevApp
		slStripCert = prevStrip
	})

	slLabels = nil
	slAppUUID = "test-app"
	slStripCert = false
	t.Setenv("COOLIFY_API_TOKEN", "fake")

	err := setLabelsCmd.RunE(setLabelsCmd, []string{})
	if err == nil {
		t.Fatal("expected error when no labels provided")
	}
	if !strings.Contains(err.Error(), "no labels") {
		t.Errorf("error should explain refusal, got: %v", err)
	}
}

// TestSetLabels_StripCertResolverEmptyAfterFilter_Refuses confirms the
// guard fires even when the caller DID pass labels but every one of them
// was stripped by --strip-cert-resolver. Without this, an operator who
// only had cert-resolver labels would have those silently dropped and
// then everything else wiped too.
func TestSetLabels_StripCertResolverEmptyAfterFilter_Refuses(t *testing.T) {
	prevLabels := slLabels
	prevApp := slAppUUID
	prevStrip := slStripCert
	t.Cleanup(func() {
		slLabels = prevLabels
		slAppUUID = prevApp
		slStripCert = prevStrip
	})

	slLabels = []string{"traefik.http.routers.x.tls.certresolver=letsencrypt"}
	slAppUUID = "test-app"
	slStripCert = true
	t.Setenv("COOLIFY_API_TOKEN", "fake")

	err := setLabelsCmd.RunE(setLabelsCmd, []string{})
	if err == nil {
		t.Fatal("expected error when filter produces empty label set")
	}
}
