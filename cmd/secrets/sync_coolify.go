package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/coolify"
)

// coolifyOptions wires the Coolify-direction sync. Most fields are flag-
// driven from cmd/secrets/sync.go; coolifyClient is injected so tests can
// substitute a fake transport.
type coolifyOptions struct {
	appUUID   string
	force     bool
	prefix    string
	apiURL    string
	apiToken  string
	stdoutW   *os.File // dry-run output goes here (os.Stdout in prod)
	newClient func(baseURL, token string) coolifyAPI
}

// coolifyAPI is the slice of coolify.Client we depend on, exposed via
// interface so tests inject a fake without spinning up an httptest server.
type coolifyAPI interface {
	ListAppEnvs(appUUID string) ([]coolify.EnvEntry, error)
	UpsertAppEnv(appUUID, key, value string, isBuildtime bool) error
	DeleteAppEnv(appUUID, envUUID string) error
}

// runSyncCoolify is the testable entry point for
// `wapps secrets sync --target=coolify`.
//
// Dispatches to the destructive-mirror Coolify sync flow:
//  1. Load .wapps.yaml (required — dest path comes from there)
//  2. Decrypt archive
//  3. List current Coolify env state on appUUID
//  4. Compute diff (add / change / remove buckets)
//  5. Print diff to stdout — operator-visible regardless of mode
//  6. If --force: apply (upsert add/change, delete remove)
//     Else (dry-run default): stop after printing — Issue 2 D3 decision
//
// Token comes from COOLIFY_API_TOKEN; URL from --coolify-url or default.
func runSyncCoolify(opts coolifyOptions) error {
	if opts.appUUID == "" {
		return fmt.Errorf("sync --target=coolify: --app <uuid> required")
	}
	if opts.apiToken == "" {
		return fmt.Errorf("sync --target=coolify: COOLIFY_API_TOKEN not set")
	}

	cfg, err := loadOrNil(wappsYAMLPath)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("sync --target=coolify: .wapps.yaml required (need dest path for archive)")
	}

	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("sync --target=coolify: WAPPS_SECRETS_PASSPHRASE not set")
	}

	archive, err := decryptArchive(cfg.Dest, passphrase)
	if err != nil {
		return err
	}

	desired := archiveToFlatMap(archive, opts.prefix)

	client := opts.newClient(opts.apiURL, opts.apiToken)
	current, err := client.ListAppEnvs(opts.appUUID)
	if err != nil {
		return fmt.Errorf("sync --target=coolify: %w", err)
	}

	diff := computeCoolifyDiff(desired, current)
	writeCoolifyDiff(opts.stdoutW, diff)

	if !opts.force {
		fmt.Fprintln(opts.stdoutW, "\nDry-run only. Re-run with --force to apply.")
		return nil
	}

	return applyCoolifyDiff(client, opts.appUUID, diff)
}

// coolifyDiff buckets desired vs current Coolify state. Computed before
// any API write so the operator sees what's about to happen.
type coolifyDiff struct {
	add    map[string]string         // key → desired value (POST)
	change map[string]coolifyChange  // key → {old, new} (PATCH)
	remove map[string]string         // key → env-uuid (DELETE)
	noop   []string                  // keys identical on both sides (visibility)
}

type coolifyChange struct {
	oldValue string
	newValue string
}

func computeCoolifyDiff(desired map[string]string, current []coolify.EnvEntry) coolifyDiff {
	diff := coolifyDiff{
		add:    make(map[string]string),
		change: make(map[string]coolifyChange),
		remove: make(map[string]string),
	}
	currentByKey := make(map[string]coolify.EnvEntry, len(current))
	for _, e := range current {
		currentByKey[e.Key] = e
	}

	for key, desiredVal := range desired {
		if existing, ok := currentByKey[key]; ok {
			if existing.Value != desiredVal {
				diff.change[key] = coolifyChange{oldValue: existing.Value, newValue: desiredVal}
			} else {
				diff.noop = append(diff.noop, key)
			}
		} else {
			diff.add[key] = desiredVal
		}
	}
	for key, existing := range currentByKey {
		if _, ok := desired[key]; !ok {
			diff.remove[key] = existing.UUID
		}
	}
	return diff
}

// writeCoolifyDiff prints a human-readable diff to w. Always called (in both
// dry-run and --force modes) so the operator has a record of what changed.
// Values are NOT printed for changes/adds — only key names and counts —
// because the diff itself may be captured by the agent transcript.
func writeCoolifyDiff(w *os.File, diff coolifyDiff) {
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintln(w, "Coolify env diff:")
	fmt.Fprintf(w, "  + %d to ADD\n", len(diff.add))
	for _, k := range sortedKeys(diff.add) {
		fmt.Fprintf(w, "      %s\n", k)
	}
	fmt.Fprintf(w, "  ~ %d to CHANGE\n", len(diff.change))
	for _, k := range sortedKeysOfChange(diff.change) {
		fmt.Fprintf(w, "      %s\n", k)
	}
	fmt.Fprintf(w, "  - %d to REMOVE\n", len(diff.remove))
	for _, k := range sortedKeys(diff.remove) {
		fmt.Fprintf(w, "      %s\n", k)
	}
	fmt.Fprintf(w, "  = %d unchanged\n", len(diff.noop))
}

func applyCoolifyDiff(client coolifyAPI, appUUID string, diff coolifyDiff) error {
	for _, key := range sortedKeys(diff.add) {
		if err := client.UpsertAppEnv(appUUID, key, diff.add[key], false); err != nil {
			return fmt.Errorf("apply ADD %s: %w", key, err)
		}
	}
	for _, key := range sortedKeysOfChange(diff.change) {
		if err := client.UpsertAppEnv(appUUID, key, diff.change[key].newValue, false); err != nil {
			return fmt.Errorf("apply CHANGE %s: %w", key, err)
		}
	}
	for _, key := range sortedKeys(diff.remove) {
		if err := client.DeleteAppEnv(appUUID, diff.remove[key]); err != nil {
			return fmt.Errorf("apply REMOVE %s: %w", key, err)
		}
	}
	fmt.Fprintf(os.Stdout, "✓ Applied: %d added, %d changed, %d removed\n",
		len(diff.add), len(diff.change), len(diff.remove))
	return nil
}

// archiveToFlatMap unwraps the tofu-output-shaped envelopes into flat
// key→value strings ready for Coolify. Non-string values (list/map/bool/
// number) are emitted as their compact JSON representation — Coolify
// stores them as strings, callers that need structured types parse JSON
// on the consumer side (same convention as `wapps secrets env --write`).
//
// Slice-aliasing note: we MUST declare a fresh envelope struct here. An
// earlier draft pre-populated Value=raw to avoid an extra allocation, but
// json.RawMessage's UnmarshalJSON reuses the backing array via append,
// which silently corrupted raw mid-loop (test output "bar"ue":"bar"} —
// the trailing bytes of the original survived after a shorter parse).
func archiveToFlatMap(archive map[string]json.RawMessage, prefix string) map[string]string {
	out := make(map[string]string, len(archive))
	for key, raw := range archive {
		var envelope struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Value) == 0 {
			// Not the tofu-output shape — emit the raw bytes as-is.
			out[prefix+key] = string(raw)
			continue
		}
		var s string
		if err := json.Unmarshal(envelope.Value, &s); err == nil {
			out[prefix+key] = s
			continue
		}
		// Non-string value: emit compact JSON (Coolify stores as string).
		out[prefix+key] = strings.TrimSpace(string(envelope.Value))
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOfChange(m map[string]coolifyChange) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
