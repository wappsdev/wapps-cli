package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

// coolifyOptions wires the Coolify-direction sync. Most fields are flag-
// driven from cmd/secrets/sync.go; coolifyClient is injected so tests can
// substitute a fake transport.
type coolifyOptions struct {
	appUUID   string
	allApps   bool   // multi-app mode driven by coolify_sync.apps in .wapps.yaml
	force     bool
	prefix    string
	apiURL    string
	apiToken  string
	stdoutW   io.Writer // dry-run output goes here (os.Stdout in prod, buffer in tests)
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
	if opts.appUUID != "" && opts.allApps {
		return fmt.Errorf("sync --target=coolify: --app and --all-apps are mutually exclusive")
	}
	if opts.appUUID == "" && !opts.allApps {
		return fmt.Errorf("sync --target=coolify: one of --app <uuid> or --all-apps required")
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

	client := opts.newClient(opts.apiURL, opts.apiToken)

	if opts.allApps {
		return runSyncCoolifyAllApps(opts, cfg, archive, client)
	}

	// Single-app, whole-archive destructive-mirror path (unchanged: vaulter
	// depends on it). deleteUnmanaged=true preserves the documented behavior
	// where Coolify keys absent from the archive are removed.
	desired := archiveToFlatMap(archive, opts.prefix)

	current, err := client.ListAppEnvs(opts.appUUID)
	if err != nil {
		return fmt.Errorf("sync --target=coolify: %w", err)
	}

	// Single-app honors the is_coolify filter (a universal correctness fix —
	// never PATCH a read-only managed env) but not exclude_keys, which is a
	// multi-app coolify_sync concept.
	diff := computeCoolifyDiff(desired, current, true, nil)
	writeCoolifyDiff(opts.stdoutW, diff)

	if !opts.force {
		fmt.Fprintln(opts.stdoutW, "\nDry-run only. Re-run with --force to apply.")
		return nil
	}

	return applyCoolifyDiff(client, opts.appUUID, diff, opts.stdoutW)
}

// runSyncCoolifyAllApps pushes a multi-app archive to each app declared in
// coolify_sync.apps. Per app: filter the archive to keys matching the app's
// archive_prefix, strip the prefix, diff against live Coolify state, print,
// and (with --force) apply. Non-destructive by default (delete_unmanaged).
//
// Failure isolation: an error on one app (e.g. 404 on a stale UUID) is
// reported and the remaining apps still run. Any failure makes the whole
// command exit non-zero so CI/scripts notice.
func runSyncCoolifyAllApps(opts coolifyOptions, cfg *config.WappsYAML, archive map[string]json.RawMessage, client coolifyAPI) error {
	w := opts.stdoutW
	if w == nil {
		w = os.Stdout
	}
	cs := cfg.CoolifySync
	if cs == nil || len(cs.Apps) == 0 {
		return fmt.Errorf("sync --target=coolify --all-apps: no apps configured (add a coolify_sync.apps block to %s)", wappsYAMLPath)
	}

	excludeKeys := make(map[string]bool, len(cs.ExcludeKeys))
	for _, k := range cs.ExcludeKeys {
		excludeKeys[k] = true
	}

	var failed []string
	for _, app := range cs.Apps {
		label := app.Name
		if label == "" {
			label = app.UUID
		}

		desired := archiveToAppMap(archive, app.ArchivePrefix)
		if len(desired) == 0 {
			// Non-fatal: a prefix matching nothing is usually a config typo
			// or an app not yet populated. Warn (names only) and move on.
			fmt.Fprintf(w, "\n⚠ %s: 0 keys matched prefix %q — skipping\n", label, app.ArchivePrefix)
			continue
		}

		current, err := client.ListAppEnvs(app.UUID)
		if err != nil {
			fmt.Fprintf(w, "\n✗ %s (%s): list envs failed: %v\n", label, app.UUID, err)
			failed = append(failed, app.UUID)
			continue
		}

		diff := computeCoolifyDiff(desired, current, cs.DeleteUnmanaged, excludeKeys)
		fmt.Fprintf(w, "\n=== %s (%s) ===\n", label, app.UUID)
		writeCoolifyDiff(w, diff)

		if opts.force {
			if err := applyCoolifyDiff(client, app.UUID, diff, w); err != nil {
				// Apply is fail-fast: some keys for this app may already be
				// written. That's safe to recover from — the next --all-apps
				// run recomputes the diff from live Coolify state, so applied
				// keys become no-ops and the rest (including any pending
				// deletes) are retried. We tell the operator that explicitly.
				fmt.Fprintf(w, "✗ %s apply failed (partial — re-run 'sync --all-apps --force' to finish; it's idempotent): %v\n", label, err)
				failed = append(failed, app.UUID)
			}
		}
	}

	if !opts.force {
		fmt.Fprintln(w, "\nDry-run only. Re-run with --all-apps --force to apply.")
	}
	if len(failed) > 0 {
		return fmt.Errorf("sync --target=coolify --all-apps: %d app(s) failed: %s", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// coolifyDiff buckets desired vs current Coolify state. Computed before
// any API write so the operator sees what's about to happen.
type coolifyDiff struct {
	add    map[string]string         // key → desired value (POST)
	change map[string]coolifyChange  // key → {old, new} (PATCH)
	remove map[string]string         // key → env-uuid (DELETE)
	noop   []string                  // keys identical on both sides (visibility)

	// Filtered-out keys, surfaced for operator visibility (names never
	// printed — only counts). skippedManaged are Coolify-generated
	// (is_coolify=true) read-only envs; skippedExcluded matched the
	// operator's coolify_sync.exclude_keys deny-list; skippedPreview are
	// per-PR preview-deployment copies (is_preview=true) — we manage only
	// the runtime entry.
	skippedManaged  int
	skippedExcluded int
	skippedPreview  int
}

// coolifyChange tracks the desired (new) value for a key whose current
// Coolify value differs. We deliberately do NOT carry the old value across
// the apply step — earlier versions kept it for "future diff display" that
// was never used and meant the Coolify-side plaintext lived in memory for
// the whole apply phase as a GC-visible string.
type coolifyChange struct {
	newValue string
}

// computeCoolifyDiff buckets desired vs current. When deleteUnmanaged is
// false, the remove bucket stays empty — Coolify keys absent from `desired`
// are left untouched (additive merge). The single-app mirror path passes
// true (its documented destructive behavior); multi-app passes the
// coolify_sync.delete_unmanaged config value (default false).
//
// Two classes of KEYS are filtered out of BOTH desired and current before
// bucketing, so they can never land in add/change/remove:
//   - Coolify-managed (is_coolify=true): read-only "magic" envs Coolify
//     generates. A PATCH would 422; a DELETE under delete_unmanaged would
//     fight Coolify. Dropping them from desired too prevents a stale archive
//     copy from being re-added.
//   - excludeKeys: operator deny-list (stripped names) for pipeline-owned
//     keys like SENTRY_RELEASE that perpetually drift.
//
// One class of ENTRIES (not keys) is filtered from current only:
//   - preview (is_preview=true): Coolify returns the same key twice when it's
//     defined for both runtime and preview, with possibly different values.
//     We manage the runtime entry (is_preview=false); the preview copy is
//     ignored. The key stays in desired and diffs against the runtime value,
//     so a preview dup no longer shows perpetual false drift. A key existing
//     ONLY as preview is treated as absent from current.
func computeCoolifyDiff(desired map[string]string, current []coolify.EnvEntry, deleteUnmanaged bool, excludeKeys map[string]bool) coolifyDiff {
	diff := coolifyDiff{
		add:    make(map[string]string),
		change: make(map[string]coolifyChange),
		remove: make(map[string]string),
	}

	// Build the skip set from Coolify-managed keys (seen in current) plus the
	// operator deny-list, and copy desired so we can prune it non-destructively.
	skip := make(map[string]bool)
	for _, e := range current {
		if e.IsCoolify {
			skip[e.Key] = true
			diff.skippedManaged++
		}
	}
	prunedDesired := make(map[string]string, len(desired))
	for k, v := range desired {
		prunedDesired[k] = v
	}
	for k := range excludeKeys {
		// Count an exclusion only when it would otherwise have mattered
		// (present on either side), so the visibility line isn't noisy with
		// deny-list entries that don't apply to this app.
		_, inDesired := prunedDesired[k]
		if inDesired || keyInCurrent(current, k) {
			if !skip[k] {
				diff.skippedExcluded++
			}
		}
		skip[k] = true
	}

	currentByKey := make(map[string]coolify.EnvEntry, len(current))
	for _, e := range current {
		if skip[e.Key] {
			continue
		}
		if e.IsPreview {
			// Per-PR preview copy — ignore. If the key also has a runtime
			// (is_preview=false) entry, that one populates currentByKey; if
			// it exists only as preview, the key is correctly absent from
			// current (not a runtime env we manage).
			diff.skippedPreview++
			continue
		}
		currentByKey[e.Key] = e
	}
	for k := range skip {
		delete(prunedDesired, k)
	}

	for key, desiredVal := range prunedDesired {
		if existing, ok := currentByKey[key]; ok {
			if existing.Value != desiredVal {
				diff.change[key] = coolifyChange{newValue: desiredVal}
			} else {
				diff.noop = append(diff.noop, key)
			}
		} else {
			diff.add[key] = desiredVal
		}
	}
	if deleteUnmanaged {
		for key, existing := range currentByKey {
			if _, ok := prunedDesired[key]; !ok {
				diff.remove[key] = existing.UUID
			}
		}
	}
	return diff
}

func keyInCurrent(current []coolify.EnvEntry, key string) bool {
	for _, e := range current {
		if e.Key == key {
			return true
		}
	}
	return false
}

// writeCoolifyDiff prints a human-readable diff to w. Always called (in both
// dry-run and --force modes) so the operator has a record of what changed.
// Values are NOT printed for changes/adds — only key names and counts —
// because the diff itself may be captured by the agent transcript.
func writeCoolifyDiff(w io.Writer, diff coolifyDiff) {
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
	if diff.skippedManaged > 0 {
		fmt.Fprintf(w, "  (skipped %d Coolify-managed keys)\n", diff.skippedManaged)
	}
	if diff.skippedExcluded > 0 {
		fmt.Fprintf(w, "  (skipped %d excluded keys)\n", diff.skippedExcluded)
	}
	if diff.skippedPreview > 0 {
		fmt.Fprintf(w, "  (skipped %d preview-context entries)\n", diff.skippedPreview)
	}
}

func applyCoolifyDiff(client coolifyAPI, appUUID string, diff coolifyDiff, w io.Writer) error {
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
	// Write through the injected writer (test buffer or os.Stdout in prod).
	// Earlier this hard-coded os.Stdout, which bypassed the stdoutW
	// discipline the rest of the function uses.
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "✓ Applied: %d added, %d changed, %d removed\n",
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
		out[prefix+key] = unwrapArchiveValue(raw)
	}
	return out
}

// archiveToAppMap is the multi-app counterpart of archiveToFlatMap: it
// selects only the archive keys that start with archivePrefix and STRIPS that
// prefix (the opposite of archiveToFlatMap's prepend). Keys not matching the
// prefix are excluded entirely — this is how Tofu outputs (lab_01_*) and other
// apps' keys are kept out of this app's push.
//
// A key equal to the prefix (stripping to "") is skipped: an empty env var
// name is never valid.
func archiveToAppMap(archive map[string]json.RawMessage, archivePrefix string) map[string]string {
	out := make(map[string]string)
	for key, raw := range archive {
		if !strings.HasPrefix(key, archivePrefix) {
			continue
		}
		stripped := strings.TrimPrefix(key, archivePrefix)
		if stripped == "" {
			continue
		}
		out[stripped] = unwrapArchiveValue(raw)
	}
	return out
}

// unwrapArchiveValue converts a single archive entry to the flat string Coolify
// stores. Tofu-output-shaped envelopes ({"value": ...}) are unwrapped; string
// values emit verbatim, non-string values (list/map/bool/number) emit their
// compact JSON. Bytes that aren't the envelope shape pass through unchanged.
//
// Slice-aliasing note: the envelope struct MUST be declared fresh per call.
// An earlier draft reused a Value=raw field; json.RawMessage's UnmarshalJSON
// appends onto the backing array and silently corrupted the source bytes.
func unwrapArchiveValue(raw json.RawMessage) string {
	var envelope struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Value) == 0 {
		return string(raw)
	}
	var s string
	if err := json.Unmarshal(envelope.Value, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(envelope.Value))
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
