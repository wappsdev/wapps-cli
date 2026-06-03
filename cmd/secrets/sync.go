package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/coolify"
	"github.com/wappsdev/wapps-cli/internal/source"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

// defaultArchiveRel is the archive path used when no .wapps.yaml declares one.
const defaultArchiveRel = "secrets/all.enc.age"

// resolveLegacyDest resolves the default archive path against an override dir
// (when --config/--project pointed at a dir lacking a parseable .wapps.yaml),
// or returns it cwd-relative when there's no override.
func resolveLegacyDest() string {
	root := overrideRoot()
	if root == "" {
		return defaultArchiveRel
	}
	return filepath.Join(root, defaultArchiveRel)
}

// wappsYAMLPath is the default config filename, used (cwd-relative) when no
// --config/--project override has been supplied — the legacy behavior.
const wappsYAMLPath = ".wapps.yaml"

// configPathOverride is set by the root command from --config/--project. When
// non-empty it is the absolute path to a .wapps.yaml; the secrets commands load
// it instead of ./.wapps.yaml, and config.Load records its directory as the
// configRoot all relative archive/target/source paths resolve against.
//
// It is a package-level var (not threaded through every runX signature) because
// those entry points are reached via cobra RunE and adding a configRoot
// argument would churn every command + test for no behavioral gain. The seam is
// test-settable; tests must SetConfigPath("") in cleanup to avoid leaking it.
var configPathOverride string

// SetConfigPath is called by cmd/root (PersistentPreRunE) with the resolved
// absolute .wapps.yaml path, or "" for the cwd default.
func SetConfigPath(path string) { configPathOverride = path }

// wappsConfigPath returns the .wapps.yaml path to load: the override when set,
// else the cwd-relative default.
func wappsConfigPath() string {
	if configPathOverride != "" {
		return configPathOverride
	}
	return wappsYAMLPath
}

// overrideRoot returns the directory of the config override (for resolving the
// default archive path when no .wapps.yaml exists), or "" when no override is
// set (→ cwd-relative legacy behavior).
func overrideRoot() string {
	if configPathOverride == "" {
		return ""
	}
	return filepath.Dir(configPathOverride)
}

var (
	syncTarget        string
	syncCoolifyApp    string
	syncCoolifyAllApps bool
	syncCoolifyURL    string
	syncForce         bool
	syncPrefix        string
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sources → encrypted archive (or push archive to a target with --target)",
	Long: `Without --target: read all sources declared in .wapps.yaml, merge
them, and write an encrypted archive to dest.

With --target=coolify: read the existing archive and push its contents to
a Coolify application's env vars. Default is dry-run — pass --force to
actually apply (which deletes Coolify-only keys to mirror the archive).

Single-app (--app): pushes the WHOLE archive to one app, mirroring
destructively (Coolify keys absent from the archive deleted on --force).

Multi-app (--all-apps): requires coolify_sync.apps in .wapps.yaml. Each app
gets only the archive keys matching its archive_prefix, prefix stripped.
Non-destructive unless coolify_sync.delete_unmanaged: true.

  wapps secrets sync                                        # rebuild archive
  wapps secrets sync --target=coolify --app <uuid>          # single-app dry-run
  wapps secrets sync --target=coolify --app <uuid> --force  # single-app apply
  wapps secrets sync --target=coolify --all-apps            # multi-app dry-run
  wapps secrets sync --target=coolify --all-apps --force    # multi-app apply`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if syncTarget == "coolify" {
			return runSyncCoolify(coolifyOptions{
				appUUID:   syncCoolifyApp,
				allApps:   syncCoolifyAllApps,
				force:     syncForce,
				prefix:    syncPrefix,
				apiURL:    syncCoolifyURL,
				apiToken:  os.Getenv("COOLIFY_API_TOKEN"),
				stdoutW:   os.Stdout,
				newClient: defaultCoolifyClient,
			})
		}
		if syncTarget != "" {
			return fmt.Errorf("sync: unknown --target %q (allowed: coolify)", syncTarget)
		}
		return runSync(cmd.Context(), os.Getenv)
	},
}

// defaultCoolifyClient returns a real coolify.Client wrapped in the
// coolifyAPI interface. Tests substitute their own fake.
func defaultCoolifyClient(baseURL, token string) coolifyAPI {
	return coolify.New(baseURL, token)
}

// runSync is the testable entry point for `wapps secrets sync`. It picks
// between two paths:
//
//   - Legacy (no .wapps.yaml): single tofu source, dest = secrets/all.enc.age.
//     Preserves the v0.5.x behavior so existing repos continue to work.
//   - Config-driven (.wapps.yaml present): one or more sources merged into the
//     archive at the configured dest. Multi-repo rollout depends on this path.
//
// lookup is os.Getenv in production; tests inject their own to drive specific
// env states without polluting the parent process.
func runSync(ctx context.Context, lookup func(string) string) error {
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return err
	}

	if cfg == nil {
		// Legacy single-tofu path.
		if err := preflightTofuEnv(lookup); err != nil {
			return err
		}
		return syncWithTofuOutput(tofu.Output, resolveLegacyDest())
	}

	// Config-driven path. Only preflight tofu env if at least one source needs it.
	if hasTofuSource(cfg.Sources) {
		if err := preflightTofuEnv(lookup); err != nil {
			return err
		}
	}

	// ResolvedSources joins each source's path/workdir to configRoot so a
	// --project sync reads the right .env.shared / tofu dir, not cwd's.
	merged, err := readAndMerge(ctx, cfg.ResolvedSources())
	if err != nil {
		return err
	}

	passphrase := lookup("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	payload, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("secrets.sync: marshal merged: %w", err)
	}

	if err := ageutil.EncryptWriteAtomic(cfg.ResolveDest(), payload, passphrase); err != nil {
		return fmt.Errorf("secrets.sync: %w", err)
	}

	// Auto-apply targets so 'sync' fully refreshes the dev environment in
	// one command — sources → archive → consumption files.
	if err := applyTargetsAfterArchiveWrite(cfg, payload, os.Stderr); err != nil {
		return err
	}

	fmt.Printf("✓ Wrote %s (%d keys from %d sources)\n",
		cfg.Dest, len(merged), len(cfg.Sources))
	emitCommitHint(cfg.Dest)
	return nil
}

// loadOrNil returns nil when the config file doesn't exist, propagates parse
// errors so typos surface loudly. Distinguishing "file missing" from "file
// broken" is the difference between gracefully falling back to legacy mode
// and overwriting a good archive with the wrong sources.
func loadOrNil(path string) (*config.WappsYAML, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("secrets.sync: stat %s: %w", path, err)
	}
	return config.Load(path)
}

func hasTofuSource(cfgs []source.Config) bool {
	for _, c := range cfgs {
		if c.Type == "tofu" {
			return true
		}
	}
	return false
}

// readAndMerge instantiates each Source, reads it under the shared context,
// and merges results. Override warnings are printed but do not fail the sync
// (the operator may have intentionally overridden a Tofu-managed secret).
func readAndMerge(ctx context.Context, cfgs []source.Config) (map[string]json.RawMessage, error) {
	parts := make([]map[string]json.RawMessage, 0, len(cfgs))
	for i, c := range cfgs {
		src, err := source.New(c)
		if err != nil {
			return nil, fmt.Errorf("secrets.sync: sources[%d]: %w", i, err)
		}
		data, err := src.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("secrets.sync: sources[%d] (%s): %w", i, src.Name(), err)
		}
		parts = append(parts, data)
	}
	merged, overridden := source.Merge(parts)
	for _, k := range overridden {
		fmt.Fprintf(os.Stderr, "⚠ key overridden by later source: %s\n", k)
	}
	return merged, nil
}

func emitCommitHint(dest string) {
	// Split "+" + "%Y-%m-%d" emits the literal shell snippet "$(date +%Y-%m-%d)"
	// for the user's shell to evaluate. Combined into one literal would trigger
	// go vet's printf format-string check (treating %Y/%m/%d as Go format verbs).
	dateFmt := "+" + "%Y-%m-%d"
	fmt.Printf("Next: git add %s && git commit -m 'chore: secret sync $(date %s)'\n", dest, dateFmt)
}

// preflightTofuEnv is a thin shim that delegates to tofu.PreflightEnv so
// both `wapps secrets sync` and `wapps doctor --for tofu` share one
// implementation. Kept as a package-local function so the existing sync
// tests don't have to import the tofu package.
func preflightTofuEnv(lookup func(string) string) error {
	return tofu.PreflightEnv(lookup)
}

func syncWithTofuOutput(outputFn func() ([]byte, error), destPath string) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	out, err := outputFn()
	if err != nil {
		return fmt.Errorf("secrets.sync: tofu output: %w", err)
	}

	if err := ageutil.EncryptWriteAtomic(destPath, out, passphrase); err != nil {
		return fmt.Errorf("secrets.sync: %w", err)
	}

	fmt.Printf("✓ Wrote %s\n", destPath)
	emitCommitHint(destPath)
	return nil
}

func init() {
	syncCmd.Flags().StringVar(&syncTarget, "target", "",
		"sync target: empty rebuilds archive from sources; 'coolify' pushes archive to a Coolify app's env")
	syncCmd.Flags().StringVar(&syncCoolifyApp, "app", "",
		"Coolify app UUID for single-app push (mutually exclusive with --all-apps)")
	syncCmd.Flags().BoolVar(&syncCoolifyAllApps, "all-apps", false,
		"push to every app in .wapps.yaml's coolify_sync.apps (prefix-stripped, non-destructive)")
	syncCmd.Flags().StringVar(&syncCoolifyURL, "coolify-url", "https://coolify.meapps.dev/api/v1",
		"Coolify API base URL")
	syncCmd.Flags().BoolVar(&syncForce, "force", false,
		"with --target=coolify: apply the diff (default is dry-run only)")
	syncCmd.Flags().StringVar(&syncPrefix, "prefix", "",
		"with --target=coolify: prefix prepended to each pushed env var name (default empty)")
	SecretsCmd.AddCommand(syncCmd)
}
