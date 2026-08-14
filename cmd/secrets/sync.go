package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/coolify"
	"github.com/wappsdev/wapps-cli/internal/source"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

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

// projectOverride, --project ile verilen ve YEREL KAYIT DEFTERİNDE OLMAYAN bir
// proje adıdır. Store'un ihtiyacı olan tek şey ad olduğundan (list/get/rm/
// projects yerel dosyaya hiç bakmaz), böyle bir çağrı repo'suz çalışır.
var projectOverride string

// SetProjectName, cmd/root'tan çağrılır: --project bir dizine çözülemediğinde
// adın kendisi buraya düşer.
func SetProjectName(name string) { projectOverride = name }

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
	syncTarget         string
	syncCoolifyApp     string
	syncCoolifyAllApps bool
	syncCoolifyURL     string
	syncForce          bool
	syncDryRun         bool
	syncPrefix         string
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Push declared sources into the store (or to a target with --target)",
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

// runSync is the testable entry point for `wapps secrets sync`: it reads the
// declared sources, merges them, and writes the result to the store in ONE
// epoch. --dry-run reports which key NAMES would change instead of writing.
//
// lookup is os.Getenv in production; tests inject their own to drive specific
// env states without polluting the parent process.
func runSync(ctx context.Context, lookup func(string) string) error {
	cfg, err := requireStoreConfig("sync")
	if err != nil {
		return err
	}
	return runSyncStore(ctx, cfg, lookup, syncDryRun, os.Stdout)
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

// preflightTofuEnv is a thin shim that delegates to tofu.PreflightEnv so
// both `wapps secrets sync` and `wapps doctor --for tofu` share one
// implementation. Kept as a package-local function so the existing sync
// tests don't have to import the tofu package.
func preflightTofuEnv(lookup func(string) string) error {
	return tofu.PreflightEnv(lookup)
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
	syncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false,
		"show which keys would be added or changed (names only) without writing")
	syncCmd.Flags().BoolVar(&syncForce, "force", false,
		"with --target=coolify: apply the diff (default is dry-run only)")
	syncCmd.Flags().StringVar(&syncPrefix, "prefix", "",
		"with --target=coolify: prefix prepended to each pushed env var name (default empty)")
	SecretsCmd.AddCommand(syncCmd)
}
