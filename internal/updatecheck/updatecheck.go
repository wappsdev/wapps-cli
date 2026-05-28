// Package updatecheck implements a best-effort "newer release available"
// notice for the wapps CLI.
//
// Design constraints (all intentional):
//   - Never affects the command's exit code. Every error path is swallowed;
//     the worst outcome is "no notice printed".
//   - Network is hit at most once per TTL (default 24h). Between checks the
//     result is served from a small JSON cache file so day-to-day commands
//     pay zero latency.
//   - Only released binaries are eligible. Local builds carry a non-semver
//     Version ("dev", "main-<sha>") which ParseSemver rejects, so developers
//     are never nagged about their own HEAD builds.
//   - Caller decides whether to invoke (TTY-only, opt-out env var) — this
//     package just does the check + notice when asked.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

const (
	// DefaultAPIURL is GitHub's "latest release" endpoint for this repo.
	// Unauthenticated requests are rate-limited to 60/hour/IP, far above
	// our once-per-day cadence.
	DefaultAPIURL = "https://api.github.com/repos/wappsdev/wapps-cli/releases/latest"
	// DefaultTTL is how long a cached result is considered fresh.
	DefaultTTL = 24 * time.Hour
	// httpTimeout caps the one network call so a hung endpoint can't stall
	// the CLI. Tight because this runs on the user's interactive path.
	httpTimeout = 2 * time.Second
)

// Options configures a check. Zero values fall back to production defaults so
// callers only set what they need; tests override everything.
type Options struct {
	CurrentVersion string           // ldflag-injected cmd.Version
	APIURL         string           // GitHub releases-latest endpoint
	CacheDir       string           // base cache dir; file lives at <dir>/wapps/version-check.json
	TTL            time.Duration    // cache freshness window
	Now            func() time.Time // injectable clock
	HTTPClient     *http.Client     // injectable transport
}

// cacheEntry is the on-disk JSON shape. Keep field names stable — older CLIs
// must tolerate reading a cache written by a newer one.
type cacheEntry struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

// githubRelease is the slice of GitHub's release JSON we read.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// MaybeNotify performs the (cached) check and writes a one-line upgrade notice
// to w when a newer release exists. It never returns an error — the whole
// point is to be invisible when anything goes wrong.
func MaybeNotify(w io.Writer, opts Options) {
	opts = withDefaults(opts)

	current, ok := ParseSemver(opts.CurrentVersion)
	if !ok {
		// Non-release build (dev / main-<sha>) — nothing to compare against.
		return
	}

	latestStr, err := latestVersion(opts)
	if err != nil || latestStr == "" {
		return
	}
	latest, ok := ParseSemver(latestStr)
	if !ok {
		return
	}

	if Compare(latest, current) > 0 {
		// SECURITY: never print the server-supplied string verbatim. We
		// reconstruct the display version from the parsed integer triple so
		// a compromised release (e.g. tag_name="v1.0.0\x1b[2J...") can't smuggle
		// terminal escape sequences onto the user's screen — only digits and
		// dots reach stderr. Same for the local CurrentVersion, which is
		// build-controlled but reconstructed for symmetry.
		fmt.Fprintf(w, "\n⚡ wapps %s is available (you have %s). Upgrade: brew upgrade wapps\n",
			latest.String(), current.String())
	}
}

func withDefaults(o Options) Options {
	if o.APIURL == "" {
		o.APIURL = DefaultAPIURL
	}
	if o.TTL == 0 {
		o.TTL = DefaultTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: httpTimeout}
	}
	if o.CacheDir == "" {
		// os.UserCacheDir honors XDG_CACHE_HOME on Linux, ~/Library/Caches
		// on macOS. If it fails (rare), we fall back to a temp dir so the
		// check still works (just without cross-run caching).
		if dir, err := os.UserCacheDir(); err == nil {
			o.CacheDir = dir
		} else {
			o.CacheDir = os.TempDir()
		}
	}
	return o
}

// latestVersion returns the newest release tag, served from cache when fresh
// and fetched + cached otherwise.
func latestVersion(opts Options) (string, error) {
	path := cachePath(opts.CacheDir)

	if entry, err := readCache(path); err == nil {
		if opts.Now().Sub(entry.CheckedAt) < opts.TTL {
			return entry.LatestVersion, nil
		}
	}

	latest, err := fetchLatest(opts)
	if err != nil {
		return "", err
	}
	// Best-effort cache write — a failure here just means we re-fetch next run.
	_ = writeCache(path, cacheEntry{CheckedAt: opts.Now(), LatestVersion: latest})
	return latest, nil
}

func cachePath(base string) string {
	return filepath.Join(base, "wapps", "version-check.json")
}

func readCache(path string) (cacheEntry, error) {
	var e cacheEntry
	data, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	return e, nil
}

func writeCache(path string, e cacheEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// Atomic write (temp + fsync + rename, unique temp name) so two wapps
	// processes refreshing the cache concurrently can't leave a torn JSON
	// file behind. Reuses the same helper the archive paths use.
	return ageutil.WriteFileAtomic(path, data, 0644)
}

func fetchLatest(opts Options) (string, error) {
	// opts.HTTPClient.Timeout already bounds the full round trip (connect +
	// TLS + headers + body). We attach a plain cancelable context so the
	// request is torn down when this function returns, but deliberately do
	// NOT add a second timeout here — stacking two 2s deadlines could let
	// the worst case approach 4s.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.APIURL, nil)
	if err != nil {
		return "", err
	}
	// GitHub recommends a UA + the v3 accept header.
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wapps-cli")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("updatecheck: GitHub returned HTTP %d", resp.StatusCode)
	}

	var rel githubRelease
	// Cap the body read defensively — the payload we need is tiny.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// semver is a parsed MAJOR.MINOR.PATCH triple. Pre-release / build metadata is
// intentionally dropped — our release tags are clean vX.Y.Z.
type semver struct {
	major, minor, patch int
}

// String renders the canonical "vX.Y.Z" form from the parsed integers. Used
// for display so no server-supplied bytes ever reach the terminal verbatim.
func (s semver) String() string {
	return fmt.Sprintf("v%d.%d.%d", s.major, s.minor, s.patch)
}

// ParseSemver parses a "vX.Y.Z" or "X.Y.Z" string. Returns ok=false for any
// non-numeric-triple input ("dev", "main-2978d52", ""), which is how local
// builds opt out of the comparison.
func ParseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Drop any pre-release/build suffix (after - or +) defensively.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{nums[0], nums[1], nums[2]}, true
}

// Compare returns >0 if a is newer than b, <0 if older, 0 if equal.
func Compare(a, b semver) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}
