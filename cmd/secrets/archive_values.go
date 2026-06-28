package secrets

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// ArchiveValues reads the config-resolved archive (honoring --config/--project
// via resolveArchivePath) and returns the values of the requested keys that are
// present. Missing keys are simply absent from the returned map.
//
// Availability is best-effort: when WAPPS_SECRETS_PASSPHRASE is unset or the
// archive file does not exist, it returns (nil, nil) so callers (e.g.
// `wapps deploy`) can fall back to environment variables without an error. A
// genuine read/decrypt/parse failure (archive present + passphrase set but
// wrong or corrupt) IS returned as an error.
//
// AI-safe: returns values only to the caller; never prints them. Exposed so
// non-secrets commands (deploy) can resolve credentials from the archive
// through the same config-root path resolution.
func ArchiveValues(keys ...string) (map[string]string, error) {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return nil, nil
	}
	archivePath := resolveArchivePath()
	enc, err := os.ReadFile(archivePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: read archive %s: %w", archivePath, err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt archive: %w", err)
	}
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(dec, &outputs); err != nil {
		return nil, fmt.Errorf("secrets: parse archive: %w", err)
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if entry, ok := outputs[k]; ok {
			out[k] = rawValueToString(entry.Value)
		}
	}
	return out, nil
}
