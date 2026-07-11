package rotation

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// MigratedSentinelKey, tombstone sentinel anahtarıdır (SPEC §10.2.7). Bayat bir
// checkout legacy arşivi çözdüğünde bunu görüp GÜRÜLTÜLÜ başarısız olmalı.
const MigratedSentinelKey = "__MIGRATED__"

// MigratedSentinel, __MIGRATED__ tombstone gövdesidir (§10.2.7).
type MigratedSentinel struct {
	Project    string `json:"project"`
	Store      string `json:"store"`
	MigratedAt string `json:"migrated_at"`
	Action     string `json:"action"`
}

// BuildTombstonePlaintext, {"__MIGRATED__": {...}} düz-metnini üretir (§10.2.7).
func BuildTombstonePlaintext(project, migratedAt string) ([]byte, error) {
	body := map[string]MigratedSentinel{
		MigratedSentinelKey: {
			Project:    project,
			Store:      "wapps-secrets",
			MigratedAt: migratedAt,
			Action:     "run `wapps secrets exec` in this repo; the git archive is retired",
		},
	}
	return json.Marshal(body)
}

// BuildTombstone, tombstone düz-metnini legacy passphrase ile şifreleyip age blob'u
// döner (§10.2.7). Bu blob, legacy all.enc.age'in ÜZERİNE yazılır → passphrase'i olan
// bayat bir checkout onu çözünce ölü değerler yerine sentinel'i görür.
func BuildTombstone(project, migratedAt, passphrase string) ([]byte, error) {
	pt, err := BuildTombstonePlaintext(project, migratedAt)
	if err != nil {
		return nil, fmt.Errorf("rotation.BuildTombstone: %w", err)
	}
	blob, err := ageutil.Encrypt(pt, passphrase)
	if err != nil {
		return nil, fmt.Errorf("rotation.BuildTombstone: encrypt: %w", err)
	}
	return blob, nil
}

// guardLegacyWrite, IRON RULE (§10.5) kod-yaptırımıdır: legacy arşive YAZILABİLECEK
// TEK şey __MIGRATED__ tombstone'udur. Rotate edilen bir gizli değer buradan geçemez
// → ErrIronRuleViolation. (Düz-metin TAM olarak {"__MIGRATED__": ...} tek-anahtarlı
// obje olmalı.)
func guardLegacyWrite(plaintext []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return fmt.Errorf("rotation.guardLegacyWrite: not the tombstone sentinel: %w", ErrIronRuleViolation)
	}
	if len(m) != 1 {
		return fmt.Errorf("rotation.guardLegacyWrite: legacy write must be the sole __MIGRATED__ sentinel: %w", ErrIronRuleViolation)
	}
	if _, ok := m[MigratedSentinelKey]; !ok {
		return fmt.Errorf("rotation.guardLegacyWrite: missing __MIGRATED__ sentinel: %w", ErrIronRuleViolation)
	}
	return nil
}

// WriteTombstone, legacy arşivin (archivePath) ÜZERİNE tombstone yazar — legacy'e
// izin verilen TEK yazma (§10.2.7). IRON RULE guard'ı (§10.5) düz-metnin yalnızca
// __MIGRATED__ sentinel'i olduğunu ZORLAR: başka herhangi bir içerik (rotate edilmiş
// bir değer dahil) ErrIronRuleViolation ile reddedilir. Gerçek pre-tombstone
// snapshot'ı git TAG'i olarak saklanır (§10.2.8, insan-eliyle).
func WriteTombstone(archivePath string, plaintext []byte, passphrase string) error {
	if err := guardLegacyWrite(plaintext); err != nil {
		return err
	}
	blob, err := ageutil.Encrypt(plaintext, passphrase)
	if err != nil {
		return fmt.Errorf("rotation.WriteTombstone: encrypt: %w", err)
	}
	if err := os.WriteFile(archivePath, blob, 0o600); err != nil {
		return fmt.Errorf("rotation.WriteTombstone: write %s: %w", archivePath, err)
	}
	return nil
}

// DetectMigrated, bir legacy ciphertext'i passphrase ile çözer ve __MIGRATED__
// tombstone'u taşıyorsa sentinel'i + true döner (§10.2.7 bayat-okuma tespiti).
func DetectMigrated(ciphertext []byte, passphrase string) (*MigratedSentinel, bool, error) {
	plaintext, err := ageutil.Decrypt(ciphertext, passphrase)
	if err != nil {
		return nil, false, fmt.Errorf("rotation.DetectMigrated: decrypt: %w", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &body); err != nil {
		return nil, false, nil // düz JSON değil → tombstone değil
	}
	raw, ok := body[MigratedSentinelKey]
	if !ok {
		return nil, false, nil
	}
	var s MigratedSentinel
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false, fmt.Errorf("rotation.DetectMigrated: sentinel body: %w", err)
	}
	return &s, true, nil
}

// ReadLegacyOrMigrated, legacy-yol CLI kodunun bayat-okuma-korumasıdır (§10.2.7):
// arşiv tombstoned ise ErrArchiveMigrated ile GÜRÜLTÜLÜ başarısız olur (kurtarma
// komutunu adlandıran); aksi halde çözülmüş düz-metni döner.
func ReadLegacyOrMigrated(ciphertext []byte, passphrase string) ([]byte, error) {
	if _, migrated, err := DetectMigrated(ciphertext, passphrase); err != nil {
		return nil, err
	} else if migrated {
		return nil, ErrArchiveMigrated
	}
	return ageutil.Decrypt(ciphertext, passphrase)
}
