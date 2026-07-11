package manifest

import (
	"encoding/json"
	"fmt"
)

// CurrentPointer, bir projenin TEK mutable objesidir (`secrets/<project>/
// current`): geçerli epoch ve geçerli manifest objesinin hash'i (SPEC §5.4.4/
// §5.5). İMZASIZDIR — bir konumlandırıcıdır (locator), otorite DEĞİL. Hiçbir
// bileşen ondan güven türetemez: current çözüldükten sonra okuyucu referans
// verilen manifest'i getirir, yazar imzasını doğrular, obje baytlarının
// ManifestSha256'ya hash'lendiğini doğrular ve monotonik epoch pin'ini uygular.
type CurrentPointer struct {
	Schema         string `json:"schema"` // "wapps-secrets/current/v1"
	Project        string `json:"project"`
	Epoch          uint64 `json:"epoch"`
	ManifestSha256 string `json:"manifestSha256"` // depolanan manifest obje baytlarının hex SHA-256'sı
}

// NewCurrentPointer, verilen manifest OBJE baytlarından (imzalı sarmalayıcı)
// bir current pointer kurar; ManifestSha256'yı obje baytları üzerinden hesaplar.
func NewCurrentPointer(project string, epoch uint64, storedManifestWrapperBytes []byte) CurrentPointer {
	return CurrentPointer{
		Schema:         SchemaCurrentPointer,
		Project:        project,
		Epoch:          epoch,
		ManifestSha256: ManifestObjectHash(storedManifestWrapperBytes),
	}
}

// Marshal, current pointer'ı JSON'a serileştirir.
func (c CurrentPointer) Marshal() ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("manifest.CurrentPointer.Marshal: %w", err)
	}
	return raw, nil
}

// ParseCurrentPointer, depolanan current baytlarını ayrıştırır ve şemayı
// doğrular.
func ParseCurrentPointer(raw []byte) (CurrentPointer, error) {
	var c CurrentPointer
	if err := json.Unmarshal(raw, &c); err != nil {
		return CurrentPointer{}, fmt.Errorf("manifest.ParseCurrentPointer: %w", err)
	}
	if c.Schema != SchemaCurrentPointer {
		return CurrentPointer{}, fmt.Errorf("manifest.ParseCurrentPointer: %q: %w", c.Schema, ErrUnsupportedSchema)
	}
	return c, nil
}

// ResolveManifest, current pointer'ın referans verdiği manifest objesinin
// baytlarının pointer'daki ManifestSha256 ile eşleştiğini doğrular (SPEC §5.5
// rule 3). Eşleşmezse cryptoid.ErrBlobHashMismatch benzeri bir bütünlük
// hatası döner. Bu, imza doğrulamasının YERİNE geçmez — imza ayrıca
// VerifyDataManifest ile doğrulanmalıdır.
func (c CurrentPointer) VerifyManifestBytes(storedManifestWrapperBytes []byte) error {
	got := ManifestObjectHash(storedManifestWrapperBytes)
	if got != c.ManifestSha256 {
		return fmt.Errorf("manifest.CurrentPointer.VerifyManifestBytes: %w", ErrEpochConflict)
	}
	return nil
}
