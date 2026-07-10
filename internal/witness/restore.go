package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// DR restore (SPEC §9.5): append-only escrow temsilinden bir projenin `current`
// pointer'ını YENİDEN KURAR ve escrow DEK wrap'lerini yeniden kurulan escrow
// özel anahtarıyla açar. İki restore yolu (§9.5.3: A restore-in-place, B full
// rebuild) escrow-replay mantığında AYNIDIR; farkları estate provisioning'de
// (Path B bootstrap bundle'dan re-provision) — bu tooling replay + pointer
// reconstruction + epoch-reset kaydını üretir; canlı R2 replay + estate provision
// İNSAN seremonisidir (TTY-only, §9.5.2). Restore ASLA agent-mode'da çalışmaz.

// RestoreReason, epoch-reset kaydının reason değeridir (§9.5.4).
type RestoreReason string

const (
	RestorePathA RestoreReason = "dr-restore-path-a" // restore-in-place
	RestorePathB RestoreReason = "dr-restore-path-b" // full rebuild
)

// DataEpochReset, per-proje DATA epoch-reset kaydıdır (SPEC §9.5.4,
// wapps.epoch-reset.v1). İstemcilerin forward-only epoch pin'i BUNSUZ bir
// restore regresyonunu ASLA kabul etmez; kayıt ≥M kök anahtarla imzalanır
// (imzalama seremoni — bu struct gövdeyi üretir, imza ceremony verb'inde).
type DataEpochReset struct {
	Schema                        string `json:"schema"`
	Project                       string `json:"project"`
	Reason                        string `json:"reason"`
	ResetFromEpoch                uint64 `json:"reset_from_epoch"`
	ResetFromManifestSha256       string `json:"reset_from_manifestSha256"`
	NewChainGenesisManifestSha256 string `json:"new_chain_genesis_manifestSha256"`
	EscrowSnapshotRef             string `json:"escrow_snapshot_ref"`
	IAT                           string `json:"iat"`
}

// SchemaDataEpochReset, §9.5.4 şema tanımlayıcısı.
const SchemaDataEpochReset = "wapps.epoch-reset.v1"

// RestoredProject, bir DR restore'un çıktısıdır (ceremony makinesi belleğinde).
type RestoredProject struct {
	Project string
	// Current, append-only temsilden yeniden kurulan mutable pointer (R2'ye
	// restore replay'inde yazılır). F2: escrow'da mutable current YOKTUR.
	Current manifest.CurrentPointer
	// Values, escrow wrap'lerinden açılan düz metin değerler (SADECE ceremony
	// makinesi; her değer rotation worklist'ine girer, §9.5.5).
	Values map[string][]byte
	// EpochReset, istemcilerin regresyonu kabul etmesi için üretilen (imzasız) kayıt.
	EpochReset DataEpochReset
}

// Restore, doğrulanmış bir escrow snapshot'ından (Verify sonucu) bir projenin
// contents'ini yeniden kurar (SPEC §9.5.2/§9.5.3). head, append-only temsilden
// türetilmiş doğrulanmış head'dir; current pointer bundan REKONSTRÜKTE edilir.
// escrowID = yeniden kurulan escrow özel kimliği (2-of-3 Shamir → §9.5.2a).
// reason = Path A veya Path B (epoch-reset kaydına yazılır).
func Restore(ctx context.Context, r Reader, res *Result, project string, escrowID *cryptoid.X25519Identity, reason RestoreReason, now time.Time) (*RestoredProject, error) {
	head, ok := res.ProjectHeads[project]
	if !ok {
		return nil, fmt.Errorf("witness.Restore: project %q not in verified result", project)
	}
	if escrowID == nil {
		return nil, fmt.Errorf("witness.Restore: nil escrow identity (reconstruct from 2-of-3 shares first)")
	}
	wrapper, ok := res.headWrapper[project]
	if !ok {
		return nil, fmt.Errorf("witness.Restore: no head wrapper for %q", project)
	}

	// current pointer'ı append-only temsilden REKONSTRÜKTE et (§9.5.3): en yüksek
	// epoch pointer-event ile tutarlı, doğrulanmış manifest zincirinin head'i.
	current := manifest.NewCurrentPointer(project, head.Epoch, wrapper)
	if current.ManifestSha256 != head.ManifestSha256 {
		return nil, fmt.Errorf("witness.Restore: reconstructed pointer hash != verified head")
	}

	// Head manifest'i parse et (Verify zaten imza+zincir doğruladı) ve escrow
	// wrap'lerini yeniden kurulan escrow kimliğiyle aç.
	obj, err := manifest.ParseSignedObject(wrapper)
	if err != nil {
		return nil, fmt.Errorf("witness.Restore: head wrapper malformed: %w", err)
	}
	man, err := manifest.ParseManifestBody(obj.Bytes)
	if err != nil {
		return nil, fmt.Errorf("witness.Restore: head body malformed: %w", err)
	}

	escrowFp := escrowID.Fingerprint()
	values := map[string][]byte{}
	for _, e := range man.Entries {
		var wrap []byte
		for _, w := range e.Wraps {
			if w.Recipient == escrowFp {
				wrap = w.Wrap
				break
			}
		}
		if wrap == nil {
			return nil, fmt.Errorf("witness.Restore: key %q has no escrow wrap (escrow-incomplete snapshot)", e.KeyName)
		}
		blob, err := r.Get(ctx, keyBlob(project, e.BlobHash))
		if err != nil {
			return nil, fmt.Errorf("witness.Restore: read blob for %q: %w", e.KeyName, err)
		}
		if verr := cryptoid.VerifyBlobHash(blob, e.BlobHash); verr != nil {
			return nil, fmt.Errorf("witness.Restore: blob hash mismatch for %q: %w", e.KeyName, verr)
		}
		dek, err := cryptoid.UnsealDEK(wrap, escrowID)
		if err != nil {
			return nil, fmt.Errorf("witness.Restore: unseal escrow DEK for %q: %w", e.KeyName, err)
		}
		slot := cryptoid.Slot{Project: project, KeyName: e.KeyName, KeyVersion: e.KeyVersion}
		pt, err := cryptoid.OpenBlob(blob, dek, slot)
		if err != nil {
			return nil, fmt.Errorf("witness.Restore: open blob for %q: %w", e.KeyName, err)
		}
		values[e.KeyName] = pt
	}

	reset := DataEpochReset{
		Schema:                        SchemaDataEpochReset,
		Project:                       project,
		Reason:                        string(reason),
		ResetFromEpoch:                head.Epoch,
		ResetFromManifestSha256:       head.ManifestSha256,
		NewChainGenesisManifestSha256: head.ManifestSha256, // yeni zincir genesis'i restore edilen head'dir
		EscrowSnapshotRef:             keyManifest(project, head.Epoch),
		IAT:                           now.UTC().Format(time.RFC3339),
	}
	return &RestoredProject{Project: project, Current: current, Values: values, EpochReset: reset}, nil
}

// Marshal, epoch-reset kaydını JSON'a serileştirir (imza seremonisi bu gövdeyi
// ≥M kök anahtarla detached-signature zarfına sarar, §9.5.4).
func (e DataEpochReset) Marshal() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("witness.DataEpochReset.Marshal: %w", err)
	}
	return b, nil
}
