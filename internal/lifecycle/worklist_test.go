package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestEmitWorklist_HighestBlastFirst, worklist'in en yüksek blast-radius ÖNCE
// sıralandığını (§8.6.3) ve rotasyon metadata'sı olmayan anahtarların NeedsTriage
// ile en önce (blocker) listelendiğini (§8.5.5) kanıtlar.
func TestEmitWorklist_HighestBlastFirst(t *testing.T) {
	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})

	// Karışık blast-tier'lı anahtarlar + metadata'sız bir anahtar (NO_META).
	seedDataMeta(t, mem, head, rwProject, a.daily, map[string][]byte{
		"CF_TOKEN": []byte("cf"), "DB_URL": []byte("db"), "DEV_KEY": []byte("dev"), "NO_META": []byte("x"),
	}, map[string]string{
		"CF_TOKEN": `{"recipe":"cf-manual","origin":"static","blast_tier":"platform-anchor"}`,
		"DB_URL":   `{"recipe":"db-role/phase1","origin":"tofu","blast_tier":"prod-shared"}`,
		"DEV_KEY":  `{"recipe":"coolify-env/start","origin":"static","blast_tier":"dev"}`,
		// NO_META: metadata yok → triyaj.
	})

	wl, err := e.EmitWorklist(WorklistRequest{
		Principal: a.id, Reason: "departure", Projects: []string{rwProject}, RunID: "wl_1",
	})
	require.NoError(t, err)
	require.Len(t, wl.Entries, 4)

	// Sıra: NO_META (triyaj/unknown) → CF_TOKEN (platform-anchor) → DB_URL (prod-shared)
	// → DEV_KEY (dev).
	order := []string{wl.Entries[0].Key, wl.Entries[1].Key, wl.Entries[2].Key, wl.Entries[3].Key}
	assert.Equal(t, []string{"NO_META", "CF_TOKEN", "DB_URL", "DEV_KEY"}, order)

	assert.True(t, wl.Entries[0].NeedsTriage, "metadata-missing key must be flagged for triage")
	assert.Equal(t, TierUnknown, wl.Entries[0].BlastTier)
	assert.Equal(t, TierPlatformAnchor, wl.Entries[1].BlastTier)
	assert.Equal(t, "cf-manual", wl.Entries[1].Recipe)
	assert.Equal(t, "tofu", wl.Entries[2].Origin)
	assert.Equal(t, "PENDING", wl.Entries[3].State, "worklist is data — G11 executes")
}
