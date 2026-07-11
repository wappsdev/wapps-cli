package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequiredSigners, katmanlı (tiered) co-sign politikasını SAF mantık olarak
// tablo-güdümlü test eder (SPEC §4.5/§4.6/§4.7).
func TestRequiredSigners(t *testing.T) {
	tests := []struct {
		name        string
		changeClass string
		proj        ProjectClass
		parentM     int
		solo        bool
		nAdmins     int
		want        Requirement
		wantErr     error
	}{
		{
			name: "roster uses root quorum m", changeClass: ChangeRoster, parentM: 2,
			want: Requirement{Class: ClassRoot, Threshold: 2},
		},
		{
			name: "roster m=3", changeClass: ChangeRoster, parentM: 3,
			want: Requirement{Class: ClassRoot, Threshold: 3},
		},
		{
			name: "epoch_reset uses root quorum m", changeClass: ChangeEpochReset, parentM: 2,
			want: Requirement{Class: ClassRoot, Threshold: 2},
		},
		{
			name: "prod grant under solo needs 1 admin", changeClass: ChangeGrant, proj: ProjectProd,
			solo: true, nAdmins: 1,
			want: Requirement{Class: ClassAdmin, Threshold: 1, DistinctHuman: false, AuditRequired: true},
		},
		{
			// §4.7 step 4: solo=true olsa bile N_h≥2 anında prod grant 2 farklı
			// admin insan gerektirir (solo & N_h=2 geçişte ulaşılabilir durum).
			name: "prod grant solo with 2 admins now needs 2 distinct", changeClass: ChangeGrant, proj: ProjectProd,
			solo: true, nAdmins: 2,
			want: Requirement{Class: ClassAdmin, Threshold: 2, DistinctHuman: true, AuditRequired: true},
		},
		{
			name: "prod grant multi-admin needs 2 distinct humans", changeClass: ChangeGrant, proj: ProjectProd,
			solo: false, nAdmins: 2,
			want: Requirement{Class: ClassAdmin, Threshold: 2, DistinctHuman: true, AuditRequired: true},
		},
		{
			name: "prod grant not-solo but single admin still 1", changeClass: ChangeGrant, proj: ProjectProd,
			solo: false, nAdmins: 1,
			want: Requirement{Class: ClassAdmin, Threshold: 1, DistinctHuman: false, AuditRequired: true},
		},
		{
			name: "lab grant always 1 admin", changeClass: ChangeGrant, proj: ProjectLab,
			solo: false, nAdmins: 3,
			want: Requirement{Class: ClassAdmin, Threshold: 1, AuditRequired: true},
		},
		{
			name: "registry needs 1 admin", changeClass: ChangeRegistry,
			want: Requirement{Class: ClassAdmin, Threshold: 1, AuditRequired: true},
		},
		{
			name: "policy needs 1 admin", changeClass: ChangePolicy,
			want: Requirement{Class: ClassAdmin, Threshold: 1, AuditRequired: true},
		},
		{
			name: "grant without project class errors", changeClass: ChangeGrant, proj: ProjectNone,
			wantErr: ErrTrustChainBroken,
		},
		{
			name: "unknown change class errors", changeClass: "nonsense",
			wantErr: ErrUnknownChangeClass,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RequiredSigners(tt.changeClass, tt.proj, tt.parentM, tt.solo, tt.nAdmins)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
