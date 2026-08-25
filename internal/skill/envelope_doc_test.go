package skill

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// Zarfın TÜKETİCİSİ ajan, ve ajanın okuduğu belge SKILL.md. Ajan modunda
// stderr'e bir JSON satırı basıp bunu ajana söylememek sözleşmeyi yarım
// bırakır. Alan adları ELLE listelenmiyor: gerçekten yayılan zarftan
// türetiliyor, böylece bir alan yeniden adlandırılırsa belge de sessizce
// eskimez.
func TestSkillMD_DocumentsErrorEnvelopeFields(t *testing.T) {
	var buf bytes.Buffer
	clierr.Emit(&buf, clierr.New(clierr.BindingUnpinned, "repo not pinned"))

	var emitted map[string]any
	if err := json.Unmarshal(buf.Bytes(), &emitted); err != nil {
		t.Fatalf("clierr.Emit did not produce JSON: %v (%q)", err, buf.String())
	}
	if len(emitted) == 0 {
		t.Fatal("envelope has no fields; nothing to document")
	}

	md := embeddedSkillMD(t)
	for field := range emitted {
		if !bytes.Contains(md, []byte(fmt.Sprintf("%q", field))) {
			t.Errorf("SKILL.md never names the envelope field %q an agent must parse", field)
		}
	}
}
