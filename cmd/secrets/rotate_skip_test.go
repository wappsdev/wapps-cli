package secrets

// rotate_skip_test.go, `wapps rotate skip`in ajan reddini KORUR.
//
// NEDEN AYRI BİR TEST DOSYASI, ve neden bir yorum yetmiyor:
//
// `wapps rotate skip` ROOT'a mount'lu (cmd/root.go: rootCmd.AddCommand(RotateCmd)).
// Yani SecretsCmd.PersistentPreRunE — agentPolicy tablosunu okuyan ve HER
// secrets verb'ünü gate'leyen hook — bu komut için HİÇ koşmuyor. Onu ajandan
// koruyan TEK şey RunE'nin İÇİNE elle yazılmış `agentmode.IsAgent()` kontrolü.
//
// Bu dosya var çünkü o kontrol SİLİNEBİLİR görünüyor. Komut eskiden yetkili
// GÖRÜNEN bir `Annotations: {wapps_agent_policy: refuse_agent}` da taşıyordu;
// annotation ÖLÜYDÜ (sıfır okuyucu) ama okuyan biri makul bir çıkarım yapardı:
// "annotation zaten reddediyor, bu kontrol fazladan". Annotation kaldırıldı —
// ama aynı çıkarım "root'a mount'lu her şey nasılsa gate'leniyordur" biçiminde
// yine yapılabilir. Yorumlar silinir; kırmızı bir test silinmez.
//
// Bu bir İDDİA testidir, bir karşılaştırma DEĞİL: pty differential iki
// ikilinin PAYLAŞTIĞI bir kusuru göremez, ve kontrolü silmek İKİ tarafta da
// aynı deliği açardı. Rust karşılığı: tests/verbgates.rs.

import (
	"testing"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

func TestRotateSkip_RefusesAnAgentWithoutThePersistentHook(t *testing.T) {
	t.Setenv("CLAUDECODE", "1") // ajan modu
	if !agentmode.IsAgent() {
		t.Skip("agent-mode detection unavailable in this environment")
	}

	// --reason ZORUNLU ve ajan kontrolünden ÖNCE koşuyor; kurulmazsa test
	// ajan reddini değil arity hatasını ölçerdi.
	rotateSkipReason = "value is a public constant"
	t.Cleanup(func() { rotateSkipReason = "" })

	err := rotateSkipCmd.RunE(rotateSkipCmd, []string{"run-1", "SOME_KEY"})
	if !clierr.Is(err, clierr.AgentModeRefused) {
		t.Fatalf("rotate skip under agent mode: want AGENT_MODE_REFUSED, got %v", err)
	}
}

// TestRotateSkip_IsNotCoveredByTheSecretsPersistentHook, yukarıdaki testin
// NEDEN gerekli olduğunu ölçer: koruma tablodan GELMİYOR.
//
// `rotate skip` SecretsCmd'nin altında değil, o yüzden gateKey onu "skip" diye
// adlandırıyor ve agentPolicy tablosunda "skip" YOK. Tablo tek koruma olsaydı
// fail-closed davranırdı — ama hook zaten koşmadığı için tablo hiç
// DANIŞILMIYOR. Bu iddia bozulursa (biri komutu SecretsCmd'ye taşırsa)
// yukarıdaki testin gerekçesi değişmiş demektir.
func TestRotateSkip_IsNotCoveredByTheSecretsPersistentHook(t *testing.T) {
	if _, ok := agentPolicy[gateKey(rotateSkipCmd)]; ok {
		t.Fatalf("agentPolicy now has an entry for %q; rotate skip's hand-written guard may be redundant — re-read cmd/root.go before deleting it", gateKey(rotateSkipCmd))
	}
	for c := rotateSkipCmd; c != nil; c = c.Parent() {
		if c.Name() == "secrets" {
			t.Fatal("rotate skip is now mounted under `secrets`; SecretsCmd.PersistentPreRunE would apply and this file's premise changed")
		}
	}
}
