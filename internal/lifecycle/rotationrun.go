package lifecycle

// RotationRunState, bir değer-rotasyon worklist run'ının yürütme durumudur (SPEC
// §8.5.5.4/§8.6.4). G11 rotasyon motoru worklist'in HER girişini yürüttükçe bu
// durumu sürer; bu motor worklist'i yalnızca ÜRETİR, değer rotasyonunu ÇALIŞTIRMAZ.
type RotationRunState struct {
	RunID string
	// Complete, run'daki HER girişin TERMİNAL (DONE veya admin-imzalı SKIPPED,
	// §8.5.5.4) olduğunu bildirir. false → hâlâ yürütülmeyi bekleyen giriş var.
	Complete bool
	// NeedsTriage, run'da rotasyon-metadata'sı eksik (ROTATION_METADATA_MISSING,
	// §8.5.5.1) bir giriş kaldığını bildirir — offboard close'u ZORUNLU olarak
	// bloklar (bu girdiler swallow EDİLMEZ).
	NeedsTriage bool
	// Pending, henüz terminal olmayan giriş sayısı (-1 = bilinmiyor/G11 bağlı değil).
	Pending int
}

// RotationRunLedger, G11 rotasyon-yürütme motorunun bir worklist run'ının
// tamamlanma durumunu bildirdiği porttur (SPEC §8.5.5/§8.6.4). Offboard CLOSE
// (§8.5.7) bir run'ın TERMİNAL olduğunu buradan doğrular: bu motor değer
// rotasyonunu YÜRÜTMEZ, yalnızca worklist üretir → close, run'lar gerçekten
// yürütülene kadar "awaiting rotation" durumunda kalır.
type RotationRunLedger interface {
	// RunState, verilen worklist run'ının yürütme durumunu döner.
	RunState(runID string) (RotationRunState, error)
}

// StubRotationRunLedger, G11 henüz BAĞLI OLMADIĞINDA kullanılan yer-tutucudur:
// hiçbir worklist girişinin yürütülMEDİĞİNİ (Complete=false) bildirir → offboard
// close bloklanır ve kayıt "awaiting rotation" (kill+rewrap+escrow done, rotation
// pending) durumunda kalır. Gerçek G11 ledger'ı bağlandığında close ilerler.
type StubRotationRunLedger struct{}

// RunState, RotationRunLedger — her zaman pending (G11 bağlı değil → hiçbir run
// yürütülmedi, close bloklanır).
func (StubRotationRunLedger) RunState(runID string) (RotationRunState, error) {
	return RotationRunState{RunID: runID, Complete: false, Pending: -1}, nil
}

// arayüz uyumluluğu.
var _ RotationRunLedger = StubRotationRunLedger{}
