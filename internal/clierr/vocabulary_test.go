package clierr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// SESSİZLİK TESTİ. registry bir map, ve Go'da eksik bir anahtar SIFIR değer
// döner: New(bilinmeyenKod) boş bir recovery ve retryable:false üretir, hiçbir
// uyarı vermeden. Bu, bir yeniden adlandırmanın SESSİZCE yarım kalabileceği
// anlamına gelir — kod adı değişir, registry anahtarı eski adında kalır ve
// zarf "recovery":"" taşır. TypeScript tarafında bunu derleyici yakalıyor
// (Record<ErrorCode, CodeSpec> eksik anahtarda derlenmez); Go'da karşılığı bu
// testtir.
func TestRegistry_EveryCodeHasRecovery(t *testing.T) {
	for _, code := range AllCodes {
		spec, ok := registry[code]
		require.Truef(t, ok, "%s is declared but has no registry entry: New(%s) would emit an empty recovery, silently", code, code)
		require.NotEmptyf(t, spec.recovery, "%s has an empty recovery line; every refusal must name its next step", code)
	}
}

// registry'de AllCodes'ta OLMAYAN bir anahtar, ya silinmiş bir kodun artığıdır
// ya da listeye eklenmesi unutulmuş bir koddur. İkisi de sözlüğü kapalı
// olmaktan çıkarır.
func TestRegistry_HasNoOrphanEntries(t *testing.T) {
	declared := make(map[Code]bool, len(AllCodes))
	for _, code := range AllCodes {
		declared[code] = true
	}
	for code := range registry {
		require.Truef(t, declared[code], "registry has %s but AllCodes does not declare it", code)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// ESTATE KESİŞİMİ — dil sınırının BU tarafındaki yarısı.
// ═══════════════════════════════════════════════════════════════════════════
//
// wapps-memory (TypeScript, ayrı depo) aynı zarfı konuşur. Bir ad İKİ tabloda
// birden geçiyorsa aynı şeyi söylemek ZORUNDA: bir okuyucu kodu bir serviste
// öğrenip ötekinde karşılaştığında zıt bir şey duymamalı. Tam olarak bu
// yüzden NOT_AVAILABLE bu tablodan çıktı.
//
// Karşı yarısı: services/memory/test/cross-repo-vocabulary.test.ts. İki dosya
// AYNI listeyi tutar; birini değiştiren ötekini de değiştirmek zorundadır ve
// her iki taraf da KENDİ deposunda düşer. Bir derleme paylaşılamadığı için
// (Go ↔ TS, iki depo) tek bir kaynaktan üretilemiyor — bedeli bu tekrar.
var sharedWithEstate = map[Code]bool{
	RateLimited:      true,
	NotFound:         false,
	ServiceMisconfig: false,
	Internal:         false,
}

func TestEstateOverlap_AgreesOnRetryable(t *testing.T) {
	for code, retryable := range sharedWithEstate {
		spec, ok := registry[code]
		require.Truef(t, ok, "%s is recorded as shared with wapps-memory but is not in this table", code)
		require.Equalf(t, retryable, spec.retryable,
			"%s disagrees with wapps-memory on retryable; a reader who learned this code there would be told the opposite here", code)
	}
}

// NOT_AVAILABLE'ın GERİ GELMESİNE karşı bekçi. Bu ad estate'te wapps-memory'ye
// aittir ve orada retryable:true'dur ("servis sakat"). Burada yeniden
// tanımlanırsa eş sesli yeniden doğar — ve bu sefer sessizce değil.
func TestEstateOverlap_DoesNotRedefineNotAvailable(t *testing.T) {
	for _, code := range AllCodes {
		require.NotEqualf(t, Code("NOT_AVAILABLE"), code,
			"NOT_AVAILABLE belongs to wapps-memory (service impaired, retryable:true); this table means ACTION_UNAVAILABLE (this invocation cannot proceed, retryable:false)")
	}
}
