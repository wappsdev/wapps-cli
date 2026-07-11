package agentmode

import (
	"bytes"
	"fmt"
	"io"
	"sort"
)

// Redaction, bir gizli değerin yerine yazılan işarettir.
const Redaction = "***"

// ScrubFloor, bir alt-süreç çıktısından GÜVENLE redakte edilebilecek en kısa gizli
// değer uzunluğudur (P3-b). exec'in eski 5-karakter tabanından DÜŞÜRÜLDÜ (4): kısa
// ama gerçek sırlar (PIN, kısa token) da redakte edilsin. Bunun ALTINDAKİ değerler
// ilgisiz çıktıyı bozmamak için scrubber'a verilmez — ama gerçek-görünümlü (yüksek
// entropili) biri atlandığında FilterScrubbable operatöre TEK bir uyarı yazar.
const ScrubFloor = 4

// commonLiteral, redakte EDİLMEYECEK yaygın/düşük-entropili literallerdir: bunları
// *** yapmak ilgisiz çıktıyı bozardı ve bunlar sır değildir.
func commonLiteral(v string) bool {
	switch v {
	case "", "null", "true", "false", "nil", "none", "n/a":
		return true
	}
	return false
}

// allDigits, v'nin yalnızca ondalık basamaklardan oluştuğunu döner (port/sayaç/index
// gibi kısa değerler — sır değil).
func allDigits(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// IsScrubbable, bir değerin scrubber'a verilip verilmeyeceğini döner: yaygın literal
// DEĞİL VE en az ScrubFloor uzunlukta.
func IsScrubbable(v string) bool {
	if commonLiteral(v) {
		return false
	}
	return len(v) >= ScrubFloor
}

// FilterScrubbable, verilen aday değer kümesinden scrubber'a verilecek alt kümeyi
// döndürür. Floor'un ALTINDA kalıp bu yüzden ATLANAN, gerçek-görünümlü (literal/
// saf-basamak OLMAYAN) en az bir değer varsa note'a TEK bir uyarı satırı yazar
// (§7.4.3, P3-b): kısa bir sır alt-sürece export edildiğinde redakte EDİLEMEZ ve
// transcript'e ulaşabilir. Uyarı ASLA değer içermez (yalnızca sayı). note nil ise
// not yazılmaz. Boş/tekrar eleme NewScrubber'da yapılır.
func FilterScrubbable(values []string, note io.Writer) []string {
	out := make([]string, 0, len(values))
	skipped := 0
	for _, v := range values {
		if IsScrubbable(v) {
			out = append(out, v)
			continue
		}
		// Atlandı — floor-altı VE gerçek-görünümlü (literal değil, saf-basamak değil)
		// bir değerse sızıntı riski var → say.
		if len(v) < ScrubFloor && !commonLiteral(v) && !allDigits(v) {
			skipped++
		}
	}
	if skipped > 0 && note != nil {
		fmt.Fprintf(note, "wapps: %d short secret value(s) below the %d-char scrub floor were NOT redacted from child output — they may appear in the transcript\n", skipped, ScrubFloor)
	}
	return out
}

// Scrubber, bir alt-sürecin stdout/stderr'ini saran STREAMING tam-eşleşme
// redaktörüdür (SPEC §7.4.3). Child env'e enjekte edilen gizli DEĞERLERİN her
// tam geçişini `***` ile değiştirir — böylece bir gizli dizeyi echo'layan
// exec-ed bir araç onu transcript'e sızdıramaz.
//
// Bir "rolling boundary buffer" kullanır: en uzun değerden bir kısa (maxLen-1)
// bayt her zaman tutulur, böylece Read chunk sınırları arasında bölünen değerler
// yine yakalanır; child çıkışında Flush ile boşaltılır.
//
// Kripto zorlaması DEĞİL, katmanlı bir azaltmadır (SPEC §2 kabul edilen risk):
// child sürecin kendisi düz metni tutar ve bant-dışı sızdırabilir. Scrubber
// TRANSCRIPT'i korur.
type Scrubber struct {
	w       io.Writer
	values  [][]byte // gizli değerler, uzunluğa göre AZALAN sıralı (uzun-önce)
	maxLen  int      // en uzun değerin uzunluğu
	pending []byte   // henüz güvenle boşaltılmamış rolling buffer
}

// NewScrubber, verilen gizli değer kümesiyle w'yi saran bir scrubber döner. Boş
// değerler ve tekrarlar elenir. Değer yoksa scrubber saydam bir passthrough olur.
func NewScrubber(w io.Writer, values []string) *Scrubber {
	seen := map[string]bool{}
	var vals [][]byte
	maxLen := 0
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		vals = append(vals, []byte(v))
		if len(v) > maxLen {
			maxLen = len(v)
		}
	}
	// Uzun değerleri önce dene: bir değer başkasının prefix'iyse, önce uzunu
	// yakala (daha fazla bayt redakte).
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	return &Scrubber{w: w, values: vals, maxLen: maxLen}
}

// Write, gelen baytları biriktirir, tam gizli-değer eşleşmelerini `***` ile
// değiştirir ve GÜVENLE boşaltılabilir öneki alttaki writer'a yazar. Girdinin
// tamamını tükettiğini bildirir (len(p), nil) — kısmi bir eşleşme olabilecek
// son (maxLen-1) baytı bir sonraki Write/Flush için tutar.
func (s *Scrubber) Write(p []byte) (int, error) {
	if len(s.values) == 0 {
		// Passthrough; yine de kısmi yazım hatalarını çağırana yansıt.
		if _, err := s.w.Write(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	s.pending = append(s.pending, p...)
	if err := s.process(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush, kalan buffer'ı (son tarama sonrası) boşaltır — child çıktığında
// çağrılmalıdır. İdempotent.
func (s *Scrubber) Flush() error {
	if len(s.values) == 0 {
		return nil
	}
	return s.process(true)
}

// process, pending buffer'ı tarar: her tam eşleşmeyi `***` ile değiştirerek
// yazar. final=false ise, olası kısmi bir eşleşmeyi korumak için son (maxLen-1)
// baytı pending'de tutar; final=true ise her şeyi boşaltır.
func (s *Scrubber) process(final bool) error {
	// Önce pending içindeki TÜM tam eşleşmeleri işle.
	for {
		idx, matchLen := s.earliestMatch(s.pending)
		if idx < 0 {
			break
		}
		if _, err := s.w.Write(s.pending[:idx]); err != nil {
			return err
		}
		if _, err := io.WriteString(s.w, Redaction); err != nil {
			return err
		}
		s.pending = s.pending[idx+matchLen:]
	}

	if final {
		if len(s.pending) > 0 {
			if _, err := s.w.Write(s.pending); err != nil {
				return err
			}
			s.pending = nil
		}
		return nil
	}

	// Kısmi-eşleşme koruması: son (maxLen-1) baytı tut, gerisini boşalt. Uzunluğu
	// ≤ maxLen olan herhangi bir gizli değer, başlangıcı bu tutulan bölgenin
	// DIŞINDA ise tamamen içerilir ve zaten yukarıda bulunurdu; sınırda başlayan
	// bir değer korunur ve bir sonraki chunk'la birleşince yakalanır.
	keep := s.maxLen - 1
	if keep < 0 {
		keep = 0
	}
	if len(s.pending) > keep {
		flush := len(s.pending) - keep
		if _, err := s.w.Write(s.pending[:flush]); err != nil {
			return err
		}
		s.pending = append(s.pending[:0], s.pending[flush:]...)
	}
	return nil
}

// earliestMatch, buf içinde herhangi bir gizli değerin EN ERKEN başlangıç
// indeksini ve eşleşen değerin uzunluğunu döner. Aynı indekste birden çok değer
// başlıyorsa EN UZUN olanı seçilir (daha çok bayt redakte). Eşleşme yoksa (-1,0).
func (s *Scrubber) earliestMatch(buf []byte) (int, int) {
	best := -1
	bestLen := 0
	for _, v := range s.values {
		i := bytes.Index(buf, v)
		if i < 0 {
			continue
		}
		if best == -1 || i < best || (i == best && len(v) > bestLen) {
			best = i
			bestLen = len(v)
		}
	}
	return best, bestLen
}
