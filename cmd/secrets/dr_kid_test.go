package secrets

// BULGU: yanlış tamamlanan bir kurtarma töreni, doğrudan AYIRT EDİLEMEZ
// görünüyordu. `dr combine` yanlış/eksik paylarla da EXIT 0 verir, 0600 bir
// dosya yazar ve tek fark BASILAN KID'dir — ama doğru kid'in nerede olduğunu
// söyleyen hiçbir otomatik yol yoktu: kid replikadaki HER manifest'in içinde
// duruyor (`entries[].wrap.kid`) ve `dr verify` o manifest'i okuyup
// ayrıştırdığı hâlde kid'i BASMIYORDU.
//
// Kapatma İKİ PARÇALI ve parçalar birbirini tamamlıyor:
//   verify  kid'i BASAR    -> beklenen değerin KAYNAĞI olur
//   combine --expect-kid   -> o değeri TÜKETİR ve uyuşmazlıkta REDDEDER
// Yalnızca ikincisi yazılsaydı operatörün elinde karşılaştıracak bir şey
// olmazdı; yalnızca birincisi yazılsaydı karşılaştırma yine ELDE yapılırdı.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// writeTestShares, rastgele bir MASTER_KEK'in 2-of-3 paylarini 0600 dosyalara
// yazar ve (yollar, master) doner. GERCEK ANAHTAR DEGIL.
func writeTestShares(t *testing.T, dir string) ([]string, []byte) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	shares, err := cryptoid.ShamirSplit(master, 3, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, len(shares))
	for i, sh := range shares {
		p := filepath.Join(dir, fmt.Sprintf("share-%d.hex", i+1))
		if werr := os.WriteFile(p, []byte(hex.EncodeToString(sh)+"\n"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		paths[i] = p
	}
	return paths, master
}

func TestDrVerifyPrintsTheWrapKid(t *testing.T) {
	dir := t.TempDir()
	master := buildSnapshot(t, dir, "alpha", map[string]string{"K": "v"})
	kid, err := cryptoid.KekKid(master)
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	drSnapshotDir = dir
	t.Cleanup(func() { drSnapshotDir = "" })
	drVerifyCmd.SetOut(out)
	if err := runDrVerify(drVerifyCmd, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Değerin KENDİSİ bir sır değil (master'ın SHA-256'sının ilk 16 hex'i) ve
	// zaten replikadaki her manifest'te duruyor — basmak yeni bir şey sızdırmaz.
	if !strings.Contains(out.String(), "kid="+kid) {
		t.Fatalf("verify çıktısı kid TAŞIMIYOR; operatör beklenen değeri nereden alacak?")
	}
}

func TestDrCombineRefusesAKidMismatchAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	shares, _ := writeTestShares(t, dir)
	outPath := filepath.Join(dir, "master.hex")

	out := new(bytes.Buffer)
	err := runDrCombineCore(out, shares[:2], outPath, "0000000000000000")
	if err == nil {
		t.Fatal("kid uyuşmazlığı KABUL EDİLDİ — sessiz arıza kapanmamış")
	}
	// FAIL-CLOSED: reddedilen bir tören DOSYA BIRAKMAMALI. Yazıp sonra hata
	// vermek, operatöre yanlış anahtarı elinde bırakırdı.
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("kid uyuşmazlığında --out dosyası YAZILMIŞ (fail-closed değil)")
	}
}

func TestDrCombineAcceptsTheMatchingKid(t *testing.T) {
	dir := t.TempDir()
	shares, master := writeTestShares(t, dir)
	outPath := filepath.Join(dir, "master.hex")
	kid, err := cryptoid.KekKid(master)
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	// Büyük harfli ve boşluklu verilmesi de KABUL EDİLMELİ: operatör bu değeri
	// bir terminalden elle taşıyor.
	if err := runDrCombineCore(out, shares[:2], outPath, "  "+strings.ToUpper(kid)+" "); err != nil {
		t.Fatalf("doğru kid REDDEDİLDİ: %v", err)
	}
	if !strings.Contains(out.String(), "kid "+kid) {
		t.Fatal("combine çıktısı kid taşımıyor")
	}
}
