package cmd

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// specRefPatterns, `--help` çıktısında YASAK olan iç-spesifikasyon referans
// biçimleridir. Bu estate iki release boyunca bunları ELLE temizledi (v0.21.1
// süpürmesi ve b18407a); temizliği koruyan bir test YOKTU, yani onları geri
// sokan mekanizma — bir Long bloğuna eklenen tek satır, ya da bir port'ta
// doc-comment'ten türetilen yardım metni — yakalanmayacaktı.
//
// Neden yasak: SPEC bu depoda YOK. "(§7.1)" bir kullanıcı için ölü bir işaret,
// açamayacağı bir belgeye yapılan referans.
var specRefPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	// "§7.4", "(§2.1/§2.3)", "bkz. §6" — bölüm işaretinin KENDİSİ.
	{"section sign (§)", regexp.MustCompile(`§`)},
	// § olmadan yazılmış hâli: "SPEC 7.5", "spec 7.5", "specification 3.10".
	{"spec + number", regexp.MustCompile(`(?i)\bspec(ification)?\s*\.?\s*\d+(\.\d+)*\b`)},
	// "section 7.4", "sections 2.1" — düz İngilizce karşılığı.
	{"section + number", regexp.MustCompile(`(?i)\bsections?\s+\d+(\.\d+)+\b`)},
}

// renderHelp, cobra'nın bir komut için ÜRETTİĞİ yardım metnini döner — yani
// kullanıcının `--help` yazınca gördüğü şey. Kaynak taramıyoruz: v0.21.1
// süpürmesi tam da bunu yaptı (`Long:` satırlarını grepledi) ve çok satırlı
// blokların devam satırlarındaki üç referansı kaçırdı.
func renderHelp(t *testing.T, c *cobra.Command) string {
	t.Helper()
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(&buf)
	t.Cleanup(func() {
		c.SetOut(nil)
		c.SetErr(nil)
	})
	if err := c.Help(); err != nil {
		t.Fatalf("render help for %q: %v", c.CommandPath(), err)
	}
	return buf.String()
}

// walkCommands, ağacın TAMAMINI (kök dâhil, her derinlikte) döner. Elle yazılmış
// bir liste DEĞİL: son temizlik iki kez tam da elle liste yüzünden eksik kaldı,
// kalan sekiz vakayı ancak programatik bir gezinti buldu.
func walkCommands(root *cobra.Command) []*cobra.Command {
	out := []*cobra.Command{root}
	for _, child := range root.Commands() {
		out = append(out, walkCommands(child)...)
	}
	return out
}

// specRefViolations, ağaçtaki her komutun yardım çıktısını gezer ve yasak
// deseni İÇEREN satırları "komut yolu: desen: satır" biçiminde döner.
func specRefViolations(t *testing.T, root *cobra.Command) []string {
	t.Helper()
	var found []string
	for _, c := range walkCommands(root) {
		help := renderHelp(t, c)
		for _, line := range strings.Split(help, "\n") {
			for _, p := range specRefPatterns {
				if p.re.MatchString(line) {
					found = append(found, fmt.Sprintf("%s: %s: %s",
						c.CommandPath(), p.name, strings.TrimSpace(line)))
				}
			}
		}
	}
	sort.Strings(found)
	return found
}

// ASIL KORUMA: bugünkü ağacın hiçbir komutunun yardım metni bir spec referansı
// içermiyor, ve bir daha içeremez.
func TestHelpText_NoSpecReferences(t *testing.T) {
	if v := specRefViolations(t, rootCmd); len(v) > 0 {
		t.Fatalf("--help output must carry no spec references (%d found):\n  %s",
			len(v), strings.Join(v, "\n  "))
	}
}

// Gezinti GERÇEKTEN ağacın derinine iniyor mu? Boş/sığ gezen bir koruma sessizce
// hiçbir şey korumaz. Alt sınır + b18407a'nın elle düzelttiği üç komut, gezinti
// için birer kanarya (kontrol listesi değil: hangi komutun taranacağını değil,
// gezintinin 2. seviyeye ULAŞTIĞINI iddia ediyorlar).
func TestHelpText_WalkReachesWholeTree(t *testing.T) {
	paths := map[string]bool{}
	for _, c := range walkCommands(rootCmd) {
		paths[c.CommandPath()] = true
	}
	if len(paths) < 40 {
		t.Errorf("walk visited only %d commands; the tree is bigger than that", len(paths))
	}
	for _, want := range []string{
		"wapps",                     // kök
		"wapps tofu",                // b18407a: §7.4
		"wapps secrets rotate-plan", // b18407a: §6.2
		"wapps dr restore",          // b18407a: §2.1/§2.3/§2.4
	} {
		if !paths[want] {
			t.Errorf("walk never reached %q; visited: %v", want, sortedKeys(paths))
		}
	}
}

// Koruma BOŞ DEĞİL: sentetik bir ağaçta, iki seviye derinde ve bir bayrak
// açıklamasında gizlenmiş referanslar yakalanıyor mu?
func TestSpecRefDetector_CatchesHiddenReferences(t *testing.T) {
	root := &cobra.Command{Use: "fake", Short: "root"}
	mid := &cobra.Command{Use: "mid", Short: "mid"}
	leaf := &cobra.Command{
		Use:   "leaf",
		Short: "leaf",
		// Çok satırlı bloğun DEVAM satırında — v0.21.1'in kaçırdığı vaka.
		Long: "First line is clean.\nSecond line derives the KEK (HKDF §2.3) and is not.",
	}
	leaf.Flags().String("out", "", "write the env file (SPEC 7.5 format)")
	deep := &cobra.Command{Use: "deep", Short: "reads the ledger, see section 6.2"}
	leaf.AddCommand(deep)
	mid.AddCommand(leaf)
	root.AddCommand(mid)

	v := specRefViolations(t, root)
	joined := strings.Join(v, "\n")
	for _, want := range []string{"HKDF §2.3", "SPEC 7.5", "section 6.2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("detector missed %q; found:\n%s", want, joined)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
