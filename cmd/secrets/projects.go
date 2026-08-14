package secrets

// projects.go, `wapps secrets projects` ailesi: store'daki PROJELERİ listeler
// ve (admin) bir projenin tamamını kaldırır.
//
// Neden gerekliydi: proje ÖRTÜK bir namespace'ti — kayıt defteri yok, ilk
// anahtar yazıldığında doğuyor — ve onu görecek hiçbir yüzey yoktu. Yerel
// `~/.config/wapps/projects.yaml` yalnızca `--project` için elle tutulan bir
// ad→dizin haritasıdır, store'la ilgisi yoktur. Sonuç: `projects: ["*"]` bir
// grant altında `navlun-app` yerine `navlun-ap` yazan bir komut sessizce yeni
// bir proje doğuruyor, kimse de fark etmiyordu.
//
// Yetki modeli, iki verb için KASITLI olarak farklıdır:
//   - list  → proje-metadata `read` (data-plane). Ajan serbest: yalnızca ADlar.
//   - rm    → global `admin` verb'i + write-AUD (control-plane), ajan REDDEDİLİR.
//     Bir projeyi silmek, oradaki her anahtarı silmenin toplamıdır; per-key
//     `delete` grant'i buna yetmez.

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "List store projects / remove one entirely",
}

var projectsListCmd = &cobra.Command{
	Use:   "list",
	Short: "GET /v1/projects — project names you can see (names only, never values)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProjectsList(cmd.OutOrStdout())
	},
}

// runProjectsList, görünür proje adlarını satır başına bir tane basar —
// `secrets list`in anahtar-adı çıktısıyla aynı biçim, aynı sözleşme.
func runProjectsList(w io.Writer) error {
	cfg, err := storeProject("projects")
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	res, err := st.Projects(context.Background())
	if err != nil {
		return err
	}
	for _, p := range res.Projects {
		fmt.Fprintln(w, p)
	}
	return nil
}

var projectsRmYes bool

var projectsRmCmd = &cobra.Command{
	Use:   "rm <PROJECT>",
	Short: "Remove a project and ALL its data (admin; irreversible; refused in agent mode)",
	Long: "Remove a project and all of its data from the store.\n\n" +
		"This deletes every key, manifest and blob under the project. It needs the\n" +
		"global `admin` verb and a write-AUD session — a per-key `delete` grant is NOT\n" +
		"enough. The append-only pointer-event trail is KEPT: it is the tamper-evident\n" +
		"record that the project existed, and deleting it would forge a clean history.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Kontrol düzlemi: ailenin gate'i `read` sınıfıdır (list için), bu YAPRAK
		// ayrıca reddedilir. env'in print-formu / get ile aynı yaprak-içi kalıp.
		if err := agentmode.Guard(agentmode.PolicyControl, agentmode.IsAgent()); err != nil {
			return err
		}
		return runProjectsRm(args[0], projectsRmYes, cmd.InOrStdin(), cmd.OutOrStdout())
	},
}

func runProjectsRm(project string, yes bool, in io.Reader, out io.Writer) error {
	if project == "" {
		return clierr.New(clierr.Internal, "secrets.projects.rm: PROJECT argument is required")
	}
	if !yes {
		ok, cerr := confirmTTY(in, out, fmt.Sprintf(
			"Remove project %s and ALL of its keys? This cannot be undone. Type 'yes' to confirm: ", project))
		if cerr != nil {
			return fmt.Errorf("secrets.projects.rm: read confirmation: %w", cerr)
		}
		if !ok {
			return clierr.New(clierr.Internal, "secrets.projects.rm: aborted (confirmation not given)")
		}
	}

	st, err := openAdminStore()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := st.ProjectDelete(ctx, project)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "✓ Removed project %s (%d objects)\n", res.Project, res.DeletedObjects)
	if res.PointerEventsKept {
		fmt.Fprintln(out, "  pointer-event trail kept (append-only DR record)")
	}
	return nil
}

func init() {
	projectsRmCmd.Flags().BoolVar(&projectsRmYes, "yes", false, "skip the interactive confirm (still refused in agent mode)")
	projectsCmd.AddCommand(projectsListCmd, projectsRmCmd)
	SecretsCmd.AddCommand(projectsCmd)
}
