package secrets

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// setFromFile, --from-file bayrağı (§7.9.3 umask-077 temp-file kalıbı).
var setFromFile string

// setOptions wires test seams (prompt source, stdin) without adding cobra flags.
// Production callers leave them nil; we substitute defaults that hit the real
// terminal.
type setOptions struct {
	// fromFile, when non-empty, reads the value from this file (the §7.9.3
	// umask-077 temp-file pattern: `printf %s "$V" > /tmp/s; set K --from-file /tmp/s`)
	// instead of prompting. Agent-friendly: no value on argv, no TTY needed.
	fromFile string
	// promptValue reads the secret value from the operator. Returns the value
	// + whether a TTY was used (false → operator may have piped, value is in
	// the clear in shell history).
	promptValue func(prompt string) (string, bool, error)
}

var setCmd = &cobra.Command{
	Use:   "set <KEY>",
	Short: "Write a secret value into the store (interactive, no echo)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSet(args[0], setOptions{
			fromFile:    setFromFile,
			promptValue: promptValueNoEcho,
		})
	},
}

// runSet, `wapps secrets set <KEY>`in çekirdeğidir: değeri (--from-file ya da
// no-echo prompt ile) yakalar ve tek-anahtar PUT ile store'a yazar. Sunucu CAS'ı
// kendisi çözer — yerel bir arşiv, git drift preflight'ı ya da paylaşılan bir
// parola YOK.
func runSet(key string, opts setOptions) error {
	if key == "" {
		return fmt.Errorf("secrets.set: KEY argument is required")
	}
	cfg, err := requireStoreConfig("set")
	if err != nil {
		return err
	}
	return runSetStore(key, cfg, opts)
}

// promptValueNoEcho reads from a TTY without echoing keystrokes. Returns
// (value, isTTY, err). When stdin isn't a TTY we fall back to plain Read so
// piped invocations work (with a warning emitted by the caller).
func promptValueNoEcho(prompt string) (string, bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", true, err
		}
		return string(b), true, nil
	}
	// Not a TTY → read one line plain. We still avoid printing the value
	// back to stdout, but the caller will print a warning that history
	// might have captured it.
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", false, err
	}
	// Strip trailing newline for parity with line-oriented input.
	v := string(b)
	for len(v) > 0 && (v[len(v)-1] == '\n' || v[len(v)-1] == '\r') {
		v = v[:len(v)-1]
	}
	return v, false, nil
}

func init() {
	setCmd.Flags().StringVar(&setFromFile, "from-file", "",
		"read the value from this file instead of prompting (§7.9.3 umask-077 temp-file pattern)")
	SecretsCmd.AddCommand(setCmd)
}
