package secrets

import (
	"errors"
	"io"
	"os"
	"os/exec"
)

// defaultExecRunner invokes the requested subprocess with the supplied env.
// stdin is wired to wapps' own stdin (TTY semantics); stdout/stderr are wired to
// the CALLER-SUPPLIED writers — in production these are streaming SCRUBBERS
// (§7.4.3) that redact any injected secret value out of the child's output so an
// exec-ed tool cannot echo a secret into the transcript. We exec by name + args
// (NOT a shell string), so there is no command-injection surface.
func defaultExecRunner(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	}
	return cmd.ProcessState.ExitCode(), nil
}
