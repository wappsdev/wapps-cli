package secrets

import (
	"errors"
	"os"
	"os/exec"
)

// defaultExecRunner invokes the requested subprocess with the supplied env.
// stdin/stdout/stderr are wired directly to wapps' own streams so the child
// inherits TTY semantics (colored output, prompts, etc.). We exec by name +
// args (NOT a shell-formatted string), so there is no command-injection
// surface area — args are operator-supplied and the OS handles them
// argv-array-style.
func defaultExecRunner(name string, args, env []string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	}
	return cmd.ProcessState.ExitCode(), nil
}
