package source

import (
	"context"
	"fmt"
	"os/exec"
)

// realTofuRunner invokes the local "tofu" binary via exec.CommandContext.
// Arguments are passed as separate strings (not a shell command), so there
// is no command-injection surface area — workdir is the only operator-
// supplied input and it only affects cmd.Dir, not the argv.
func realTofuRunner(ctx context.Context, workdir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "tofu", "output", "-json")
	if workdir != "" {
		cmd.Dir = workdir
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tofu output -json: %w", err)
	}
	return out, nil
}
