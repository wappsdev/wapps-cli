package tofu

import (
	"fmt"
	"os/exec"
)

func Output() ([]byte, error) {
	cmd := exec.Command("tofu", "output", "-json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tofu.Output: %w", err)
	}
	return out, nil
}
