package source

import (
	"context"
	"encoding/json"
	"fmt"
)

// tofuSource shells out to "tofu output -json" in the configured workdir.
//
// The output shape from "tofu output -json" is exactly what Source.Read returns,
// so this adapter is a thin wrapper plus directory dispatch. Empty workdir
// means "current working directory" (preserves the legacy behavior of
// internal/tofu/output.go).
type tofuSource struct {
	workdir string

	// runner is dependency-injected so tests can substitute a fake. Production
	// callers leave it nil; we default to realTofuRunner.
	runner tofuRunner
}

type tofuRunner func(ctx context.Context, workdir string) ([]byte, error)

func newTofuSource(cfg Config) (*tofuSource, error) {
	if cfg.Path != "" {
		return nil, fmt.Errorf("source[tofu]: unexpected field 'path' (use 'workdir')")
	}
	return &tofuSource{workdir: cfg.Workdir, runner: realTofuRunner}, nil
}

func (t *tofuSource) Name() string {
	if t.workdir == "" {
		return "tofu (cwd)"
	}
	return "tofu (workdir=" + t.workdir + ")"
}

func (t *tofuSource) Type() string { return "tofu" }

func (t *tofuSource) Read(ctx context.Context) (map[string]json.RawMessage, error) {
	raw, err := t.runner(ctx, t.workdir)
	if err != nil {
		return nil, fmt.Errorf("source[%s]: %w", t.Name(), err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("source[%s]: parse tofu output: %w", t.Name(), err)
	}
	return out, nil
}
