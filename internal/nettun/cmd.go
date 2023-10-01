package nettun

import (
	"context"
	"os/exec"

	"github.com/rs/zerolog"
)

type CommandRunner interface {
	RunCommand(ctx context.Context, name string, args ...string) error
}

type systemCommandRunner struct {
	log zerolog.Logger
}

func (r systemCommandRunner) RunCommand(ctx context.Context, name string, args ...string) error {
	stdout := r.log.With().
		Str("cmd", name).
		Strs("args", args).
		Str("type", "stdout").
		Str(zerolog.LevelFieldName, zerolog.DebugLevel.String()).
		Logger()

	stderr := r.log.With().
		Str(zerolog.LevelFieldName, zerolog.ErrorLevel.String()).
		Str("cmd", name).
		Strs("args", args).
		Str("type", "stderr").
		Logger()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
