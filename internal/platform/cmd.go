package platform

import (
	"context"
	"os/exec"
	"sync"

	"github.com/rs/zerolog"
)

var (
	cmdRunner CommandRunner
	cmdOnce   sync.Once
)

type CommandRunner interface {
	RunCommand(ctx context.Context, name string, args ...string) error
}

type systemCommandRunner struct {
	log zerolog.Logger
}

func (r systemCommandRunner) RunCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

	r.log.Debug().
		Str("cmd", name).
		Strs("cmdline", cmd.Args).
		Msgf("running command %s", cmd.Args)

	stdout := r.log.With().
		Str("cmd", name).
		Strs("cmdline", cmd.Args).
		Str("type", "stdout").
		Str(zerolog.LevelFieldName, zerolog.DebugLevel.String()).
		Logger()

	stderr := r.log.With().
		Str(zerolog.LevelFieldName, zerolog.ErrorLevel.String()).
		Str("cmd", name).
		Strs("cmdline", cmd.Args).
		Str("type", "stderr").
		Logger()

	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// GetCommandRunner returns global command runner.
func GetCommandRunner(logger zerolog.Logger) CommandRunner {
	cmdOnce.Do(func() {
		cmdRunner = systemCommandRunner{
			log: logger.With().Str("context", "cmd").Logger(),
		}
	})

	return cmdRunner
}
