package platform

import (
	"context"
	"os"
	"os/exec"
	"sync"

	"github.com/rs/zerolog"
)

var (
	cmdRunner CommandRunner
	cmdOnce   sync.Once

	_, isCmdDryRun = os.LookupEnv("COLIMA_TUN_DRY_RUN")
)

type CommandRunner interface {
	RunCommand(ctx context.Context, name string, args ...string) error
}

type noopCommandRunner struct {
	log zerolog.Logger
}

func (s noopCommandRunner) RunCommand(ctx context.Context, name string, args ...string) error {
	s.log.Debug().
		Str("cmd", name).
		Strs("cmdline", append([]string{name}, args...)).
		Msgf("running command: '%s %s'", name, args)
	return nil
}

type systemCommandRunner struct {
	log zerolog.Logger
}

func (r systemCommandRunner) RunCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

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
		if isCmdDryRun {
			cmdRunner = noopCommandRunner{log: logger}
			return
		}
		cmdRunner = systemCommandRunner{log: logger}
	})

	return cmdRunner
}
