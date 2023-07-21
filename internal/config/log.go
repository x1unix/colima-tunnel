package config

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

type LogConfig struct {
	Level zerolog.Level `env:"LEVEL" flag:"level" default:"info" usage:"Log level (debug,info,warn,error)"`
	File  string        `env:"FILE" flag:"file" usage:"Log file path"`
}

func (cfg LogConfig) NewLogger() (zerolog.Logger, io.Closer, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	conWriter := zerolog.NewConsoleWriter()
	if cfg.File == "" {
		return buildLogger(cfg.Level, conWriter), io.NopCloser(nil), nil
	}

	f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return zerolog.Logger{}, nil, fmt.Errorf("failed to create log file: %w", err)
	}

	w := io.MultiWriter(conWriter, f)
	return buildLogger(cfg.Level, w), f, nil
}

func buildLogger(level zerolog.Level, writer io.Writer) zerolog.Logger {
	return zerolog.New(writer).Level(level).With().Str("context", "app").Timestamp().Logger()
}
