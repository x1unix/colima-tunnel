package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/x1unix/colima-nat-tun/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	logger, closer, err := cfg.Log.NewLogger()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize logger")
	}

	defer closer.Close()
	log.Logger = logger
	if err := run(logger, cfg); err != nil {
		_ = closer.Close()
		logger.Fatal().Err(err).Msg("failed to start daemon")
	}
}

func run(logger zerolog.Logger, cfg *config.Config) error {
	logger.Info().
		Str("profile", cfg.Colima.ProfileName).
		Msgf("reading Colima settings from %q ...", cfg.Colima.ExpandedDirectory())

	tunCfg, err := cfg.Colima.NewTunnelConfig()
	if err != nil {
		return err
	}

	logger.Info().
		Str("host", tunCfg.Server).
		Str("user", tunCfg.User).
		Int("keys_count", len(tunCfg.PrivateKeys)).
		Msg("ssh settings loaded successfully")
	return nil
}
