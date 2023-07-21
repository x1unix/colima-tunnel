package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cristalhq/aconfig"
	"github.com/cristalhq/aconfig/aconfigdotenv"
	"github.com/cristalhq/aconfig/aconfigtoml"
)

type Config struct {
	Net    NetworkConfig
	Colima ColimaConfig
	Log    LogConfig
}

type NetworkConfig struct {
	IP   string `env:"IP" flag:"ip" default:"100.64.0.10" usage:"Client IP address"`
	CIDR string `env:"CIDR" flag:"cidr" default:"100.64.0.0/24" usage:"Subnet CIDR"`
}

func Load() (*Config, error) {
	cfg := new(Config)

	loader := aconfig.LoaderFor(cfg, aconfig.Config{
		AllowUnknownFields: false,
		AllowUnknownEnvs:   true,
		AllowUnknownFlags:  false,
		FlagDelimiter:      "-",
		DontGenerateTags:   false,
		FailOnFileNotFound: false,
		FileFlag:           "config",
		FileDecoders: map[string]aconfig.FileDecoder{
			".conf": aconfigtoml.New(),
			".env":  aconfigdotenv.New(),
		},
	})

	if err := loader.Load(); err != nil {
		if isHelpError(err) {
			os.Exit(1)
		}

		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return cfg, nil
}

func isHelpError(err error) bool {
	if err == nil {
		return false
	}

	if u := errors.Unwrap(err); u != nil {
		err = u
	}

	return strings.HasSuffix(err.Error(), "help requested")
}
