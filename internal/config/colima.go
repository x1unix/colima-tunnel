package config

import (
	"fmt"
	"github.com/kevinburke/ssh_config"
	"github.com/x1unix/colima-nat-tun/internal/sshtun"
	"os"
	"path/filepath"
)

const (
	defaultProfile = "default"
	vmNamePrefix   = "colima-"
)

type ColimaConfig struct {
	Directory   string `env:"DIR" flag:"dir" default:"$HOME/.colima" usage:"Colima directory"`
	ProfileName string `env:"PROFILE" flag:"profile" default:"default" usage:"Colima VM profile name"`
}

func (cfg ColimaConfig) ExpandedDirectory() string {
	return os.ExpandEnv(cfg.Directory)
}

func (cfg ColimaConfig) NewTunnelConfig() (*sshtun.Config, error) {
	rootDir := cfg.ExpandedDirectory()
	sshConfigFile := filepath.Join(rootDir, "ssh_config")
	hostName := getSSHAlias(cfg.ProfileName)

	sshCfg, err := loadSSHConfig(sshConfigFile)
	if err != nil {
		return nil, err
	}

	host, ok := findHostConfig(sshCfg, hostName)
	if !ok {
		return nil, fmt.Errorf(
			"cannot find configuration for profile %q in ssh config file %q (host: %q)",
			cfg.ProfileName, sshConfigFile, hostName,
		)
	}

	tunCfg, err := sshtun.NewConfigFromHost(host)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot load ssh configuration: %w (ssh config file: %q)",
			err, sshConfigFile,
		)
	}

	return tunCfg, nil
}

func findHostConfig(cfg *ssh_config.Config, hostName string) (*ssh_config.Host, bool) {
	for _, v := range cfg.Hosts {
		if isWildcardHost(v) {
			continue
		}

		if !v.Matches(hostName) {
			continue
		}

		return v, true
	}

	return nil, false
}

func isWildcardHost(cfg *ssh_config.Host) bool {
	if len(cfg.Patterns) == 0 {
		return false
	}

	for _, pattern := range cfg.Patterns {
		str := pattern.String()
		if str == "*" {
			return true
		}
	}

	return false
}

func loadSSHConfig(fileName string) (*ssh_config.Config, error) {
	sshConfigFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open Colima ssh config file: %w", err)
	}

	defer sshConfigFile.Close()

	cfg, err := ssh_config.Decode(sshConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Colima ssh config file %q: %w", fileName, err)
	}

	return cfg, nil
}

func getSSHAlias(profileName string) string {
	if profileName == defaultProfile {
		return "colima"
	}

	return vmNamePrefix + profileName
}
