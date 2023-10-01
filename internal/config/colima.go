package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/kevinburke/ssh_config"
	"github.com/x1unix/colima-nat-tun/internal/sshtun"
)

const (
	defaultProfile = "default"
	vmNamePrefix   = "colima-"
)

type ColimaConfig struct {
	Directory      string        `env:"DIR" flag:"dir" default:"$HOME/.colima" usage:"Colima directory"`
	ProfileName    string        `env:"PROFILE" flag:"profile" default:"default" usage:"Colima VM profile name"`
	ConnectTimeout time.Duration `env:"CONN_TIMEOUT" flag:"timeout" default:"5s" usage:"SSH and Docker connect timeout"`
}

// ExpandedDirectory returns Colima directory path with expanded environment variables.
func (cfg ColimaConfig) ExpandedDirectory() string {
	return os.ExpandEnv(cfg.Directory)
}

// NewDockerClient constructs a new Docker API client for Colima profile.
func (cfg ColimaConfig) NewDockerClient() (*docker.Client, error) {
	sockFileDir := filepath.Join(cfg.ExpandedDirectory(), cfg.ProfileName, "docker.sock")
	if _, err := os.Stat(sockFileDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf(
				"docker socker doesn't exists, please ensure that Colima VM is running (socket: %q)", sockFileDir,
			)
		}

		return nil, fmt.Errorf("cannot access docker socket: %w (socket: %q)", err, sockFileDir)
	}

	c, err := docker.NewClientWithOpts(
		docker.WithAPIVersionNegotiation(),
		docker.WithTLSClientConfigFromEnv(),
		docker.WithHost("unix://"+sockFileDir),

		// WithTimeout() breaks Docker events polling, disable for now.
		//docker.WithTimeout(cfg.ConnectTimeout),
	)
	if err != nil {
		err = fmt.Errorf("failed to build docker client: %w", err)
	}

	return c, err
}

// NewTunnelConfig constructs a new SSH tunnel manager config.
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

	tunCfg.ConnectTimeout = cfg.ConnectTimeout
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

	if isSSHConfigEmpty(cfg) {
		return nil, fmt.Errorf("empty Colima ssh config, please ensure that colima VM is running (file: %s)", fileName)
	}
	return cfg, nil
}

func getSSHAlias(profileName string) string {
	if profileName == defaultProfile {
		return "colima"
	}

	return vmNamePrefix + profileName
}

func isSSHConfigEmpty(cfg *ssh_config.Config) bool {
	for _, host := range cfg.Hosts {
		if len(host.Nodes) > 0 {
			return false
		}
	}

	return true
}
