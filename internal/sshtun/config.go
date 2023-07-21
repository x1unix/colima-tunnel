package sshtun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	// Server is SSH server address.
	//
	// Address is in format "host:port"
	Server string

	// User is SSH user.
	User string

	// PrivateKeys is a list SSH private keys for auth.
	//
	// Use ssh.ParsePrivateKey to create a new key.
	PrivateKeys []ssh.Signer

	// ConnectTimeout is SSH connection timeout
	ConnectTimeout time.Duration
}

type sshHostConfig struct {
	hostName string
	port     string
	user     string
	keys     []ssh.Signer
}

func (cfg *sshHostConfig) apply(key, value string) error {
	key = strings.ToLower(key)
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}

	switch key {
	case "user":
		cfg.user = value
	case "port":
		cfg.port = value
	case "hostname":
		cfg.hostName = value
	case "identityfile":
		keyFile, err := os.ReadFile(value)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}

		keyData, err := ssh.ParsePrivateKey(keyFile)
		if err != nil {
			return fmt.Errorf("failed to parse private key %q: %w", keyFile, err)
		}

		cfg.keys = append(cfg.keys, keyData)
	}

	return nil
}

func (cfg *sshHostConfig) toConfig() (*Config, error) {
	if cfg.port == "" {
		return nil, errors.New("missing Port parameter")
	}

	if cfg.user == "" {
		return nil, errors.New("missing User section")
	}

	if len(cfg.keys) == 0 {
		return nil, errors.New("missing IdentityFile section. At least 1 ssh key required")
	}

	return &Config{
		Server:      net.JoinHostPort(cfg.hostName, cfg.port),
		User:        cfg.user,
		PrivateKeys: cfg.keys,
	}, nil
}

// NewConfigFromHost constructs a new tunnel config from SSH config host section.
func NewConfigFromHost(host *ssh_config.Host) (*Config, error) {
	sshCfg := &sshHostConfig{
		hostName: "127.0.0.1",
		keys:     make([]ssh.Signer, 0, 2),
	}

	for _, node := range host.Nodes {
		switch t := node.(type) {
		case *ssh_config.Empty:
			continue
		case *ssh_config.KV:
			// keys are case-insensitive per the spec
			if err := sshCfg.apply(t.Key, t.Value); err != nil {
				return nil, fmt.Errorf(
					"error reading parameter %s: %w (at %s)",
					t.Key, err, t.Pos().String(),
				)
			}
		case *ssh_config.Include:
			return nil, fmt.Errorf("include is not supported (at %s)", t.Pos().String())
		default:
			return nil, fmt.Errorf("unsupported ssh config section %T", t)
		}
	}

	return sshCfg.toConfig()
}
