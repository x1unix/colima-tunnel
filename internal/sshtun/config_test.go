package sshtun

import (
	"os"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestNewConfigFromHost(t *testing.T) {
	cases := map[string]struct {
		host        string
		sshConfig   string
		expectError string
		expect      Config
	}{
		"should load config": {
			host:      "test",
			sshConfig: "testdata/ssh_config-valid",
			expect: Config{
				Server: "127.0.0.12:2222",
				User:   "root",
				PrivateKeys: []ssh.Signer{
					mustReadKeyFile(t, "testdata/key-valid-1.pem"),
					mustReadKeyFile(t, "testdata/key-valid-2.pem"),
				},
			},
		},
		"should require keys": {
			host:        "test",
			sshConfig:   "testdata/ssh_config-no-keys",
			expectError: "missing IdentityFile section. At least 1 ssh key required",
		},
		"should require user": {
			host:        "test",
			sshConfig:   "testdata/ssh_config-no-user",
			expectError: "missing User section",
		},
		"should require port": {
			host:        "test",
			sshConfig:   "testdata/ssh_config-no-port",
			expectError: "missing Port parameter",
		},
		"should check key path": {
			host:        "test",
			sshConfig:   "testdata/ssh_config-bad-key",
			expectError: "error reading parameter IdentityFile: failed to read private key",
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			f, err := os.ReadFile(c.sshConfig)
			require.NoError(t, err)
			sshCfg, err := ssh_config.DecodeBytes(f)
			require.NoError(t, err)
			require.NotEmpty(t, sshCfg.Hosts, "empty ssh config file")
			host := lookupHost(t, c.host, sshCfg)
			got, err := NewConfigFromHost(host)
			if c.expectError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), c.expectError)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, c.expect, *got)
		})
	}
}

func lookupHost(t *testing.T, name string, cfg *ssh_config.Config) *ssh_config.Host {
	for _, v := range cfg.Hosts {
		if isWildcardHost(v) {
			continue
		}

		if !v.Matches(name) {
			continue
		}

		return v
	}

	t.Fatalf("cannot find host %q in ssh config", name)
	return nil
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

func mustReadKeyFile(t *testing.T, name string) ssh.Signer {
	t.Helper()
	f, err := os.ReadFile(name)
	require.NoError(t, err, "failed to open key file")

	k, err := ssh.ParsePrivateKey(f)
	require.NoError(t, err, "failed to parse private key")
	return k
}
