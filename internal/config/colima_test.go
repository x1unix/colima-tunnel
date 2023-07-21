package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/x1unix/colima-nat-tun/internal/sshtun"
	"golang.org/x/crypto/ssh"
)

func TestColimaConfig_ExpandedDirectory(t *testing.T) {
	t.Setenv("FOOBAR", "teststr")
	expect := "teststr/foobar"
	cfg := ColimaConfig{
		Directory: "$FOOBAR/foobar",
	}

	require.Equal(t, cfg.ExpandedDirectory(), expect)
}

func TestColimaConfig_NewTunnelConfig(t *testing.T) {
	cases := map[string]struct {
		profile     string
		dirName     string
		expectError string
		expect      sshtun.Config
	}{
		"should load config for default profile": {
			profile: defaultProfile,
			dirName: "testdata",
			expect: sshtun.Config{
				Server: "127.0.0.1:59244",
				User:   "colima",
				PrivateKeys: []ssh.Signer{
					mustReadKeyFile(t, "testdata/key.pem"),
				},
			},
		},
		"should load config for other profiles": {
			profile: "x86",
			dirName: "testdata",
			expect: sshtun.Config{
				Server: "127.0.0.1:59658",
				User:   "superbob",
				PrivateKeys: []ssh.Signer{
					mustReadKeyFile(t, "testdata/key.pem"),
				},
			},
		},
		"should validate if profile config is correct": {
			profile:     "broken",
			dirName:     "testdata",
			expectError: "TODO",
		},
		"should validate if profile exists": {
			profile:     "not-exists",
			dirName:     "testdata",
			expectError: `cannot find configuration for profile "not-exists"`,
		},
		"should validate ssh config file": {
			profile:     "foobar",
			dirName:     "testdata/not-exists",
			expectError: "failed to open Colima ssh config file",
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			cfg := ColimaConfig{
				Directory:   c.dirName,
				ProfileName: c.profile,
			}

			got, err := cfg.NewTunnelConfig()
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

func mustReadKeyFile(t *testing.T, name string) ssh.Signer {
	t.Helper()
	f, err := os.ReadFile(name)
	require.NoError(t, err, "failed to open key file")

	k, err := ssh.ParsePrivateKey(f)
	require.NoError(t, err, "failed to parse private key")
	return k
}
