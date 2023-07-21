package sshtun

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type Manager struct {
	log zerolog.Logger
	cfg Config

	client *ssh.Client
}

// NewManager returns a new SSH tunnel manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		log: log.Logger.With().Str("context", "ssh").Logger(),
		cfg: cfg,
	}
}

// Connect establishes connection to SSH server.
func (m *Manager) Connect() error {
	m.log.Debug().
		Str("host", m.cfg.Server).
		Str("user", m.cfg.User).
		Dur("timeout", m.cfg.ConnectTimeout).
		Msg("connecting to ssh server...")

	client, err := ssh.Dial("tcp", m.cfg.Server, &ssh.ClientConfig{
		User: m.cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(m.cfg.PrivateKeys...),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  m.logBannerMsg,
		Timeout:         m.cfg.ConnectTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server %q: %w", m.cfg.Server, err)
	}

	m.client = client
	m.log.Info().
		Str("host", m.cfg.Server).
		Str("user", m.cfg.User).
		Msg("ssh connection established")
	return nil
}

func (m *Manager) Close() error {
	if m.client == nil {
		return nil
	}

	m.log.Info().Msg("closing ssh connection...")
	return m.client.Close()
}

func (m *Manager) logBannerMsg(msg string) error {
	m.log.Debug().Msgf("server: %s", msg)
	return nil
}
