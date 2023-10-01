package nettun

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/songgao/water"
)

const (
	maxMTU = 1600
	minMTU = 576
)

type Tunnel struct {
	log zerolog.Logger
	cfg Config

	isListening atomic.Bool
	iface       *water.Interface
	netMgr      NetworkManager
	ctx         context.Context
	cancelFn    context.CancelFunc
}

func NewTunnel(log zerolog.Logger, cfg Config) *Tunnel {
	logger := log.With().Str("context", "listener").Logger()

	return &Tunnel{
		log:    logger,
		cfg:    cfg,
		netMgr: GetNetworkManager(log),
	}
}

func (l *Tunnel) Start(ctx context.Context) error {
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	l.iface = iface
	l.log.Info().
		Str("tun", iface.Name()).
		Msgf("started TUN interface: %s", iface.Name())
	if err := l.configureTunnel(ctx); err != nil {
		return err
	}

	l.ctx, l.cancelFn = context.WithCancel(ctx)
	l.listen(l.ctx)
	return nil
}

func (l *Tunnel) Close() error {
	if l.cancelFn == nil {
		return errors.New("listener already closed")
	}

	l.cancelFn()
	l.closeInterface()
	l.cancelFn = nil
	return nil
}

func (l *Tunnel) listen(ctx context.Context) {
	defer l.closeInterface()

	l.isListening.Store(true)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// TODO: use bytes pool
		packet := make([]byte, l.cfg.MTU)
		n, err := l.iface.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				// Just exit immediately if context already canceled
				return
			}

			_ = l.iface.Close()
			l.log.Fatal().Err(err).Msg("failed to read packet")
			return
		}

		go l.handlePacket(packet[:n])
	}
}

func (l *Tunnel) handlePacket(packet []byte) {
	l.log.Debug().Hex("packet", packet).
		Msg("received packet")

	// As this is a p2p tunnel, we're expecting a IP packet here.

}

func (l *Tunnel) closeInterface() {
	if !l.isListening.Load() {
		l.log.Debug().Msg("listener already closed, skip close")
		return
	}

	l.isListening.Store(false)
	l.log.Info().Str("iface", l.iface.Name()).
		Msg("closing the tunnel interface...")

	if err := l.iface.Close(); err != nil {
		l.log.Warn().Err(err).Str("iface", l.iface.Name()).
			Msg("failed to close the tunnel")
		return
	}

	l.log.Debug().Str("iface", l.iface.Name()).
		Msg("tunnel closed successfully")
}

func (l *Tunnel) configureTunnel(ctx context.Context) error {
	ifaceName := l.iface.Name()

	l.log.Info().
		Str("tun", ifaceName).
		IPAddr("client_ip", l.cfg.ClientIP).
		IPAddr("gateway_ip", l.cfg.GatewayIP).
		IPPrefix("net", *l.cfg.Network).
		Msg("assigning IP address...")

	err := l.netMgr.SetInterfaceAddress(
		ctx, l.iface.Name(), l.cfg.ClientIP, l.cfg.GatewayIP,
	)
	if err != nil {
		return fmt.Errorf("failed to configure tunnel IP address: %w", err)
	}

	l.log.Debug().
		Str("tun", ifaceName).
		Uint("mtu", l.cfg.MTU).
		Msg("updating interface MTU...")
	err = l.netMgr.SetInterfaceMTU(ctx, l.iface.Name(), l.cfg.MTU)
	if err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}
