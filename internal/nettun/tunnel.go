package nettun

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/songgao/water"
	"github.com/x1unix/colima-nat-tun/internal/platform"
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
	netMgr      platform.NetworkManager
	ctx         context.Context
	cancelFn    context.CancelFunc
	fragBuff    fragmentBuffer
}

func NewTunnel(log zerolog.Logger, cfg Config) *Tunnel {
	logger := log.With().Str("context", "listener").Logger()

	return &Tunnel{
		log:      logger,
		cfg:      cfg,
		fragBuff: newFragmentBuffer(),
		netMgr:   platform.GetNetworkManager(log),
	}
}

// Name returns tunnel interface name.
func (tun *Tunnel) Name() string {
	if tun == nil {
		return ""
	}

	return tun.iface.Name()
}

// Start starts network tunnel.
func (tun *Tunnel) Start(ctx context.Context) error {
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	tun.iface = iface
	tun.log.Info().
		Str("tun", iface.Name()).
		Msgf("started TUN interface: %s", iface.Name())
	if err := tun.configureTunnel(ctx); err != nil {
		return err
	}

	tun.ctx, tun.cancelFn = context.WithCancel(ctx)
	tun.listen(tun.ctx)
	return nil
}

func (tun *Tunnel) Close() error {
	if tun.cancelFn == nil {
		return errors.New("listener already closed")
	}

	tun.cancelFn()
	tun.closeInterface()
	tun.cancelFn = nil
	return nil
}

func (tun *Tunnel) listen(ctx context.Context) {
	defer tun.closeInterface()

	tun.isListening.Store(true)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// TODO: use bytes pool
		rawPacket := make([]byte, tun.cfg.MTU)
		n, err := tun.iface.Read(rawPacket)
		if err != nil {
			if ctx.Err() != nil {
				// Just exit immediately if context already canceled
				return
			}

			_ = tun.iface.Close()
			tun.log.Fatal().Err(err).Msg("failed to read packet")
			return
		}

		packet, err := ParsePacket(rawPacket[:n])
		if err != nil {
			tun.log.Err(err).
				Hex("data", rawPacket[:n]).
				Msg("failed to parse packet")
			continue
		}

		if packet.IsFragmented() {
			tun.handleFragmentedPacket(packet)
		}

		// TODO: Use worker pool instead?
		go tun.handlePacket(packet)
	}
}

func (tun *Tunnel) handlePacket(packet *Packet) {
	tun.log.Debug().
		Stringer("src", packet.Source).
		Stringer("dst", packet.Dest).
		Stringer("protocol", packet.Protocol).
		Uint8("ip_ver", packet.Version).
		Hex("payload", packet.Payload).
		Msg("received network packet")

}

func (tun *Tunnel) handleFragmentedPacket(packet *Packet) {
	tun.log.Debug().
		Stringer("src", packet.Source).
		Stringer("dst", packet.Dest).
		Stringer("protocol", packet.Protocol).
		Uint8("ip_ver", packet.Version).
		Bool("is_first", packet.FragmentData.IsFirst).
		Bool("is_last", packet.FragmentData.IsLast).
		Hex("fragment", packet.FragmentData.Fragment).
		Int("offset", packet.FragmentData.FragmentOffset).
		Msg("received fragmented network packet")

	if !packet.FragmentData.IsLast {
		tun.fragBuff.addFragment(packet)
		return
	}

	data, err := tun.fragBuff.assemblyFragments(packet)
	if err != nil {
		tun.log.Err(err).
			Uint32("id", packet.ID).
			Stringer("src", packet.Source).
			Stringer("dst", packet.Dest).
			Stringer("proto", packet.Protocol).
			Int("offset", packet.FragmentData.FragmentOffset).
			Msg("failed to get packet fragments")
		return
	}

	assembledPacket, err := ParsePacketWithHeader(packet.IPHeader, data)
	if err != nil {
		tun.log.Err(err).
			Uint32("id", packet.ID).
			Stringer("src", packet.Source).
			Stringer("dst", packet.Dest).
			Stringer("proto", packet.Protocol).
			Hex("data", data).
			Int("offset", packet.FragmentData.FragmentOffset).
			Msg("failed to assembly packet from fragments")
		return
	}

	tun.log.Debug().
		Uint32("id", packet.ID).
		Stringer("src", packet.Source).
		Stringer("dst", packet.Dest).
		Stringer("proto", packet.Protocol).
		Int("offset", packet.FragmentData.FragmentOffset).
		Msg("successfully assembled packet")

	// TODO: Use worker pool instead?
	go tun.handlePacket(assembledPacket)
}

func (tun *Tunnel) closeInterface() {
	if !tun.isListening.Load() {
		tun.log.Debug().Msg("listener already closed, skip close")
		return
	}

	tun.isListening.Store(false)
	tun.log.Info().Str("iface", tun.iface.Name()).
		Msg("closing the tunnel interface...")

	if err := tun.iface.Close(); err != nil {
		tun.log.Warn().Err(err).Str("iface", tun.iface.Name()).
			Msg("failed to close the tunnel")
		return
	}

	tun.log.Debug().Str("iface", tun.iface.Name()).
		Msg("tunnel closed successfully")
}

func (tun *Tunnel) configureTunnel(ctx context.Context) error {
	ifaceName := tun.iface.Name()

	tun.log.Info().
		Str("tun", ifaceName).
		IPAddr("client_ip", tun.cfg.ClientIP).
		IPAddr("gateway_ip", tun.cfg.GatewayIP).
		IPPrefix("net", *tun.cfg.Network).
		Msg("assigning IP address...")

	err := tun.netMgr.SetInterfaceAddress(
		ctx, tun.iface.Name(), tun.cfg.ClientIP, tun.cfg.GatewayIP,
	)
	if err != nil {
		return fmt.Errorf("failed to configure tunnel IP address: %w", err)
	}

	tun.log.Debug().
		Str("tun", ifaceName).
		Uint("mtu", tun.cfg.MTU).
		Msg("updating interface MTU...")
	err = tun.netMgr.SetInterfaceMTU(ctx, tun.iface.Name(), tun.cfg.MTU)
	if err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}
