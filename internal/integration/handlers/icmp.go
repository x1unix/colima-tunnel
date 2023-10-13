package handlers

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/x1unix/colima-nat-tun/internal/nettun"
)

var _ nettun.PacketHandler = (*ICMPv4Handler)(nil)

// ICMPTypeCodeEchoRequest is ICMP echo request combined type and code.
const ICMPTypeCodeEchoRequest = layers.ICMPv4TypeCode(layers.ICMPv4TypeEchoRequest << 8)

type Pinger interface {
	// Ping checks whether passed IP address is reachable
	Ping(addr netip.Addr) bool
}

type ICMPv4Handler struct {
	logger zerolog.Logger
	pinger Pinger
}

func NewICMPv4Handler(logger zerolog.Logger, pinger Pinger) *ICMPv4Handler {
	return &ICMPv4Handler{
		logger: logger.With().Str("context", "ping").Logger(),
		pinger: pinger,
	}
}

func (h ICMPv4Handler) HandlePacket(ctx context.Context, packet *nettun.Packet, writer io.Writer) error {
	if packet.Layers.ICMP == nil {
		return errors.New("not an ICMP packet")
	}

	icmp4, ok := packet.Layers.ICMP.(*layers.ICMPv4)
	if !ok {
		return fmt.Errorf("bad ICMP layer type %T", icmp4)
	}

	if icmp4.TypeCode != ICMPTypeCodeEchoRequest {
		return fmt.Errorf("unsupported ICMP request: %[1]s (%[1]d)", icmp4.TypeCode)
	}

	isAlive := h.pinger.Ping(packet.DstIP)
	h.logger.Info().
		Stringer("dst", packet.DstIP).
		Bool("alive", isAlive).
		Msg("got ping request")
	if !isAlive {
		// Discard packet if address is unreachable
		return nil
	}

	id, err := newIPv4ID()
	if err != nil {
		return err
	}

	ipLayer := &layers.IPv4{
		Version:    4,
		Id:         id,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        uint8(packet.HopLimit),
		Protocol:   packet.Protocol,
		SrcIP:      packet.DstIP.AsSlice(),
		DstIP:      packet.SrcIP.AsSlice(),
	}
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoReply,
		Id:       icmp4.Id,
		Seq:      icmp4.Seq,
	}
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options, ipLayer, icmpLayer, gopacket.Payload(icmp4.Payload))
	if err != nil {
		return fmt.Errorf("failed to serialize layers: %w", err)
	}

	_, err = writer.Write(buffer.Bytes())
	return err
}

func newIPv4ID() (uint16, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(65535))
	if err != nil {
		return 0, fmt.Errorf("failed to generate IPv4 ID: %w", err)
	}

	return uint16(v.Uint64()), nil
}
