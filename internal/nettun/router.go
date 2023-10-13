package nettun

import (
	"context"
	"fmt"
	"io"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

var _ PacketHandler = (*PacketRouter)(nil)

// ProtocolHandlers is key-value pair of protocol name and packet handler.
type ProtocolHandlers = map[layers.IPProtocol]PacketHandler

// PacketRouter routes packets to different handlers depending on IP packet protocol.
type PacketRouter struct {
	logger   zerolog.Logger
	handlers ProtocolHandlers
}

func NewPacketRouter(logger zerolog.Logger, handlers ProtocolHandlers) *PacketRouter {
	return &PacketRouter{
		logger:   logger.With().Str("context", "router").Logger(),
		handlers: handlers,
	}
}

func (router PacketRouter) HandlePacket(ctx context.Context, packet *Packet, writer io.Writer) error {
	handler, ok := router.handlers[packet.Protocol]
	if !ok {
		return fmt.Errorf("no handler for protocol %s", packet.Protocol)
	}

	return handler.HandlePacket(ctx, packet, writer)
}
