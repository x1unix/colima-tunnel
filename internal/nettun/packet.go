package nettun

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Layers contains separated packet frames.
type Layers struct {
	TCP  *layers.TCP
	UDP  *layers.UDP
	ICMP gopacket.Layer
}

// FragmentData contains IP fragment information.
type FragmentData struct {
	Fragment gopacket.Fragment

	// FragmentOffset is fragment position from the start of original packet.
	FragmentOffset int

	// IsLast identifies if it's a last fragment.
	IsLast bool

	// IsFirst identifies if it's a first fragment.
	IsFirst bool
}

// IPHeader contains version-independent IP packet information.
type IPHeader struct {
	// ID is packet ID.
	ID uint32

	// Version is IP protocol version.
	Version uint8

	// SourceIP is sender IP address.
	SrcIP netip.Addr

	// DstIP is destination IP address.
	DstIP netip.Addr

	// Length is packet total length including metadata.
	Length int

	// HopLimit is max packet hop count.
	HopLimit uint

	// Protocol identifies inner layer protocol.
	//
	// For IPv6 it keeps value of NextHeader value.
	Protocol layers.IPProtocol

	// FragmentData contains fragment information.
	//
	// Nil when packet is not fragmented.
	FragmentData *FragmentData

	// RawHeader is raw IP header
	RawHeader gopacket.Layer
}

// IsFragmented returns whether a packet is fragmented.
func (h IPHeader) IsFragmented() bool {
	return h.FragmentData != nil
}

// Packet is parsed IP packet payload.
type Packet struct {
	IPHeader

	// Source is packet sender address.
	Source net.Addr

	// Dest is packet destination address.
	Dest net.Addr

	// Layers contains separated packet layers.
	Layers Layers

	// Payload is actual packet payload.
	//
	// Extracted from transport layer.
	Payload []byte
}

// ParsePacket parses IP packet from bytes.
func ParsePacket(data []byte) (*Packet, error) {
	header, payload, err := parseIPHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP header: %w", err)
	}

	if header.IsFragmented() {
		// TODO: extract zone for IPv6 packets
		return &Packet{
			IPHeader: *header,
			Source:   &net.IPAddr{IP: header.SrcIP.AsSlice()},
			Dest:     &net.IPAddr{IP: header.DstIP.AsSlice()},
		}, nil
	}

	packet, err := parseProtocolPayload(header, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP packet contents: %w", err)
	}

	return packet, nil
}

// ParsePacketWithHeader constructs a new packet with passed IP header and parsed payload.
//
// Payload is TCP/UDP or other transport layer payload.
func ParsePacketWithHeader(header IPHeader, payload []byte) (*Packet, error) {
	headerSize := 0
	if rawHeader := header.RawHeader; rawHeader != nil {
		headerSize = len(rawHeader.LayerContents())
	}

	header.FragmentData = nil
	header.Length = headerSize + len(payload)

	return parseProtocolPayload(&header, payload)
}

// SplitAddr extracts IP address and port from net.Addr.
//
// Returns nil net.IP value if net.Addr value is nil or unsupported.
func SplitAddr(addr net.Addr) (net.IP, int) {
	switch t := addr.(type) {
	case *net.TCPAddr:
		return t.IP, t.Port
	case *net.UDPAddr:
		return t.IP, t.Port
	case *net.IPAddr:
		return t.IP, 0
	}

	return nil, 0
}
