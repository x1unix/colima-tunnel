package nettun

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TransportType uint

func (t TransportType) String() string {
	switch t {
	case TCPTransportType:
		return "tcp"
	case UDPTransportType:
		return "udp"
	case NoTransportType:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

const (
	NoTransportType TransportType = iota
	TCPTransportType
	UDPTransportType
)

type NetworkType uint

func (t NetworkType) String() string {
	switch t {
	case IPv4Network:
		return "ipv4"
	case IPv6Network:
		return "ipv6"
	case NoNetwork:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

const (
	NoNetwork NetworkType = iota
	IPv4Network
	IPv6Network
)

// Layers contains separated packet frames.
type Layers struct {
	// Transport is transport layer packet frame.
	//
	// Usually it's pointer to layers.TCP or layers.UDP.
	Transport any

	// Network is network packet frame.
	//
	// Usually it's pointer to layers.IPv6 or layers.IPv4
	Network any

	// Control contains network control layer, usually ICMP.
	Control any
}

// Packet is parsed IP packet payload.
type Packet struct {
	// Source is packet sender address.
	Source net.Addr

	// Dest is packet destination address.
	Dest net.Addr

	// TransportType is transport layer type.
	TransportType TransportType

	// NetworkType is network layer type.
	NetworkType NetworkType

	// Layers contains separated packet layers.
	Layers Layers

	// Payload is actual packet payload.
	//
	// Extracted from transport layer.
	Payload []byte
}

// ParsePacket parses IP packet contents from payload.
func ParsePacket(data []byte) (*Packet, error) {
	var (
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		udp   layers.UDP
		icmp4 layers.ICMPv4
		icmp6 layers.ICMPv6

		fragment gopacket.Fragment
		payload  gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4, &ip4, &ip6, &icmp4, &icmp6, &tcp, &udp, &payload, &fragment,
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	err := parser.DecodeLayers(data, &decodedLayers)
	if err != nil {
		return nil, fmt.Errorf("failed to decode layers: %w", err)
	}

	var (
		srcPort        int
		dstPort        int
		srcIP          net.IP
		dstIP          net.IP
		netType        NetworkType
		transportType  TransportType
		packetContents []byte
		l              Layers
	)
	for _, layerType := range decodedLayers {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP = ip4.SrcIP
			dstIP = ip4.DstIP
			netType = IPv4Network
			l.Network = &ip4
		case layers.LayerTypeIPv6:
			srcIP = ip6.SrcIP
			dstIP = ip6.DstIP
			netType = IPv6Network
			l.Network = &ip6
		case layers.LayerTypeTCP:
			srcPort = int(tcp.SrcPort)
			dstPort = int(tcp.DstPort)
			transportType = TCPTransportType
			l.Transport = &tcp
		case layers.LayerTypeUDP:
			srcPort = int(udp.SrcPort)
			dstPort = int(udp.DstPort)
			transportType = UDPTransportType
			l.Transport = &udp
		case layers.LayerTypeICMPv4:
			// src and dest IP is parsed at layer above
			l.Control = &icmp4
		case layers.LayerTypeICMPv6:
			// src and dest IP is parsed at layer above
			l.Control = &icmp6
		case gopacket.LayerTypePayload:
			packetContents = payload
		case gopacket.LayerTypeFragment:
			packetContents = fragment
		default:
			// TODO: support SCTP?
			// TODO: support Fragment!!!
			return nil, fmt.Errorf("unsupported layer type: %s", layerType.String())
		}
	}

	// TODO: support Fragment - https://chat.openai.com/share/3d3ad75a-cef1-4e01-9064-0f4cd75a00ec
	packet := Packet{
		TransportType: transportType,
		NetworkType:   netType,
		Layers:        l,
		Payload:       packetContents,
	}

	if l.Control != nil {
		packet.Source = &net.IPAddr{IP: srcIP}
		packet.Dest = &net.IPAddr{IP: dstIP}
		return &packet, nil
	}

	switch transportType {
	case TCPTransportType:
		packet.Source = &net.TCPAddr{
			IP:   srcIP,
			Port: srcPort,
		}
		packet.Dest = &net.TCPAddr{
			IP:   dstIP,
			Port: dstPort,
		}
	case UDPTransportType:
		packet.Source = &net.UDPAddr{
			IP:   srcIP,
			Port: srcPort,
		}
		packet.Dest = &net.UDPAddr{
			IP:   dstIP,
			Port: dstPort,
		}
	default:
		return nil, errors.New("missing transport or control layer")
	}

	return &packet, nil
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
