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
	Transport gopacket.Layer

	// Network is network packet frame.
	//
	// Usually it's pointer to layers.IPv6 or layers.IPv4
	Network gopacket.Layer

	// Control contains network control layer, usually ICMP.
	Control gopacket.Layer
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

type IPData struct {
	// ID is packet ID.
	ID uint16

	// Length is packet total length including metadata.
	Length int

	// TTL is max packet hop count.
	TTL uint

	// FragmentData contains fragment information.
	//
	// Nil when packet is not fragmented.
	FragmentData *FragmentData
}

// Packet is parsed IP packet payload.
type Packet struct {
	IPData

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

// IsFragmented returns whether a packet is fragmented.
func (p Packet) IsFragmented() bool {
	return p.FragmentData != nil
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

	// TODO: use IP protocol field instead
	var (
		srcPort        int
		dstPort        int
		srcIP          net.IP
		dstIP          net.IP
		ipData         IPData
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

			ipData = IPData{
				ID:           ip4.Id,
				Length:       int(ip4.Length),
				TTL:          uint(ip4.TTL),
				FragmentData: extractFragmentData(&ip4),
			}
		case layers.LayerTypeIPv6:
			srcIP = ip6.SrcIP
			dstIP = ip6.DstIP
			netType = IPv6Network
			l.Network = &ip6
			ipData = IPData{
				Length:       int(ip6.Length),
				TTL:          uint(ip6.HopLimit),
				FragmentData: extractFragmentData(&ip4),
			}
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
			if ipData.FragmentData == nil {
				return nil, fmt.Errorf("unexpected fragment layer: %x", fragment)
			}

			ipData.FragmentData.Fragment = fragment
		default:
			// TODO: support SCTP?
			return nil, fmt.Errorf("unsupported layer type: %s", layerType.String())
		}
	}

	packet := Packet{
		IPData:        ipData,
		TransportType: transportType,
		NetworkType:   netType,
		Layers:        l,
		Payload:       packetContents,
	}

	// Skip transport parsing if packet is fragmented, or it's ICMP packet.
	if l.Control != nil || packet.IsFragmented() {
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

func extractFragmentData(pkg gopacket.Layer) *FragmentData {
	ip4, ok := pkg.(*layers.IPv4)
	if !ok {
		// TODO: support IPv6
		return nil
	}

	fragData := FragmentData{
		FragmentOffset: int(ip4.FragOffset * 8),
	}

	// If this is a fragment?
	if ip4.Flags&layers.IPv4MoreFragments != 0 {
		fragData.IsFirst = ip4.FragOffset == 0
		return &fragData
	}

	// Is it a last fragment?
	if ip4.FragOffset > 0 {
		fragData.IsLast = true
		return &fragData
	}

	return nil
}
