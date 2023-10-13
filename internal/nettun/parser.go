package nettun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type noopDecodeFeedback struct{}

// SetTruncated implements gopacket.DecodeFeedback
func (_ noopDecodeFeedback) SetTruncated() {}

// layerDecoderFunc parses packet layer with IP header into Packet.
type layerDecoderFunc = func(layer gopacket.Layer, ipData *IPHeader, p *Packet) error

// decoders are key-value pair of IP payload type and decoder.
var protoDecoders = map[layers.IPProtocol]payloadDecoder{
	layers.IPProtocolTCP:    newPayloadDecoder(layers.LayerTypeTCP, parseTCP),
	layers.IPProtocolUDP:    newPayloadDecoder(layers.LayerTypeUDP, parseUDP),
	layers.IPProtocolICMPv4: newPayloadDecoder(layers.LayerTypeICMPv4, parseICMPv4),
	layers.IPProtocolICMPv6: newPayloadDecoder(layers.LayerTypeICMPv6, parseICMPv6),
}

// payloadDecoder contains necessary information to parse IP packet payload.
type payloadDecoder struct {
	layerType    gopacket.LayerType
	layerDecoder layerDecoderFunc
}

func newPayloadDecoder(layerType gopacket.LayerType, decodeFunc layerDecoderFunc) payloadDecoder {
	return payloadDecoder{
		layerType:    layerType,
		layerDecoder: decodeFunc,
	}
}

func parseIPHeader(data []byte) (*IPHeader, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("empty packet")
	}

	// IP packet version stored in 4 lower bits of first byte.
	version := data[0] >> 4
	switch version {
	case 4:
		return parseIPv4Header(data)
	case 6:
		return parseIPv6Header(data)
	default:
		return nil, nil, fmt.Errorf("invalid version in IP header: %d (%x)", version, data[0])
	}
}

func parseIPv6Header(data []byte) (*IPHeader, []byte, error) {
	ip6 := new(layers.IPv6)
	if err := ip6.DecodeFromBytes(data, noopDecodeFeedback{}); err != nil {
		return nil, nil, err
	}

	srcIP, _ := netip.AddrFromSlice(ip6.SrcIP)
	dstIP, _ := netip.AddrFromSlice(ip6.DstIP)

	return &IPHeader{
		// FIXME: is FlowLabel really packet ID for ipv6?
		Version:      6,
		ID:           ip6.FlowLabel,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		Length:       int(ip6.Length),
		HopLimit:     uint(ip6.HopLimit),
		Protocol:     ip6.NextHeader,
		RawHeader:    ip6,
		FragmentData: extractFragmentData(ip6),
	}, ip6.LayerPayload(), nil
}

func parseIPv4Header(data []byte) (*IPHeader, []byte, error) {
	ip4 := new(layers.IPv4)
	if err := ip4.DecodeFromBytes(data, noopDecodeFeedback{}); err != nil {
		return nil, nil, err
	}

	srcIP, _ := netip.AddrFromSlice(ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(ip4.DstIP)

	return &IPHeader{
		Version:      4,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		ID:           uint32(ip4.Id),
		Length:       int(ip4.Length),
		HopLimit:     uint(ip4.TTL),
		Protocol:     ip4.Protocol,
		RawHeader:    ip4,
		FragmentData: extractFragmentData(ip4),
	}, ip4.LayerPayload(), nil
}

func parseProtocolPayload(ipData *IPHeader, data []byte) (*Packet, error) {
	ipProto := ipData.Protocol
	decoder, ok := protoDecoders[ipProto]
	if !ok {
		return nil, fmt.Errorf("no decoder for %s layer", ipProto)
	}

	packet := gopacket.NewPacket(data, decoder.layerType, gopacket.Default)
	layer := packet.Layer(decoder.layerType)
	if layer == nil {
		return nil, fmt.Errorf("cannot find %s layer in IP packet payload", ipProto)
	}

	p := &Packet{
		Source:   &net.IPAddr{IP: ipData.SrcIP.AsSlice()},
		Dest:     &net.IPAddr{IP: ipData.DstIP.AsSlice()},
		IPHeader: *ipData,
		Payload:  layer.LayerPayload(),
	}

	err := decoder.layerDecoder(layer, ipData, p)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s layer: %w", ipProto, err)
	}

	return p, nil
}

func parseTCP(layer gopacket.Layer, ipData *IPHeader, p *Packet) error {
	tcp, err := safeCast[*layers.TCP](layer)
	if err != nil {
		return err
	}

	p.Source = &net.TCPAddr{
		IP:   ipData.SrcIP.AsSlice(),
		Port: int(tcp.SrcPort),
	}
	p.Dest = &net.TCPAddr{
		IP:   ipData.DstIP.AsSlice(),
		Port: int(tcp.DstPort),
	}

	p.Layers.TCP = tcp
	return nil
}

func parseUDP(layer gopacket.Layer, ipData *IPHeader, p *Packet) error {
	udp, err := safeCast[*layers.UDP](layer)
	if err != nil {
		return err
	}

	p.Source = &net.UDPAddr{
		IP:   ipData.SrcIP.AsSlice(),
		Port: int(udp.SrcPort),
	}
	p.Dest = &net.UDPAddr{
		IP:   ipData.DstIP.AsSlice(),
		Port: int(udp.DstPort),
	}

	p.Layers.UDP = udp
	return nil
}

func parseICMPv4(layer gopacket.Layer, _ *IPHeader, p *Packet) error {
	icmp, err := safeCast[*layers.ICMPv4](layer)
	if err != nil {
		return err
	}

	p.Layers.ICMP = icmp
	return nil
}

func parseICMPv6(layer gopacket.Layer, _ *IPHeader, p *Packet) error {
	icmp, err := safeCast[*layers.ICMPv6](layer)
	if err != nil {
		return err
	}

	p.Layers.ICMP = icmp
	return nil
}

func extractFragmentData(pkg gopacket.Layer) *FragmentData {
	ip4, ok := pkg.(*layers.IPv4)
	if !ok {
		// TODO: support IPv6
		return nil
	}

	fragData := FragmentData{
		FragmentOffset: int(ip4.FragOffset * 8),
		Fragment:       pkg.LayerPayload(),
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

func safeCast[T any](v any) (T, error) {
	got, ok := v.(T)
	if !ok {
		return got, fmt.Errorf("cannot cast %T to %T", v, got)
	}

	return got, nil
}
