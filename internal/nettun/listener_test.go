package nettun

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGoPacket(t *testing.T) {
	src := []byte{
		0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x71, 0x30, 0x64, 0x40, 0x00, 0x0A, 0x64, 0x40, 0x00, 0xFE, 0xC0, 0xEA, 0x00, 0x50, 0x86, 0xDB, 0x69, 0xAE, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x02, 0xFF, 0xFF, 0x30, 0xE0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0A, 0xA0, 0x53, 0xEA, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00,
	}
	var (
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP

		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ip6, &tcp, &udp, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	fmt.Println("Decoding packet")
	err := parser.DecodeLayers(src, &decodedLayers)
	for _, typ := range decodedLayers {
		fmt.Println("  Successfully decoded layer type", typ)
		switch typ {
		case layers.LayerTypeEtherIP:
			t.Log()
		case layers.LayerTypeIPv4:
			t.Log("    IP4 ", ip4.SrcIP, ip4.DstIP)
		case layers.LayerTypeIPv6:
			t.Log("    IP6 ", ip6.SrcIP, ip6.DstIP)
		case layers.LayerTypeTCP:
			t.Log("    TCP ", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeUDP:
			t.Log("    UDP ", udp.SrcPort, udp.DstPort)
		}
	}

	require.NoError(t, err, "failed to decode layers")
}
