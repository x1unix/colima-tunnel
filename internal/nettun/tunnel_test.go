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
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		udp   layers.UDP
		icmp4 layers.ICMPv4
		icmp6 layers.ICMPv6

		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4, &icmp4, &icmp6, &ip4, &ip6, &tcp, &udp, &payload,
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)
	fmt.Println("Decoding packet")
	err := parser.DecodeLayers(src, &decodedLayers)
	for _, typ := range decodedLayers {
		fmt.Println("  Successfully decoded layer type", typ)
		switch typ {
		case layers.LayerTypeEtherIP:
			t.Log("EtherIP!")
		case layers.LayerTypeIPv4:
			t.Logf("    IP4: source=%s dest=%s", ip4.SrcIP, ip4.DstIP)
		case layers.LayerTypeIPv6:
			t.Logf("    IP6: source=%s dest=%s", ip6.SrcIP, ip6.DstIP)
		case layers.LayerTypeTCP:
			t.Logf("    TCP: source=%d dest=%d", tcp.SrcPort, tcp.DstPort)
		case layers.LayerTypeUDP:
			t.Logf("    UDP: source=%d dest=%d", udp.SrcPort, udp.DstPort)
		}
	}

	t.Log("packet payload:", payload)
	require.NoError(t, err, "failed to decode layers")
}
