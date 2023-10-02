package nettun

import (
	"net"
	"os"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestSplitAddr(t *testing.T) {
	cases := map[string]struct {
		wantIP   net.IP
		wantPort int
		input    net.Addr
	}{
		"tcp": {
			wantIP:   net.IPv4(10, 11, 0, 1),
			wantPort: 80,
			input: &net.TCPAddr{
				IP:   net.IPv4(10, 11, 0, 1),
				Port: 80,
			},
		},
		"udp": {
			wantIP:   net.IPv4(192, 168, 254, 1),
			wantPort: 4028,
			input: &net.UDPAddr{
				IP:   net.IPv4(192, 168, 254, 1),
				Port: 4028,
			},
		},
		"ip-only": {
			wantIP: net.IPv4(1, 1, 1, 1),
			input: &net.IPAddr{
				IP: net.IPv4(1, 1, 1, 1),
			},
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			addr, port := SplitAddr(c.input)
			require.Equal(t, c.wantIP, addr)
			require.Equal(t, c.wantPort, port)
		})
	}
}

func staticSource(src ...byte) func(t *testing.T) []byte {
	return func(_ *testing.T) []byte {
		return src
	}
}

func fileSource(fname string) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		t.Helper()
		data, err := os.ReadFile(fname)
		require.NoError(t, err, "failed to open file:", fname)
		return data
	}
}

func TestParsePacket(t *testing.T) {
	cases := map[string]struct {
		src       func(t *testing.T) []byte
		expect    *Packet
		expectErr string
	}{
		"should decode TCP SYN": {
			src: fileSource("testdata/tcp-syn.bin"),
			expect: &Packet{
				Source: &net.TCPAddr{
					IP:   net.IP{100, 64, 0, 10},
					Port: 49386,
				},
				Dest: &net.TCPAddr{
					IP:   net.IP{100, 64, 0, 254},
					Port: 80,
				},
				TransportType: TCPTransportType,
				NetworkType:   IPv4Network,
				Layers: Layers{
					Transport: &layers.TCP{
						SrcPort:    49386,
						DstPort:    80,
						Seq:        2262526382,
						DataOffset: 11,
						SYN:        true,
						Window:     65535,
						Checksum:   12512,
					},
					Network: &layers.IPv4{
						Version:    4,
						IHL:        5,
						TOS:        0,
						Length:     64,
						Id:         0,
						Flags:      layers.IPv4DontFragment,
						FragOffset: 0,
						TTL:        64,
						Protocol:   layers.IPProtocolTCP,
						Checksum:   28976,
						SrcIP:      net.IP{100, 64, 0, 10},
						DstIP:      net.IP{100, 64, 0, 254},
					},
				},
				Payload: nil,
			},
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			src := c.src(t)
			got, err := ParsePacket(src)
			if c.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), c.expectErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			sanitizeIncomparable(t, got)
			sanitizeIncomparable(t, c.expect)
			require.Equal(t, c.expect, got)
		})
	}
}

func sanitizeIncomparable(t *testing.T, pkg *Packet) {
	cleanLayer(t, pkg.Layers.Network)
	cleanLayer(t, pkg.Layers.Control)
	cleanLayer(t, pkg.Layers.Transport)
}

func cleanLayer(t *testing.T, l any) {
	if l == nil {
		return
	}

	switch tLayer := l.(type) {
	case *layers.IPv4:
		tLayer.BaseLayer = layers.BaseLayer{}
		tLayer.DstIP = trimIPBytes(tLayer.DstIP)
		tLayer.SrcIP = trimIPBytes(tLayer.SrcIP)
	case *layers.IPv6:
		tLayer.BaseLayer = layers.BaseLayer{}
		tLayer.DstIP = trimIPBytes(tLayer.DstIP)
		tLayer.SrcIP = trimIPBytes(tLayer.SrcIP)
	case *layers.TCP:
		old := *tLayer
		*tLayer = layers.TCP{
			SrcPort:    old.SrcPort,
			DstPort:    old.DstPort,
			Seq:        old.Seq,
			Ack:        old.Ack,
			DataOffset: old.DataOffset,
			FIN:        old.FIN,
			SYN:        old.SYN,
			RST:        old.RST,
			PSH:        old.PSH,
			ACK:        old.ACK,
			URG:        old.URG,
			ECE:        old.ECE,
			CWR:        old.CWR,
			NS:         old.NS,
			Window:     old.Window,
			Checksum:   old.Checksum,
			Urgent:     old.Urgent,
		}
	case *layers.UDP:
		old := *tLayer
		*tLayer = layers.UDP{
			SrcPort:  old.SrcPort,
			DstPort:  old.DstPort,
			Checksum: old.Checksum,
		}
	default:
		t.Fatalf("unsupported layer type %T", l)
	}
}

func trimIPBytes(src net.IP) net.IP {
	// although IP address strings are equal, but byte contents are different
	return net.ParseIP(src.String())
}
