package nettun

import (
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
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
		"TCP SYN": {
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
				IPHeader: IPHeader{
					Length:   64,
					TTL:      64,
					Version:  4,
					Protocol: layers.IPProtocolTCP,
					SrcIP:    net.IP{100, 64, 0, 10},
					DstIP:    net.IP{100, 64, 0, 254},
					RawHeader: &layers.IPv4{
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
				Layers: Layers{
					TCP: &layers.TCP{
						SrcPort:    49386,
						DstPort:    80,
						Seq:        2262526382,
						DataOffset: 11,
						SYN:        true,
						Window:     65535,
						Checksum:   12512,
					},
				},
				// require.Equal don't consider nil and empty slices equal.
				Payload: []byte{},
			},
		},
		"UDP first fragment": {
			src: fileSource("testdata/udp-frag-1.bin"),
			expect: &Packet{
				Source: &net.IPAddr{
					IP: net.IP{100, 64, 0, 10},
				},
				Dest: &net.IPAddr{
					IP: net.IP{10, 20, 0, 10},
				},
				IPHeader: IPHeader{
					Version:  4,
					ID:       0xd933,
					Length:   1500,
					TTL:      64,
					SrcIP:    net.IP{100, 64, 0, 10},
					DstIP:    net.IP{10, 20, 0, 10},
					Protocol: layers.IPProtocolUDP,
					FragmentData: &FragmentData{
						FragmentOffset: 0,
						IsFirst:        true,
					},
					RawHeader: &layers.IPv4{
						Version:    4,
						IHL:        5,
						TOS:        0,
						Length:     1500,
						Id:         0xd933,
						Flags:      layers.IPv4MoreFragments,
						FragOffset: 0,
						TTL:        64,
						Protocol:   layers.IPProtocolUDP,
						Checksum:   0x0d76,
						SrcIP:      net.IP{100, 64, 0, 10},
						DstIP:      net.IP{10, 20, 0, 10},
					},
				},
				Payload: nil,
			},
		},
		"UDP final fragment": {
			src: fileSource("testdata/udp-frag-fin.bin"),
			expect: &Packet{
				Source: &net.IPAddr{
					IP: net.IP{100, 64, 0, 10},
				},
				Dest: &net.IPAddr{
					IP: net.IP{10, 20, 0, 10},
				},
				IPHeader: IPHeader{
					Version:  4,
					ID:       0xd933,
					Length:   88,
					TTL:      64,
					SrcIP:    net.IP{100, 64, 0, 10},
					DstIP:    net.IP{10, 20, 0, 10},
					Protocol: layers.IPProtocolUDP,
					FragmentData: &FragmentData{
						FragmentOffset: 4440,
						IsLast:         true,
					},
					RawHeader: &layers.IPv4{
						Version:    4,
						IHL:        5,
						TOS:        0,
						Length:     88,
						Id:         0xd933,
						FragOffset: 555,
						TTL:        64,
						Protocol:   layers.IPProtocolUDP,
						Checksum:   0x30cf,
						SrcIP:      net.IP{100, 64, 0, 10},
						DstIP:      net.IP{10, 20, 0, 10},
					},
				},
				Payload: nil,
			},
		},
		"ICMP IPv6": {
			src: fileSource("testdata/ipv6-icmp.bin"),
			expect: &Packet{
				Source: &net.IPAddr{
					IP: net.ParseIP("2001:db8:1::1"),
				},
				Dest: &net.IPAddr{
					IP: net.ParseIP("2001:db8:2::2"),
				},
				IPHeader: IPHeader{
					Length:   16,
					TTL:      64,
					Version:  6,
					ID:       295493,
					Protocol: layers.IPProtocolICMPv6,
					SrcIP:    net.ParseIP("2001:db8:1::1"),
					DstIP:    net.ParseIP("2001:db8:2::2"),
					RawHeader: &layers.IPv6{
						Version:    6,
						Length:     16,
						HopLimit:   64,
						NextHeader: layers.IPProtocolICMPv6,
						FlowLabel:  295493,
						SrcIP:      net.ParseIP("2001:db8:1::1"),
						DstIP:      net.ParseIP("2001:db8:2::2"),
					},
				},
				Layers: Layers{
					ICMP: &layers.ICMPv6{
						BaseLayer: layers.BaseLayer{
							Payload: []byte{
								33, 193, 0, 7, 92, 152, 37, 228, 0, 2, 78, 15,
							},
						},
						TypeCode: 32768,
						Checksum: 0x31e7,
					},
				},
				Payload: []byte{
					33, 193, 0, 7, 92, 152, 37, 228, 0, 2, 78, 15,
				},
			},
		},
		"invalid packet": {
			src:       fileSource("testdata/badpacket.bin"),
			expectErr: "failed to parse IP header: invalid version in IP header",
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
	if pkg.FragmentData != nil {
		pkg.FragmentData.Fragment = []byte("fragment data placeholder")
	}

	pkg.SrcIP = trimIPBytes(pkg.SrcIP)
	pkg.DstIP = trimIPBytes(pkg.DstIP)
	cleanLayer(t, pkg.Layers.TCP)
	cleanLayer(t, pkg.Layers.UDP)
	cleanLayer(t, pkg.Layers.ICMP)
	cleanLayer(t, pkg.RawHeader)
}

func cleanLayer(t *testing.T, l gopacket.Layer) {
	if l == nil {
		return
	}

	switch tLayer := l.(type) {
	case *layers.IPv4:
		if tLayer == nil {
			return
		}
		tLayer.BaseLayer = layers.BaseLayer{}
		tLayer.DstIP = trimIPBytes(tLayer.DstIP)
		tLayer.SrcIP = trimIPBytes(tLayer.SrcIP)
	case *layers.IPv6:
		if tLayer == nil {
			return
		}
		tLayer.BaseLayer = layers.BaseLayer{}
		tLayer.DstIP = trimIPBytes(tLayer.DstIP)
		tLayer.SrcIP = trimIPBytes(tLayer.SrcIP)
	case *layers.TCP:
		if tLayer == nil {
			return
		}
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
		if tLayer == nil {
			return
		}
		old := *tLayer
		*tLayer = layers.UDP{
			SrcPort:  old.SrcPort,
			DstPort:  old.DstPort,
			Checksum: old.Checksum,
		}
	case *layers.ICMPv6:
		tLayer.Contents = nil
	case *layers.ICMPv4:
		tLayer.Contents = nil
	}
}

func trimIPBytes(src net.IP) net.IP {
	// although IP address strings are equal, but byte contents are different
	return net.ParseIP(src.String())
}
