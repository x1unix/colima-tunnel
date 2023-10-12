package nettun

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
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

func TestParsePacketWithHeader(t *testing.T) {
	files := []string{
		"udp-frag-1.bin",
		"udp-frag-2.bin",
		"udp-frag-3.bin",
		"udp-frag-fin.bin",
	}

	var (
		header  IPHeader
		payload []byte
	)

	fragbuf := newFragmentBuffer()
	for i, fname := range files {
		isLast := i == len(files)-1
		data := readFile(t, filepath.Join("testdata", fname))
		packet, err := ParsePacket(data)
		require.NoErrorf(t, err, "failed to parse fragment %s", fname)
		if isLast {
			b, err := fragbuf.assemblyFragments(packet)
			require.NoError(t, err, "failed to assembly fragments")
			header = packet.IPHeader
			payload = b
			break
		}

		fragbuf.addFragment(packet)
	}

	expect := &Packet{
		Source: &net.UDPAddr{
			IP:   net.IP{100, 64, 0, 10},
			Port: 55387,
		},
		Dest: &net.UDPAddr{
			IP:   net.IP{10, 20, 0, 10},
			Port: 5344,
		},
		IPHeader: IPHeader{
			Version:   4,
			ID:        0xd933,
			Length:    4528,
			HopLimit:  64,
			SrcIP:     net.IP{100, 64, 0, 10},
			DstIP:     net.IP{10, 20, 0, 10},
			Protocol:  layers.IPProtocolUDP,
			RawHeader: header.RawHeader,
		},
		Layers: Layers{
			UDP: &layers.UDP{
				BaseLayer: layers.BaseLayer{
					Payload:  payload[8:],
					Contents: payload[:8],
				},
				SrcPort:  55387,
				DstPort:  5344,
				Length:   4508,
				Checksum: 0x9f30,
			},
		},
		Payload: bytes.Repeat([]byte{'a'}, 4500),
	}

	result, err := ParsePacketWithHeader(header, payload)
	require.NoError(t, err, "ParsePacketWithHeader error")

	// truncate private variables in obtained value
	oldUDP := *result.Layers.UDP
	result.Layers.UDP = &layers.UDP{
		BaseLayer: oldUDP.BaseLayer,
		SrcPort:   oldUDP.SrcPort,
		DstPort:   oldUDP.DstPort,
		Length:    oldUDP.Length,
		Checksum:  oldUDP.Checksum,
	}

	require.Equal(t, expect, result)
}

func TestParsePacket(t *testing.T) {
	cases := map[string]struct {
		src       string
		expect    *Packet
		expectErr string
	}{
		"TCP SYN": {
			src: "testdata/tcp-syn.bin",
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
					HopLimit: 64,
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
			src: "testdata/udp-frag-1.bin",
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
					HopLimit: 64,
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
			src: "testdata/udp-frag-fin.bin",
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
					HopLimit: 64,
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
			src: "testdata/ipv6-icmp.bin",
			expect: &Packet{
				Source: &net.IPAddr{
					IP: net.ParseIP("2001:db8:1::1"),
				},
				Dest: &net.IPAddr{
					IP: net.ParseIP("2001:db8:2::2"),
				},
				IPHeader: IPHeader{
					Length:   16,
					HopLimit: 64,
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
			src:       "testdata/badpacket.bin",
			expectErr: "failed to parse IP header: invalid version in IP header",
		},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			data := readFile(t, c.src)
			got, err := ParsePacket(data)
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
	cleanLayer(pkg.Layers.TCP)
	cleanLayer(pkg.Layers.UDP)
	cleanLayer(pkg.Layers.ICMP)
	cleanLayer(pkg.RawHeader)
}

func cleanLayer(l gopacket.Layer) {
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

func readFile(t *testing.T, fname string) []byte {
	t.Helper()
	data, err := os.ReadFile(fname)
	require.NoError(t, err, "failed to open file:", fname)
	return data
}
