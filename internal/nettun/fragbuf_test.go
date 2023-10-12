package nettun

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssemblyFragments(t *testing.T) {
	files := []string{
		"udp-frag-1.bin",
		"udp-frag-2.bin",
		"udp-frag-3.bin",
		"udp-frag-fin.bin",
	}

	var finalPkt *Packet
	fragbuff := newFragmentBuffer()
	for _, file := range files {
		chunk, err := os.ReadFile("testdata/" + file)
		require.NoError(t, err, "read file err")
		pkt, err := ParsePacket(chunk)
		require.NoError(t, err, "parse packet err")
		if pkt.FragmentData.IsLast {
			finalPkt = pkt
			continue
		}

		fragbuff.addFragment(pkt)
	}

	require.NotNil(t, finalPkt, "no final packet")
	data, err := fragbuff.assemblyFragments(finalPkt)
	require.NoError(t, err, "failed to concat fragments")
	t.Logf("%x", data)
}
