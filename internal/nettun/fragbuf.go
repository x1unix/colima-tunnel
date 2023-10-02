package nettun

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const fragmentChunkBufferSize = 10

// ipBytes is fixed size array that holds IP address.
//
// Supports both v4 and v6 addresses.
type ipBytes [16]byte

// fragKey is packet fragment identification key.
type fragKey struct {
	ipVer uint8
	proto layers.IPProtocol
	id    uint16
	srcIP ipBytes
	dstIP ipBytes
}

// fragKeyFromPacket constructs fragment key from packet.
func fragKeyFromPacket(p *Packet) fragKey {
	var ipVer uint8 = 4
	if p.NetworkType == IPv6Network {
		ipVer = 6
	}

	return fragKey{
		id:    p.ID,
		ipVer: ipVer,
		srcIP: ipBytesFromAddr(p.Source),
		dstIP: ipBytesFromAddr(p.Dest),
		proto: p.Protocol,
	}
}

func ipBytesFromAddr(addr net.Addr) ipBytes {
	ipAddr, _ := SplitAddr(addr)

	var result ipBytes
	copy(result[:], ipAddr)
	return result
}

type chunk struct {
	offset  int
	payload gopacket.Fragment
}

type fragmentBuffer struct {
	chunks map[fragKey][]chunk
}

func newFragmentBuffer() fragmentBuffer {
	return fragmentBuffer{
		chunks: make(map[fragKey][]chunk, fragmentChunkBufferSize),
	}
}

func (buff fragmentBuffer) addFragment(p *Packet) int {
	key := fragKeyFromPacket(p)

	arr, ok := buff.chunks[key]
	if !ok {
		arr = make([]chunk, 0, fragmentChunkBufferSize)
	}

	arr = append(arr, chunk{
		offset:  p.FragmentData.FragmentOffset,
		payload: p.FragmentData.Fragment,
	})

	buff.chunks[key] = arr
	return len(arr)
}

func (buff fragmentBuffer) collectFragments(p *Packet) {

}
