package nettun

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/x1unix/colima-nat-tun/internal/util/typeutil"
)

const fragmentChunkBufferSize = 10

// ipBytes is fixed size array that holds IP address.
//
// Supports both v4 and v6 addresses.
type ipBytes [16]byte

// fragKey is packet fragment identification key.
type fragKey struct {
	id    uint32
	ipVer uint8
	proto layers.IPProtocol
	srcIP ipBytes
	dstIP ipBytes
}

// fragKeyFromHeader constructs fragment key from packet.
func fragKeyFromHeader(header IPHeader) fragKey {
	return fragKey{
		id:    header.ID,
		ipVer: header.Version,
		srcIP: ipBytesFromAddr(header.SrcIP),
		dstIP: ipBytesFromAddr(header.DstIP),
		proto: header.Protocol,
	}
}

func ipBytesFromAddr(addr net.IP) ipBytes {
	var result ipBytes
	copy(result[:], addr)
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
	key := fragKeyFromHeader(p.IPHeader)

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

// assemblyFragments assembles packet payload from previously received fragments and passed final fragment.
//
// Receives a final IP fragment packet and assembles all previously received fragments together.
func (buff fragmentBuffer) assemblyFragments(p *Packet) ([]byte, error) {
	if p.FragmentData == nil || !p.FragmentData.IsLast {
		return nil, errors.New("passed packet is not last fragment")
	}

	key := fragKeyFromHeader(p.IPHeader)
	chunks, ok := buff.chunks[key]
	if !ok {
		return nil, errors.New("missing previous fragments for package")
	}

	defer delete(buff.chunks, key)
	chunks = append(chunks, chunk{
		offset:  p.FragmentData.FragmentOffset,
		payload: p.FragmentData.Fragment,
	})

	typeutil.Sort(chunks, func(a, b chunk) bool {
		return a.offset < b.offset
	})

	totalLen := p.FragmentData.FragmentOffset + len(p.FragmentData.Fragment)
	data := make([]byte, 0, totalLen)
	for _, frag := range chunks {
		data = append(data, frag.payload...)
	}

	return data, nil
}
