package nettun

import (
	"fmt"

	"github.com/songgao/packets/ethernet"
)

type pkgTypeStringer struct {
	t ethernet.Ethertype
}

func (s pkgTypeStringer) String() string {
	switch s.t {
	case ethernet.IPv4:
		return "IPv4"
	case ethernet.ARP:
		return "ARP"
	case ethernet.WakeOnLAN:
		return "WakeOnLAN"
	case ethernet.TRILL:
		return "TRILL"
	case ethernet.DECnetPhase4:
		return "DECnetPhase4"
	case ethernet.RARP:
		return "RARP"
	case ethernet.AppleTalk:
		return "AppleTalk"
	case ethernet.AARP:
		return "AARP"
	case ethernet.IPX1:
		return "IPX1"
	case ethernet.IPX2:
		return "IPX2"
	case ethernet.QNXQnet:
		return "QNXQnet"
	case ethernet.IPv6:
		return "IPv6"
	case ethernet.EthernetFlowControl:
		return "EthernetFlowControl"
	case ethernet.IEEE802_3:
		return "IEEE802_3"
	case ethernet.CobraNet:
		return "CobraNet"
	case ethernet.MPLSUnicast:
		return "MPLSUnicast"
	case ethernet.MPLSMulticast:
		return "MPLSMulticast"
	case ethernet.PPPoEDiscovery:
		return "PPPoEDiscovery"
	case ethernet.PPPoESession:
		return "PPPoESession"
	case ethernet.JumboFrames:
		return "JumboFrames"
	case ethernet.HomePlug1_0MME:
		return "HomePlug1_0MME"
	case ethernet.IEEE802_1X:
		return "IEEE802_1X"
	case ethernet.PROFINET:
		return "PROFINET"
	case ethernet.HyperSCSI:
		return "HyperSCSI"
	case ethernet.AoE:
		return "AoE"
	case ethernet.EtherCAT:
		return "EtherCAT"
	case ethernet.EthernetPowerlink:
		return "EthernetPowerlink"
	case ethernet.LLDP:
		return "LLDP"
	case ethernet.SERCOS3:
		return "SERCOS3"
	case ethernet.WSMP:
		return "WSMP"
	case ethernet.HomePlugAVMME:
		return "HomePlugAVMME"
	case ethernet.MRP:
		return "MRP"
	case ethernet.IEEE802_1AE:
		return "IEEE802_1AE"
	case ethernet.IEEE1588:
		return "IEEE1588"
	case ethernet.IEEE802_1ag:
		return "IEEE802_1ag"
	case ethernet.FCoE:
		return "FCoE"
	case ethernet.FCoEInit:
		return "FCoEInit"
	case ethernet.RoCE:
		return "RoCE"
	case ethernet.CTP:
		return "CTP"
	case ethernet.VeritasLLT:
		return "VeritasLLT"
	default:
		return fmt.Sprintf("Unknown(%x)", s.t)
	}
}
