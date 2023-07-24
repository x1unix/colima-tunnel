package nettun

import (
	"errors"
	"fmt"
	"net"
)

type Config struct {
	// ClientIP is client IP address in tunnel network.
	ClientIP net.IP

	// GatewayIP is virtual gateway IP address.
	GatewayIP net.IP

	// Network is tunnel IP network.
	Network *net.IPNet

	// MTU is maximum transmission unit (MTU) size
	MTU uint
}

func NewConfig(clientIP, cidr string, mtu uint) (*Config, error) {
	clientAddr := net.ParseIP(clientIP)
	if len(clientAddr) == 0 {
		return nil, fmt.Errorf("invalid client IP address %s", clientAddr)
	}

	ip, vnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid network address: %w", err)
	}

	if !vnet.Contains(clientAddr) {
		return nil, fmt.Errorf("client IP %s is outside of network %s", ip, vnet)
	}

	if mtu > maxMTU || mtu < minMTU {
		return nil,
			fmt.Errorf("invalid MTU size %d. MTU size should be between %d and %d",
				mtu, minMTU, maxMTU,
			)
	}

	if len(clientAddr) > 4 {
		return nil, errors.New("only IPv4 networks are supported")
	}

	gatewayAddr := getLastIP(vnet)
	if gatewayAddr.Equal(clientAddr) {
		return nil, fmt.Errorf(
			"invalid client IP. IP address %q is reserved, please use a different address", clientAddr,
		)
	}

	return &Config{
		ClientIP:  clientAddr,
		GatewayIP: getLastIP(vnet),
		Network:   vnet,
		MTU:       mtu,
	}, nil
}

func getLastIP(ipNet *net.IPNet) net.IP {
	// Get the IP address and network mask from the IPNet object
	ip := ipNet.IP
	mask := ipNet.Mask

	// Calculate the broadcast address by performing a bitwise OR
	// between the IP address and the bitwise NOT of the network mask
	broadcastIP := make(net.IP, len(ip))
	for i := range ip {
		broadcastIP[i] = ip[i] | ^mask[i]
	}

	// Calculate the last usable IP address (one less than the broadcast address)
	lastIP := make(net.IP, len(broadcastIP))
	copy(lastIP, broadcastIP)
	for i := len(lastIP) - 1; i >= 0; i-- {
		if broadcastIP[i] > 0 {
			lastIP[i] = broadcastIP[i] - 1
			break
		}
	}

	return lastIP
}
