package nettun

import (
	"context"
	"net"
	"sync"

	"github.com/rs/zerolog"
)

var (
	mgr  NetworkManager
	once sync.Once
)

// NetworkManager is network and routing table manager interface.
type NetworkManager interface {
	// SetInterfaceAddress configures client IP address and network gateway for network interface.
	SetInterfaceAddress(ctx context.Context, iface string, clientIP, gatewayIP net.IP) error

	// SetInterfaceMTU configures interface max transfer unit (MTU).
	SetInterfaceMTU(ctx context.Context, iface string, mtu uint) error

	// AddRoute adds rule to route specific subnet to network interface into routing table.
	AddRoute(ctx context.Context, subnet, iface string) error

	// RemoveRoute removes routing rule for specified subnet from routing table.
	RemoveRoute(ctx context.Context, subnet string) error
}

// GetNetworkManager returns global network manager.
func GetNetworkManager(logger zerolog.Logger) NetworkManager {
	once.Do(func() {
		mgr = provideSystemNetworkManager(logger)
	})

	return mgr
}
