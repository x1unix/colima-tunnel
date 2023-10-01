package platform

import (
	"context"
	"net"
	"sync"

	"github.com/rs/zerolog"
)

var (
	mgr     NetworkManager
	mgrOnce sync.Once
)

// RouteTableManager is network routing table manager.
type RouteTableManager interface {
	// AddRoute adds rule to route specific subnet to network interface into routing table.
	AddRoute(ctx context.Context, subnet, iface string) error

	// RemoveRoute removes routing rule for specified subnet from routing table.
	RemoveRoute(ctx context.Context, subnet string) error
}

// NetworkManager is network and routing table manager interface.
type NetworkManager interface {
	RouteTableManager

	// SetInterfaceAddress configures client IP address and network gateway for network interface.
	SetInterfaceAddress(ctx context.Context, iface string, clientIP, gatewayIP net.IP) error

	// SetInterfaceMTU configures interface max transfer unit (MTU).
	SetInterfaceMTU(ctx context.Context, iface string, mtu uint) error
}

// GetNetworkManager returns global network manager.
func GetNetworkManager(logger zerolog.Logger) NetworkManager {
	mgrOnce.Do(func() {
		mgr = provideSystemNetworkManager(logger)
	})

	return mgr
}
