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

// NetworkManager is OS-independent network manager interface.
type NetworkManager interface {
	// SetInterfaceAddress configures client IP address and network gateway for network interface.
	SetInterfaceAddress(ctx context.Context, iface string, clientIP, gatewayIP net.IP) error

	// SetInterfaceMTU configures interface max transfer unit (MTU).
	SetInterfaceMTU(ctx context.Context, iface string, mtu uint) error
}

// GetNetworkManager returns global network manager.
func GetNetworkManager(logger zerolog.Logger) NetworkManager {
	once.Do(func() {
		mgr = provideSystemNetworkManager(logger)
	})

	return mgr
}
