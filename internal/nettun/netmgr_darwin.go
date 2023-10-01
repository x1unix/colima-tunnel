package nettun

import (
	"context"
	"net"
	"strconv"

	"github.com/rs/zerolog"
)

const ifconfigCmd = "ifconfig"

type darwinNetworkManager struct {
	cmdRunner CommandRunner
}

func newDarwinNetworkManager(runner CommandRunner) darwinNetworkManager {
	return darwinNetworkManager{
		cmdRunner: runner,
	}
}

func (mgr darwinNetworkManager) SetInterfaceAddress(ctx context.Context, iface string, clientIP, gatewayIP net.IP) error {
	return mgr.cmdRunner.RunCommand(
		ctx, ifconfigCmd,
		iface, clientIP.String(), gatewayIP.String(),
	)
}

func (mgr darwinNetworkManager) SetInterfaceMTU(ctx context.Context, iface string, mtu uint) error {
	return mgr.cmdRunner.RunCommand(
		ctx, ifconfigCmd,
		iface, "mtu", strconv.FormatUint(uint64(mtu), 10),
	)
}

func provideSystemNetworkManager(logger zerolog.Logger) NetworkManager {
	return newDarwinNetworkManager(systemCommandRunner{
		log: logger,
	})
}
