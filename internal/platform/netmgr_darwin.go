package platform

import (
	"context"
	"net"
	"strconv"

	"github.com/rs/zerolog"
)

const (
	ifconfigCmd = "ifconfig"
	routeCmd    = "route"
)

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

func (mgr darwinNetworkManager) AddRoute(ctx context.Context, subnet, iface string) error {
	return mgr.cmdRunner.RunCommand(
		ctx, routeCmd, "-q", "-n", "add",
		"-inet", subnet, "-interface", iface,
	)
}

func (mgr darwinNetworkManager) RemoveRoute(ctx context.Context, subnet string) error {
	return mgr.cmdRunner.RunCommand(
		ctx, routeCmd, "-q", "-n", "delete",
		"-inet", subnet,
	)
}

func provideSystemNetworkManager(logger zerolog.Logger) NetworkManager {
	return newDarwinNetworkManager(GetCommandRunner(logger))
}
