package integration

import (
	"context"
	"net/netip"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/hashicorp/go-set"
	"github.com/rs/zerolog"
)

var _ ContainerEventHandler = (*ContainerStatusListener)(nil)

type ContainerStatusListener struct {
	log zerolog.Logger

	addrs *set.Set[netip.Addr]
	lock  *sync.Mutex
}

func NewContainerStatusListener(log zerolog.Logger) *ContainerStatusListener {
	return &ContainerStatusListener{
		log:   log.With().Str("context", "container").Logger(),
		lock:  new(sync.Mutex),
		addrs: set.New[netip.Addr](0),
	}
}

// IsAddressReachable returns whether any container with passed IP address is running.
func (listener ContainerStatusListener) IsAddressReachable(addr netip.Addr) bool {
	listener.lock.Lock()
	defer listener.lock.Unlock()
	return listener.addrs.Contains(addr)
}

func (listener ContainerStatusListener) HandleContainersListReady(_ context.Context, containers []types.Container) {
	listener.lock.Lock()
	defer listener.lock.Unlock()

	listener.addrs = set.New[netip.Addr](len(containers))
	for _, container := range containers {
		listener.log.Debug().
			Str("container_id", container.ID).
			Msgf("importing %d IPs from running container", len(container.NetworkSettings.Networks))

		listener.updateIPsWithContainer(container.ID, container.NetworkSettings.Networks, true)
	}
}

func (listener ContainerStatusListener) HandleContainerStarted(_ context.Context, container types.ContainerJSON) {
	listener.lock.Lock()
	defer listener.lock.Unlock()
	listener.log.Debug().Str("container_id", container.ID).Msg("container started")
	listener.updateIPsWithContainer(container.ID, container.NetworkSettings.Networks, true)
}

func (listener ContainerStatusListener) HandleContainerDied(_ context.Context, container types.ContainerJSON) {
	listener.lock.Lock()
	defer listener.lock.Unlock()
	listener.log.Debug().Str("container_id", container.ID).Msg("container died")
	listener.updateIPsWithContainer(container.ID, container.NetworkSettings.Networks, false)
}

func (listener ContainerStatusListener) updateIPsWithContainer(containerID string, nets map[string]*network.EndpointSettings, alive bool) {
	for netName, netCfg := range nets {
		addr, err := netip.ParseAddr(netCfg.IPAddress)
		if err != nil {
			listener.log.Err(err).Str("container_id", containerID).
				Str("network", netName).
				Msgf("failed to parse container IP address %q", netCfg.IPAddress)
			continue
		}

		if alive {
			listener.addrs.Insert(addr)
			return
		}

		listener.addrs.Remove(addr)
	}

}
