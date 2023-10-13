package integration

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/rs/zerolog"
)

// NetworkEventHandler handles network lifecycle events
type NetworkEventHandler interface {
	io.Closer

	HandleNetworksListReady(ctx context.Context, nets []types.NetworkResource)
	HandleNetworkCreated(ctx context.Context, network types.NetworkResource)
	HandleNetworkDestroyed(ctx context.Context, network types.NetworkResource)
}

type ContainerEventHandler interface {
	HandleContainersListReady(ctx context.Context, containers []types.Container)
	HandleContainerStarted(ctx context.Context, container types.ContainerJSON)
	HandleContainerDied(ctx context.Context, container types.ContainerJSON)
}

type EventHandlers struct {
	Network   NetworkEventHandler
	Container ContainerEventHandler
}

// DockerListener listens for Docker network and container create and destroy events.
type DockerListener struct {
	log      zerolog.Logger
	client   *docker.Client
	handlers EventHandlers

	knownNetworks   map[string]types.NetworkResource
	knownContainers map[string]types.ContainerJSON

	cancelFn context.CancelFunc
}

func NewDockerListener(log zerolog.Logger, client *docker.Client, handlers EventHandlers) *DockerListener {
	return &DockerListener{
		log:      log.With().Str("context", "docker").Logger(),
		client:   client,
		handlers: handlers,
	}
}

// Start subscribes and listens for Docker network events.
func (listener *DockerListener) Start(ctx context.Context) error {
	if err := listener.warmUpNetworksList(ctx); err != nil {
		return err
	}
	if err := listener.warmUpContainerList(ctx); err != nil {
		return err
	}

	workerCtx, cancelFn := context.WithCancel(ctx)
	msgs, errs := listener.client.Events(workerCtx, types.EventsOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "network"),
			filters.Arg("event", "create"),
			filters.Arg("event", "destroy"),

			filters.Arg("type", "container"),
			filters.Arg("event", "die"),
			filters.Arg("event", "start"),
		),
	})

	// Return error if subscribe fails
	select {
	case err := <-errs:
		cancelFn()
		listener.closeHandler()
		if errors.Is(err, context.Canceled) {
			return nil
		}

		return fmt.Errorf("failed to subscribe to Docker events: %w", err)
	default:
	}

	listener.cancelFn = cancelFn
	listener.log.Info().Msg("subscribed to Docker events")
	go listener.listenEvents(workerCtx, msgs, errs)
	return nil
}

func (listener *DockerListener) warmUpContainerList(ctx context.Context) error {
	handler := listener.handlers.Container
	if handler == nil {
		return nil
	}

	containers, err := listener.client.ContainerList(ctx, types.ContainerListOptions{
		All: false,
	})
	if err != nil {
		return fmt.Errorf("failed to get Docker containers list: %w", err)
	}

	listener.log.Debug().Msgf("fetched %d containers from Docker", len(containers))
	handler.HandleContainersListReady(ctx, containers)

	listener.knownContainers = make(map[string]types.ContainerJSON)
	for _, container := range containers {
		listener.knownContainers[container.ID] = types.ContainerJSON{
			ContainerJSONBase: &types.ContainerJSONBase{
				ID:          container.ID,
				Name:        container.Names[0],
				GraphDriver: types.GraphDriverData{},
				SizeRw:      nil,
				SizeRootFs:  nil,
			},
			NetworkSettings: &types.NetworkSettings{
				Networks: container.NetworkSettings.Networks,
			},
		}
	}
	return nil
}

func (listener *DockerListener) warmUpNetworksList(ctx context.Context) error {
	handler := listener.handlers.Network
	if handler == nil {
		return nil
	}

	networks, err := listener.client.NetworkList(ctx, types.NetworkListOptions{
		Filters: filters.NewArgs(
			// See: https://github.com/chipmk/docker-mac-net-connect/blob/main/networkmanager/networkmanager.go#L73C32-L73C32
			filters.Arg("scope", "local"),
		),
	})
	if err != nil {
		return fmt.Errorf("failed to get Docker networks list: %w", err)
	}

	// Notify initial networks list & prefill known networks map
	listener.log.Debug().Msgf("fetched %d networks from Docker", len(networks))
	handler.HandleNetworksListReady(ctx, networks)
	listener.knownNetworks = make(map[string]types.NetworkResource, len(networks))
	for _, network := range networks {
		listener.knownNetworks[network.ID] = network
	}

	return nil
}

func (listener *DockerListener) listenEvents(ctx context.Context, msgs <-chan events.Message, errs <-chan error) {
	defer listener.log.Debug().Msg("listener closed")
	defer listener.closeHandler()

	for {
		select {
		case <-ctx.Done():
			listener.log.Debug().Msg("context done, closing listener")
			return
		case err, ok := <-errs:
			if !ok {
				return
			}
			listener.log.Err(err).Msg("failed to fetch event, shutting down listener")
			return
		case event, ok := <-msgs:
			if !ok {
				listener.log.Debug().Msg("events channel closed, closing listener")
				return
			}

			switch event.Type {
			case "network":
				if err := listener.handleNetworkEvent(ctx, event); err != nil {
					listener.log.Err(err).
						Str("network_id", event.Actor.ID).
						Str("action", event.Action).
						Msg("failed to handle Docker network event")
				}
			case "container":
				if err := listener.handleNetworkEvent(ctx, event); err != nil {
					listener.log.Err(err).
						Str("container_id", event.Actor.ID).
						Str("action", event.Action).
						Msg("failed to handle Docker container event")
				}
			}
		}
	}
}

// Close explicitly closes event listener.
func (listener *DockerListener) Close() error {
	if listener.cancelFn == nil {
		return errors.New("listener is closed")
	}

	listener.cancelFn()
	return nil
}

func (listener *DockerListener) handleNetworkEvent(ctx context.Context, event events.Message) error {
	networkID := event.Actor.ID
	handler := listener.handlers.Network
	if handler == nil {
		return nil
	}

	switch event.Action {
	case "create":
		network, err := listener.client.NetworkInspect(ctx, networkID, types.NetworkInspectOptions{})
		if err != nil {
			return fmt.Errorf("failed to get network %s: %w", networkID, err)
		}

		listener.knownNetworks[networkID] = network
		handler.HandleNetworkCreated(ctx, network)
	case "destroy":
		network, ok := listener.knownNetworks[networkID]
		if !ok {
			return fmt.Errorf("unkown network destroyed: %s", networkID)
		}

		handler.HandleNetworkDestroyed(ctx, network)
		delete(listener.knownNetworks, networkID)
	}

	return nil
}

func (listener *DockerListener) handleContainerEvent(ctx context.Context, event events.Message) error {
	containerID := event.Actor.ID
	handler := listener.handlers.Container
	if handler == nil {
		return nil
	}

	switch event.Action {
	case "start":
		container, err := listener.client.ContainerInspect(ctx, containerID)
		if err != nil {
			return fmt.Errorf("failed to get container %s: %w", containerID, err)
		}

		listener.knownContainers[containerID] = container
		handler.HandleContainerStarted(ctx, container)
	case "die":
		container, ok := listener.knownContainers[containerID]
		if !ok {
			return fmt.Errorf("unkown container destroyed: %s", containerID)
		}

		handler.HandleContainerDied(ctx, container)
		delete(listener.knownContainers, containerID)
	}

	return nil
}

func (listener *DockerListener) closeHandler() {
	if listener.handlers.Network == nil {
		return
	}

	if err := listener.handlers.Network.Close(); err != nil {
		listener.log.Err(err).Msg("event handler returned an error on close")
	}
}
