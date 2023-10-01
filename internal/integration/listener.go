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

	HandleNetworksListReady(nets []types.NetworkResource)
	HandleNetworkCreated(network types.NetworkResource)
	HandleNetworkDestroyed(network types.NetworkResource)
}

// DockerListener listens for Docker network create and destroy events.
type DockerListener struct {
	log     zerolog.Logger
	client  *docker.Client
	handler NetworkEventHandler

	knownNetworks map[string]types.NetworkResource
	cancelFn      context.CancelFunc
}

func NewDockerListener(log zerolog.Logger, client *docker.Client, handler NetworkEventHandler) *DockerListener {
	return &DockerListener{
		log:     log.With().Str("context", "docker").Logger(),
		client:  client,
		handler: handler,
	}
}

// Start subscribes and listens for Docker network events.
func (listener *DockerListener) Start(ctx context.Context) error {
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
	listener.handler.HandleNetworksListReady(networks)
	listener.knownNetworks = make(map[string]types.NetworkResource, len(networks))
	for _, network := range networks {
		listener.knownNetworks[network.ID] = network
	}

	workerCtx, cancelFn := context.WithCancel(ctx)
	msgs, errs := listener.client.Events(workerCtx, types.EventsOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "network"),
			filters.Arg("event", "create"),
			filters.Arg("event", "destroy"),
		),
	})

	// Return error if subscribe fails
	select {
	case err := <-errs:
		cancelFn()
		listener.closeHandler()
		return fmt.Errorf("failed to subscribe to Docker events: %w", err)
	default:
	}

	listener.cancelFn = cancelFn
	listener.log.Info().Msg("subscribed to Docker network events")
	go listener.listenEvents(workerCtx, msgs, errs)
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

			if event.Type != "network" {
				continue
			}

			if err := listener.handleNetworkEvent(ctx, event); err != nil {
				listener.log.Err(err).
					Str("network_id", event.Actor.ID).
					Str("action", event.Action).
					Msg("failed to handle Docker network event")
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

	switch event.Action {
	case "create":
		network, err := listener.client.NetworkInspect(ctx, networkID, types.NetworkInspectOptions{})
		if err != nil {
			return fmt.Errorf("failed to get network %s: %w", networkID, err)
		}

		listener.knownNetworks[networkID] = network
		listener.handler.HandleNetworkCreated(network)
	case "destroy":
		network, ok := listener.knownNetworks[networkID]
		if !ok {
			return fmt.Errorf("unkown network destroyed: %s", networkID)
		}

		listener.handler.HandleNetworkDestroyed(network)
		delete(listener.knownNetworks, networkID)
	}

	return nil
}

func (listener *DockerListener) closeHandler() {
	if err := listener.handler.Close(); err != nil {
		listener.log.Err(err).Msg("event handler returned an error on close")
	}
}
