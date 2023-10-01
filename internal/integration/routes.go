package integration

import (
	"context"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-set"
	"github.com/rs/zerolog"
	"github.com/x1unix/colima-nat-tun/internal/platform"
)

var _ NetworkEventHandler = (*RouteTableManager)(nil)

// RouteTableManager keeps routing table up to date with Docker networks.
type RouteTableManager struct {
	log           zerolog.Logger
	interfaceName string
	networkMgr    platform.RouteTableManager

	subnets *set.Set[string]
	lock    sync.Mutex
}

func NewRouteTableManager(log zerolog.Logger, netMgr platform.RouteTableManager, interfaceName string) *RouteTableManager {
	return &RouteTableManager{
		log:           log.With().Str("context", "route").Logger(),
		interfaceName: interfaceName,
		networkMgr:    netMgr,
	}
}

// Close removes all registered routes.
func (r *RouteTableManager) Close() error {
	var (
		errs     error
		hasError bool
	)

	// Prevent concurrent close from multiple goroutines
	r.lock.Lock()
	defer r.lock.Unlock()

	r.log.Debug().Msg("removing all registered rules")
	r.subnets.RemoveFunc(func(subnet string) bool {
		err := r.networkMgr.RemoveRoute(context.Background(), subnet)
		if err != nil {
			hasError = true
			errs = multierror.Append(errs, err)
		}
		return true
	})

	if hasError {
		return multierror.Flatten(errs)
	}

	return nil
}

func (r *RouteTableManager) HandleNetworksListReady(ctx context.Context, nets []types.NetworkResource) {
	r.subnets = set.New[string](len(nets))
	r.log.Info().Msgf("creating routes for %d existing networks", len(nets))

	for _, network := range nets {
		r.HandleNetworkCreated(ctx, network)
	}
}

func (r *RouteTableManager) HandleNetworkCreated(ctx context.Context, network types.NetworkResource) {
	for _, cfg := range network.IPAM.Config {
		r.log.Info().Msgf("adding route for subnet %s", cfg.Subnet)
		r.subnets.Insert(cfg.Subnet)

		if err := r.networkMgr.AddRoute(ctx, cfg.Subnet, r.interfaceName); err != nil {
			r.log.Err(err).Msgf("failed to add route for subnet %s", cfg.Subnet)
		}
	}
}

func (r *RouteTableManager) HandleNetworkDestroyed(ctx context.Context, network types.NetworkResource) {
	for _, cfg := range network.IPAM.Config {
		r.log.Info().Msgf("removing route for subnet %s", cfg.Subnet)
		r.subnets.Remove(cfg.Subnet)

		if err := r.networkMgr.RemoveRoute(ctx, cfg.Subnet); err != nil {
			r.log.Err(err).Msgf("failed to remove route for subnet %s", cfg.Subnet)
		}
	}
}
