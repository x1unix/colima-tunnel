package config

import (
	"context"
	"os/signal"
	"syscall"
)

// NewApplicationContext returns a new process execution context.
//
// Context is alive until process receive any termination signal.
func NewApplicationContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
}
