package client

import (
	"context"
	"net/netip"

	"github.com/AdguardTeam/golibs/service"
)

// Storage is an interface for storing clients.
type Storage interface {
	// Get returns the client for addr and questionDomain.  addr must be valid
	// and must not be mapped.  questionDomain must be valid non-FQDN in lower
	// case.
	//
	// c must not be nil if ok is true.  It must be safe for concurrent use.
	Get(ctx context.Context, addr netip.Addr, questionDomain string) (c Client, ok bool)

	// Interface is used to start necessary background routines and release the
	// resources after shutdown.
	service.Interface
}

// EmptyStorage is an implementation of [Storage] that does nothing.
type EmptyStorage struct {
	service.Empty
}

// type check
var _ Storage = (*EmptyStorage)(nil)

// Get implements the [Storage] interface for EmptyStorage.  It always returns
// nil and false.
func (EmptyStorage) Get(_ context.Context, _ netip.Addr, _ string) (c Client, ok bool) {
	return nil, false
}
