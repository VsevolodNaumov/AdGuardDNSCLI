// Package client contains client-related structures and logic.
package client

import (
	"github.com/AdguardTeam/dnsproxy/proxy"
)

// Client is an interface for DNS clients.
type Client interface {
	// Upstreams returns the upstream configuration for the client.  upstreams
	// must not be nil, unless documented otherwise.
	Upstreams() (upstreams *proxy.CustomUpstreamConfig)
}

// StaticClient is a [Client] implementation that returns a static upstream
// config.
type StaticClient struct {
	// upstreams is a set of upstreams for this client.  It must not be nil.
	upstreams *proxy.CustomUpstreamConfig
}

// NewStaticClient creates a new properly initialized StaticClient.  conf must
// be valid.
func NewStaticClient(upstreams *proxy.CustomUpstreamConfig) (sc *StaticClient) {
	return &StaticClient{
		upstreams: upstreams,
	}
}

// type check
var _ Client = (*StaticClient)(nil)

// Upstreams implements the [Client] interface for *StaticClient.
func (s *StaticClient) Upstreams() (upstreams *proxy.CustomUpstreamConfig) {
	return s.upstreams
}

// StaticClientConfig is a mapping of domain names to static clients.  Its keys,
// if not empty, must be valid non-FQDNs.  Its values must be valid.
type StaticClientConfig map[string]*StaticClient
