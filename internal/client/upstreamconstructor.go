package client

import "github.com/AdguardTeam/dnsproxy/upstream"

// UpstreamConstructor is an interface for constructing upstreams from
// addresses.  Its only purpose is to simplify testing of [DefaultStorage].
type UpstreamConstructor interface {
	// AddressToUpstream constructs an upstream from the given address and
	// options.  If opts is nil, the default options are used.
	//
	// See [upstream.AddressToUpstream].
	AddressToUpstream(addr string, opts *upstream.Options) (u upstream.Upstream, err error)
}

// DefaultUpstreamConstructor is a default implementation of
// [UpstreamConstructor] that uses [upstream.AddressToUpstream] to construct
// upstreams.
type DefaultUpstreamConstructor struct{}

// type check
var _ UpstreamConstructor = DefaultUpstreamConstructor{}

// AddressToUpstream implements the [UpstreamConstructor] interface for
// [DefaultUpstreamConstructor].
func (DefaultUpstreamConstructor) AddressToUpstream(
	addr string,
	opts *upstream.Options,
) (u upstream.Upstream, err error) {
	return upstream.AddressToUpstream(addr, opts)
}
