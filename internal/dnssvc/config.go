package dnssvc

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil"
)

// Config is the configuration for [DNSService].
type Config struct {
	// BaseLogger used as the base logger for the DNS subservices.  It must not
	// be nil.
	BaseLogger *slog.Logger

	// Logger is the logger for the DNS service.  It must not be nil.
	Logger *slog.Logger

	// PrivateSubnets is the set of IP networks considered private.  The PTR
	// requests for ARPA domains considered private if the domain contains an IP
	// from one of the networks and the request came from the client within one
	// of the networks.  It must not be nil.
	PrivateSubnets netutil.SubnetSet

	// ClientStorage stores clients according to their addresses.  It must not
	// be nil.  Storage must not be shut down until the [DNSService.Shutdown]
	// returns.
	ClientStorage client.Storage

	// Bootstrap is a bootstrap resolver.  If it is nil, than
	// [net.DefaultResolver] will be used.
	Bootstrap upstream.Resolver

	// GeneralUpstreams represents the general upstreams.  It must be valid.
	GeneralUpstreams *proxy.UpstreamConfig

	// PrivateRDNSUpstreams represents the private upstreams.  If it is nil, the
	// usage of private RDNS will be disabled.
	PrivateRDNSUpstreams *proxy.UpstreamConfig

	// Cache is the configuration for the DNS results cache.  It must not be
	// nil.
	Cache *CacheConfig

	// Fallbacks describes DNS fallback upstream servers.  It must not be nil.
	//
	// TODO(m.kazantsev): Move out of there to be able to remove the bootstraps
	// as well.
	Fallbacks *FallbackConfig

	// ClientGetter is the function to get the client for a request.  It must
	// not be nil.
	ClientGetter ClientGetter

	// BindRetry is the configuration for retrying to bind to listen addresses.
	// It must not be nil.
	BindRetry *BindRetryConfig

	// PendingRequests is the configuration for duplicate requests handling.
	// It must not be nil.
	PendingRequests *PendingRequestsConfig

	// ListenAddrs is the list of served addresses.  It must contain at least
	// one entry.  It must not be empty and must contain only valid addresses.
	ListenAddrs []netip.AddrPort
}

// BindRetryConfig configures retrying to bind to listen addresses.
type BindRetryConfig struct {
	// Enabled enables retrying to bind to listen addresses.
	Enabled bool

	// Interval is the interval to wait between retries.  It must be
	// non-negative.
	Interval time.Duration

	// Count is the maximum number of attempts excluding the first one.
	Count uint
}

// PendingRequestsConfig configures duplicate requests handling.
type PendingRequestsConfig struct {
	// Enabled determines whether duplicate simultaneous requests should be
	// tracked and use the result of the first one.
	Enabled bool
}
