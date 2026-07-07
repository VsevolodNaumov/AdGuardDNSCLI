package client

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/timeutil"
)

// unit is a convenience alias for an empty struct.
type unit = struct{}

// DefaultStorageConfig is a configuration structure for [DefaultStorage].
type DefaultStorageConfig struct {
	// Logger is used for logging storage operations.  It must not be nil.
	Logger *slog.Logger

	// Static is a mapping of IP prefixes to clients' domain specifications that
	// are known in advance.  Each key, if not empty, and value must be valid.
	// Prefixes must not overlap.
	//
	// TODO(e.burkov):  Consider initializing the upstreams in this package,
	// instead of passing them from the outside.
	Static map[netip.Prefix]StaticClientConfig

	// HumanIDSource is used to identify dynamically created clients.  It must
	// not be nil, use [EmptyHumanIDSource] if no identification is needed.
	HumanIDSource HumanIDSource

	// UpstreamConstructor is used to construct upstreams from addresses.  It
	// must not be nil.
	UpstreamConstructor UpstreamConstructor

	// Identifiable defines the filter for addresses that should be identified
	// and turned into autodevice clients.  If Autodevice is not empty, it must
	// not be nil, use [IsIdentifiable] wrapped in [netutil.SubnetSetFunc] as a
	// sensible default.
	Identifiable netutil.SubnetSet

	// Autodevice is a mapping of IP prefixes to configurations of clients that
	// should be created automatically on demand.  Empty prefix defines a
	// default configuration for all addresses that are not covered by other
	// prefixes, all of which must be valid and must not overlap.  Each value
	// must be valid.
	Autodevice map[netip.Prefix]AutodeviceClientConfig

	// Clock is used to get the current time and run timers.  It must not be
	// nil.
	Clock timeutil.ClockAfter

	// CleanupIvl is the interval at which expired clients are cleaned up.  It
	// must be positive if Autodevice is not empty.
	CleanupIvl time.Duration

	// CacheEnabled controls whether dynamically created custom upstream configs
	// get their own cache.
	CacheEnabled bool

	// CacheSize is the size of the dynamically created custom upstream cache.
	// It must be positive if CacheEnabled is true.
	CacheSize int
}

// DefaultStorage is a default implementation of the [Storage] interface.
type DefaultStorage struct {
	clock timeutil.ClockAfter

	humanIDSource       HumanIDSource
	upstreamConstructor UpstreamConstructor
	identifiable        netutil.SubnetSet

	logger *slog.Logger

	// identifyQueue is used to avoid concurrent calls to the humanIDSource for
	// the same address.  Unlike searchQueue, it only protects the
	// identification, as the same address may be used to create multiple
	// clients for different domains.
	identifyQueue *queue[netip.Addr, *ValidHumanID]

	// searchQueue is used to avoid concurrent searches for the same address and
	// domain.  Unlike identifyQueue, it protects the entire search, as each
	// address and domain pair can only have one client.
	searchQueue *queue[searchRequest, Client]

	// mu protects clients.
	mu *sync.RWMutex

	gcDone     chan unit
	autodevice []*autodeviceConfig

	// clients stores known clients.  It must only be accessed under mu and kept
	// sorted by prefix.  It also must not contain empty and overlapping
	// prefixes
	clients []*storedClient

	cleanupIvl time.Duration
}

// NewDefaultStorage creates a new properly configured *DefaultStorage.  c must
// be valid.
func NewDefaultStorage(c *DefaultStorageConfig) (s *DefaultStorage) {
	// Use the number of configured static prefixes as the initial capacity of
	// the clients slice, as it is a good enough estimate for the initial
	// capacity.
	clients := make([]*storedClient, 0, len(c.Static))

	for prefix, conf := range c.Static {
		for domain, client := range conf {
			cl := &storedClient{
				validUntil: time.Time{},
				client:     client,
				prefix:     prefix,
				domain:     domain,
			}

			clients = append(clients, cl)
		}
	}
	slices.SortStableFunc(clients, (*storedClient).compare)

	// Use the number of configured autodevice prefixes as the initial capacity
	// of the autodevice slice, as it is a good enough estimate for the initial
	// capacity.
	autodevice := make([]*autodeviceConfig, 0, len(c.Autodevice))
	for prefix, conf := range c.Autodevice {
		for domain, cliConf := range conf {
			autodevice = append(autodevice, &autodeviceConfig{
				conf:         cliConf,
				prefix:       prefix,
				domain:       domain,
				cacheSize:    int(c.CacheSize),
				cacheEnabled: c.CacheEnabled,
			})
		}
	}
	slices.SortStableFunc(autodevice, (*autodeviceConfig).compare)

	return &DefaultStorage{
		clock:               c.Clock,
		logger:              c.Logger,
		humanIDSource:       c.HumanIDSource,
		upstreamConstructor: c.UpstreamConstructor,
		identifiable:        c.Identifiable,
		identifyQueue:       newQueue[netip.Addr, *ValidHumanID](),
		searchQueue:         newQueue[searchRequest, Client](),
		autodevice:          autodevice,
		mu:                  &sync.RWMutex{},
		clients:             clients,
		cleanupIvl:          c.CleanupIvl,
		gcDone:              make(chan unit),
	}
}

// type check
var _ Storage = (*DefaultStorage)(nil)

// Get implements the [Storage] interface for *DefaultStorage.
func (d *DefaultStorage) Get(
	ctx context.Context,
	addr netip.Addr,
	questionDomain string,
) (c Client, ok bool) {
	req := searchRequest{
		addr:   addr,
		domain: questionDomain,
	}

	c, err := d.searchQueue.push(ctx, req)
	if err != nil {
		d.logger.DebugContext(ctx, "queuing client", "addr", addr, slogutil.KeyError, err)

		return nil, false
	} else if c != nil {
		return c, true
	}
	defer func() { d.searchQueue.done(req, c, err) }()

	l := d.logger.With("addr", addr, "domain", questionDomain)
	l.DebugContext(ctx, "searching client")

	c = d.findValidClient(addr, questionDomain)
	if c != nil {
		l.DebugContext(ctx, "found client")

		return c, true
	}

	l.DebugContext(ctx, "no valid client found")

	c = d.findAutodevice(ctx, l, addr, questionDomain)
	if c != nil {
		return c, true
	}

	// Set the error to make sure that queue receives a negative result.
	err = errors.ErrNoValue

	return nil, false
}

// type check
var _ service.Interface = (*DefaultStorage)(nil)

// Start implements the [service.Interface] interface for *DefaultStorage.
func (d *DefaultStorage) Start(ctx context.Context) (err error) {
	if len(d.autodevice) > 0 {
		go d.runGC(ctx)
	}

	return nil
}

// Shutdown implements the [service.Interface] interface for *DefaultStorage.
func (d *DefaultStorage) Shutdown(ctx context.Context) (err error) {
	close(d.gcDone)

	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error

	for _, c := range d.clients {
		err = c.client.Upstreams().Close()
		if err != nil {
			err = fmt.Errorf("closing upstreams for %q and %s: %w", c.domain, c.prefix, err)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// searchRequest is a key for a search request in the queue.  It is used to
// deduplicate concurrent searches for the same address and domain.
type searchRequest struct {
	addr   netip.Addr
	domain string
}

// findValidClient finds a valid client for addr.  c is nil if no valid client
// is found.  addr must be valid and domain, if not empty, must be a valid
// non-FQDN in lower case.
func (d *DefaultStorage) findValidClient(addr netip.Addr, domain string) (c Client) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.clock.Now()

	for _, cli := range d.clients {
		if !cli.matches(addr, domain) {
			continue
		}

		if !cli.isValidAt(now) {
			// The client is no longer valid, reinitialize it.  Note, that
			// clients are sorted in such a way that the first match is the most
			// specific one, so there is no need to search further for valid
			// clients.
			return nil
		}

		return cli.client
	}

	return nil
}

// findAutodevice finds an autodevice client for addr, if it is identifiable and
// matches one of the autodevice configurations.  c is nil if a Client couldn't
// be created for addr and domain.
func (d *DefaultStorage) findAutodevice(
	ctx context.Context,
	logger *slog.Logger,
	addr netip.Addr,
	domain string,
) (c Client) {
	if len(d.autodevice) == 0 {
		d.logger.Log(ctx, slogutil.LevelTrace, "no autodevice clients configured")

		return nil
	}

	if !d.identifiable.Contains(addr) {
		logger.DebugContext(ctx, "address is not identifiable")

		return nil
	}

	for _, auto := range d.autodevice {
		if !auto.matches(addr, domain) {
			continue
		}

		logger.DebugContext(ctx, "creating client", "pref", auto.prefix)

		var err error
		c, err = d.newAutodeviceClient(
			ctx,
			addr,
			auto.domain,
			auto.conf,
			auto.cacheEnabled,
			auto.cacheSize,
		)
		if err != nil {
			logger.ErrorContext(ctx, "initializing client", slogutil.KeyError, err)

			return nil
		}

		logger.DebugContext(ctx, "created client", "pref", auto.prefix)

		return c
	}

	logger.DebugContext(ctx, "no autodevice client found")

	return nil
}

// newAutodeviceClient initializes an autodevice client for the given address
// and configuration.
func (d *DefaultStorage) newAutodeviceClient(
	ctx context.Context,
	addr netip.Addr,
	domain string,
	c *AutodeviceUpstreamConfig,
	cacheEnabled bool,
	cacheSize int,
) (cli Client, err error) {
	hid, err := d.identify(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("identifying client %q: %w", addr, err)
	}

	cli, err = newAutodeviceClient(hid.ID, c, d.upstreamConstructor, cacheEnabled, cacheSize)
	if err != nil {
		return nil, fmt.Errorf("creating autodevice client for %q and %s: %w", domain, addr, err)
	}

	sc := &storedClient{
		validUntil: hid.Until,
		client:     cli,
		// For autodevice clients use the exact address as the prefix, so that
		// it is not used for other addresses.
		prefix: netip.PrefixFrom(addr, addr.BitLen()),
		domain: domain,
	}

	err = d.insertAutodeviceClient(ctx, sc)
	if err != nil {
		return nil, fmt.Errorf("inserting autodevice client for %q and %s: %w", domain, addr, err)
	}

	return cli, nil
}

// identify returns a *ValidHumanID for addr, making only one concurrent call to
// the underlying [HumanIDSource].  It returns an error if the identification
// fails.  addr must be a valid unmapped global unicast or private IP.
func (d *DefaultStorage) identify(
	ctx context.Context,
	addr netip.Addr,
) (hid *ValidHumanID, err error) {
	hid, err = d.identifyQueue.push(ctx, addr)
	if err != nil {
		d.logger.DebugContext(ctx, "queuing client", "addr", addr, slogutil.KeyError, err)

		return nil, err
	} else if hid != nil {
		return hid, nil
	}
	defer func() { d.identifyQueue.done(addr, hid, err) }()

	hid, err = d.humanIDSource.Identify(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("identifying client %q: %w", addr, err)
	}

	return hid, nil
}

// insertAutodeviceClient inserts a new autodevice client into the storage.  It
// returns an error if there are conflicts, the client is closed in that case.
// sc must not be nil, and its prefix must be single-IP.
func (d *DefaultStorage) insertAutodeviceClient(ctx context.Context, sc *storedClient) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	idx, found := slices.BinarySearchFunc(d.clients, sc, (*storedClient).compare)
	if !found {
		d.clients = slices.Insert(d.clients, idx, sc)

		return nil
	}

	auto, ok := d.clients[idx].client.(*autodeviceClient)
	if !ok {
		err = fmt.Errorf("found static client: %w", errors.ErrDuplicated)

		return errors.WithDeferred(err, sc.client.Upstreams().Close())
	}

	d.setFinalizer(ctx, auto)
	d.clients[idx] = sc

	return nil
}

// runGC periodically cleans up expired clients from the storage.  It's intended
// to be run in a separate goroutine.
func (d *DefaultStorage) runGC(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, d.logger)

	for {
		select {
		case now := <-d.clock.After(d.cleanupIvl):
			d.logger.DebugContext(ctx, "collecting garbage")

			d.cleanExpired(ctx, now)
		case <-ctx.Done():
			d.logger.ErrorContext(ctx, "garbage collection finished", slogutil.KeyError, ctx.Err())

			return
		case <-d.gcDone:
			d.logger.DebugContext(ctx, "garbage collection finished")

			return
		}
	}
}

// cleanExpired removes expired clients from the storage.  now must not be
// empty.
func (d *DefaultStorage) cleanExpired(ctx context.Context, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.clients = slices.DeleteFunc(d.clients, func(c *storedClient) (remove bool) {
		auto, ok := c.client.(*autodeviceClient)
		if !ok || c.isValidAt(now) {
			return false
		}

		d.setFinalizer(ctx, auto)

		return true
	})
}

// setFinalizer sets a finalizer to c's upstreams to close them when they are no
// longer used.  d.mu must be locked and c must be removed from d under the same
// lock.
//
// TODO(e.burkov):  Consider using [runtime.AddCleanup] instead of finalizers.
func (d *DefaultStorage) setFinalizer(ctx context.Context, c Client) {
	runtime.SetFinalizer(c.Upstreams(), func(closer *proxy.CustomUpstreamConfig) {
		d.logger.DebugContext(ctx, "cleaning expired client")

		err := closer.Close()
		if err != nil {
			d.logger.ErrorContext(ctx, "cleaning expired client", slogutil.KeyError, err)
		}
	})
}

// storedClient is a client stored in [DefaultStorage].
type storedClient struct {
	validUntil time.Time
	client     Client

	// prefix must be valid for any client stored in [DefaultStorage].  If
	// client is [*autodeviceClient], prefix must be a single IP address.
	prefix netip.Prefix

	// domain is a non-FQDN domain name.  A question domain should be equal or a
	// subdomain of this domain to match, empty domain matches any question
	// domain.
	domain string
}

// isValidAt checks whether s is valid for now.
func (c *storedClient) isValidAt(now time.Time) (ok bool) {
	return c.validUntil.IsZero() || now.Before(c.validUntil)
}

// compare is a method for sorting stored clients by prefix and domain.  other
// must not be nil.
//
// TODO(e.burkov):  DRY with [autodeviceConfig.compare].
func (c *storedClient) compare(other *storedClient) (res int) {
	switch {
	case c.prefix == (netip.Prefix{}):
		if other.prefix == (netip.Prefix{}) {
			return compareDomains(c.domain, other.domain)
		}

		return 1
	case other.prefix == (netip.Prefix{}):
		return -1
	default:
		// Go on.
	}

	if a, b := c.prefix.IsSingleIP(), other.prefix.IsSingleIP(); a != b {
		if a {
			return -1
		}

		return 1
	}

	res = c.prefix.Compare(other.prefix)
	if res == 0 {
		return compareDomains(c.domain, other.domain)
	}

	return res
}

// compareDomains compares domains sorting more specific domains first, empty
// domains last, and otherwise comparing labels from right to left.  a and b
// must be valid non-FQDNs in the same letter case or empty.
func compareDomains(a, b string) (res int) {
	const labelSep = '.'

	for {
		if a == "" {
			if b == "" {
				return 0
			}

			return 1
		} else if b == "" {
			return -1
		}

		aLastDot := strings.LastIndexByte(a, labelSep)
		bLastDot := strings.LastIndexByte(b, labelSep)

		aLabel := a[aLastDot+1:]
		bLabel := b[bLastDot+1:]

		res = strings.Compare(aLabel, bLabel)
		if res != 0 {
			return res
		}

		a = a[:max(0, aLastDot)]
		b = b[:max(0, bLastDot)]
	}
}

// matchesDomain returns true if question is equal to configured or is its
// subdomain.  Empty configured matches any question domain.
func matchesDomain(question, configured string) (ok bool) {
	return configured == "" || question == configured || netutil.IsSubdomain(question, configured)
}

// matches returns true if c matches addr and domain pair.  addr must be valid,
// domain, if not empty, must be a valid non-FQDN.
//
// TODO(e.burkov):  DRY with [autodeviceConfig.matches].
func (c *storedClient) matches(addr netip.Addr, domain string) (ok bool) {
	if c.prefix != (netip.Prefix{}) && !c.prefix.Contains(addr) {
		return false
	}

	if !matchesDomain(domain, c.domain) {
		return false
	}

	return true
}
