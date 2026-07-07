package client_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
)

const (
	// testValidUntilIvl is a test interval of a valid time.
	testValidUntilIvl = 1 * time.Hour

	// testIPv4HumanID is a test [client.HumanID].
	//
	// Note: Keep in sync with testIPv4.
	testIPv4HumanID = client.HumanID("dev-192-0-2-1")

	// testTimeout is the common timeout for tests.
	testTimeout = 1 * time.Second
)

// testLogger is a common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// testIPv4 is a common IPv4 address for tests.
var testIPv4 = netip.MustParseAddr("192.0.2.1")

// testHumanIDSource is a mock implementation of the [client.HumanIDSource]
// interface.
type testHumanIDSource struct {
	onIdentify func(ctx context.Context, addr netip.Addr) (id *client.ValidHumanID, err error)
}

// type check
var _ client.HumanIDSource = (*testHumanIDSource)(nil)

// Identify implements the [client.HumanIDSource] interface for
// *testHumanIDSource.
func (s *testHumanIDSource) Identify(
	ctx context.Context,
	addr netip.Addr,
) (id *client.ValidHumanID, err error) {
	return s.onIdentify(ctx, addr)
}

// testClock is a mock implementation of the [timeutil.ClockAfter] interface.
//
// TODO(e.burkov):  Implement the [timeutil.ClockAfter] interface for
// [*faketime.Clock].
type testClock struct {
	faketime.Clock
	onAfter func(d time.Duration) (c <-chan time.Time)
}

// type check
var _ timeutil.ClockAfter = (*testClock)(nil)

// After implements the [timeutil.ClockAfter] interface for *testClock.
func (c *testClock) After(d time.Duration) (ch <-chan time.Time) {
	return c.onAfter(d)
}

// newTestClock returns a fake clock for tests and a channel that returned on
// c.After calls.  nowPtr must not be nil.
func newTestClock(tb testing.TB, nowPtr *time.Time) (c *testClock, ch chan<- time.Time) {
	tb.Helper()

	onNow := func() (t time.Time) {
		return *nowPtr
	}

	after := make(chan time.Time)
	onAfter := func(_ time.Duration) (ch <-chan time.Time) {
		return after
	}

	return &testClock{
		Clock:   faketime.Clock{OnNow: onNow},
		onAfter: onAfter,
	}, after
}

// testUpstreamConstructor is a mock [UpstreamConstructor] implementation for
// tests.
type testUpstreamConstructor struct {
	onAddressToUpstream func(addr string, opts *upstream.Options) (u upstream.Upstream, err error)
}

// type check
var _ client.UpstreamConstructor = (*testUpstreamConstructor)(nil)

// AddressToUpstream implements the [UpstreamConstructor] interface for
// *testUpstreamConstructor.
func (c *testUpstreamConstructor) AddressToUpstream(
	addr string,
	opts *upstream.Options,
) (u upstream.Upstream, err error) {
	return c.onAddressToUpstream(addr, opts)
}

type testUpstream struct {
	onAddress  func() (addr string)
	onClose    func() (err error)
	onExchange func(req *dns.Msg) (resp *dns.Msg, err error)
}

// type check
var _ upstream.Upstream = (*testUpstream)(nil)

// Address implements the [upstream.Upstream] interface for *testUpstream.
func (u *testUpstream) Address() (addr string) {
	return u.onAddress()
}

// Exchange implements the [upstream.Upstream] interface for *testUpstream.
func (u *testUpstream) Exchange(req *dns.Msg) (_ *dns.Msg, _ error) {
	return u.onExchange(req)
}

// Close implements the [upstream.Upstream] interface for *testUpstream.
func (u *testUpstream) Close() (err error) {
	return u.onClose()
}

// comparableUpstream is a mock [upstream.Upstream] implementation for tests.
type comparableUpstream struct {
	opts *upstream.Options
	addr string
}

// type check
var _ upstream.Upstream = (*comparableUpstream)(nil)

// Address implements the [upstream.Upstream] interface for *Upstream.
func (u *comparableUpstream) Address() (addr string) {
	return u.addr
}

// Exchange implements the [upstream.Upstream] interface for *Upstream.
func (u *comparableUpstream) Exchange(req *dns.Msg) (_ *dns.Msg, _ error) {
	panic(testutil.UnexpectedCall(req))
}

// Close implements the [upstream.Upstream] interface for *Upstream.
func (u *comparableUpstream) Close() (err error) {
	return nil
}

// newComparableUpstreamConstructor returns a new [UpstreamConstructor] that
// creates upstreams comparable with [assert.Equal].
func newComparableUpstreamConstructor() (uc *testUpstreamConstructor) {
	f := func(addr string, opts *upstream.Options) (u upstream.Upstream, err error) {
		return &comparableUpstream{
			opts: opts,
			addr: addr,
		}, nil
	}

	return &testUpstreamConstructor{
		onAddressToUpstream: f,
	}
}
