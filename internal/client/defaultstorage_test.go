package client_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUpstreamURL is a common upstream URL for tests.
const testUpstreamURL = "https://dns.example/dns-query"

// testAutodeviceUpstreamConfig is a common autodevice upstream configuration
// for tests.
var testAutodeviceUpstreamConfig = &client.AutodeviceUpstreamConfig{
	UpstreamTemplate: errors.Must(url.Parse(testUpstreamURL)),
	DeviceType:       errors.Must(client.NewDeviceType("mac")),
	ProfileID:        errors.Must(client.NewProfileID("abcdefgh")),
}

// testAutodeviceClientConfig is a common autodevice client configuration for
// tests.
var testAutodeviceClientConfig = client.AutodeviceClientConfig{
	"": testAutodeviceUpstreamConfig,
}

func TestDefaultStorage_ByAddr_static(t *testing.T) {
	t.Parallel()

	const anotherUpstreamURL = "tls://dns.example/dns-query"

	cli1Addr1 := netip.MustParseAddr("192.0.2.0")
	cli1Pref1 := netip.PrefixFrom(cli1Addr1, 31)

	cli1Addr2 := netip.MustParseAddr("192.0.2.4")
	cli1Pref2 := netip.PrefixFrom(cli1Addr2, 30)

	cli2Addr1 := netip.MustParseAddr("198.51.100.0")
	cli2Pref1 := netip.PrefixFrom(cli2Addr1, 32)

	absentAddr := cli2Addr1.Next()

	upsConf1 := errors.Must(proxy.ParseUpstreamsConfig([]string{testUpstreamURL}, nil))
	custUpsConf1 := proxy.NewCustomUpstreamConfig(upsConf1, false, 0, false)

	upsConf2 := errors.Must(proxy.ParseUpstreamsConfig([]string{anotherUpstreamURL}, nil))
	custUpsConf2 := proxy.NewCustomUpstreamConfig(upsConf2, false, 0, false)

	cli1 := client.NewStaticClient(custUpsConf1)
	cli2 := client.NewStaticClient(custUpsConf2)

	testCases := []struct {
		static   map[netip.Prefix]*client.StaticClient
		name     string
		searches []testSearch
	}{{
		name:   "empty",
		static: nil,
		searches: []testSearch{{
			addr: absentAddr,
			want: nil,
		}, {
			addr: cli1Addr2.Prev(),
			want: nil,
		}},
	}, {
		name: "single",
		static: map[netip.Prefix]*client.StaticClient{
			cli1Pref1: cli1,
			cli1Pref2: cli1,
		},
		searches: []testSearch{{
			addr: cli1Addr1,
			want: custUpsConf1,
		}, {
			addr: cli1Addr2,
			want: custUpsConf1,
		}, {
			addr: cli2Addr1.Next(),
			want: nil,
		}, {
			addr: absentAddr,
			want: nil,
		}},
	}, {
		name: "multiple",
		static: map[netip.Prefix]*client.StaticClient{
			cli1Pref1: cli1,
			cli1Pref2: cli1,
			cli2Pref1: cli2,
		},
		searches: []testSearch{{
			addr: cli1Addr1,
			want: custUpsConf1,
		}, {
			addr: cli1Addr2,
			want: custUpsConf1,
		}, {
			addr: cli2Addr1,
			want: custUpsConf2,
		}, {
			addr: absentAddr,
			want: nil,
		}},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := client.NewDefaultStorage(&client.DefaultStorageConfig{
				Logger:              testLogger,
				Clock:               timeutil.SystemClock{},
				UpstreamConstructor: client.DefaultUpstreamConstructor{},
				Static:              tc.static,
			})
			servicetest.RequireRun(t, cs, testTimeout)

			runSearchesTests(t, cs, tc.searches)
		})
	}
}

func TestDefaultStorage_ByAddr_autodevice(t *testing.T) {
	t.Parallel()

	addrSpecific := testIPv4
	prefSpecific := netip.PrefixFrom(addrSpecific, addrSpecific.BitLen())
	addrDefault := netip.MustParseAddr("198.51.100.7")

	source := &testHumanIDSource{
		onIdentify: func(_ context.Context, addr netip.Addr) (id *client.ValidHumanID, err error) {
			idStr := hex.EncodeToString(addr.AsSlice())

			return &client.ValidHumanID{
				ID:    client.HumanID(idStr),
				Until: time.Now().Add(testValidUntilIvl),
			}, nil
		},
	}

	idSpecific := errors.Must(source.Identify(t.Context(), addrSpecific)).ID
	idDefault := errors.Must(source.Identify(t.Context(), addrDefault)).ID

	upsConf := testAutodeviceUpstreamConfig

	upsCons := newComparableUpstreamConstructor()

	extIDSpecific := fmt.Sprintf("%s-%s-%s", upsConf.DeviceType, upsConf.ProfileID, idSpecific)
	upsURLSpecific := upsConf.UpstreamTemplate.JoinPath(extIDSpecific).String()
	upsConfSpecific := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{
			errors.Must(upsCons.AddressToUpstream(upsURLSpecific, upsConf.Options)),
		},
	}
	custConfSpecific := proxy.NewCustomUpstreamConfig(upsConfSpecific, false, 0, false)

	extIDDefault := fmt.Sprintf("%s-%s-%s", upsConf.DeviceType, upsConf.ProfileID, idDefault)
	upsURLDefault := upsConf.UpstreamTemplate.JoinPath(extIDDefault).String()
	upsConfDefault := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{
			errors.Must(upsCons.AddressToUpstream(upsURLDefault, upsConf.Options)),
		},
	}
	custConfDefault := proxy.NewCustomUpstreamConfig(upsConfDefault, false, 0, false)

	testCases := []struct {
		autodevice map[netip.Prefix]client.AutodeviceClientConfig
		name       string
		searches   []testSearch
	}{{
		name: "general_only",
		autodevice: map[netip.Prefix]client.AutodeviceClientConfig{
			{}: testAutodeviceClientConfig,
		},
		searches: []testSearch{{
			addr: addrDefault,
			want: custConfDefault,
		}, {
			addr: addrSpecific,
			want: custConfSpecific,
		}},
	}, {
		name: "both",
		autodevice: map[netip.Prefix]client.AutodeviceClientConfig{
			prefSpecific: testAutodeviceClientConfig,
			{}:           testAutodeviceClientConfig,
		},
		searches: []testSearch{{
			addr: addrSpecific,
			want: custConfSpecific,
		}, {
			addr: addrDefault,
			want: custConfDefault,
		}},
	}, {
		name: "specific_only",
		autodevice: map[netip.Prefix]client.AutodeviceClientConfig{
			prefSpecific: testAutodeviceClientConfig,
		},
		searches: []testSearch{{
			addr: addrDefault,
			want: nil,
		}, {
			addr: addrSpecific,
			want: custConfSpecific,
		}},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := client.NewDefaultStorage(&client.DefaultStorageConfig{
				Logger:              testLogger,
				Clock:               timeutil.SystemClock{},
				HumanIDSource:       source,
				UpstreamConstructor: upsCons,
				Autodevice:          tc.autodevice,
				// Never cleanup in this test.
				CleanupIvl: 10 * testTimeout,
			})
			servicetest.RequireRun(t, cs, testTimeout)

			runSearchesTests(t, cs, tc.searches)
		})
	}
}

func TestDefaultStorage_ByAddr_autodeviceCache(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock, afterCh := newTestClock(t, &now)

	source := &testHumanIDSource{
		onIdentify: func(_ context.Context, addr netip.Addr) (id *client.ValidHumanID, err error) {
			return &client.ValidHumanID{
				ID:    client.HumanID(hex.EncodeToString(addr.AsSlice())),
				Until: now.Add(testValidUntilIvl),
			}, nil
		},
	}
	cs := client.NewDefaultStorage(&client.DefaultStorageConfig{
		Logger:              testLogger,
		Clock:               clock,
		HumanIDSource:       source,
		UpstreamConstructor: client.DefaultUpstreamConstructor{},
		Autodevice: map[netip.Prefix]client.AutodeviceClientConfig{
			{}: testAutodeviceClientConfig,
		},
		CleanupIvl: testValidUntilIvl / 2,
	})
	servicetest.RequireRun(t, cs, testTimeout)

	var first client.Client
	var ok bool

	require.True(t, t.Run("first", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)

		first, ok = cs.ByAddr(ctx, testIPv4)
		require.True(t, ok)

		assert.NotNil(t, first)
	}))

	require.True(t, t.Run("cache", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)

		var cached client.Client
		cached, ok = cs.ByAddr(ctx, testIPv4)
		require.True(t, ok)

		assert.Same(t, first, cached)
	}))

	var refreshed client.Client

	now = now.Add(testValidUntilIvl + 1*time.Second)
	testutil.RequireSend(t, afterCh, now, testTimeout)

	require.True(t, t.Run("expire", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)

		refreshed, ok = cs.ByAddr(ctx, testIPv4)
		require.True(t, ok)

		assert.NotSame(t, first, refreshed)
	}))

	require.True(t, t.Run("cache_after_expire", func(t *testing.T) {
		ctx := testutil.ContextWithTimeout(t, testTimeout)

		var latest client.Client
		latest, ok = cs.ByAddr(ctx, testIPv4)
		require.True(t, ok)

		assert.Same(t, refreshed, latest)
		assert.NotSame(t, first, refreshed)
	}))
}

// testSearch is a case of searching through a particular clients set.
type testSearch struct {
	want *proxy.CustomUpstreamConfig
	addr netip.Addr
}

// runSearchesTests runs tests on a particular clients set, stored in searches.
// t and cs must not be nil.
func runSearchesTests(t *testing.T, cs client.Storage, searches []testSearch) {
	t.Helper()

	for _, sc := range searches {
		t.Run(sc.addr.String(), func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			c, ok := cs.ByAddr(ctx, sc.addr)
			require.Equal(t, sc.want != nil, ok)

			if sc.want == nil {
				return
			}

			require.NotNil(t, c)

			assert.Equal(t, sc.want, c.Upstreams())
		})
	}
}
