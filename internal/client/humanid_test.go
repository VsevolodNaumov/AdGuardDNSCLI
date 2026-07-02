package client_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultHumanIDSource_Identify(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock, _ := newTestClock(t, &now)

	testIPv4MappedIPv6 := netip.AddrFrom16(testIPv4.As16())
	testIPv6 := netip.MustParseAddr("2001:db8::1")
	ipv6Str := testIPv6.StringExpanded()

	src := client.NewDefaultHumanIDSource(&client.DefaultHumanIDSourceConfig{
		Clock:       clock,
		ValidityIvl: timeutil.Duration(testValidUntilIvl),
	})

	testCases := []struct {
		addr   netip.Addr
		wantID *client.ValidHumanID
		name   string
	}{{
		name: "success-ipv4",
		addr: testIPv4,
		wantID: &client.ValidHumanID{
			ID:    testIPv4HumanID,
			Until: now.Add(testValidUntilIvl),
		},
	}, {
		name: "success-ipv6",
		addr: testIPv6,
		wantID: &client.ValidHumanID{
			ID:    client.HumanID("dev-" + strings.ReplaceAll(ipv6Str, ":", "-")),
			Until: now.Add(testValidUntilIvl),
		},
	}, {
		name: "success-ipv4-mapped-ipv6",
		addr: testIPv4MappedIPv6,
		wantID: &client.ValidHumanID{
			ID:    testIPv4HumanID,
			Until: now.Add(testValidUntilIvl),
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)

			id, err := src.Identify(ctx, tc.addr)
			require.NoError(t, err)

			assert.Equal(t, tc.wantID, id)
		})
	}
}

func TestConsequentIDSource_Identify(t *testing.T) {
	t.Parallel()

	now := time.Now()

	humanID := &client.ValidHumanID{
		ID:    testIPv4HumanID,
		Until: now.Add(testValidUntilIvl),
	}

	clock, _ := newTestClock(t, &now)
	srcConf := &client.DefaultHumanIDSourceConfig{
		Clock:       clock,
		ValidityIvl: timeutil.Duration(testValidUntilIvl),
	}

	noValueErrMsg := errors.ErrNoValue.Error()

	testCases := []struct {
		addr       netip.Addr
		wantID     *client.ValidHumanID
		name       string
		wantErrMsg string
		src        client.ConsequentHumanIDSource
	}{{
		name: "success",
		addr: testIPv4,
		src: client.ConsequentHumanIDSource{
			client.NewDefaultHumanIDSource(srcConf),
		},
		wantID: humanID,
	}, {
		name:       "err-empty-sources",
		wantErrMsg: noValueErrMsg,
		addr:       testIPv4,
		src: client.ConsequentHumanIDSource{
			client.EmptyHumanIDSource{},
			client.EmptyHumanIDSource{},
		},
	}, {
		name:       "err-no-sources",
		wantErrMsg: noValueErrMsg,
		addr:       testIPv4,
		src:        nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, testTimeout)

			id, err := tc.src.Identify(ctx, tc.addr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			assert.Equal(t, tc.wantID, id)
		})
	}
}
