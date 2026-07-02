package client_test

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTTL is a test time to live of entities.
const testTTL = 300

// TODO(m.kazantsev):  Consider creating DNS server only once before the
// testcases.
func TestRDNSIDSource_Identify(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock, _ := newTestClock(t, &now)

	reverseIPv4, reverseErr := dns.ReverseAddr(testIPv4.String())
	require.NoError(t, reverseErr)

	ptrHeader := dns.RR_Header{
		Name:   reverseIPv4,
		Rrtype: dns.TypePTR,
		Class:  dns.ClassINET,
		Ttl:    testTTL,
	}

	mxHeader := dns.RR_Header{
		Name:   reverseIPv4,
		Rrtype: dns.TypeMX,
		Class:  dns.ClassINET,
		Ttl:    testTTL,
	}

	testCases := []struct {
		name   string
		wantID *client.ValidHumanID
		answ   []dns.RR
		rcode  uint16
	}{{
		name: "success",
		answ: []dns.RR{&dns.PTR{
			Hdr: ptrHeader,
			Ptr: "foo.bar.",
		}},
		rcode: dns.RcodeSuccess,
		wantID: &client.ValidHumanID{
			ID:    client.HumanID("foo-bar"),
			Until: now.Add(testTTL * time.Second),
		},
	}, {
		name: "multiple_answers",
		answ: []dns.RR{
			&dns.MX{
				Hdr: mxHeader,
				Mx:  "bar.",
			},
			&dns.PTR{
				Hdr: ptrHeader,
				Ptr: "bar.foo.",
			},
		},
		rcode: dns.RcodeSuccess,
		wantID: &client.ValidHumanID{
			ID:    client.HumanID("bar-foo"),
			Until: now.Add(testTTL * time.Second),
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := runTestDNSServer(t, tc.answ, int(tc.rcode))

			src := newTestRDNSIDSource(t, clock, addr)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			ctx = slogutil.ContextWithLogger(ctx, testLogger)

			id, err := src.Identify(ctx, testIPv4)
			testutil.AssertErrorMsg(t, "", err)
			assert.Equal(t, tc.wantID, id)

			// Obtain the same value, but from cache.
			id, err = src.Identify(ctx, testIPv4)
			testutil.AssertErrorMsg(t, "", err)
			assert.Equal(t, tc.wantID, id)
		})
	}
}

func TestRDNSIDSource_Identify_errors(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock, _ := newTestClock(t, &now)

	codeRefused := uint16(dns.RcodeRefused)

	testCases := []struct {
		addr       netip.Addr
		name       string
		wantErrMsg string
		rcode      uint16
	}{{
		name: "err_bad_rcode",
		addr: testIPv4,
		wantErrMsg: "response code: not equal to expected value: got " +
			strconv.Itoa(int(codeRefused)) + ", want 0",
		rcode: codeRefused,
	}, {
		name:       "err_no_valid_resp",
		addr:       testIPv4,
		wantErrMsg: "ptr responses for " + testIPv4.String() + ": no value",
		rcode:      dns.RcodeSuccess,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			addr := runTestDNSServer(t, nil, int(tc.rcode))

			src := newTestRDNSIDSource(t, clock, addr)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			ctx = slogutil.ContextWithLogger(ctx, testLogger)

			id, err := src.Identify(ctx, tc.addr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Nil(t, id)

			id, err = src.Identify(ctx, tc.addr)
			testutil.AssertErrorMsg(t, "no valid response was received from dns", err)
			assert.Nil(t, id)
		})
	}
}

func TestRDNSIDSource_Identify_duplicates(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock, _ := newTestClock(t, &now)

	reverseIPv4, reverseErr := dns.ReverseAddr(testIPv4.String())
	require.NoError(t, reverseErr)

	ptrHeader := dns.RR_Header{
		Name:   reverseIPv4,
		Rrtype: dns.TypePTR,
		Class:  dns.ClassINET,
		Ttl:    testTTL,
	}

	answ := []dns.RR{&dns.PTR{
		Hdr: ptrHeader,
		Ptr: "foo.bar.",
	}}

	t.Run("err_duplicate_human_id", func(t *testing.T) {
		t.Parallel()

		addr := runTestDNSServer(t, answ, dns.RcodeSuccess)

		src := newTestRDNSIDSource(t, clock, addr)

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		ctx = slogutil.ContextWithLogger(ctx, testLogger)

		id, err := src.Identify(ctx, testIPv4)
		testutil.AssertErrorMsg(t, "", err)
		assert.NotNil(t, id)

		const wantErrMsg = `ptr responses for 192.0.2.2: answer: at index 0: ` +
			`human id "foo-bar": duplicated value`

		id, err = src.Identify(ctx, testIPv4.Next())
		testutil.AssertErrorMsg(t, wantErrMsg, err)
		assert.Nil(t, id)
	})
}

// runTestDNSServer is a helper that runs a DNS server that serves requests with
// given data using the TCP protocol.
func runTestDNSServer(tb testing.TB, answ []dns.RR, rcode int) (addr net.Addr) {
	tb.Helper()

	ready := make(chan struct{})

	s := &dns.Server{
		Addr: netip.AddrPortFrom(netutil.IPv4Localhost(), 0).String(),
		Net:  "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			pt := testutil.NewPanicT(tb)

			msg := &dns.Msg{}
			msg.SetReply(r)
			msg.Answer = slices.Clone(answ)
			msg.Rcode = rcode

			err := w.WriteMsg(msg)
			require.NoError(pt, err)
		}),
	}

	s.NotifyStartedFunc = func() {
		addr = s.Listener.Addr()
		close(ready)
	}

	go func() {
		pt := testutil.NewPanicT(tb)
		err := s.ListenAndServe()
		require.NoError(pt, err)
	}()

	testutil.CleanupAndRequireSuccess(tb, s.Shutdown)
	testutil.RequireReceive(tb, ready, testTimeout)

	return addr
}

// newTestRDNSIDSource creates a new upstream and a new *client.RDNSIDSource for
// tests.
func newTestRDNSIDSource(
	tb testing.TB,
	clock timeutil.Clock,
	addr net.Addr,
) (src *client.RDNSIDSource) {
	tb.Helper()

	upstrm, err := upstream.NewUpstreamResolver("tcp://"+addr.String(), nil)
	require.NoError(tb, err)

	upstreamConf := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{upstrm},
	}

	src = client.NewRDNSIDSource(&client.RDNSIDSourceConfig{
		Clock:          clock,
		UpstreamConfig: upstreamConf,
	})

	return src
}
