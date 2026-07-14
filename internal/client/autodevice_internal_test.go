package client

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO(e.burkov):  Test with domains.
func TestAutodeviceConfig_Compare(t *testing.T) {
	t.Parallel()

	var (
		confNarrow  = &storedAutodeviceClient{prefix: netip.MustParsePrefix("192.0.2.0/31")}
		confMedium  = &storedAutodeviceClient{prefix: netip.MustParsePrefix("192.0.2.127/30")}
		confWide    = &storedAutodeviceClient{prefix: netip.MustParsePrefix("192.0.4.0/24")}
		confGeneral = &storedAutodeviceClient{prefix: netip.Prefix{}}
	)

	testCases := []struct {
		name string
		in   []*storedAutodeviceClient
		want []*storedAutodeviceClient
	}{{
		name: "valid_only",
		in:   []*storedAutodeviceClient{confMedium, confNarrow, confWide},
		want: []*storedAutodeviceClient{confNarrow, confMedium, confWide},
	}, {
		name: "with_empty",
		in:   []*storedAutodeviceClient{confGeneral, confMedium, confNarrow, confWide},
		want: []*storedAutodeviceClient{confNarrow, confMedium, confWide, confGeneral},
	}, {
		name: "several_empty",
		in:   []*storedAutodeviceClient{confGeneral, confWide, confMedium, confNarrow, confGeneral},
		want: []*storedAutodeviceClient{confNarrow, confMedium, confWide, confGeneral, confGeneral},
	}, {
		name: "empty_only",
		in:   []*storedAutodeviceClient{confGeneral, confGeneral},
		want: []*storedAutodeviceClient{confGeneral, confGeneral},
	}, {
		name: "empty_at_end",
		in:   []*storedAutodeviceClient{confNarrow, confMedium, confWide, confGeneral},
		want: []*storedAutodeviceClient{confNarrow, confMedium, confWide, confGeneral},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			slices.SortStableFunc(tc.in, (*storedAutodeviceClient).compare)
			assert.Equal(t, tc.want, tc.in)
		})
	}
}
