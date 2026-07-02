package client

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAutodeviceConfig_Compare(t *testing.T) {
	t.Parallel()

	var (
		confNarrow  = &autodeviceConfig{prefix: netip.MustParsePrefix("192.0.2.0/31")}
		confMedium  = &autodeviceConfig{prefix: netip.MustParsePrefix("192.0.2.127/30")}
		confWide    = &autodeviceConfig{prefix: netip.MustParsePrefix("192.0.4.0/24")}
		confGeneral = &autodeviceConfig{prefix: netip.Prefix{}}
	)

	testCases := []struct {
		name string
		in   []*autodeviceConfig
		want []*autodeviceConfig
	}{{
		name: "valid_only",
		in:   []*autodeviceConfig{confMedium, confNarrow, confWide},
		want: []*autodeviceConfig{confNarrow, confMedium, confWide},
	}, {
		name: "with_empty",
		in:   []*autodeviceConfig{confGeneral, confMedium, confNarrow, confWide},
		want: []*autodeviceConfig{confNarrow, confMedium, confWide, confGeneral},
	}, {
		name: "several_empty",
		in:   []*autodeviceConfig{confGeneral, confWide, confMedium, confNarrow, confGeneral},
		want: []*autodeviceConfig{confNarrow, confMedium, confWide, confGeneral, confGeneral},
	}, {
		name: "empty_only",
		in:   []*autodeviceConfig{confGeneral, confGeneral},
		want: []*autodeviceConfig{confGeneral, confGeneral},
	}, {
		name: "empty_at_end",
		in:   []*autodeviceConfig{confNarrow, confMedium, confWide, confGeneral},
		want: []*autodeviceConfig{confNarrow, confMedium, confWide, confGeneral},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			slices.SortStableFunc(tc.in, (*autodeviceConfig).compare)
			assert.Equal(t, tc.want, tc.in)
		})
	}
}
