package client

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareDomains(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   []string
		want []string
	}{{
		name: "simple",
		in:   []string{"", "example", "www.example", "mail.www.example"},
		want: []string{"mail.www.example", "www.example", "example", ""},
	}, {
		name: "same_suffix",
		in:   []string{"b.example", "a.example", "z.a.example", "example"},
		want: []string{"z.a.example", "a.example", "b.example", "example"},
	}, {
		name: "different_suffixes",
		in:   []string{"example.org", "example.com", "a.example.net"},
		want: []string{"example.com", "a.example.net", "example.org"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			slices.SortStableFunc(tc.in, compareDomains)
			assert.Equal(t, tc.want, tc.in)
		})
	}
}
