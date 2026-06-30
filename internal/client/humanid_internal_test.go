package client

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/stretchr/testify/require"
)

func FuzzFQDNToHumanID(f *testing.F) {
	for _, seed := range []string{
		"",
		"f",
		"foo",
		"foo-bar",
		"foo--bar",
		"foo.",
		"foo.bar",
		"foo.bar.",
		".",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		id, err := fqdnToHumanID(input)
		if err != nil {
			require.Empty(t, id)

			return
		}

		require.NotEmpty(t, id)
		require.NotContains(t, string(id), ".")

		_, err = newHumanID(string(id))
		require.NoError(t, err)
	})
}

// newHumanID converts a simple string into a HumanID and makes sure that it's
// valid.  It does not wrap the error to be used in places where that could
// create additional allocations.
//
// NOTE:  Keep in sync with https://github.com/AdguardTeam/AdGuardDNS/blob/3f26cca7e094801647ea6e93503d6ed61c545737/internal/agd/humanid.go#L45.
func newHumanID(s string) (id HumanID, err error) {
	err = validate.InRange("s", len(s), minHumanIDLen, maxHumanIDLen)
	if err != nil {
		// Don't wrap the error, because the caller should do that.
		return "", err
	}

	err = netutil.ValidateHostnameLabel(s)
	if err != nil {
		// Don't wrap the error, because the caller should do that.
		return "", err
	}

	if i := strings.Index(s, "---"); i >= 0 {
		return "", fmt.Errorf("at index %d: max 2 consecutive hyphens are allowed", i)
	}

	return HumanID(s), nil
}
