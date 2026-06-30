package client

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
)

// HumanID is an identifier for DNS client.  It must be unique for each client
// among a single [Storage].
type HumanID string

// ProfileID is the ID of a profile.
//
// TODO(e.burkov):  Consider moving to agdc.
type ProfileID string

// DeviceType is a type of a device.
//
// TODO(e.burkov):  Consider moving to agdc.
type DeviceType string

// Constants for [HumanID] validation.
const (
	// maxHumanIDLen is the maximum length of HumanID.
	maxHumanIDLen = netutil.MaxDomainLabelLen - DeviceTypeLen - ProfileIDLen - 2*len("-")

	// minHumanIDLen is the minimum length of HumanID.
	//
	// NOTE:  Keep in sync with https://github.com/AdguardTeam/AdGuardDNS/blob/3f26cca7e094801647ea6e93503d6ed61c545737/internal/agd/humanid.go#L23.
	minHumanIDLen = 1
)

// Constants for upstream templates.
//
// TODO(e.burkov):  Consider moving to agdc.
const (
	// DeviceTypeLen is the length of DeviceType.
	DeviceTypeLen = 3

	// ProfileIDLen is the length of ProfileID.
	ProfileIDLen = 8
)

// fqdnToHumanID converts a FQDN string into HumanID, if possible.
func fqdnToHumanID(fqdn string) (id HumanID, err error) {
	domain := strings.TrimSuffix(fqdn, ".")

	err = validate.NoLessThan("domain", len(domain), minHumanIDLen)
	if err != nil {
		// Don't wrap the error, because it is informative enough as is.
		return "", err
	}

	if len(domain) > maxHumanIDLen {
		domain = strings.TrimSuffix(domain[:maxHumanIDLen], ".")
	}

	idStr := strings.ReplaceAll(domain, ".", "-")

	err = netutil.ValidateHostnameLabel(idStr)
	if err != nil {
		// Don't wrap the error, because it is informative enough as is.
		return "", err
	}

	if i := strings.Index(idStr, "---"); i >= 0 {
		return "", fmt.Errorf("at index %d: max 2 consecutive hyphens are allowed", i)
	}

	return HumanID(idStr), nil
}
