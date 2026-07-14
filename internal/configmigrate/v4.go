package configmigrate

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
)

// migrateTo4 migrates the configuration from version 3 to version 4.  It adds
// the autodevice object to each dns.upstream.groups entry:
//
// # Before:
//
//	dns:
//	    upstream:
//	        groups:
//	            'default':
//	                # …
//	            # …
//	        # …
//	    # …
//	# …
//	schema_version: 3
//
// # After:
//
//	dns:
//	    upstream:
//	        groups:
//	            'default':
//	                # …
//	                autodevice:
//	                    enabled: false
//	            # …
//	        # …
//	    # …
//	# …
//	schema_version: 4
func (m *Migrator) migrateTo4(ctx context.Context, conf yObj) (err error) {
	const target SchemaVersion = 4

	groupsVal, err := fieldChainVal[yObj](conf, "dns", "upstream", "groups")
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	const key = "autodevice"

	disabledAutodevice := yObj{
		"enabled": false,
	}

	var errs []error

	for _, groupName := range slices.Sorted(maps.Keys(groupsVal)) {
		var groupVal yObj
		groupVal, err = fieldVal[yObj](groupsVal, groupName)
		if err != nil {
			err = fmt.Errorf("%q: %w", groupName, err)
			errs = append(errs, err)

			continue
		}

		_, ok := groupVal[key]
		if ok {
			err = fmt.Errorf("%q: %s: %w", groupName, key, errors.ErrUnexpectedValue)
			errs = append(errs, err)

			continue
		}

		groupVal[key] = maps.Clone(disabledAutodevice)
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("dns: upstream: groups: %w", err)
	}

	conf[SchemaVersionKey] = target

	return nil
}
