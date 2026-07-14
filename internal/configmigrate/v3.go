package configmigrate

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// migrateTo3 migrates the configuration from version 2 to version 3.  It adds
// the pending_requests object to the dns.server section:
//
// # Before:
//
//	dns:
//	    server:
//	        # …
//	    # …
//	# …
//	schema_version: 2
//
// # After:
//
//	dns:
//	    server:
//	        pending_requests:
//	            enabled: true
//	        # …
//	    # …
//	# …
//	schema_version: 3
func (m *Migrator) migrateTo3(ctx context.Context, conf yObj) (err error) {
	const target SchemaVersion = 3

	serverVal, err := fieldChainVal[yObj](conf, "dns", "server")
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	const key = "pending_requests"

	_, ok := serverVal[key]
	if ok {
		return fmt.Errorf("%s: %w", key, errors.ErrUnexpectedValue)
	}

	serverVal[key] = yObj{
		"enabled": true,
	}

	conf[SchemaVersionKey] = target

	return nil
}
