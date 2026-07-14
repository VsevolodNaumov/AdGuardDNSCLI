package configmigrate

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
)

// migrateTo2 migrates the configuration from version 1 to version 2.  It adds
// the bind_retry object to the dns.server section:
//
// # Before:
//
//	dns:
//	    server:
//	        # …
//	    # …
//	# …
//	schema_version: 1
//
// # After:
//
//	dns:
//	    server:
//	        bind_retry:
//	            enabled: true
//	            interval: 1s
//	            count: 4
//	        # …
//	    # …
//	# …
//	schema_version: 2
func (m *Migrator) migrateTo2(ctx context.Context, conf yObj) (err error) {
	const target SchemaVersion = 2

	serverVal, err := fieldChainVal[yObj](conf, "dns", "server")
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	const key = "bind_retry"

	_, ok := serverVal[key]
	if ok {
		return fmt.Errorf("%s: %w", key, errors.ErrUnexpectedValue)
	}

	serverVal[key] = yObj{
		"enabled":  true,
		"interval": timeutil.Duration(1 * time.Second),
		"count":    4,
	}

	conf[SchemaVersionKey] = target

	return nil
}
