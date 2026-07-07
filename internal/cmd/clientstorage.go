package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// defaultClientCleanupIvl is the default interval to run the client storage
// cleanup.
//
// TODO(e.burkov):  Make configurable.
const defaultClientCleanupIvl = 5 * time.Minute

// initClientStorage creates and starts a [client.Storage].  All arguments must
// not be nil.
func initClientStorage(
	ctx context.Context,
	baseLogger *slog.Logger,
	ups upstreamConfigs,
	cacheConf *cacheConfig,
	svcHdlr *serviceHandler,
) (s client.Storage, err error) {
	clientStrgConf := &client.DefaultStorageConfig{
		Logger:              baseLogger.With(slogutil.KeyPrefix, "client_storage"),
		Clock:               timeutil.SystemClock{},
		Static:              ups.initStaticClients(cacheConf),
		HumanIDSource:       client.EmptyHumanIDSource{},
		UpstreamConstructor: client.DefaultUpstreamConstructor{},
		// TODO(e.burkov):  Consider making configurable.
		Identifiable: netutil.SubnetSetFunc(client.IsIdentifiable),
		CleanupIvl:   defaultClientCleanupIvl,
		// #nosec G115 -- The value is validated to not exceed [math.MaxInt].
		CacheSize:    int(cacheConf.ClientSize),
		CacheEnabled: cacheConf.Enabled,
	}

	cs := client.NewDefaultStorage(clientStrgConf)

	err = cs.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting client storage: %w", err)
	}

	svcHdlr.add(cs)

	return cs, nil
}
