package cmd

import (
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// newClientStorage creates a new implementation of the [client.Storage]
// interface.  All arguments must not be nil.
func newClientStorage(
	baseLogger *slog.Logger,
	ups upstreamConfigs,
	cacheConf *cacheConfig,
) (s client.Storage) {
	conf := cacheConf.toInternal()

	clientStrgConf := &client.DefaultStorageConfig{
		Logger: baseLogger.With(slogutil.KeyPrefix, "client_storage"),
		Clock:  timeutil.SystemClock{},
		Static: ups.initStaticClients(conf),
	}

	return client.NewDefaultStorage(clientStrgConf)
}
