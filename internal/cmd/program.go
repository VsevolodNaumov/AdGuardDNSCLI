package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/dnssvc"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/version"
	osservice "github.com/kardianos/service"
)

// program is the implementation of the [osservice.Interface] interface for
// AdGuard DNS CLI.
type program struct {
	// TODO(e.burkov):  Add *options?

	// conf is the parsed configuration to run the program.  It appears nil on
	// any service action and must not be accessed.
	conf   *configuration
	logger *slog.Logger

	// TODO(e.burkov):  Use [io.Closer].
	logFile *os.File
	done    chan struct{}
	errCh   chan error
}

// type check
var _ osservice.Interface = (*program)(nil)

// serviceProgramPrefix is the default and recommended prefix for the logger of
// the default [osservice.Interface] implementation.
const serviceProgramPrefix = "program"

// Start implements the [osservice.Interface] interface for [*program].
func (prog *program) Start(_ osservice.Service) (err error) {
	ctx := context.Background()
	l := prog.logger.With(slogutil.KeyPrefix, serviceProgramPrefix)

	// TODO(a.garipov): Copy logs configuration from the WIP abt. slog.
	l.InfoContext(
		ctx,
		"AdGuard DNS CLI starting",
		"version", version.Version(),
		"revision", version.Revision(),
		"branch", version.Branch(),
		"commit_time", version.CommitTime(),
		"race", version.RaceEnabled,
		"verbose", l.Enabled(ctx, slog.LevelDebug),
	)

	svcHdlr := newServiceHandler(prog.done, service.SignalHandlerShutdownTimeout)

	dnsConf, err := prog.buildDNSConfig(l, svcHdlr)
	if err != nil {
		// Don't wrap the error, because it is informative enough as is.
		return err
	}

	dnsSvc, err := dnssvc.New(dnsConf)
	if err != nil {
		return fmt.Errorf("creating dns service: %w", err)
	}

	err = dnsSvc.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting dns service: %w", err)
	}

	svcHdlr.add(dnsSvc)

	l.DebugContext(ctx, "dns service started")

	svcHdlrLog := prog.logger.With(slogutil.KeyPrefix, "service_handler")

	go svcHdlr.handle(ctx, svcHdlrLog, prog.errCh)

	return nil
}

// buildDNSConfig builds a new DNS configuration.  l and svcHdlr must not be
// nil.
func (prog *program) buildDNSConfig(
	l *slog.Logger,
	svcHdlr *serviceHandler,
) (conf *dnssvc.Config, err error) {
	boot, closers, err := newResolvers(prog.conf.DNS.Bootstrap, l)
	if err != nil {
		return nil, fmt.Errorf("creating resolvers: %w", err)
	}

	svcHdlr.add(closers)

	ups, privateUps, err := newUpstreams(prog.conf.DNS.Upstream, l, boot)
	if err != nil {
		return nil, fmt.Errorf("creating upstreams: %w", err)
	}

	// Use the upstream configuration with no client specification as the
	// general one.  Also remove it from the map, to build the clients list.
	generalUps := ups[netip.Prefix{}]
	delete(ups, netip.Prefix{})

	cs := newClientStorage(prog.logger, ups, prog.conf.DNS.Cache)

	svcHdlr.add(cs)

	dnsConf := prog.conf.DNS.toInternal(prog.logger, cs, generalUps, privateUps, boot)

	return dnsConf, nil
}

// Stop implements the [osservice.Interface] interface for [*program].
func (prog *program) Stop(_ osservice.Service) (err error) {
	close(prog.done)

	return <-prog.errCh
}

// closeLogs closes the log files and syslog handler, if there are any.
func (prog *program) closeLogs(ctx context.Context) {
	// At this point, just use stderr with defaults.
	l := slogutil.New(&slogutil.Config{
		Output: os.Stderr,
	}).With(slogutil.KeyPrefix, serviceProgramPrefix)

	if prog.logFile != nil {
		err := prog.logFile.Close()
		if err != nil {
			err = fmt.Errorf("closing log file: %w", err)
			l.ErrorContext(ctx, "stopping", slogutil.KeyError, err)
		}
	}

	h := prog.logger.Handler()
	if c, ok := h.(io.Closer); ok {
		err := c.Close()
		if err != nil {
			err = fmt.Errorf("closing system logger: %w", err)
			l.ErrorContext(ctx, "stopping", slogutil.KeyError, err)
		}
	}
}
