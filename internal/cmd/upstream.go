package cmd

import (
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNSCLI/internal/agdc"
	"github.com/AdguardTeam/AdGuardDNSCLI/internal/agdcslog"
	"github.com/AdguardTeam/AdGuardDNSCLI/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
)

// upstreamConfig is the configuration for the DNS upstream servers.
type upstreamConfig struct {
	// Groups contains all the groups of servers.
	Groups upstreamGroupsConfig `yaml:"groups"`

	// Timeout constrains the time for sending requests and receiving responses.
	Timeout timeutil.Duration `yaml:"timeout"`
}

// type check
var _ validate.Interface = (*upstreamConfig)(nil)

// Validate implements the [validate.Interface] interface for *upstreamConfig.
func (c *upstreamConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.Positive("timeout", c.Timeout),
	}
	errs = validate.Append(errs, "groups", c.Groups)

	return errors.Join(errs...)
}

// indexedMatch is a key for matchSet.  It's essentially an
// [upstreamMatchConfig] with a lowercased question domain.
type indexedMatch struct {
	domain string
	client netip.Prefix
}

// matchSet validates that no two matches have the same domain and client in
// different upstream groups.
type matchSet map[indexedMatch]agdc.UpstreamGroupName

// addMatch returns an error if m conflicts with the ones in s.  name is the
// name of the group containing m.
//
// TODO(e.burkov):  Validate the prefixes don't overlap if not equal.
func (s matchSet) addMatch(name agdc.UpstreamGroupName, m *upstreamMatchConfig) (err error) {
	key := m.toIndexedMatch()
	another, ok := s[key]
	if !ok {
		s[key] = name

		return nil
	}

	if another == name {
		return errors.ErrDuplicated
	}

	return fmt.Errorf("conflicts with group %q", another)
}

// upstreamGroupsConfig is the configuration for a set of groups of DNS upstream
// servers.
type upstreamGroupsConfig map[agdc.UpstreamGroupName]*upstreamGroupConfig

// requiredGroups is the list of groups that must be present in a valid
// [upstreamGroupsConfig].
var requiredGroups = []agdc.UpstreamGroupName{
	agdc.UpstreamGroupNameDefault,
}

// predefinedGroups is the list of groups that must have no match criteria in a
// valid [upstreamGroupsConfig].
var predefinedGroups = []agdc.UpstreamGroupName{
	agdc.UpstreamGroupNameDefault,
	agdc.UpstreamGroupNamePrivate,
}

// type check
var _ validate.Interface = upstreamGroupsConfig(nil)

// Validate implements the [validate.Interface] interface for
// upstreamGroupsConfig.
func (c upstreamGroupsConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	var errs []error
	for _, name := range requiredGroups {
		if _, ok := c[name]; !ok {
			err = fmt.Errorf("group %q: must be present", name)
			errs = append(errs, err)
		}
	}

	errs = c.validateGroups(errs)

	return errors.Join(errs...)
}

// validateGroups appends the errors of validating groups within c to errs and
// returns the result.
func (c upstreamGroupsConfig) validateGroups(errs []error) (res []error) {
	ms := matchSet{}
	for _, name := range slices.Sorted(maps.Keys(c)) {
		g := c[name]

		var err error
		if slices.Contains(predefinedGroups, name) {
			err = g.validateAsPredefined(name)
		} else {
			err = g.validateAsCustom(ms, name)
		}
		if err != nil {
			err = fmt.Errorf("group %q: %w", name, err)
			errs = append(errs, err)
		}
	}

	return errs
}

// upstreamGroupConfig is the configuration for a group of DNS upstream servers.
type upstreamGroupConfig struct {
	// Address is the URL of the upstream server for this group.
	Address string `yaml:"address"`

	// Autodevice is the configuration for creating upstreams automatically for
	// this group.
	Autodevice *autodeviceConfig `yaml:"autodevice"`

	// Match is the set of criteria for choosing this group.
	Match []*upstreamMatchConfig `yaml:"match"`
}

// validateAsPredefined returns an error if c is not a valid predefined upstream
// group configuration that should have no match criteria.
//
// TODO(e.burkov):  Support autodevice for the private group.  It requires
// changes in dnsproxy.
func (c *upstreamGroupConfig) validateAsPredefined(name agdc.UpstreamGroupName) (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	errs := []error{
		validate.EmptySlice("match", c.Match),
	}

	err = c.Autodevice.Validate()
	if err != nil {
		errs = append(
			errs,
			fmt.Errorf("autodevice: %w", err),
			validate.NotEmpty("address", c.Address),
		)

		return errors.Join(errs...)
	}

	if !c.Autodevice.Enabled {
		errs = append(errs, validate.NotEmpty("address", c.Address))

		return errors.Join(errs...)
	}

	if name == agdc.UpstreamGroupNamePrivate {
		errs = append(errs, fmt.Errorf("autodevice: %q group doesn't support autodevice", name))

		return errors.Join(errs...)
	}

	errs = append(errs, validateAutodeviceAddress(c.Address))

	return errors.Join(errs...)
}

// validateAsCustom returns an error if c is not a valid custom upstream group
// configuration for group named n within the set s.
func (c *upstreamGroupConfig) validateAsCustom(s matchSet, n agdc.UpstreamGroupName) (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	var errs []error

	if err = c.Autodevice.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("autodevice: %w", err))
	} else if !c.Autodevice.Enabled {
		errs = append(errs, validate.NotEmpty("address", c.Address))
	} else {
		errs = append(errs, validateAutodeviceAddress(c.Address))
	}

	for i, m := range c.Match {
		err = m.validate(s, n)
		if err != nil {
			err = fmt.Errorf("match: at index %d: %w", i, err)
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// validateAutodeviceAddress returns an error if address is not a valid URL for
// an autodevice upstream.
func validateAutodeviceAddress(address string) (err error) {
	if err = validate.NotEmpty("address", address); err != nil {
		return err
	}

	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}

	switch s := u.Scheme; s {
	case client.SchemeHTTPS, client.SchemeTLS, client.SchemeQUIC:
		// Supported schemes.
	default:
		return fmt.Errorf("address: scheme: %w, %q", errors.ErrBadEnumValue, s)
	}

	return nil
}

// upstreamMatchConfig is the configuration for criteria for choosing an
// upstream group.
type upstreamMatchConfig struct {
	// Client is the client's subnet to match.  Prefix itself should be masked.
	Client netutil.Prefix `yaml:"client"`

	// QuestionDomain is the domain name from request's question to match.
	QuestionDomain string `yaml:"question_domain"`
}

// validate returns error if c is not valid.
func (c *upstreamMatchConfig) validate(s matchSet, name agdc.UpstreamGroupName) (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case *c == (upstreamMatchConfig{}):
		return errors.ErrEmptyValue
	default:
		return c.validateValues(s, name)
	}
}

// validateValues returns error if c contains invalid values.  c must not be
// nil.
func (c *upstreamMatchConfig) validateValues(s matchSet, name agdc.UpstreamGroupName) (err error) {
	var errs []error

	if c.QuestionDomain != "" {
		err = netutil.ValidateDomainName(c.QuestionDomain)
		if err != nil {
			err = fmt.Errorf("question_domain: %w", err)
			errs = append(errs, err)
		}
	}

	// TODO(e.burkov):  It may be useful to be able to specify the whole address
	// and only change the mask.
	if c.Client.Prefix != c.Client.Masked() {
		bitNum := c.Client.Bits()
		err = fmt.Errorf("client: %s must has at most %d significant bits", c.Client, bitNum)
		errs = append(errs, err)
	}

	errs = append(errs, s.addMatch(name, c))

	return errors.Join(errs...)
}

// toIndexedMatch converts the upstream match configuration to a key for
// [matchSet].
func (c *upstreamMatchConfig) toIndexedMatch() (im indexedMatch) {
	return indexedMatch{
		domain: strings.ToLower(c.QuestionDomain),
		client: c.Client.Prefix,
	}
}

// newUpstreams builds the upstreams from conf, filling generalUps, privateUps,
// staticUps, and autodeviceUps.  conf must be valid.  baseLogger, boot,
// generalUps, privateUps, staticUps, and autodeviceUps must not be nil.
func newUpstreams(
	conf *upstreamConfig,
	baseLogger *slog.Logger,
	boot upstream.Resolver,
	generalUps *proxy.UpstreamConfig,
	privateUps *proxy.UpstreamConfig,
	staticUps staticUpstreamConfigs,
	autodeviceUps autodeviceClients,
) (err error) {
	defer func() { err = errors.Annotate(err, "creating upstreams: %w") }()

	var errs []error
	for _, name := range slices.Sorted(maps.Keys(conf.Groups)) {
		g := conf.Groups[name]

		opts := &upstream.Options{
			Logger: baseLogger.With(
				agdcslog.KeyUpstreamType, agdcslog.UpstreamTypeMain,
				agdcslog.KeyUpstreamGroup, name,
			),
			Timeout:   time.Duration(conf.Timeout),
			Bootstrap: boot,
		}

		// Don't deduplicate the upstreams by URL, as they may be shared between
		// the configurations, which are closed independently.

		switch name {
		case agdc.UpstreamGroupNameDefault:
			err = g.addDefaultGroup(generalUps, autodeviceUps, opts)
		case agdc.UpstreamGroupNamePrivate:
			err = g.addPrivateGroup(privateUps, opts)
		default:
			if g.Autodevice.Enabled {
				err = g.addAutodeviceGroup(autodeviceUps, opts)
			} else {
				err = g.addCommonGroup(staticUps, opts)
			}
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("group %q: %w", name, err))
		}
	}

	return errors.Join(errs...)
}

// addDefaultGroup adds the upstreams from c, which must be a general group, to
// generalUps and autodeviceUps.  generalUps and autodeviceUps must not be nil.
func (c *upstreamGroupConfig) addDefaultGroup(
	generalUps *proxy.UpstreamConfig,
	autodeviceUps autodeviceClients,
	opts *upstream.Options,
) (err error) {
	if c.Autodevice.Enabled {
		cliConf := autodeviceUps[netip.Prefix{}]
		if cliConf == nil {
			cliConf = client.AutodeviceClientConfig{}
			autodeviceUps[netip.Prefix{}] = cliConf
		}

		var upsTmpl *url.URL
		upsTmpl, err = url.Parse(c.Address)
		if err != nil {
			return fmt.Errorf("address: %w", err)
		}

		cliConf[""] = &client.AutodeviceUpstreamConfig{
			UpstreamTemplate: upsTmpl,
			DeviceType:       client.DeviceType(c.Autodevice.DeviceType),
			ProfileID:        client.ProfileID(c.Autodevice.ProfileID),
			Options:          opts,
		}
	}

	u, err := upstream.AddressToUpstream(c.Address, opts)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	generalUps.Upstreams = append(generalUps.Upstreams, u)

	return nil
}

// addPrivateGroup adds the upstreams from c to privateUps.  privateUps must not
// be nil.
func (c *upstreamGroupConfig) addPrivateGroup(
	privateUps *proxy.UpstreamConfig,
	opts *upstream.Options,
) (err error) {
	u, err := upstream.AddressToUpstream(c.Address, opts)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	privateUps.Upstreams = append(privateUps.Upstreams, u)

	return nil
}

// addAutodeviceGroup adds the upstreams from c to autodeviceUps.  autodeviceUps
// must not be nil.
func (c *upstreamGroupConfig) addAutodeviceGroup(
	autodeviceUps autodeviceClients,
	opts *upstream.Options,
) (err error) {
	var upsTmpl *url.URL
	upsTmpl, err = url.Parse(c.Address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}

	for i, m := range c.Match {
		pref := m.Client.Prefix

		cliConf := autodeviceUps[pref]
		if cliConf == nil {
			cliConf = client.AutodeviceClientConfig{}
			autodeviceUps[pref] = cliConf
		}

		domain := strings.ToLower(m.QuestionDomain)
		_, ok := cliConf[domain]
		if ok {
			const errFmt = "match: at index %d: for client %q and domain %q: %w"

			return fmt.Errorf(errFmt, i, m.Client.Prefix, m.QuestionDomain, errors.ErrDuplicated)
		}

		cliConf[domain] = &client.AutodeviceUpstreamConfig{
			UpstreamTemplate: upsTmpl,
			DeviceType:       client.DeviceType(c.Autodevice.DeviceType),
			ProfileID:        client.ProfileID(c.Autodevice.ProfileID),
			Options:          opts,
		}
	}

	return nil
}

// addCommonGroup adds upstreams configured in c to staticUps.  staticUps must
// not be nil.
func (c *upstreamGroupConfig) addCommonGroup(
	staticUps staticUpstreamConfigs,
	opts *upstream.Options,
) (err error) {
	for i, m := range c.Match {
		var u upstream.Upstream
		u, err = upstream.AddressToUpstream(c.Address, opts)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return fmt.Errorf("match: at index %d: address: %w", i, err)
		}

		cliConf, ok := staticUps[m.Client.Prefix]
		if !ok {
			cliConf = map[string]*proxy.UpstreamConfig{}
			staticUps[m.Client.Prefix] = cliConf
		}

		domain := strings.ToLower(m.QuestionDomain)
		_, ok = cliConf[domain]
		if ok {
			const errFmt = "match: at index %d: for client %q and domain %q: %w"

			return fmt.Errorf(errFmt, i, m.Client.Prefix, m.QuestionDomain, errors.ErrDuplicated)
		}

		cliConf[domain] = &proxy.UpstreamConfig{
			Upstreams: []upstream.Upstream{u},
		}
	}

	return nil
}
