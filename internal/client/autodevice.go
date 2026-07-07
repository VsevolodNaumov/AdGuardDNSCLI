package client

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
)

// Constants for valid encrypted DNS upstream schemes.
const (
	// SchemeHTTPS is the scheme for DNS-over-HTTPS upstreams.
	SchemeHTTPS = urlutil.SchemeHTTPS

	// SchemeQUIC is the scheme for DNS-over-QUIC upstreams.
	SchemeQUIC = "quic"

	// SchemeTLS is the scheme for DNS-over-TLS upstreams.
	SchemeTLS = "tls"
)

// AutodeviceUpstreamConfig defines the configuration for clients that are
// automatically created on demand.
type AutodeviceUpstreamConfig struct {
	// UpstreamTemplate is a template for creating upstream configurations for
	// new clients.  It must be valid and have an encrypted DNS protocol scheme,
	// i.e.:
	//  - [SchemeHTTPS]
	//  - [SchemeQUIC]
	//  - [SchemeTLS]
	UpstreamTemplate *url.URL

	// Options are used to create dynamic upstreams.
	Options *upstream.Options

	// DeviceType specifies the type of device that will be created for new
	// clients.  It must be valid.
	DeviceType DeviceType

	// ProfileID specifies the profile to which new clients will be added.  It
	// must be valid.
	ProfileID ProfileID
}

// upstreamURL returns an upstream upstreamURL for a client with id.  id must be
// valid.
func (c *AutodeviceUpstreamConfig) upstreamURL(id HumanID) (u *url.URL, err error) {
	extID := strings.Join([]string{
		string(c.DeviceType),
		string(c.ProfileID),
		string(id),
	}, "-")

	u = c.UpstreamTemplate

	switch strings.ToLower(u.Scheme) {
	case SchemeHTTPS:
		return u.JoinPath(extID), nil
	case SchemeQUIC, SchemeTLS:
		tmpl := netutil.CloneURL(u)
		tmpl.Host = extID + "." + tmpl.Host

		return tmpl, nil
	default:
		return nil, fmt.Errorf("upstream template: %w: %q", errors.ErrBadEnumValue, u.Scheme)
	}
}

// AutodeviceClientConfig is the mapping of question domains to autodevice
// client configurations.  Its keys, if not empty, must be valid non-FQDNs.  Its
// values must be valid.
type AutodeviceClientConfig map[string]*AutodeviceUpstreamConfig

// toUpstreamConfig converts the *AutodeviceUpstreamConfig into a
// *proxy.UpstreamConfig.  hid must be valid.
func (c *AutodeviceUpstreamConfig) toUpstreamConfig(
	hid HumanID,
	upsCons UpstreamConstructor,
) (uc *proxy.UpstreamConfig, err error) {
	defer func() {
		err = errors.Annotate(err, "client with human id %q: %w", hid)
	}()

	upsURL, err := c.upstreamURL(hid)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	u, err := upsCons.AddressToUpstream(upsURL.String(), c.Options)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{u},
	}, nil
}

// autodeviceClient is a dynamic client configuration matched by subnet.
type autodeviceClient struct {
	upstreams *proxy.CustomUpstreamConfig
}

// newAutodeviceClient creates a new autodevice client with hid and c.  hid must
// be valid, c must not be nil.
func newAutodeviceClient(
	hid HumanID,
	c *AutodeviceUpstreamConfig,
	upsCons UpstreamConstructor,
	cacheEnabled bool,
	cacheSize int,
) (cli *autodeviceClient, err error) {
	upsConf, err := c.toUpstreamConfig(hid, upsCons)
	if err != nil {
		return nil, fmt.Errorf("creating upstream configuration for autodevice client: %w", err)
	}

	return &autodeviceClient{
		upstreams: proxy.NewCustomUpstreamConfig(upsConf, cacheEnabled, cacheSize, false),
	}, nil
}

// type check
var _ Client = (*autodeviceClient)(nil)

// Upstreams implements the [Client] interface for *autodeviceClient.
func (c *autodeviceClient) Upstreams() (uc *proxy.CustomUpstreamConfig) {
	return c.upstreams
}

// autodeviceConfig is a complete configuration for an autodevice client under
// specific IP subnet.
type autodeviceConfig struct {
	conf         *AutodeviceUpstreamConfig
	prefix       netip.Prefix
	domain       string
	cacheSize    int
	cacheEnabled bool
}

// compare is a method for sorting autodevice configurations by prefix and
// domain.  Empty prefix is sorted last, so that it is only used if no other
// configuration matches.  other must not be nil.
func (c *autodeviceConfig) compare(other *autodeviceConfig) (res int) {
	switch {
	case c.prefix == (netip.Prefix{}):
		if other.prefix == (netip.Prefix{}) {
			return compareDomains(c.domain, other.domain)
		}

		return 1
	case other.prefix == (netip.Prefix{}):
		return -1
	default:
		// Go on.
	}

	res = c.prefix.Compare(other.prefix)
	if res == 0 {
		return compareDomains(c.domain, other.domain)
	}

	return res
}

// matches returns true if c matches addr and domain pair.  addr must be valid,
// domain, if not empty, must be a valid non-FQDN.
func (c *autodeviceConfig) matches(addr netip.Addr, domain string) (ok bool) {
	if c.prefix != (netip.Prefix{}) && !c.prefix.Contains(addr) {
		return false
	}

	if !matchesDomain(domain, c.domain) {
		return false
	}

	return true
}
