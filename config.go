package egresseddie

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/capnspacehook/glob"
	"github.com/capnspacehook/glob/syntax/lexer"

	"github.com/capnspacehook/egress-eddie/resolve"
)

const (
	selfFilterName = "self-filter"

	globTokens = `*?[]{}\`
)

type Config struct {
	DNSResponseQueue uint16
	SelfDNSQueue     uint16
	ResolverIP       string
	ResolveWithDoH   bool
	// TODO: require an IP or resolve host before filters start?
	DoHURL        string
	DoHServerName string
	Filters       []FilterOptions

	enforcerCreator enforcerCreator
	sender          resolve.DNSSender
	injector        resolve.DNSInjector
}

type FilterOptions struct {
	Name            string
	DNSQueue        uint16
	TrafficQueue    uint16
	AllowAllDomains bool
	AllowAnswersFor time.Duration
	ReCacheEvery    time.Duration

	AllowedDomains []string
	AllowedTargets []string
	CachedDomains  []string
	CachedTargets  []string

	AllowedAnswerCIDRs    []netip.Prefix
	DisallowedAnswerCIDRs []netip.Prefix

	allowedDomainMatchers []glob.Glob
	allowedTargetMatchers []glob.Glob
}

func ParseConfig(confPath string) (*Config, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}

	return parseConfigBytes(data)
}

func parseConfigBytes(cb []byte) (*Config, error) {
	var config Config

	md, err := toml.Decode(string(cb), &config)
	if err != nil {
		return nil, err
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		var sb strings.Builder
		sb.WriteString("unknown keys ")
		for i, key := range undec {
			sb.WriteString(strconv.Quote(key.String()))
			if i != len(undec)-1 {
				sb.WriteString(", ")
			}
		}

		return nil, errors.New(sb.String())
	}

	if err := checkConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func checkConfig(config *Config) error {
	// check global options
	if len(config.Filters) == 0 {
		return errors.New("at least one filter must be specified")
	}
	if config.DNSResponseQueue == 0 {
		return errors.New(`"dnsResponseQueue" must be set`)
	}

	if !config.ResolveWithDoH {
		if config.ResolverIP != "" {
			if _, err := netip.ParseAddr(config.ResolverIP); err != nil {
				return fmt.Errorf(`parsing "resolverIP" %q: %w`, config.ResolverIP, err)
			}
		}

		if config.DoHURL != "" {
			return errors.New(`"resolveWithDoH" must be set when "dohURL" is set`)
		} else if config.DoHServerName != "" {
			return errors.New(`"resolveWithDoH" must be set when "dohServerName" is set`)
		}
	} else {
		if config.ResolverIP != "" {
			return errors.New(`"resolverIP" must not be set when "resolveWithDoH" is set`)
		}

		if config.DoHURL == "" {
			return errors.New(`"dohURL" must be set when "resolveWithDoH" is set`)
		}
		dohURL, err := url.Parse(config.DoHURL)
		if err != nil {
			return fmt.Errorf("parsing DoH URL %q: %w", config.DoHURL, err)
		}
		if dohURL.Scheme != "https" {
			return fmt.Errorf(`DoH URL %q must use scheme "https"`, config.DoHURL)
		}
		if dohURL.Host == "" {
			return fmt.Errorf(`DoH URL %q must have a host`, config.DoHURL)
		}
		if dohURL.Path != "" {
			return fmt.Errorf(`DoH URL %q must not have a path`, config.DoHURL)
		}
	}

	var (
		allCachedDomains []string
		allCachedTargets []string
		filterNames      = make(map[string]int)
		filterQueues     = make(map[uint16]string)
	)

	// check individual filter options
	for i, filterOpt := range config.Filters {
		if filterOpt.Name == "" {
			return fmt.Errorf(`filter #%d: "name" must be set`, i)
		}
		if filterOpt.Name == selfFilterName {
			return fmt.Errorf("filter #%d: filter name %q is reserved and must not be used", i, selfFilterName)
		}

		if filterOpt.DNSQueue == 0 && len(filterOpt.CachedDomains) == 0 {
			return fmt.Errorf(`filter %q: "dnsQueue" must be set`, filterOpt.Name)
		}
		if filterOpt.DNSQueue != 0 && len(filterOpt.AllowedDomains) == 0 && len(filterOpt.CachedDomains) > 0 {
			return fmt.Errorf(`filter %q: "dnsQueue" must not be set when "allowedDomains" is empty and "cachedDomains" is not empty`, filterOpt.Name)
		}
		if config.DNSResponseQueue == filterOpt.DNSQueue {
			return fmt.Errorf(`filter %q: "dnsResponseQueue" and "dnsQueue" must be different`, filterOpt.Name)
		}

		if filterOpt.TrafficQueue == 0 {
			return fmt.Errorf(`filter %q: "trafficQueue" must be set`, filterOpt.Name)
		}
		if config.DNSResponseQueue == filterOpt.TrafficQueue {
			return fmt.Errorf(`filter %q: "dnsResponseQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if filterOpt.DNSQueue != 0 && filterOpt.TrafficQueue != 0 && filterOpt.DNSQueue == filterOpt.TrafficQueue {
			return fmt.Errorf(`filter %q: "dnsQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if len(filterOpt.AllowedDomains) == 0 && !filterOpt.AllowAllDomains && len(filterOpt.CachedDomains) == 0 {
			return fmt.Errorf(`filter %q: "allowedDomains" must not be empty`, filterOpt.Name)
		}
		if len(filterOpt.AllowedDomains) > 0 && filterOpt.AllowAllDomains {
			return fmt.Errorf(`filter %q: "allowedDomains" must be empty when "allowAllDomains" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor == 0 && len(filterOpt.AllowedDomains) > 0 {
			return fmt.Errorf(`filter %q: "allowAnswersFor" must be set when "allowedDomains" is not empty`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor == 0 && filterOpt.AllowAllDomains {
			return fmt.Errorf(`filter %q: "allowAnswersFor" must be set when "allowAllDomains" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor < 0 {
			return fmt.Errorf(`filter %q: "allowAnswersFor" must not be negative`, filterOpt.Name)
		}

		// TODO: this might be a valid config
		if len(filterOpt.CachedDomains) > 0 && filterOpt.AllowAllDomains {
			return fmt.Errorf(`filter %q: "cachedDomains" must be empty when "allowAllDomains" is true`, filterOpt.Name)
		}
		if len(filterOpt.CachedTargets) > 0 && filterOpt.AllowAllDomains {
			return fmt.Errorf(`filter %q: "cachedTargets" must be empty when "allowAllDomains" is true`, filterOpt.Name)
		}

		if len(filterOpt.CachedTargets) > 0 && len(filterOpt.CachedDomains) == 0 {
			return fmt.Errorf(`filter %q: "cachedTargets" must be empty when "cachedDomains" is empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CachedDomains) > 0 {
			return fmt.Errorf(`filter %q: "reCacheEvery" must be set when "cachedDomains" is not empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery != 0 && len(filterOpt.CachedDomains) == 0 {
			return fmt.Errorf(`filter %q: "reCacheEvery" must not be set when "cachedDomains" is empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery < 0 {
			return fmt.Errorf(`filter %q: "reCacheEvery" must not be negative`, filterOpt.Name)
		}

		for j, name := range filterOpt.AllowedDomains {
			isPattern := strings.ContainsAny(name, globTokens)
			if !isPattern {
				if err := validLowerDomainName(name); err != nil {
					return fmt.Errorf("filter %q: allowed domain name %q is invalid: domain name %w", filterOpt.Name, name, err)
				}
			}

			g, err := createDomainMatcher(name)
			if err != nil {
				return fmt.Errorf("filter %q: compiling allowed domain name pattern %q: %w", filterOpt.Name, name, err)
			}
			config.Filters[i].allowedDomainMatchers = append(config.Filters[i].allowedDomainMatchers, g)

			if slices.Contains(filterOpt.CachedDomains, name) {
				return fmt.Errorf("filter %q: allowed domain name %q is specified as a domain name to be cached as well", filterOpt.Name, name)
			}
			if containsAfter(filterOpt.AllowedDomains, name, j) {
				return fmt.Errorf("filter %q: allowed domain name %q is specified more than once", filterOpt.Name, name)
			}
		}

		for j, name := range filterOpt.AllowedTargets {
			isPattern := strings.ContainsAny(name, globTokens)
			if !isPattern {
				if err := validLowerDomainName(name); err != nil {
					return fmt.Errorf("filter %q: allowed target name %q is invalid: domain name %w", filterOpt.Name, name, err)
				}
			}

			g, err := createDomainMatcher(name)
			if err != nil {
				return fmt.Errorf("filter %q: compiling allowed target name pattern %q: %w", filterOpt.Name, name, err)
			}
			config.Filters[i].allowedTargetMatchers = append(config.Filters[i].allowedTargetMatchers, g)

			if slices.Contains(filterOpt.AllowedDomains, name) {
				return fmt.Errorf("filter %q: allowed target name %q is specified as an allowed domain name as well", filterOpt.Name, name)
			}
			if slices.Contains(filterOpt.CachedDomains, name) {
				return fmt.Errorf("filter %q: allowed target name %q is specified as a domain name to be cached as well", filterOpt.Name, name)
			}
			if slices.Contains(filterOpt.CachedTargets, name) {
				return fmt.Errorf("filter %q: allowed target name %q is specified as a target name to be cached as well", filterOpt.Name, name)
			}
			if containsAfter(filterOpt.AllowedTargets, name, j) {
				return fmt.Errorf("filter %q: allowed target name %q is specified more than once", filterOpt.Name, name)
			}
		}

		for j, name := range filterOpt.CachedDomains {
			isPattern := strings.ContainsAny(name, globTokens)
			if isPattern {
				return fmt.Errorf("filter %q: domain name to be cached %q is a glob pattern, domain names to be cached must be exact domain names only", filterOpt.Name, name)
			}

			if err := validLowerDomainName(name); err != nil {
				return fmt.Errorf("filter %q: domain name to be cached %q is invalid: domain name %w", filterOpt.Name, name, err)
			}
			if containsAfter(filterOpt.CachedDomains, name, j) {
				return fmt.Errorf("filter %q: domain name to be cached %q is specified more than once", filterOpt.Name, name)
			}
		}

		for j, name := range filterOpt.CachedTargets {
			isPattern := strings.ContainsAny(name, globTokens)
			if !isPattern {
				if err := validLowerDomainName(name); err != nil {
					return fmt.Errorf("filter %q: target name to be cached %q is invalid: domain name %w", filterOpt.Name, name, err)
				}
			}

			if _, err := createDomainMatcher(name); err != nil {
				return fmt.Errorf("filter %q: compiling target name to be cached pattern %q: %w", filterOpt.Name, name, err)
			}

			if containsAfter(filterOpt.CachedTargets, name, j) {
				return fmt.Errorf("filter %q: target name to be cached %q is specified more than once", filterOpt.Name, name)
			}
		}

		for j, cidr := range filterOpt.AllowedAnswerCIDRs {
			if containsAfter(filterOpt.AllowedAnswerCIDRs, cidr, j) {
				return fmt.Errorf("filter %q: allowed answer CIDR %s is specified more than once", filterOpt.Name, cidr)
			}
		}
		for j, cidr := range filterOpt.DisallowedAnswerCIDRs {
			for _, allowedCIDR := range filterOpt.AllowedAnswerCIDRs {
				if allowedCIDR == cidr {
					return fmt.Errorf("filter %q: allowed and disallowed answer CIDRs %s are the same", filterOpt.Name, cidr)
				}
				if allowedCIDR.Contains(cidr.Addr()) {
					return fmt.Errorf("filter %q: disallowed answer CIDR %s overlaps with allowed answer CIDR %s", filterOpt.Name, cidr, allowedCIDR)
				}
			}

			if containsAfter(filterOpt.DisallowedAnswerCIDRs, cidr, j) {
				return fmt.Errorf("filter %q: disallowed answer CIDR %s is specified more than once", filterOpt.Name, cidr)
			}
		}

		if idx, ok := filterNames[filterOpt.Name]; ok {
			return fmt.Errorf(`filter #%d: filter name %q is already used by filter #%d`, i, filterOpt.Name, idx)
		}
		if filterOpt.DNSQueue != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue]; ok {
				return fmt.Errorf(`filter %q: "dnsQueue" %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue, name)
			}
		}
		if filterOpt.TrafficQueue != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue]; ok {
				return fmt.Errorf(`filter %q: "trafficQueue" %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue, name)
			}
		}

		if len(filterOpt.CachedDomains) > 0 {
			allCachedDomains = append(allCachedDomains, filterOpt.CachedDomains...)
		}
		if len(filterOpt.CachedTargets) > 0 {
			allCachedTargets = append(allCachedTargets, filterOpt.CachedTargets...)
		}

		filterNames[filterOpt.Name] = i
		if filterOpt.DNSQueue != 0 {
			filterQueues[filterOpt.DNSQueue] = filterOpt.Name
		}
		if filterOpt.TrafficQueue != 0 {
			filterQueues[filterOpt.TrafficQueue] = filterOpt.Name
		}
	}

	if config.SelfDNSQueue == 0 && len(allCachedDomains) > 0 {
		return errors.New(`"selfDNSQueue" must be set when at least one filter has a non-empty "cachedDomains"`)
	}
	if config.SelfDNSQueue != 0 && len(allCachedDomains) == 0 {
		return errors.New(`"selfDNSQueue" must only be set when at least one filter has a non-empty "cachedDomains"`)
	}

	if config.DNSResponseQueue == config.SelfDNSQueue {
		return errors.New(`"dnsResponseQueue" and "selfDNSQueue" must be different`)
	}
	for _, filter := range config.Filters {
		if config.SelfDNSQueue != 0 && filter.DNSQueue != 0 && config.SelfDNSQueue == filter.DNSQueue {
			return fmt.Errorf(`filter %q: "selfDNSQueue" and "dnsQueue" must be different`, filter.Name)
		}
		if config.SelfDNSQueue != 0 && filter.TrafficQueue != 0 && config.SelfDNSQueue == filter.TrafficQueue {
			return fmt.Errorf(`filter %q: "selfDNSQueue" and "trafficQueue" must be different`, filter.Name)
		}
	}

	// if 'selfDNSQueue' is specified, create a filter that will allow
	// Egress Eddie to only make required DNS queries
	if config.SelfDNSQueue != 0 {
		selfFilter := FilterOptions{
			Name:     selfFilterName,
			DNSQueue: config.SelfDNSQueue,
		}

		if len(allCachedDomains) > 0 {
			// this has no bearing on filtering logic, it's just so the
			// config tests can assert the self-filter is build properly
			selfFilter.AllowedDomains = allCachedDomains

			selfFilter.allowedDomainMatchers = make([]glob.Glob, len(allCachedDomains))
			for i, name := range allCachedDomains {
				m, err := createDomainMatcher(name)
				if err != nil {
					return fmt.Errorf("compiling domain name to be cached pattern %q: %w", name, err)
				}

				selfFilter.allowedDomainMatchers[i] = m
			}

		}
		if len(allCachedTargets) > 0 {
			// this has no bearing on filtering logic, it's just so the
			// config tests can assert the self-filter is build properly
			selfFilter.AllowedTargets = allCachedTargets

			selfFilter.allowedTargetMatchers = make([]glob.Glob, len(allCachedTargets))
			for i, name := range allCachedTargets {
				m, err := createDomainMatcher(name)
				if err != nil {
					return fmt.Errorf("compiling target name to be cached pattern %q: %w", name, err)
				}

				selfFilter.allowedTargetMatchers[i] = m
			}
		}

		config.Filters = append([]FilterOptions{selfFilter}, config.Filters...)
	}

	return nil
}

func createDomainMatcher(name string) (glob.Glob, error) {
	// enforce that the pattern contains no uppercase characters to make
	// domain matching case-insensitive later and to prevent surprising
	// behavior if instead the pattern was silently lowercased instead
	if err := checkPattern(name); err != nil {
		return nil, err
	}

	return glob.Compile(name, '.')
}

func checkPattern(pattern string) error {
	if pattern == "" {
		return errors.New("pattern is empty")
	}
	if pattern[len(pattern)-1] == '.' {
		return errors.New("pattern ends with a dot; fully qualified domain names are never given to glob matchers so this pattern will never match anything")
	}

	l := lexer.NewLexer(pattern)
	for {
		token := l.Next()
		switch token.Type {
		case lexer.EOF:
			return nil
		case lexer.Error:
			return errors.New(token.Raw)
		case lexer.RangeLow:
			fallthrough
		case lexer.RangeHigh:
			fallthrough
		case lexer.Text:
			for _, r := range token.Raw {
				if r >= 'A' && r <= 'Z' {
					return fmt.Errorf("pattern contains uppercase character %c, only lowercase characters are allowed in patterns to allow for case-insensitive matching", r)
				}
				if !validDomainRune(r) {
					return fmt.Errorf("pattern contains illegal character %c", r)
				}
			}
		default:
			// ignore other token types
		}
	}
}

// checkPattern will return an error if any uppercase characters are
// found but this allows us to have less confusing error messages
// without mentioning a pattern
func validLowerDomainName(dn string) error {
	if err := validDomainName(dn); err != nil {
		return err
	}

	if dn[len(dn)-1] == '.' {
		return errors.New("domain name ends with a dot; fully qualified domain names are not allowed")
	}
	if strings.ToLower(dn) != dn {
		return errors.New("contains uppercase characters, only lowercase characters are allowed in patterns to allow for case-insensitive matching")
	}

	return nil
}

func validDomainName(dn string) error {
	if dn == "" {
		return errors.New("is empty")
	} else if len(dn) > 255 {
		return errors.New("exceeds 255 characters")
	}

	if dn[0] == '.' {
		return errors.New("starts with a dot")
	}

	labelLen := 0
	lastRune := rune(-1)
	for _, r := range dn {
		labelLen++

		if labelLen == 1 && r == '-' {
			return errors.New("label starts with a dash")
		}

		if r == '.' {
			if labelLen-1 > 63 {
				return errors.New("label exceeds 63 characters")
			} else if lastRune == '-' {
				return errors.New("label ends with a dash")
			} else if labelLen == 1 && lastRune == '.' {
				return errors.New("label is empty")
			}

			labelLen = 0
		} else if !validDomainRune(r) {
			return fmt.Errorf("contains illegal character %c", r)
		}

		lastRune = r
	}

	if labelLen > 63 {
		return errors.New("label exceeds 63 characters")
	} else if lastRune == '-' {
		return errors.New("label ends with a dash")
	}

	return nil
}

func validDomainRune(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
		return true
	}
	return false
}

func containsAfter[T comparable](s []T, v T, i int) bool {
	if i == len(s)-1 {
		return false
	}
	return slices.Contains(s[i+1:], v)
}
