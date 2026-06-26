package egresseddie

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/capnspacehook/glob"
	"github.com/capnspacehook/glob/syntax/lexer"
)

const (
	selfFilterName = "self-filter"

	globTokens = `*?[]{}\`
)

type queue struct {
	IPv4 uint16
	IPv6 uint16
}

func (q queue) valid() bool {
	if !q.eitherSet() {
		return true
	}

	return q.IPv4 != q.IPv6
}

func (q queue) eitherSet() bool {
	return q.IPv4 != 0 || q.IPv6 != 0
}

func (q queue) bothSet() bool {
	return q.IPv4 != 0 && q.IPv6 != 0
}

func queuesShared(q1, q2 queue) bool {
	if q1.IPv4 != 0 && q2.IPv4 != 0 && q1.IPv4 == q2.IPv4 {
		return true
	}
	if q1.IPv6 != 0 && q2.IPv6 != 0 && q1.IPv6 == q2.IPv6 {
		return true
	}

	if q1.IPv4 != 0 && q2.IPv6 != 0 && q1.IPv4 == q2.IPv6 {
		return true
	}
	if q1.IPv6 != 0 && q2.IPv4 != 0 && q1.IPv6 == q2.IPv4 {
		return true
	}

	return false
}

type Config struct {
	InboundDNSQueue queue
	SelfDNSQueue    queue
	Filters         []FilterOptions

	enforcerCreator enforcerCreator
	resolver        resolver
}

type FilterOptions struct {
	Name            string
	DNSQueue        queue
	TrafficQueue    queue
	AllowAllDomains bool
	AllowAnswersFor time.Duration
	ReCacheEvery    time.Duration
	AllowedDomains  []string
	CachedDomains   []string

	allowedDomainMatchers []glob.Glob
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

	if len(config.Filters) == 0 {
		return nil, errors.New("at least one filter must be specified")
	}
	if !config.InboundDNSQueue.eitherSet() {
		return nil, errors.New(`"inboundDNSQueue" must be set`)
	}
	if !config.InboundDNSQueue.valid() {
		return nil, errors.New(`"inboundDNSQueue.ipv4" and "inboundDNSQueue.ipv6" cannot be the same`)
	}

	ipv4Used := config.InboundDNSQueue.IPv4 != 0
	ipv6Used := config.InboundDNSQueue.IPv6 != 0

	var (
		allCachedDomains []string
		filterNames      = make(map[string]int)
		filterQueues     = make(map[uint16]string)
	)

	for i, filterOpt := range config.Filters {
		if filterOpt.Name == "" {
			return nil, fmt.Errorf(`filter #%d: "name" must be set`, i)
		}

		if !filterOpt.DNSQueue.eitherSet() && len(filterOpt.CachedDomains) == 0 {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must be set`, filterOpt.Name)
		}
		if !filterOpt.DNSQueue.valid() {
			return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv4" and "dnsQueue.ipv6" cannot be the same`, filterOpt.Name)
		}
		if ipv4Used && filterOpt.DNSQueue.eitherSet() && filterOpt.DNSQueue.IPv4 == 0 {
			return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`, filterOpt.Name)
		}
		if !ipv4Used && filterOpt.DNSQueue.bothSet() {
			return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`, filterOpt.Name)
		}
		if ipv6Used && filterOpt.DNSQueue.eitherSet() && filterOpt.DNSQueue.IPv6 == 0 {
			return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`, filterOpt.Name)
		}
		if !ipv6Used && filterOpt.DNSQueue.bothSet() {
			return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`, filterOpt.Name)
		}
		if filterOpt.DNSQueue.eitherSet() && len(filterOpt.AllowedDomains) == 0 && len(filterOpt.CachedDomains) > 0 {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must not be set when "allowedDomains" is empty and "cachedHostames" is not empty`, filterOpt.Name)
		}
		if queuesShared(config.InboundDNSQueue, filterOpt.DNSQueue) {
			return nil, fmt.Errorf(`filter %q: "inboundDNSQueue" and "dnsQueue" must be different`, filterOpt.Name)
		}

		if !filterOpt.TrafficQueue.eitherSet() && !filterOpt.AllowAllDomains {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must be set`, filterOpt.Name)
		}
		if !filterOpt.TrafficQueue.valid() {
			return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv4" and "trafficQueue.ipv6" cannot be the same`, filterOpt.Name)
		}
		if ipv4Used && filterOpt.TrafficQueue.eitherSet() && filterOpt.TrafficQueue.IPv4 == 0 {
			return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`, filterOpt.Name)
		}
		if !ipv4Used && filterOpt.TrafficQueue.bothSet() {
			return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`, filterOpt.Name)
		}
		if ipv6Used && filterOpt.TrafficQueue.eitherSet() && filterOpt.TrafficQueue.IPv6 == 0 {
			return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`, filterOpt.Name)
		}
		if !ipv6Used && filterOpt.TrafficQueue.bothSet() {
			return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`, filterOpt.Name)
		}
		if filterOpt.TrafficQueue.eitherSet() && filterOpt.AllowAllDomains {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must not be set when "allowAllDomains" is true`, filterOpt.Name)
		}
		if queuesShared(config.InboundDNSQueue, filterOpt.TrafficQueue) {
			return nil, fmt.Errorf(`filter %q: "inboundDNSQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if queuesShared(filterOpt.DNSQueue, filterOpt.TrafficQueue) {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if len(filterOpt.AllowedDomains) == 0 && !filterOpt.AllowAllDomains && len(filterOpt.CachedDomains) == 0 {
			return nil, fmt.Errorf(`filter %q: "allowedDomains" must not be empty`, filterOpt.Name)
		}
		if len(filterOpt.AllowedDomains) > 0 && filterOpt.AllowAllDomains {
			return nil, fmt.Errorf(`filter %q: "allowedDomains" must be empty when "allowAllDomains" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor == 0 && len(filterOpt.AllowedDomains) > 0 {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must be set when "allowedDomains" is not empty`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor != 0 && filterOpt.AllowAllDomains {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must not be set when "allowAllDomains" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor < 0 {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must not be negative`, filterOpt.Name)
		}

		if len(filterOpt.CachedDomains) > 0 && filterOpt.AllowAllDomains {
			return nil, fmt.Errorf(`filter %q: "cachedDomains" must be empty when "allowAllDomains" is true`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CachedDomains) > 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must be set when "cachedDomains" is not empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery != 0 && len(filterOpt.CachedDomains) == 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must not be set when "cachedDomains" is empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery < 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must not be negative`, filterOpt.Name)
		}

		for j, name := range filterOpt.AllowedDomains {
			isPattern := strings.ContainsAny(name, globTokens)
			if !isPattern {
				if err := validDomainName(name); err != nil {
					return nil, fmt.Errorf("filter %q: allowed domain name %q is invalid: %w", filterOpt.Name, name, err)
				}
			}

			g, err := createDomainMatcher(name)
			if err != nil {
				return nil, fmt.Errorf("filter %q: compiling allowed domain name pattern %q: %w", filterOpt.Name, name, err)
			}
			config.Filters[i].allowedDomainMatchers = append(config.Filters[i].allowedDomainMatchers, g)

			if slices.Contains(filterOpt.CachedDomains, name) {
				return nil, fmt.Errorf("filter %q: allowed domain name %q is specified as a domain name to be cached as well", filterOpt.Name, name)
			}
			if j != len(filterOpt.AllowedDomains)-1 && slices.Contains(filterOpt.AllowedDomains[j+1:], name) {
				return nil, fmt.Errorf("filter %q: allowed domain name %q is specified more than once", filterOpt.Name, name)
			}
		}

		for j, name := range filterOpt.CachedDomains {
			isPattern := strings.ContainsAny(name, globTokens)
			if isPattern {
				return nil, fmt.Errorf("filter %q: domain name to be cached %q is a glob pattern", filterOpt.Name, name)
			}

			if err := validDomainName(name); err != nil {
				return nil, fmt.Errorf("filter %q: domain name to be cached %q is invalid: %w", filterOpt.Name, name, err)
			}
			if j != len(filterOpt.CachedDomains)-1 && slices.Contains(filterOpt.CachedDomains[j+1:], name) {
				return nil, fmt.Errorf("filter %q: domain name to be cached %q is specified more than once", filterOpt.Name, name)
			}
		}

		if idx, ok := filterNames[filterOpt.Name]; ok {
			return nil, fmt.Errorf(`filter #%d: filter name %q is already used by filter #%d`, i, filterOpt.Name, idx)
		}
		if filterOpt.DNSQueue.IPv4 != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue.IPv4]; ok {
				return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv4" %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue.IPv4, name)
			}
		}
		if filterOpt.DNSQueue.IPv6 != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue.IPv6]; ok {
				return nil, fmt.Errorf(`filter %q: "dnsQueue.ipv6" %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue.IPv6, name)
			}
		}
		if filterOpt.TrafficQueue.IPv4 != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue.IPv4]; ok {
				return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv4" %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue.IPv4, name)
			}
		}
		if filterOpt.TrafficQueue.IPv6 != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue.IPv6]; ok {
				return nil, fmt.Errorf(`filter %q: "trafficQueue.ipv6" %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue.IPv6, name)
			}
		}

		if len(filterOpt.CachedDomains) > 0 {
			allCachedDomains = append(allCachedDomains, filterOpt.CachedDomains...)
		}

		filterNames[filterOpt.Name] = i
		if filterOpt.DNSQueue.IPv4 != 0 {
			filterQueues[filterOpt.DNSQueue.IPv4] = filterOpt.Name
		}
		if filterOpt.DNSQueue.IPv6 != 0 {
			filterQueues[filterOpt.DNSQueue.IPv6] = filterOpt.Name
		}
		if filterOpt.TrafficQueue.IPv4 != 0 {
			filterQueues[filterOpt.TrafficQueue.IPv4] = filterOpt.Name
		}
		if filterOpt.TrafficQueue.IPv6 != 0 {
			filterQueues[filterOpt.TrafficQueue.IPv6] = filterOpt.Name
		}
	}

	if !config.SelfDNSQueue.eitherSet() && len(allCachedDomains) > 0 {
		return nil, errors.New(`"selfDNSQueue" must be set when at least one filter has a non-empty "cachedDomains"`)
	}
	if config.SelfDNSQueue.eitherSet() && len(allCachedDomains) == 0 {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter has a non-empty "cachedDomains"`)
	}
	if !config.SelfDNSQueue.valid() {
		return nil, errors.New(`"selfDNSQueue.ipv4" and "selfDNSQueue.ipv6" cannot be the same`)
	}
	if ipv4Used && config.SelfDNSQueue.eitherSet() && config.SelfDNSQueue.IPv4 == 0 {
		return nil, errors.New(`"selfDNSQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`)
	}
	if !ipv4Used && config.SelfDNSQueue.bothSet() {
		return nil, errors.New(`"selfDNSQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`)
	}
	if ipv6Used && config.SelfDNSQueue.eitherSet() && config.SelfDNSQueue.IPv6 == 0 {
		return nil, errors.New(`"selfDNSQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`)
	}
	if !ipv6Used && config.SelfDNSQueue.bothSet() {
		return nil, errors.New(`"selfDNSQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`)
	}

	if queuesShared(config.InboundDNSQueue, config.SelfDNSQueue) {
		return nil, errors.New(`"inboundDNSQueue" and "selfDNSQueue" must be different`)
	}
	for _, filter := range config.Filters {
		if queuesShared(config.SelfDNSQueue, filter.DNSQueue) {
			return nil, fmt.Errorf(`filter %q: "selfDNSQueue" and "dnsQueue" must be different`, filter.Name)
		}
		if queuesShared(config.SelfDNSQueue, filter.TrafficQueue) {
			return nil, fmt.Errorf(`filter %q: "selfDNSQueue" and "trafficQueue" must be different`, filter.Name)
		}
	}

	// if 'selfDNSQueue' is specified, create a filter that will allow
	// Egress Eddie to only make required DNS queries
	if config.SelfDNSQueue.eitherSet() {
		selfFilter := FilterOptions{
			Name:     selfFilterName,
			DNSQueue: config.SelfDNSQueue,
		}

		for _, name := range allCachedDomains {
			m, err := createDomainMatcher(name)
			if err != nil {
				return nil, fmt.Errorf("compiling domain name to be cached pattern %q: %w", name, err)
			}

			selfFilter.allowedDomainMatchers = append(selfFilter.allowedDomainMatchers, m)
		}

		if len(allCachedDomains) > 0 {
			selfFilter.AllowedDomains = append(selfFilter.AllowedDomains, allCachedDomains...)
		}

		config.Filters = append([]FilterOptions{selfFilter}, config.Filters...)
	}

	return &config, nil
}

func createDomainMatcher(name string) (glob.Glob, error) {
	// lowercase text portions of the pattern so we can match it
	// case-insensitively later
	lowerName, err := lowercasePattern(name)
	if err != nil {
		return nil, err
	}

	return glob.Compile(lowerName, '.')
}

// TODO: document that character class chars will be lowercased but
// ranges won't be
func lowercasePattern(name string) (string, error) {
	if name == "" {
		return "", errors.New("domain name is empty")
	}

	l := lexer.NewLexer(name)

	var lowerName string
	for {
		token := l.Next()
		switch token.Type {
		case lexer.EOF:
			return lowerName, nil
		case lexer.Error:
			return "", errors.New(token.Raw)
		case lexer.Text:
			for _, r := range token.Raw {
				if !validDomainRune(r) {
					return "", fmt.Errorf("domain name contains illegal character %c", r)
				}
			}

			lowerName += strings.ToLower(token.Raw)
		default:
			lowerName += token.Raw
		}
	}
}

func validDomainName(dn string) error {
	if dn == "" {
		return errors.New("domain name is empty")
	} else if len(dn) > 255 {
		return errors.New("domain name exceeds 255 characters")
	}

	if dn[0] == '.' {
		return errors.New("domain name starts with a dot")
	}

	labelLen := 0
	lastRune := rune(-1)
	for _, r := range dn {
		labelLen++

		if labelLen == 1 && r == '-' {
			return errors.New("domain name label starts with a dash")
		}

		if r == '.' {
			if labelLen > 63 {
				return errors.New("domain name label exceeds 63 characters")
			} else if lastRune == '-' {
				return errors.New("domain name label ends with a dash")
			}

			labelLen = 0
		} else if !validDomainRune(r) {
			return fmt.Errorf("domain name contains illegal character %c", r)
		}

		lastRune = r
	}

	return nil
}

func validDomainRune(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
		return true
	}
	return false
}
