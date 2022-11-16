package egresseddie

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	// only needed for go:linkname directive
	_ "unsafe"

	"github.com/BurntSushi/toml"
	"golang.org/x/exp/slices"
)

const selfFilterName = "self-filter"

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
	Name              string
	DNSQueue          queue
	TrafficQueue      queue
	AllowAllHostnames bool
	LookupUnknownIPs  bool
	AllowAnswersFor   time.Duration
	ReCacheEvery      time.Duration
	AllowedHostnames  []string
	CachedHostnames   []string
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
		preformReverseLookups bool
		allCachedHostnames    []string

		filterNames  = make(map[string]int)
		filterQueues = make(map[uint16]string)
	)

	for i, filterOpt := range config.Filters {
		if filterOpt.Name == "" {
			return nil, fmt.Errorf(`filter #%d: "name" must be set`, i)
		}

		if !filterOpt.DNSQueue.eitherSet() && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
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
		if filterOpt.DNSQueue.eitherSet() && len(filterOpt.AllowedHostnames) == 0 && (len(filterOpt.CachedHostnames) > 0 || filterOpt.LookupUnknownIPs) {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`, filterOpt.Name)
		}
		if queuesShared(config.InboundDNSQueue, filterOpt.DNSQueue) {
			return nil, fmt.Errorf(`filter %q: "inboundDNSQueue" and "dnsQueue" must be different`, filterOpt.Name)
		}

		if !filterOpt.TrafficQueue.eitherSet() && !filterOpt.AllowAllHostnames {
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
		if filterOpt.TrafficQueue.eitherSet() && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must not be set when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if queuesShared(config.InboundDNSQueue, filterOpt.TrafficQueue) {
			return nil, fmt.Errorf(`filter %q: "inboundDNSQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if queuesShared(filterOpt.DNSQueue, filterOpt.TrafficQueue) {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" and "trafficQueue" must be different`, filterOpt.Name)
		}

		if len(filterOpt.AllowedHostnames) == 0 && !filterOpt.AllowAllHostnames && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
			return nil, fmt.Errorf(`filter %q: "allowedHostnames" must not be empty`, filterOpt.Name)
		}
		if len(filterOpt.AllowedHostnames) > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "allowedHostnames" must be empty when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor == 0 && len(filterOpt.AllowedHostnames) > 0 {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must be set when "allowedHostnames" is not empty`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor != 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must not be set when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if filterOpt.AllowAnswersFor < 0 {
			return nil, fmt.Errorf(`filter %q: "allowAnswersFor" must not be negative`, filterOpt.Name)
		}

		if len(filterOpt.CachedHostnames) > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "cachedHostnames" must be empty when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CachedHostnames) > 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must be set when "cachedHostnames" is not empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery != 0 && len(filterOpt.CachedHostnames) == 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must not be set when "cachedHostnames" is empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery < 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must not be negative`, filterOpt.Name)
		}

		for i, name := range filterOpt.AllowedHostnames {
			if !validDomainName(name) {
				return nil, fmt.Errorf("filter %q: allowed hostname %q is not a valid domain name", filterOpt.Name, name)
			}
			if slices.Contains(filterOpt.CachedHostnames, name) {
				return nil, fmt.Errorf("filter %q: allowed hostname %q is specified as a hostname to be cached as well", filterOpt.Name, name)
			}
			if i != len(filterOpt.AllowedHostnames)-1 && slices.Contains(filterOpt.AllowedHostnames[i+1:], name) {
				return nil, fmt.Errorf("filter %q: allowed hostname %q is specified more than once", filterOpt.Name, name)
			}
		}
		for i, name := range filterOpt.CachedHostnames {
			if !validDomainName(name) {
				return nil, fmt.Errorf("filter %q: hostname to be cached %q is not a valid domain name", filterOpt.Name, name)
			}
			if i != len(filterOpt.CachedHostnames)-1 && slices.Contains(filterOpt.CachedHostnames[i+1:], name) {
				return nil, fmt.Errorf("filter %q: hostname to be cached %q is specified more than once", filterOpt.Name, name)
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

		if filterOpt.LookupUnknownIPs {
			preformReverseLookups = true
		}
		if len(filterOpt.CachedHostnames) > 0 {
			allCachedHostnames = append(allCachedHostnames, filterOpt.CachedHostnames...)
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

	if !config.SelfDNSQueue.eitherSet() && (preformReverseLookups || len(allCachedHostnames) > 0) {
		return nil, errors.New(`"selfDNSQueue" must be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
	}
	if config.SelfDNSQueue.eitherSet() && !preformReverseLookups && len(allCachedHostnames) == 0 {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
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

		if preformReverseLookups {
			selfFilter.AllowedHostnames = []string{
				"in-addr.arpa",
				"ip6.arpa",
			}
		}
		if len(allCachedHostnames) > 0 {
			selfFilter.AllowedHostnames = append(selfFilter.AllowedHostnames, allCachedHostnames...)
		}

		config.Filters = append([]FilterOptions{selfFilter}, config.Filters...)
	}

	return &config, nil
}

func validDomainName(dn string) bool {
	if !isDomainName(dn) {
		return false
	}
	// A domain name ending with a dot is technically allowed (I think),
	// but because seemingly all DNS clients chop off the trailing dot
	// when making DNS requests, Egress Eddie can't properly validate
	// these domains. For simplicity, don't allow them.
	if dn[len(dn)-1] == '.' {
		return false
	}

	return true
}

//go:linkname isDomainName net.isDomainName
func isDomainName(s string) bool
