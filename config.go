package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

const selfFilterName = "self-filter"

type duration time.Duration

func (d *duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = duration(dur)

	return nil
}

type queue struct {
	IPv4 uint16
	IPv6 uint16
}

func (q queue) valid() bool {
	if !q.set() {
		return true
	}

	return q.IPv4 != q.IPv6
}

func (q queue) set() bool {
	return q.IPv4 != 0 || q.IPv6 != 0
}

func queuesShared(q1, q2 queue) bool {
	if q1.IPv4 != 0 && q2.IPv4 != 0 && q1.IPv4 == q2.IPv4 {
		return true
	}
	if q1.IPv6 != 0 && q2.IPv6 != 0 && q1.IPv6 == q2.IPv6 {
		return true
	}

	return false
}

type Config struct {
	InboundDNSQueue queue
	SelfDNSQueue    queue
	Filters         []FilterOptions
}

type FilterOptions struct {
	Name              string
	DNSQueue          queue
	TrafficQueue      queue
	AllowAllHostnames bool
	LookupUnknownIPs  bool
	AllowAnswersFor   duration
	ReCacheEvery      duration
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

	if err := toml.Unmarshal(cb, &config); err != nil {
		return nil, err
	}

	if len(config.Filters) == 0 {
		return nil, errors.New("at least one filter must be specified")
	}
	if !config.InboundDNSQueue.set() {
		return nil, errors.New(`"inboundDNSQueue" must be set`)
	}

	var (
		preformReverseLookups bool
		allCachedHostnames    []string

		filterNames  = make(map[string]int)
		filterQueues = make(map[uint16]string)
	)
	for i, filterOpt := range config.Filters {
		// TODO: check that dnsQueue and trafficQueue ipv4,ipv6 set consistently
		if filterOpt.Name == "" {
			return nil, fmt.Errorf(`filter #%d: "name" must be set`, i)
		}
		if !filterOpt.DNSQueue.set() && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must be set`, filterOpt.Name)
		}
		if !filterOpt.TrafficQueue.set() && !filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must be set`, filterOpt.Name)
		}
		if filterOpt.TrafficQueue.set() && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must not be set when "allowAllHostnames" is true`, filterOpt.Name)
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
		if len(filterOpt.CachedHostnames) > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "cachedHostnames" must be empty when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CachedHostnames) > 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must be set when "cachedHostnames" is not empty`, filterOpt.Name)
		}
		if filterOpt.ReCacheEvery > 0 && len(filterOpt.CachedHostnames) == 0 {
			return nil, fmt.Errorf(`filter %q: "reCacheEvery" must not be set when "cachedHostnames" is empty`, filterOpt.Name)
		}
		if filterOpt.DNSQueue.set() && len(filterOpt.AllowedHostnames) == 0 && (len(filterOpt.CachedHostnames) > 0 || filterOpt.LookupUnknownIPs) {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`, filterOpt.Name)
		}

		if idx, ok := filterNames[filterOpt.Name]; ok {
			return nil, fmt.Errorf(`filter #%d: filter name %q is already used by filter #%d`, i, filterOpt.Name, idx)
		}
		if filterOpt.DNSQueue.IPv4 != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue.IPv4]; ok {
				return nil, fmt.Errorf(`filter %q: dnsQueue.ipv4 %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue.IPv4, name)
			}
		}
		if filterOpt.DNSQueue.IPv6 != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue.IPv6]; ok {
				return nil, fmt.Errorf(`filter %q: dnsQueue.ipv6 %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue.IPv6, name)
			}
		}
		if filterOpt.TrafficQueue.IPv4 != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue.IPv4]; ok {
				return nil, fmt.Errorf(`filter %q: trafficQueue.ipv4 %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue.IPv4, name)
			}
		}
		if filterOpt.TrafficQueue.IPv6 != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue.IPv6]; ok {
				return nil, fmt.Errorf(`filter %q: trafficQueue.ipv6 %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue.IPv6, name)
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

	if !config.SelfDNSQueue.set() && (preformReverseLookups || len(allCachedHostnames) > 0) {
		return nil, errors.New(`"selfDNSQueue" must be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
	}
	if config.SelfDNSQueue.set() && !preformReverseLookups && len(allCachedHostnames) == 0 {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
	}
	if queuesShared(config.InboundDNSQueue, config.SelfDNSQueue) {
		return nil, errors.New(`"inboundDNSQueue" and "selfDNSQueue" must be different`)
	}

	// if 'selfDNSQueue' is specified, create a filter that will allow
	// Egress Eddie to only make required DNS queries
	if config.SelfDNSQueue.set() {
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
