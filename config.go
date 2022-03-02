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

type Config struct {
	InboundDNSQueue uint16
	SelfDNSQueue    uint16
	IPv6            bool
	Filters         []FilterOptions
}

type FilterOptions struct {
	Name              string
	DNSQueue          uint16 `toml:"dnsQueue"`
	TrafficQueue      uint16
	IPv6              bool
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
	if config.InboundDNSQueue == 0 {
		return nil, errors.New(`"inboundDNSQueue" must be set`)
	}

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
		if filterOpt.DNSQueue == 0 && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must be set`, filterOpt.Name)
		}
		if filterOpt.TrafficQueue == 0 && !filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must be set`, filterOpt.Name)
		}
		if filterOpt.TrafficQueue > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter %q: "trafficQueue" must not be set when "allowAllHostnames" is true`, filterOpt.Name)
		}
		if filterOpt.DNSQueue == filterOpt.TrafficQueue {
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
		if filterOpt.DNSQueue != 0 && len(filterOpt.AllowedHostnames) == 0 && (len(filterOpt.CachedHostnames) > 0 || filterOpt.LookupUnknownIPs) {
			return nil, fmt.Errorf(`filter %q: "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`, filterOpt.Name)
		}

		if idx, ok := filterNames[filterOpt.Name]; ok {
			return nil, fmt.Errorf(`filter #%d: filter name %q is already used by filter #%d`, i, filterOpt.Name, idx)
		}
		if filterOpt.DNSQueue != 0 {
			if name, ok := filterQueues[filterOpt.DNSQueue]; ok {
				return nil, fmt.Errorf(`filter %q: dnsQueue %d is already used by filter %q`, filterOpt.Name, filterOpt.DNSQueue, name)
			}
		}
		if filterOpt.TrafficQueue != 0 {
			if name, ok := filterQueues[filterOpt.TrafficQueue]; ok {
				return nil, fmt.Errorf(`filter %q: trafficQueue %d is already used by filter %q`, filterOpt.Name, filterOpt.TrafficQueue, name)
			}
		}

		if filterOpt.LookupUnknownIPs {
			preformReverseLookups = true
		}
		if len(filterOpt.CachedHostnames) > 0 {
			allCachedHostnames = append(allCachedHostnames, filterOpt.CachedHostnames...)
		}

		filterNames[filterOpt.Name] = i
		if filterOpt.DNSQueue != 0 {
			filterQueues[filterOpt.DNSQueue] = filterOpt.Name
		}
		if filterOpt.TrafficQueue != 0 {
			filterQueues[filterOpt.TrafficQueue] = filterOpt.Name
		}
	}

	if config.SelfDNSQueue == 0 && (preformReverseLookups || len(allCachedHostnames) > 0) {
		return nil, errors.New(`"selfDNSQueue" must be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
	}
	if config.SelfDNSQueue > 0 && !preformReverseLookups && len(allCachedHostnames) == 0 {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`)
	}
	if config.InboundDNSQueue == config.SelfDNSQueue {
		return nil, errors.New(`"inboundDNSQueue" and "selfDNSQueue" must be different`)
	}

	// if 'selfDNSQueue' is specified, create a filter that will allow
	// Egress Eddie to only make required DNS queries
	if config.SelfDNSQueue > 0 {
		selfFilter := FilterOptions{
			Name:     selfFilterName,
			DNSQueue: config.SelfDNSQueue,
			IPv6:     config.IPv6,
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
