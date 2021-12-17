package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml"
)

type Config struct {
	InboundDNSQueue uint16
	SelfDNSQueue    uint16
	IPv6            bool
	Filters         []FilterOptions
}

type FilterOptions struct {
	DNSQueue          uint16 `toml:"dnsQueue"`
	TrafficQueue      uint16
	IPv6              bool
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
	)
	for i, filterOpt := range config.Filters {
		if filterOpt.DNSQueue == 0 && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" must be set`, i)
		}
		if filterOpt.TrafficQueue == 0 && !filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must be set`, i)
		}
		if filterOpt.TrafficQueue > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must not be set when "allowAllHostnames" is true`, i)
		}
		if filterOpt.DNSQueue == filterOpt.TrafficQueue {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" and "trafficQueue" must be different`, i)
		}
		if len(filterOpt.AllowedHostnames) == 0 && !filterOpt.AllowAllHostnames && len(filterOpt.CachedHostnames) == 0 && !filterOpt.LookupUnknownIPs {
			return nil, fmt.Errorf(`filter #%d: "allowedHostnames" must not be empty`, i)
		}
		if len(filterOpt.AllowedHostnames) > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter #%d: "allowedHostnames" must be empty when "allowAllHostnames" is true`, i)
		}
		if filterOpt.AllowAnswersFor == 0 && len(filterOpt.AllowedHostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: "allowAnswersFor" must be set when "allowedHostnames" is not empty`, i)
		}
		if filterOpt.AllowAnswersFor != 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter #%d: "allowAnswersFor" must not be set when "allowAllHostnames" is true`, i)
		}
		if len(filterOpt.CachedHostnames) > 0 && filterOpt.AllowAllHostnames {
			return nil, fmt.Errorf(`filter #%d: "cachedHostnames" must be empty when "allowAllHostnames" is true`, i)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CachedHostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: "reCacheEvery" must be set when "cachedHostnames" is not empty`, i)
		}
		if filterOpt.ReCacheEvery > 0 && len(filterOpt.CachedHostnames) == 0 {
			return nil, fmt.Errorf(`filter #%d: "reCacheEvery" must not be set when "cachedHostnames" is empty`, i)
		}
		if filterOpt.DNSQueue != 0 && len(filterOpt.AllowedHostnames) == 0 && (len(filterOpt.CachedHostnames) > 0 || filterOpt.LookupUnknownIPs) {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`, i)
		}

		if filterOpt.LookupUnknownIPs {
			preformReverseLookups = true
		}
		if len(filterOpt.CachedHostnames) > 0 {
			allCachedHostnames = append(allCachedHostnames, filterOpt.CachedHostnames...)
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
