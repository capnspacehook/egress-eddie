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
	CacheHostnames    []string
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
		allCacheHostnames     []string
	)
	for i, filterOpt := range config.Filters {
		if filterOpt.DNSQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" must be set`, i)
		}
		if !filterOpt.AllowAllHostnames && filterOpt.TrafficQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must be set`, i)
		}
		if filterOpt.AllowAllHostnames && filterOpt.TrafficQueue > 0 {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must not be set when "allowAllHostnames" is true`, i)
		}
		if filterOpt.DNSQueue == filterOpt.TrafficQueue {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" and "trafficQueue" must be different`, i)
		}
		if !filterOpt.AllowAllHostnames && len(filterOpt.CacheHostnames) == 0 && len(filterOpt.AllowedHostnames) == 0 {
			return nil, fmt.Errorf(`filter #%d: "allowedHostnames" must be non-empty`, i)
		}
		if filterOpt.AllowAllHostnames && len(filterOpt.AllowedHostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: "allowedHostnames" must be empty when "allowAllHostnames" is true`, i)
		}
		if filterOpt.AllowAllHostnames && len(filterOpt.CacheHostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: "cacheHostnames" must be empty when "allowAllHostnames" is true`, i)
		}
		if filterOpt.ReCacheEvery == 0 && len(filterOpt.CacheHostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: "reCacheEvery" must be set when "cacheHostnames" is non-empty`, i)
		}
		if filterOpt.ReCacheEvery > 0 && len(filterOpt.CacheHostnames) == 0 {
			return nil, fmt.Errorf(`filter #%d: "reCacheEvery" must not be set when "cacheHostnames" is empty`, i)
		}

		if filterOpt.LookupUnknownIPs {
			preformReverseLookups = true
		}
		if len(filterOpt.CacheHostnames) > 0 {
			allCacheHostnames = append(allCacheHostnames, filterOpt.CacheHostnames...)
		}
	}

	if config.SelfDNSQueue == 0 && (preformReverseLookups || len(allCacheHostnames) > 0) {
		return nil, errors.New(`"selfDNSQueue" must be set when at least one filter either sets "lookupUnknownIPs" to true or "cacheHostnames" is non-empty`)
	}
	if config.SelfDNSQueue > 0 && !preformReverseLookups && len(allCacheHostnames) == 0 {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cacheHostnames" is non-empty`)
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
		if len(allCacheHostnames) > 0 {
			selfFilter.AllowedHostnames = append(selfFilter.AllowedHostnames, allCacheHostnames...)
		}

		config.Filters = append([]FilterOptions{selfFilter}, config.Filters...)
	}

	return &config, nil
}
