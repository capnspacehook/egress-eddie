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
	Hostnames         []string
}

func ParseConfig(confPath string) (*Config, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if len(config.Filters) == 0 {
		return nil, errors.New("at least one filter must be specified")
	}
	if config.InboundDNSQueue == 0 {
		return nil, errors.New(`"inboundDNSQueue" must be set`)
	}

	var preformReverseLookups bool
	for i, filterOpt := range config.Filters {
		if filterOpt.DNSQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" must be set`, i)
		}
		if !filterOpt.AllowAllHostnames && filterOpt.TrafficQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must be set`, i)
		}
		if filterOpt.AllowAllHostnames && filterOpt.TrafficQueue > 0 {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" should not be set when "allowAllHostnames" is true`, i)
		}
		if !filterOpt.AllowAllHostnames && len(filterOpt.Hostnames) == 0 {
			return nil, fmt.Errorf(`filter #%d: at least one hostname must be specified`, i)
		}
		if filterOpt.AllowAllHostnames && len(filterOpt.Hostnames) > 0 {
			return nil, fmt.Errorf(`filter #%d: no hostnames should be specified when "allowAllHostnames" is true`, i)
		}

		if filterOpt.LookupUnknownIPs {
			preformReverseLookups = true
		}
	}

	if config.SelfDNSQueue > 0 && !preformReverseLookups {
		return nil, errors.New(`"selfDNSQueue" must only be set when at least one filter sets "lookupUnknownIPs" to true`)
	}

	// if 'selfDNSQueue' is specified, create a filter that will allow
	// Egress Eddie to only make reverse IP lookups
	if config.SelfDNSQueue > 0 {
		selfFilter := FilterOptions{
			DNSQueue: config.SelfDNSQueue,
			IPv6:     config.IPv6,
			Hostnames: []string{
				"in-addr.arpa",
				"ip6.arpa",
			},
		}

		config.Filters = append([]FilterOptions{selfFilter}, config.Filters...)
	}

	return &config, nil
}
