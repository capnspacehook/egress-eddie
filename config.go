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
	IPv6            bool
	Filters         []FilterOptions
}

type FilterOptions struct {
	DNSQueue     uint16 `toml:"dnsQueue"`
	TrafficQueue uint16
	IPv6         bool
	AllowIPsFor  time.Duration
	Hostnames    []string
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

	for i, filterOpt := range config.Filters {
		if filterOpt.DNSQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "dnsQueue" must be set`, i)
		}
		if filterOpt.TrafficQueue == 0 {
			return nil, fmt.Errorf(`filter #%d: "trafficQueue" must be set`, i)
		}
		if len(filterOpt.Hostnames) == 0 {
			return nil, fmt.Errorf(`filter #%d: at least one hostname must be specified`, i)
		}
	}

	return &config, nil
}
