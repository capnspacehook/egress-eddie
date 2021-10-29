package main

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Filters []FilterOptions
}

type FilterOptions struct {
	DNSQueue     uint16
	TrafficQueue uint16
	IPv6         bool
	Hostnames    []string
}

func ParseConfig(confPath string) (*Config, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	d := toml.NewDecoder(f)
	d.SetStrict(true)

	var config Config
	if err := d.Decode(&config); err != nil {
		var sme *toml.StrictMissingError
		if errors.As(err, &sme) {
			return nil, errors.New(sme.String())
		}
		return nil, err
	}

	return &config, nil
}
