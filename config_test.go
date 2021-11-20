package main

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestParseConfig(t *testing.T) {
	configTests := []struct {
		testName       string
		configStr      string
		expectedConfig *Config
		expectedErr    string
	}{
		{
			"empty", "", nil, "at least one filter must be specified",
		},
		{
			"inboundDNSQueue not set",
			"[[filters]]",
			nil,
			`"inboundDNSQueue" must be set`,
		},
		{
			"dnsQueue not set",
			`
inboundDNSQueue = 1

[[filters]]`,
			nil,
			`filter #0: "dnsQueue" must be set`,
		},
		{
			"trafficQueue not set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000`,
			nil,
			`filter #0: "trafficQueue" must be set`,
		},
		{
			"dnsQueue and trafficQueue same",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1000`,
			nil,
			`filter #0: "dnsQueue" and "trafficQueue" must be different`,
		},
		{
			"inboundDNSQueue and selfDNSQueue same",
			`
inboundDNSQueue = 1
selfDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
lookupUnknownIPs = true
allowedHostnames = ["foo"]`,
			nil,
			`"inboundDNSQueue" and "selfDNSQueue" must be different`,
		},
		// TODO: test all filters have different queues
		{
			"trafficQueue and AllowAllHostnames set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowAllHostnames = true`,
			nil,
			`filter #0: "trafficQueue" must not be set when "allowAllHostnames" is true`,
		},
		{
			"allowedHostnames empty",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001`,
			nil,
			`filter #0: "allowedHostnames" must be non-empty`,
		},
		{
			"allowedHostnames non-empty and allowAllHostnames is set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true
allowedHostnames = ["foo"]`,
			nil,
			`filter #0: "allowedHostnames" must be empty when "allowAllHostnames" is true`,
		},
		{
			"cacheHostnames non-empty and allowAllHostnames is set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true
cacheHostnames = ["foo"]`,
			nil,
			`filter #0: "cacheHostnames" must be empty when "allowAllHostnames" is true`,
		},
		{
			"cacheHostnames non-empty and reCacheEvery is not set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
cacheHostnames = ["foo"]`,
			nil,
			`filter #0: "reCacheEvery" must be set when "cacheHostnames" is non-empty`,
		},
		{
			"cacheHostnames empty and reCacheEvery is set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
allowedHostnames = ["foo"]`,
			nil,
			`filter #0: "reCacheEvery" must not be set when "cacheHostnames" is empty`,
		},
		{
			"selfDNSQueue set",
			`
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]`,
			nil,
			`"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cacheHostnames" is non-empty`,
		},
		{
			"valid allowAllHostnames is set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true`,
			&Config{
				InboundDNSQueue: 1,
				Filters: []FilterOptions{
					{
						DNSQueue:          1000,
						AllowAllHostnames: true,
					},
				},
			},
			"",
		},
		{
			"valid allowAllHostnames is not set",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			&Config{
				InboundDNSQueue: 1,
				Filters: []FilterOptions{
					{
						DNSQueue:     1000,
						TrafficQueue: 1001,
						AllowedHostnames: []string{
							"foo",
							"bar",
							"baz.barf",
						},
					},
				},
			},
			"",
		},
		{
			"valid allowAllHostnames mixed",
			`
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]

[[filters]]
dnsQueue = 2000
allowAllHostnames = true`,
			&Config{
				InboundDNSQueue: 1,
				Filters: []FilterOptions{
					{
						DNSQueue:     1000,
						TrafficQueue: 1001,
						AllowedHostnames: []string{
							"foo",
							"bar",
							"baz.barf",
						},
					},
					{
						DNSQueue:          2000,
						AllowAllHostnames: true,
					},
				},
			},
			"",
		},
		{
			"valid cacheHostnames",
			`
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
cacheHostnames = [
	"oof",
	"rab",
]`,
			&Config{
				InboundDNSQueue: 1,
				SelfDNSQueue:    100,
				Filters: []FilterOptions{
					{
						DNSQueue: 100,
						AllowedHostnames: []string{
							"oof",
							"rab",
						},
					},
					{
						DNSQueue:     1000,
						TrafficQueue: 1001,
						ReCacheEvery: time.Second,
						CacheHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			"",
		},
		{
			"valid allowedHostnames and cacheHostnames",
			`
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
cacheHostnames = [
	"oof",
	"rab",
]
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			&Config{
				InboundDNSQueue: 1,
				SelfDNSQueue:    100,
				Filters: []FilterOptions{
					{
						DNSQueue: 100,
						AllowedHostnames: []string{
							"oof",
							"rab",
						},
					},
					{
						DNSQueue:     1000,
						TrafficQueue: 1001,
						ReCacheEvery: time.Second,
						AllowedHostnames: []string{
							"foo",
							"bar",
							"baz.barf",
						},
						CacheHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			"",
		},
		{
			"valid lookupUnknownIPs is set",
			`
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
lookupUnknownIPs = true
reCacheEvery = "1s"
cacheHostnames = [
	"oof",
	"rab",
]
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			&Config{
				InboundDNSQueue: 1,
				SelfDNSQueue:    100,
				Filters: []FilterOptions{
					{
						DNSQueue: 100,
						AllowedHostnames: []string{
							"in-addr.arpa",
							"ip6.arpa",
							"oof",
							"rab",
						},
					},
					{
						DNSQueue:         1000,
						TrafficQueue:     1001,
						LookupUnknownIPs: true,
						ReCacheEvery:     time.Second,
						AllowedHostnames: []string{
							"foo",
							"bar",
							"baz.barf",
						},
						CacheHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			"",
		},
	}

	is := is.New(t)
	for _, tt := range configTests {
		t.Run(tt.testName, func(t *testing.T) {
			is := is.New(t)

			config, err := parseConfigBytes([]byte(tt.configStr))
			if tt.expectedErr == "" {
				is.NoErr(err)
			} else {
				is.Equal(err.Error(), tt.expectedErr)
			}
			is.Equal(config, tt.expectedConfig)
		})
	}
}
