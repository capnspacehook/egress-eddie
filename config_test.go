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
			testName:       "empty",
			configStr:      "",
			expectedConfig: nil,
			expectedErr:    "at least one filter must be specified",
		},
		{
			testName:       "inboundDNSQueue not set",
			configStr:      "[[filters]]",
			expectedConfig: nil,
			expectedErr:    `"inboundDNSQueue" must be set`,
		},
		{
			testName: "dnsQueue not set",
			configStr: `
inboundDNSQueue = 1

[[filters]]`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "dnsQueue" must be set`,
		},
		{
			testName: "trafficQueue not set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "trafficQueue" must be set`,
		},
		{
			testName: "dnsQueue and trafficQueue same",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1000`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "dnsQueue" and "trafficQueue" must be different`,
		},
		{
			testName: "inboundDNSQueue and selfDNSQueue same",
			configStr: `
inboundDNSQueue = 1
selfDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
lookupUnknownIPs = true
allowedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `"inboundDNSQueue" and "selfDNSQueue" must be different`,
		},
		// TODO: test all filters have different queues
		{
			testName: "trafficQueue and AllowAllHostnames set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowAllHostnames = true`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "trafficQueue" must not be set when "allowAllHostnames" is true`,
		},
		{
			testName: "allowedHostnames empty",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "allowedHostnames" must be non-empty`,
		},
		{
			testName: "allowedHostnames non-empty and allowAllHostnames is set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true
allowedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "allowedHostnames" must be empty when "allowAllHostnames" is true`,
		},
		{
			testName: "cachedHostnames non-empty and allowAllHostnames is set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true
cachedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "cachedHostnames" must be empty when "allowAllHostnames" is true`,
		},
		{
			testName: "cachedHostnames non-empty and reCacheEvery is not set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
cachedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "reCacheEvery" must be set when "cachedHostnames" is non-empty`,
		},
		{
			testName: "cachedHostnames empty and reCacheEvery is set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
allowedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `filter #0: "reCacheEvery" must not be set when "cachedHostnames" is empty`,
		},
		{
			testName: "selfDNSQueue set",
			configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]`,
			expectedConfig: nil,
			expectedErr:    `"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is non-empty`,
		},
		{
			testName: "valid allowAllHostnames is set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
allowAllHostnames = true`,
			expectedConfig: &Config{
				InboundDNSQueue: 1,
				Filters: []FilterOptions{
					{
						DNSQueue:          1000,
						AllowAllHostnames: true,
					},
				},
			},
			expectedErr: "",
		},
		{
			testName: "valid allowAllHostnames is not set",
			configStr: `
inboundDNSQueue = 1

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			expectedConfig: &Config{
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
			expectedErr: "",
		},
		{
			testName: "valid allowAllHostnames mixed",
			configStr: `
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
			expectedConfig: &Config{
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
			expectedErr: "",
		},
		{
			testName: "valid cachedHostnames",
			configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
cachedHostnames = [
	"oof",
	"rab",
]`,
			expectedConfig: &Config{
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
						CachedHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			testName: "valid allowedHostnames and cachedHostnames",
			configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
cachedHostnames = [
	"oof",
	"rab",
]
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			expectedConfig: &Config{
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
						CachedHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			testName: "valid lookupUnknownIPs is set",
			configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
dnsQueue = 1000
trafficQueue = 1001
lookupUnknownIPs = true
reCacheEvery = "1s"
cachedHostnames = [
	"oof",
	"rab",
]
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
			expectedConfig: &Config{
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
						CachedHostnames: []string{
							"oof",
							"rab",
						},
					},
				},
			},
			expectedErr: "",
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
