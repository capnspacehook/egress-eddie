package main

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

var configTests = []struct {
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
		testName: "inboundDNSQueue not valid",
		configStr: `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 1

[[filters]]`,
		expectedConfig: nil,
		expectedErr:    `"inboundDNSQueue.ipv4" and "inboundDNSQueue.ipv6" cannot be the same`,
	},
	{
		testName: "name not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]`,
		expectedConfig: nil,
		expectedErr:    `filter #0: "name" must be set`,
	},
	{
		testName: "dnsQueue not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must be set`,
	},
	{
		testName: "dnsQueue not valid",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue.ipv4" and "dnsQueue.ipv6" cannot be the same`,
	},
	{
		testName: "dnsQueue ipv4 not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv6 = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`,
	},
	{
		testName: "dnsQueue ipv4 set",
		configStr: `
inboundDNSQueue.ipv6 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`,
	},
	{
		testName: "dnsQueue ipv6 not set",
		configStr: `
inboundDNSQueue.ipv6 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`,
	},
	{
		testName: "dnsQueue ipv6 set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`,
	},
	{
		testName: "inboundDNSQueue and dnsQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1
		`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "inboundDNSQueue" and "dnsQueue" must be different`,
	},
	{
		testName: "inboundDNSQueue and dnsQueue same mixed",
		configStr: `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 2

[[filters]]
name = "foo"
dnsQueue.ipv4 = 2
dnsQueue.ipv6 = 3
		`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "inboundDNSQueue" and "dnsQueue" must be different`,
	},
	{
		testName: "trafficQueue not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue" must be set`,
	},
	{
		testName: "trafficQueue not valid",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue.ipv4" and "trafficQueue.ipv6" cannot be the same`,
	},
	{
		testName: "trafficQueue ipv4 not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv6 = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`,
	},
	{
		testName: "trafficQueue ipv4 set",
		configStr: `
inboundDNSQueue.ipv6 = 1

[[filters]]
name = "foo"
dnsQueue.ipv6 = 1010
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`,
	},
	{
		testName: "trafficQueue ipv6 not set",
		configStr: `
inboundDNSQueue.ipv6 = 1

[[filters]]
name = "foo"
dnsQueue.ipv6 = 1000
trafficQueue.ipv4 = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`,
	},
	{
		testName: "trafficQueue ipv6 set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`,
	},
	{
		testName: "inboundDNSQueue and trafficQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1
		`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "inboundDNSQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "dnsQueue and trafficQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "selfDNSQueue invalid",
		configStr: `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10
selfDNSQueue.ipv4 = 2
selfDNSQueue.ipv6 = 2

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue.ipv4" and "selfDNSQueue.ipv6" cannot be the same`,
	},
	{
		testName: "selfDNSQueue ipv4 not set",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv6 = 2

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue.ipv4" must be set when "inboundDNSQueue.ipv4" is set`,
	},
	{
		testName: "selfDNSQueue ipv4 set",
		configStr: `
inboundDNSQueue.ipv6 = 1
selfDNSQueue.ipv4 = 2
selfDNSQueue.ipv6 = 3

[[filters]]
name = "foo"
dnsQueue.ipv6 = 1000
trafficQueue.ipv6 = 1001
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue.ipv4" must not be set when "inboundDNSQueue.ipv4" is not set`,
	},
	{
		testName: "selfDNSQueue ipv6 not set",
		configStr: `
inboundDNSQueue.ipv6 = 1
selfDNSQueue.ipv4 = 2

[[filters]]
name = "foo"
dnsQueue.ipv6 = 1000
trafficQueue.ipv6 = 1001
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue.ipv6" must be set when "inboundDNSQueue.ipv6" is set`,
	},
	{
		testName: "selfDNSQueue ipv6 set",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 2
selfDNSQueue.ipv6 = 3

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue.ipv6" must not be set when "inboundDNSQueue.ipv6" is not set`,
	},
	{
		testName: "inboundDNSQueue and selfDNSQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
lookupUnknownIPs = true
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"inboundDNSQueue" and "selfDNSQueue" must be different`,
	},
	{
		testName: "trafficQueue and AllowAllHostnames set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAllHostnames = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue" must not be set when "allowAllHostnames" is true`,
	},
	{
		testName: "allowedHostnames empty",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedHostnames" must not be empty`,
	},
	{
		testName: "allowedHostnames not empty and allowAllHostnames is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAllHostnames = true
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedHostnames" must be empty when "allowAllHostnames" is true`,
	},
	{
		testName: "allowedHostnames not empty and allowAnswersFor is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must be set when "allowedHostnames" is not empty`,
	},
	{
		testName: "allowAllHostnames set and allowAnswersFor is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAnswersFor = "5s"
allowAllHostnames = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must not be set when "allowAllHostnames" is true`,
	},
	{
		testName: "cachedHostnames not empty and allowAllHostnames is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
allowAllHostnames = true
cachedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "cachedHostnames" must be empty when "allowAllHostnames" is true`,
	},
	{
		testName: "cachedHostnames not empty and reCacheEvery is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
cachedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must be set when "cachedHostnames" is not empty`,
	},
	{
		testName: "cachedHostnames empty and reCacheEvery is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
allowAnswersFor = "5s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must not be set when "cachedHostnames" is empty`,
	},
	{
		testName: "dnsQueue set and cachedHostnames not empty",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`,
	},
	{
		testName: "dnsQueue and lookupUnknownIPs set",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
lookupUnknownIPs = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must not be set when "allowedHostnames" is empty and either "cachedHostames" is not empty or "lookupUnknownIPs" is true`,
	},
	{
		testName: "selfDNSQueue set",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue" must only be set when at least one filter either sets "lookupUnknownIPs" to true or "cachedHostnames" is not empty`,
	},
	{
		testName: "duplicate filter names",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]

[[filters]]
name = "foo"
dnsQueue.ipv4 = 2000
trafficQueue.ipv4 = 2001
allowAnswersFor = "10s"
allowedHostnames = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter #1: filter name "foo" is already used by filter #0`,
	},
	{
		testName: "duplicate dnsQueues",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 2001
allowAnswersFor = "10s"
allowedHostnames = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": dnsQueue.ipv4 1000 is already used by filter "foo"`,
	},
	{
		testName: "duplicate trafficQueues",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedHostnames = ["foo"]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 2000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedHostnames = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": trafficQueue.ipv4 1001 is already used by filter "foo"`,
	},
	{
		testName: "selfDNSQueue and dnsQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 100
trafficQueue.ipv4 = 1001
lookupUnknownIPs = true
allowAnswersFor = "10s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "selfDNSQueue" and "dnsQueue" must be different`,
	},
	{
		testName: "selfDNSQueue and trafficQueue same",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 100
lookupUnknownIPs = true
allowAnswersFor = "10s"
allowedHostnames = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "selfDNSQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "valid allowAllHostnames is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAllHostnames = true`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			Filters: []FilterOptions{
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					AllowAllHostnames: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid allowAllHostnames is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "5s"
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			Filters: []FilterOptions{
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					AllowAnswersFor: duration(5 * time.Second),
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
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "5s"
allowedHostnames = [
	"foo",
	"bar",
	"baz.barf",
]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 2000
allowAllHostnames = true`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			Filters: []FilterOptions{
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					AllowAnswersFor: duration(5 * time.Second),
					AllowedHostnames: []string{
						"foo",
						"bar",
						"baz.barf",
					},
				},
				{
					Name: "bar",
					DNSQueue: queue{
						IPv4: 2000,
					},
					AllowAllHostnames: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid cachedHostnames",
		configStr: `
	inboundDNSQueue.ipv4 = 1
	selfDNSQueue.ipv4 = 100

	[[filters]]
	name = "foo"
	trafficQueue.ipv4 = 1001
	reCacheEvery = "1s"
	cachedHostnames = [
		"oof",
		"rab",
	]`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
			},
			Filters: []FilterOptions{
				{
					Name: selfFilterName,
					DNSQueue: queue{
						IPv4: 100,
					},
					AllowedHostnames: []string{
						"oof",
						"rab",
					},
				},
				{
					Name: "foo",
					TrafficQueue: queue{
						IPv4: 1001,
					},
					ReCacheEvery: duration(time.Second),
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
		testName: "valid lookupUnknownIPs",
		configStr: `
	inboundDNSQueue.ipv4 = 1
	selfDNSQueue.ipv4 = 100

	[[filters]]
	name = "foo"
	trafficQueue.ipv4 = 1001
	lookupUnknownIPs = true`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
			},
			Filters: []FilterOptions{
				{
					Name: selfFilterName,
					DNSQueue: queue{
						IPv4: 100,
					},
					AllowedHostnames: []string{
						"in-addr.arpa",
						"ip6.arpa",
					},
				},
				{
					Name: "foo",
					TrafficQueue: queue{
						IPv4: 1001,
					},
					LookupUnknownIPs: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid allowedHostnames and cachedHostnames",
		configStr: `
	inboundDNSQueue.ipv4 = 1
	selfDNSQueue.ipv4 = 100

	[[filters]]
	name = "foo"
	dnsQueue.ipv4 = 1000
	trafficQueue.ipv4 = 1001
	reCacheEvery = "1s"
	cachedHostnames = [
		"oof",
		"rab",
	]
	allowAnswersFor = "5s"
	allowedHostnames = [
		"foo",
		"bar",
		"baz.barf",
	]`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
			},
			Filters: []FilterOptions{
				{
					Name: selfFilterName,
					DNSQueue: queue{
						IPv4: 100,
					},
					AllowedHostnames: []string{
						"oof",
						"rab",
					},
				},
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					ReCacheEvery:    duration(time.Second),
					AllowAnswersFor: duration(5 * time.Second),
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
		testName: "valid lookupUnknownIPs",
		configStr: `
	inboundDNSQueue.ipv4 = 1
	selfDNSQueue.ipv4 = 100

	[[filters]]
	name = "foo"
	dnsQueue.ipv4 = 1000
	trafficQueue.ipv4 = 1001
	lookupUnknownIPs = true
	allowAnswersFor = "5s"
	allowedHostnames = [
		"foo",
		"bar",
		"baz.barf",
	]`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
			},
			Filters: []FilterOptions{
				{
					Name: selfFilterName,
					DNSQueue: queue{
						IPv4: 100,
					},
					AllowedHostnames: []string{
						"in-addr.arpa",
						"ip6.arpa",
					},
				},
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					LookupUnknownIPs: true,
					AllowAnswersFor:  duration(5 * time.Second),
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
		testName: "valid lookupUnknownIPs is set and cachedHostnames is not empty",
		configStr: `
	inboundDNSQueue.ipv4 = 1
	selfDNSQueue.ipv4 = 100

	[[filters]]
	name = "foo"
	dnsQueue.ipv4 = 1000
	trafficQueue.ipv4 = 1001
	lookupUnknownIPs = true
	reCacheEvery = "1s"
	cachedHostnames = [
		"oof",
		"rab",
	]
	allowAnswersFor = "5s"
	allowedHostnames = [
		"foo",
		"bar",
		"baz.barf",
	]`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
			},
			Filters: []FilterOptions{
				{
					Name: selfFilterName,
					DNSQueue: queue{
						IPv4: 100,
					},
					AllowedHostnames: []string{
						"in-addr.arpa",
						"ip6.arpa",
						"oof",
						"rab",
					},
				},
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					LookupUnknownIPs: true,
					ReCacheEvery:     duration(time.Second),
					AllowAnswersFor:  duration(5 * time.Second),
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

func TestParseConfig(t *testing.T) {
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
