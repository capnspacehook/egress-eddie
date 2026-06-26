package egresseddie

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
		testName:       "unknown key",
		configStr:      "foo=1",
		expectedConfig: nil,
		expectedErr:    `unknown keys "foo"`,
	},
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "5s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
		expectedConfig: nil,
		expectedErr:    `"inboundDNSQueue" and "selfDNSQueue" must be different`,
	},
	{
		testName: "trafficQueue and AllowAllDomains set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAllDomains = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue" must not be set when "allowAllDomains" is true`,
	},
	{
		testName: "allowedDomains empty",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedDomains" must not be empty`,
	},
	{
		testName: "allowedDomains not empty and allowAllDomains is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAllDomains = true
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedDomains" must be empty when "allowAllDomains" is true`,
	},
	{
		testName: "allowedDomains not empty and allowAnswersFor is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must be set when "allowedDomains" is not empty`,
	},
	{
		testName: "allowAllDomains set and allowAnswersFor is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAnswersFor = "5s"
allowAllDomains = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must not be set when "allowAllDomains" is true`,
	},
	{
		testName: "negative allowAnswersFor",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "-1m"
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must not be negative`,
	},
	{
		testName: "cachedDomains not empty and allowAllDomains is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
allowAllDomains = true
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "cachedDomains" must be empty when "allowAllDomains" is true`,
	},
	{
		testName: "cachedDomains not empty and reCacheEvery is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must be set when "cachedDomains" is not empty`,
	},
	{
		testName: "cachedDomains empty and reCacheEvery is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
allowAnswersFor = "5s"
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must not be set when "cachedDomains" is empty`,
	},
	{
		testName: "negative reCacheEvery",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
reCacheEvery = "-1m"
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must not be negative`,
	},
	{
		testName: "dnsQueue set and cachedDomains not empty",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must not be set when "allowedDomains" is empty and "cachedHostames" is not empty`,
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
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue" must only be set when at least one filter has a non-empty "cachedDomains"`,
	},
	{
		testName: "invalid allowed domain name",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedDomains = [""]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": allowed domain name "" is invalid: domain name is empty`,
	},
	{
		testName: "shared allowed and cached domain name",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedDomains = ["foo"]
reCacheEvery = "10s"
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": allowed domain name "foo" is specified as a domain name to be cached as well`,
	},
	{
		testName: "duplicate allowed domain name",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedDomains = [
	"twice",
	"twice",
]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": allowed domain name "twice" is specified more than once`,
	},
	{
		testName: "invalid cached domain name",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
reCacheEvery = "10s"
cachedDomains = [""]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": domain name to be cached "" is invalid: domain name is empty`,
	},
	{
		testName: "duplicate cached domain name",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
reCacheEvery = "10s"
cachedDomains = [
	"twice",
	"twice",
]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": domain name to be cached "twice" is specified more than once`,
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
allowedDomains = ["foo"]

[[filters]]
name = "foo"
dnsQueue.ipv4 = 2000
trafficQueue.ipv4 = 2001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
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
allowedDomains = ["foo"]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 2001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": "dnsQueue.ipv4" 1000 is already used by filter "foo"`,
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
allowedDomains = ["foo"]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 2000
trafficQueue.ipv4 = 1001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": "trafficQueue.ipv4" 1001 is already used by filter "foo"`,
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
allowAnswersFor = "10s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
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
allowAnswersFor = "10s"
allowedDomains = ["foo"]
cachedDomains = ["bar"]
reCacheEvery = "1s"`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "selfDNSQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "allowedDomain with uppercase characters",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "5s"
allowedDomains = [
	"domain.com",
	"*.domain.[A-Z]om",
]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": compiling allowed domain name pattern "*.domain.[A-Z]om": pattern contains uppercase character A, only lowercase characters are allowed in patterns to allow for case-insensitive matching`,
	},
	{
		testName: "cachedDomain with pattern",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedDomains = [
	"domain.com",
	"*.domain.[A-Z]om",
]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": domain name to be cached "*.domain.[A-Z]om" is a glob pattern, domain names to be cached must be exact domain names only`,
	},
	{
		testName: "valid allowAllDomains is set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
allowAllDomains = true`,
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
					AllowAllDomains: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid allowAllDomains is not set",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "5s"
allowedDomains = [
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
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
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
		testName: "valid allowAllDomains mixed",
		configStr: `
inboundDNSQueue.ipv4 = 1

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
allowAnswersFor = "5s"
allowedDomains = [
	"foo",
	"bar",
	"baz.barf",
]

[[filters]]
name = "bar"
dnsQueue.ipv4 = 2000
allowAllDomains = true`,
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
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
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
					AllowAllDomains: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid cachedDomains",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedDomains = [
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
					AllowedDomains: []string{
						"oof",
						"rab",
					},
				},
				{
					Name: "foo",
					TrafficQueue: queue{
						IPv4: 1001,
					},
					ReCacheEvery: time.Second,
					CachedDomains: []string{
						"oof",
						"rab",
					},
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid allowedDomains and cachedDomains",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedDomains = [
	"oof",
	"rab",
]
allowAnswersFor = "5s"
allowedDomains = [
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
					AllowedDomains: []string{
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
					ReCacheEvery:    time.Second,
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
						"foo",
						"bar",
						"baz.barf",
					},
					CachedDomains: []string{
						"oof",
						"rab",
					},
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "cachedDomains is not empty",
		configStr: `
inboundDNSQueue.ipv4 = 1
selfDNSQueue.ipv4 = 100

[[filters]]
name = "foo"
dnsQueue.ipv4 = 1000
trafficQueue.ipv4 = 1001
reCacheEvery = "1s"
cachedDomains = [
	"oof",
	"rab",
]
allowAnswersFor = "5s"
allowedDomains = [
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
					AllowedDomains: []string{"oof", "rab"},
				},
				{
					Name: "foo",
					DNSQueue: queue{
						IPv4: 1000,
					},
					TrafficQueue: queue{
						IPv4: 1001,
					},
					ReCacheEvery:    time.Second,
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
						"foo",
						"bar",
						"baz.barf",
					},
					CachedDomains: []string{
						"oof",
						"rab",
					},
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid multiple filters",
		configStr: `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10
selfDNSQueue.ipv4 = 100
selfDNSQueue.ipv6 = 110

[[filters]]
name = "test1"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011
allowAnswersFor = "5s"
allowedDomains = [
	"foo",
	"bar",
]

[[filters]]
name = "test3"
trafficQueue.ipv4 = 3001
trafficQueue.ipv6 = 3011
reCacheEvery = "1s"
cachedDomains = [
	"oof",
	"rab",
]

[[filters]]
name = "test4"
dnsQueue.ipv4 = 4000
dnsQueue.ipv6 = 4010
allowAllDomains = true`,
		expectedConfig: &Config{
			InboundDNSQueue: queue{
				IPv4: 1,
				IPv6: 10,
			},
			SelfDNSQueue: queue{
				IPv4: 100,
				IPv6: 110,
			},
			Filters: []FilterOptions{
				{
					Name: "self-filter",
					DNSQueue: queue{
						IPv4: 100,
						IPv6: 110,
					},
					AllowedDomains: []string{"oof", "rab"},
				},
				{
					Name: "test1",
					DNSQueue: queue{
						IPv4: 1000,
						IPv6: 1010,
					},
					TrafficQueue: queue{
						IPv4: 1001,
						IPv6: 1011,
					},
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
						"foo",
						"bar",
					},
				},
				{
					Name: "test3",
					TrafficQueue: queue{
						IPv4: 3001,
						IPv6: 3011,
					},
					ReCacheEvery: time.Second,
					CachedDomains: []string{
						"oof",
						"rab",
					},
				},
				{
					Name: "test4",
					DNSQueue: queue{
						IPv4: 4000,
						IPv6: 4010,
					},
					AllowAllDomains: true,
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
				is.True(err != nil)
				is.Equal(tt.expectedErr, err.Error())
			}

			if config != nil {
				// clear matchers so we can compare the rest of the config
				for i := range config.Filters {
					config.Filters[i].allowedDomainMatchers = nil
				}
			}
			is.Equal(tt.expectedConfig, config)
		})
	}
}

func TestValidDomainName(t *testing.T) {
	is := is.New(t)

	tests := []struct {
		name       string
		domainName string
		err        string
	}{
		{
			name:       "valid",
			domainName: "domain.com",
		},
		{
			name:       "valid with dash",
			domainName: "domain-name.com",
		},
		{
			name:       "valid many labels",
			domainName: "a.b.c.d.e.f.g.domain.com",
		},
		{
			name:       "valid with dot at end",
			domainName: "domain.com.",
		},
		{
			name:       "with underscore",
			domainName: "domain_name.com",
			err:        "domain name contains illegal character _",
		},
		{
			name:       "with symbol",
			domainName: "sub#dom.domain.com",
			err:        "domain name contains illegal character #",
		},
		{
			name:       "with leading hyphen",
			domainName: "-sub.domain.com",
			err:        "domain name label starts with a dash",
		},
		{
			name:       "with trailing hyphen",
			domainName: "sub-.domain.com",
			err:        "domain name label ends with a dash",
		},
		{
			name:       "too long",
			domainName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			err:        "domain name exceeds 255 characters",
		},
		{
			name:       "label too long",
			domainName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.domain.com",
			err:        "domain name label exceeds 63 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			err := validDomainName(tt.domainName)
			if tt.err == "" {
				is.NoErr(err)
			} else {
				is.True(err != nil)
				is.Equal(tt.err, err.Error())
			}
		})
	}
}
