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
		testName: "name not set",
		configStr: `
inboundDNSQueue = 1

[[filters]]`,
		expectedConfig: nil,
		expectedErr:    `filter #0: "name" must be set`,
	},
	{
		testName: "dnsQueue not set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must be set`,
	},
	{
		testName: "inboundDNSQueue and dnsQueue same",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1
		`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "inboundDNSQueue" and "dnsQueue" must be different`,
	},
	{
		testName: "trafficQueue not set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue" must be set`,
	},
	{
		testName: "inboundDNSQueue and trafficQueue same",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1
		`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "inboundDNSQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "dnsQueue and trafficQueue same",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1000`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" and "trafficQueue" must be different`,
	},
	{
		testName: "inboundDNSQueue and selfDNSQueue same",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAllDomains = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "trafficQueue" must not be set when "allowAllDomains" is true`,
	},
	{
		testName: "allowedDomains empty",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedDomains" must not be empty`,
	},
	{
		testName: "allowedDomains not empty and allowAllDomains is set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
allowAllDomains = true
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowedDomains" must be empty when "allowAllDomains" is true`,
	},
	{
		testName: "allowedDomains not empty and allowAnswersFor is not set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must be set when "allowedDomains" is not empty`,
	},
	{
		testName: "allowAllDomains set and allowAnswersFor is set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
allowAnswersFor = "5s"
allowAllDomains = true`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must not be set when "allowAllDomains" is true`,
	},
	{
		testName: "negative allowAnswersFor",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "-1m"
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "allowAnswersFor" must not be negative`,
	},
	{
		testName: "cachedDomains not empty and allowAllDomains is set",
		configStr: `
inboundDNSQueue = 1

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
inboundDNSQueue = 1

[[filters]]
name = "foo"
trafficQueue = 1001
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must be set when "cachedDomains" is not empty`,
	},
	{
		testName: "cachedDomains empty and reCacheEvery is set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
allowAnswersFor = "5s"
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must not be set when "cachedDomains" is empty`,
	},
	{
		testName: "negative reCacheEvery",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
trafficQueue = 1001
reCacheEvery = "-1m"
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "reCacheEvery" must not be negative`,
	},
	{
		testName: "dnsQueue set and cachedDomains not empty",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
reCacheEvery = "1s"
cachedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": "dnsQueue" must not be set when "allowedDomains" is empty and "cachedDomains" is not empty`,
	},
	{
		testName: "selfDNSQueue set",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = ["foo"]`,
		expectedConfig: nil,
		expectedErr:    `"selfDNSQueue" must only be set when at least one filter has a non-empty "cachedDomains"`,
	},
	{
		testName: "invalid allowed domain name",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = [""]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": allowed domain name "" is invalid: domain name is empty`,
	},
	{
		testName: "shared allowed and cached domain name",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
trafficQueue = 1001
reCacheEvery = "10s"
cachedDomains = [""]`,
		expectedConfig: nil,
		expectedErr:    `filter "foo": domain name to be cached "" is invalid: domain name is empty`,
	},
	{
		testName: "duplicate cached domain name",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
trafficQueue = 1001
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = ["foo"]

[[filters]]
name = "foo"
dnsQueue = 2000
trafficQueue = 2001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter #1: filter name "foo" is already used by filter #0`,
	},
	{
		testName: "duplicate dnsQueues",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = ["foo"]

[[filters]]
name = "bar"
dnsQueue = 1000
trafficQueue = 2001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": "dnsQueue" 1000 is already used by filter "foo"`,
	},
	{
		testName: "duplicate trafficQueues",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = ["foo"]

[[filters]]
name = "bar"
dnsQueue = 2000
trafficQueue = 1001
allowAnswersFor = "10s"
allowedDomains = ["bar"]`,
		expectedConfig: nil,
		expectedErr:    `filter "bar": "trafficQueue" 1001 is already used by filter "foo"`,
	},
	{
		testName: "selfDNSQueue and dnsQueue same",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 100
trafficQueue = 1001
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 100
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
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
inboundDNSQueue = 1

[[filters]]
name = "foo"
trafficQueue = 1001
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
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
allowAllDomains = true`,
		expectedConfig: &Config{
			InboundDNSQueue: 1,
			Filters: []FilterOptions{
				{
					Name:            "foo",
					DNSQueue:        1000,
					AllowAllDomains: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid allowAllDomains is not set",
		configStr: `
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "5s"
allowedDomains = [
	"foo",
	"bar",
	"baz.barf",
]`,
		expectedConfig: &Config{
			InboundDNSQueue: 1,
			Filters: []FilterOptions{
				{
					Name:            "foo",
					DNSQueue:        1000,
					TrafficQueue:    1001,
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
inboundDNSQueue = 1

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "5s"
allowedDomains = [
	"foo",
	"bar",
	"baz.barf",
]

[[filters]]
name = "bar"
dnsQueue = 2000
allowAllDomains = true`,
		expectedConfig: &Config{
			InboundDNSQueue: 1,
			Filters: []FilterOptions{
				{
					Name:            "foo",
					DNSQueue:        1000,
					TrafficQueue:    1001,
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
						"foo",
						"bar",
						"baz.barf",
					},
				},
				{
					Name:            "bar",
					DNSQueue:        2000,
					AllowAllDomains: true,
				},
			},
		},
		expectedErr: "",
	},
	{
		testName: "valid cachedDomains",
		configStr: `
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
trafficQueue = 1001
reCacheEvery = "1s"
cachedDomains = [
	"oof",
	"rab",
]`,
		expectedConfig: &Config{
			InboundDNSQueue: 1,
			SelfDNSQueue:    100,
			Filters: []FilterOptions{
				{
					Name:     selfFilterName,
					DNSQueue: 100,
					AllowedDomains: []string{
						"oof",
						"rab",
					},
				},
				{
					Name:         "foo",
					TrafficQueue: 1001,
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
			InboundDNSQueue: 1,
			SelfDNSQueue:    100,
			Filters: []FilterOptions{
				{
					Name:     selfFilterName,
					DNSQueue: 100,
					AllowedDomains: []string{
						"oof",
						"rab",
					},
				},
				{
					Name:            "foo",
					DNSQueue:        1000,
					TrafficQueue:    1001,
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "foo"
dnsQueue = 1000
trafficQueue = 1001
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
			InboundDNSQueue: 1,
			SelfDNSQueue:    100,
			Filters: []FilterOptions{
				{
					Name:           selfFilterName,
					DNSQueue:       100,
					AllowedDomains: []string{"oof", "rab"},
				},
				{
					Name:            "foo",
					DNSQueue:        1000,
					TrafficQueue:    1001,
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
inboundDNSQueue = 1
selfDNSQueue = 100

[[filters]]
name = "test1"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "5s"
allowedDomains = [
	"foo",
	"bar",
]

[[filters]]
name = "test3"
trafficQueue = 3001
reCacheEvery = "1s"
cachedDomains = [
	"oof",
	"rab",
]

[[filters]]
name = "test4"
dnsQueue = 4000
allowAllDomains = true`,
		expectedConfig: &Config{
			InboundDNSQueue: 1,
			SelfDNSQueue:    100,
			Filters: []FilterOptions{
				{
					Name:           "self-filter",
					DNSQueue:       100,
					AllowedDomains: []string{"oof", "rab"},
				},
				{
					Name:            "test1",
					DNSQueue:        1000,
					TrafficQueue:    1001,
					AllowAnswersFor: 5 * time.Second,
					AllowedDomains: []string{
						"foo",
						"bar",
					},
				},
				{
					Name:         "test3",
					TrafficQueue: 3001,
					ReCacheEvery: time.Second,
					CachedDomains: []string{
						"oof",
						"rab",
					},
				},
				{
					Name:            "test4",
					DNSQueue:        4000,
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
			err:        "contains illegal character _",
		},
		{
			name:       "with symbol",
			domainName: "sub#dom.domain.com",
			err:        "contains illegal character #",
		},
		{
			name:       "with leading hyphen",
			domainName: "-sub.domain.com",
			err:        "label starts with a dash",
		},
		{
			name:       "with trailing hyphen",
			domainName: "sub-.domain.com",
			err:        "label ends with a dash",
		},
		{
			name:       "too long",
			domainName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			err:        "exceeds 255 characters",
		},
		{
			name:       "label too long",
			domainName: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.domain.com",
			err:        "label exceeds 63 characters",
		},
		{
			name:       "last label too long",
			domainName: "sub.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			err:        "label exceeds 63 characters",
		},
		{
			name:       "empty label",
			domainName: "a..com",
			err:        "label is empty",
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
