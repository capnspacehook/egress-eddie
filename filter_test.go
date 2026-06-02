package egresseddie

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/matryer/is"
	"github.com/miekg/dns"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"hegel.dev/go/hegel"

	"github.com/capnspacehook/egress-eddie/timedcache"
)

func TestDomainAllowed(t *testing.T) {
	skipIfTestingBinary(t)

	hegel.Test(t, func(ht *hegel.T) {
		allowedDomain := hegel.Draw(ht, hegel.Domains())
		label := string(hegel.Draw(ht, hegel.Binary(1, 63)))
		_, isValidDomain := dns.IsDomainName(label)

		trailingDot := label[len(label)-1] == '.'

		f := &filter{
			opts: &FilterOptions{
				AllowedDomains: []string{allowedDomain},
			},
			logger: zap.NewNop(),

			additionalDomains: timedcache.New[string](zap.NewNop(), false),
		}

		if !checkDomainAllowed(ht, f, strings.ToLower(allowedDomain)) {
			ht.Fatal("lowercased allowed domain should be allowed")
		}
		if !checkDomainAllowed(ht, f, strings.ToUpper(allowedDomain)) {
			ht.Fatal("uppercased allowed domain should be allowed")
		}

		if !checkDomainAllowed(ht, f, allowedDomain) {
			ht.Fatal("allowed domain should be allowed")
		}
		if !checkDomainAllowed(ht, f, "."+allowedDomain) {
			ht.Fatal("allowed domain with leading dot should be allowed")
		}
		if isValidDomain {
			newDomain := label + "." + allowedDomain
			if !checkDomainAllowed(ht, f, newDomain) {
				ht.Fatal("subdomain of allowed domain should be allowed")
			}
			if !checkDomainAllowed(ht, f, strings.ToLower(newDomain)) {
				ht.Fatal("lowercased subdomain of allowed domain should be allowed")
			}
			if !checkDomainAllowed(ht, f, strings.ToUpper(newDomain)) {
				ht.Fatal("uppercased subdomain of allowed domain should be allowed")
			}
		}

		if strings.EqualFold(label, allowedDomain) {
			if checkDomainAllowed(ht, f, label) {
				ht.Fatal("random domain should not be allowed")
			}
		}
		if !trailingDot {
			if checkDomainAllowed(ht, f, label+allowedDomain) {
				ht.Fatal("random string prepended to allowed domain should not be allowed")
			}
		}
		if checkDomainAllowed(ht, f, allowedDomain+label) {
			ht.Fatal("random string concatenated to allowed domain should not be allowed")
		}
		if checkDomainAllowed(ht, f, allowedDomain+"."+label) {
			ht.Fatal("random label concatenated to allowed domain should not be allowed")
		}
		if checkDomainAllowed(ht, f, label+allowedDomain+label) {
			ht.Fatal("random string surrounding allowed domain should not be allowed")
		}
		if checkDomainAllowed(ht, f, label+"."+allowedDomain+"."+label) {
			ht.Fatal("random label surrounding allowed domain should not be allowed")
		}
	})
}

func checkDomainAllowed(ht *hegel.T, f *filter, domain string) bool {
	ht.Helper()

	ht.Note(domain)

	return f.domainAllowed(domain)
}

func TestFiltersStart(t *testing.T) {
	skipIfTestingBinary(t)

	configBytes := []byte(`
inboundDNSQueue.ipv6 = 10
selfDNSQueue.ipv6 = 110

[[filters]]
name = "test"
dnsQueue.ipv6 = 1010
trafficQueue.ipv6 = 1011
reCacheEvery = "1m"
cachedDomains = [
	"example.com",
]
allowAnswersFor = "1s"
allowedDomains = [
	"test.org"
]`)

	is := is.New(t)

	config, err := parseConfigBytes(configBytes)
	is.NoErr(err)

	config.enforcerCreator = newMockEnforcer

	t.Run("filters waiting", func(t *testing.T) {
		is := is.New(t)

		initMockEnforcers()

		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false)
		is.NoErr(err)
		t.Cleanup(func() {
			cancel()
			f.Stop()
		})

		finishedAt := make(chan time.Time)

		go func() {
			mockEnforcers[config.InboundDNSQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished DNS reply queue")
			finishedAt <- time.Now()
		}()
		// the self-filter will be the first filter
		testFilter := config.Filters[1]
		go func() {
			mockEnforcers[testFilter.DNSQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished DNS request queue")
			finishedAt <- time.Now()
		}()
		go func() {
			mockEnforcers[testFilter.TrafficQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished generic queue")
			finishedAt <- time.Now()
		}()

		time.Sleep(time.Second)
		startedAt := time.Now()
		f.Start()
		t.Log("starting filters")

		for range 3 {
			t := <-finishedAt
			is.True(t.After(startedAt)) // packet handling should have finished after filters were started
		}
	})

	t.Run("stopping without starting", func(t *testing.T) {
		is := is.New(t)

		// test that goroutines are cleanly shutdown
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		// use real nfqueues
		config.enforcerCreator = nil
		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false)
		is.NoErr(err)

		cancel()
		f.Stop()
	})
}
