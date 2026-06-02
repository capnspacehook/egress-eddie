package egresseddie

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"hegel.dev/go/hegel"

	"github.com/capnspacehook/egress-eddie/timedcache"
)

func TestDomainAllowed(t *testing.T) {
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
