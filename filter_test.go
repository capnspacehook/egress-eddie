package egresseddie

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"pgregory.net/rapid"

	"github.com/capnspacehook/egress-eddie/timedcache"
)

const (
	domainRegex = `(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])`
	labelRegex  = "[a-zA-Z0-9]{1,63}"
)

func TestDomainAllowed(t *testing.T) {
	rapid.Check(t, testDomainAllowed)
}

func FuzzDomainAllowed(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testDomainAllowed))
}

func testDomainAllowed(t *rapid.T) {
	allowedDomain := rapid.StringMatching(domainRegex).Draw(t, "allowedDomain")
	label := rapid.StringMatching(labelRegex).Draw(t, "label")
	_, isValidDomain := dns.IsDomainName(label)

	trailingDot := label[len(label)-1] == '.'
	equal := strings.EqualFold(label, allowedDomain)

	lastDotIdx := strings.LastIndexByte(allowedDomain, '.')
	var lastLabelEqual bool
	if lastDotIdx != -1 && len(allowedDomain) > lastDotIdx+1 {
		lastLabelEqual = strings.EqualFold(allowedDomain[lastDotIdx+1:], label)
	}

	f := &filter{
		opts: &FilterOptions{
			AllowedDomains: []string{allowedDomain},
		},
		logger: zap.NewNop(),

		additionalDomains: timedcache.New[string](zap.NewNop(), false),
	}

	if !f.domainAllowed(strings.ToLower(allowedDomain)) {
		t.Fatal("lowercased allowed domain should be allowed")
	}
	if !f.domainAllowed(strings.ToUpper(allowedDomain)) {
		t.Fatal("uppercased allowed domain should be allowed")
	}

	if !f.domainAllowed(allowedDomain) {
		t.Fatal("allowed domain should be allowed")
	}
	if !f.domainAllowed("." + allowedDomain) {
		t.Fatal("allowed domain with leading dot should be allowed")
	}
	if isValidDomain {
		newDomain := label + "." + allowedDomain
		if !f.domainAllowed(newDomain) {
			t.Fatal("subdomain of allowed domain should be allowed")
		}
		if !f.domainAllowed(strings.ToLower(newDomain)) {
			t.Fatal("lowercased subdomain of allowed domain should be allowed")
		}
		if !f.domainAllowed(strings.ToUpper(newDomain)) {
			t.Fatal("uppercased subdomain of allowed domain should be allowed")
		}
	}

	if !trailingDot {
		if f.domainAllowed(label + allowedDomain) {
			t.Fatal("random string prepended to allowed domain should not be allowed")
		}
	}
	if f.domainAllowed(allowedDomain + label) {
		t.Fatal("random string concatenated to allowed domain should not be allowed")
	}
	if f.domainAllowed(label + allowedDomain + label) {
		t.Fatal("random string surrounding allowed domain should not be allowed")
	}

	if !equal && !lastLabelEqual {
		if f.domainAllowed(allowedDomain + "." + label) {
			t.Fatal("random label concatenated to allowed domain should not be allowed")
		}
		if f.domainAllowed(label + "." + allowedDomain + "." + label) {
			t.Fatal("random label surrounding allowed domain should not be allowed")
		}
	}
	if equal && !f.domainAllowed(label) {
		t.Fatal("label equal to allowed domain should be allowed")
	}
}
