package egresseddie

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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

func FuzzConnectionID(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testConnectionID))
}

func TestConnectionID(t *testing.T) {
	rapid.Check(t, testConnectionID)
}

func testConnectionID(t *rapid.T) {
	ipv6 := rapid.Bool().Draw(t, "ipv6")
	var srcIP, dstIP netip.Addr
	if !ipv6 {
		srcIP = GenIPv4Addr().Draw(t, "srcIP")
		dstIP = GenIPv4Addr().Draw(t, "dstIP")
	} else {
		srcIP = GenIPv6Addr().Draw(t, "srcIP")
		dstIP = GenIPv6Addr().Draw(t, "dstIP")
	}
	srcPort := rapid.Uint16().Draw(t, "srcPort")
	dstPort := rapid.Uint16().Draw(t, "dstPort")

	var ipLayer gopacket.SerializableLayer
	if !ipv6 {
		ipv4Layer := rapid.Make[layers.IPv4]().Draw(t, "ipv4Layer")
		ipv4Layer.Protocol = layers.IPProtocolUDP
		ipv4Layer.SrcIP = srcIP.AsSlice()
		ipv4Layer.DstIP = dstIP.AsSlice()
		ipv4Layer.Payload = nil
		ipv4Layer.Contents = nil
		ipLayer = &ipv4Layer
	} else {
		ipv6Layer := rapid.Make[layers.IPv6]().Draw(t, "ipv6Layer")
		ipv6Layer.NextHeader = layers.IPProtocolUDP
		ipv6Layer.SrcIP = srcIP.AsSlice()
		ipv6Layer.DstIP = dstIP.AsSlice()
		ipv6Layer.Payload = nil
		ipv6Layer.Contents = nil
		ipLayer = &ipv6Layer
	}

	dnsMsg := dns.Msg{
		Question: []dns.Question{
			{
				Name:   "domain.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	dnsBytes, err := dnsMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	payload := gopacket.Payload(dnsBytes)

	udpLayer := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	err = gopacket.SerializeLayers(buf, opts, ipLayer, &udpLayer, payload)
	if err != nil {
		t.Skip()
	}

	_, connID, err := parseDNSPacket(buf.Bytes(), ipv6, true)
	if err != nil {
		t.Skip()
	}

	// inverse
	if !ipv6 {
		ipv4Layer := ipLayer.(*layers.IPv4)
		ipv4Layer.SrcIP = dstIP.AsSlice()
		ipv4Layer.DstIP = srcIP.AsSlice()
	} else {
		ipv6Layer := ipLayer.(*layers.IPv6)
		ipv6Layer.SrcIP = dstIP.AsSlice()
		ipv6Layer.DstIP = srcIP.AsSlice()
	}
	udpLayer.SrcPort = layers.UDPPort(dstPort)
	udpLayer.DstPort = layers.UDPPort(srcPort)

	buf = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, ipLayer, &udpLayer, payload)
	if err != nil {
		t.Skip()
	}

	_, connID2, err := parseDNSPacket(buf.Bytes(), ipv6, false)
	if err != nil {
		t.Skip()
	}

	if connID != connID2 {
		t.Fatal("connection IDs should be the same")
	}
}
