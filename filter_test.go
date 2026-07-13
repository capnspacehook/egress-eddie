package egresseddie

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/capnspacehook/glob"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
	"pgregory.net/rapid"

	"github.com/capnspacehook/egress-eddie/packet"
	"github.com/capnspacehook/egress-eddie/timedcache"
)

func TestDomainAllowed(t *testing.T) {
	t.Parallel()

	rapid.Check(t, testDomainAllowed)
}

func FuzzDomainAllowed(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testDomainAllowed))
}

func testDomainAllowed(t *rapid.T) {
	allowedDomain := GenDomainName().Draw(t, "allowedDomain")
	label := GenLabel().Draw(t, "label")

	equal := strings.EqualFold(label, allowedDomain)
	lastDotIdx := strings.LastIndexByte(allowedDomain, '.')
	var lastLabelEqual bool
	if lastDotIdx != -1 && len(allowedDomain) > lastDotIdx+1 {
		lastLabelEqual = strings.EqualFold(allowedDomain[lastDotIdx+1:], label)
	}

	lowerAllowedDomain := strings.ToLower(allowedDomain)
	matcher, err := createDomainMatcher(lowerAllowedDomain)
	if err != nil {
		t.Fatal(err)
	}
	subPattern := "*." + lowerAllowedDomain
	subMatcher, err := createDomainMatcher(subPattern)
	if err != nil {
		t.Fatal(err)
	}

	f := &filter{
		opts: &FilterOptions{
			allowedDomainMatchers: []glob.Glob{matcher, subMatcher},
		},
		logger: zap.NewNop(),

		allowedTargets: timedcache.New[string, struct{}](zap.NewNop(), false),
	}

	if !domainAllowed(t, f, strings.ToLower(allowedDomain)) {
		t.Fatal("lowercased allowed domain should be allowed")
	}
	if !domainAllowed(t, f, strings.ToUpper(allowedDomain)) {
		t.Fatal("uppercased allowed domain should be allowed")
	}

	if !domainAllowed(t, f, allowedDomain) {
		t.Fatal("allowed domain should be allowed")
	}
	if domainAllowed(t, f, "."+allowedDomain) {
		t.Fatal("allowed domain with leading dot should not be allowed")
	}
	newDomain := label + "." + allowedDomain
	if !domainAllowed(t, f, newDomain) {
		t.Fatal("subdomain of allowed domain should be allowed")
	}
	if !domainAllowed(t, f, strings.ToLower(newDomain)) {
		t.Fatal("lowercased subdomain of allowed domain should be allowed")
	}
	if !domainAllowed(t, f, strings.ToUpper(newDomain)) {
		t.Fatal("uppercased subdomain of allowed domain should be allowed")
	}

	if domainAllowed(t, f, label+allowedDomain) {
		t.Fatal("random string prepended to allowed domain should not be allowed")
	}
	if domainAllowed(t, f, allowedDomain+label) {
		t.Fatal("random string concatenated to allowed domain should not be allowed")
	}
	if domainAllowed(t, f, label+allowedDomain+label) {
		t.Fatal("random string surrounding allowed domain should not be allowed")
	}

	if !equal && !lastLabelEqual {
		if domainAllowed(t, f, allowedDomain+"."+label) {
			t.Fatal("random label concatenated to allowed domain should not be allowed")
		}
		if domainAllowed(t, f, label+"."+allowedDomain+"."+label) {
			t.Fatal("random label surrounding allowed domain should not be allowed")
		}
	}
	if equal && !domainAllowed(t, f, label) {
		t.Fatal("label equal to allowed domain should be allowed")
	}
}

func domainAllowed(t *rapid.T, f *filter, domain string) bool {
	t.Helper()

	ok, err := f.domainAllowed(domain)
	if err != nil {
		t.Log(err)
	}
	return ok
}

func FuzzConnectionID(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testConnectionID))
}

func TestConnectionID(t *testing.T) {
	t.Parallel()

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
		ipv4Layer := GenIPv4Layer().Draw(t, "ipv4Layer")
		ipv4Layer.Protocol = layers.IPProtocolUDP
		ipv4Layer.SrcIP = srcIP.AsSlice()
		ipv4Layer.DstIP = dstIP.AsSlice()
		ipv4Layer.Payload = nil
		ipv4Layer.Contents = nil
		ipLayer = &ipv4Layer
	} else {
		ipv6Layer := GenIPv6Layer().Draw(t, "ipv6Layer")
		ipv6Layer.NextHeader = layers.IPProtocolUDP
		ipv6Layer.SrcIP = srcIP.AsSlice()
		ipv6Layer.DstIP = dstIP.AsSlice()
		ipv6Layer.Payload = nil
		ipv6Layer.Contents = nil
		ipLayer = &ipv6Layer
	}

	dnsMsg := dns.NewMsg("domain.com.", dns.TypeA)
	if err := dnsMsg.Pack(); err != nil {
		t.Fatal(err)
	}
	payload := gopacket.Payload(dnsMsg.Data)

	udpLayer := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, &udpLayer, payload)
	if err != nil {
		t.Skip()
	}

	dec := packet.NewDNSDecoder()

	_, connID, err := dec.DecodeDNSPacket(buf.Bytes(), ipv6, true)
	if err != nil {
		t.Skip()
	}

	// inverse
	if !ipv6 {
		ipv4Layer, ok := ipLayer.(*layers.IPv4)
		if !ok {
			t.Fatalf("unexpected IPv4 layer type %T", ipLayer)
		}
		ipv4Layer.SrcIP = dstIP.AsSlice()
		ipv4Layer.DstIP = srcIP.AsSlice()
	} else {
		ipv6Layer, ok := ipLayer.(*layers.IPv6)
		if !ok {
			t.Fatalf("unexpected IPv6 layer type %T", ipLayer)
		}

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

	_, connID2, err := dec.DecodeDNSPacket(buf.Bytes(), ipv6, false)
	if err != nil {
		t.Skip()
	}

	if connID != connID2 {
		t.Fatal("connection IDs should be the same")
	}
}

func TestStripPrefixLabels(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		pd := GenPrefixedDomainName().Draw(t, "prefixedDomain")

		stripped, numLabels := stripPrefixLabels(pd.Name)
		if numLabels != pd.PrefixLabels {
			t.Errorf("numLabels mismatch: want %d, got %d", pd.PrefixLabels, numLabels)
		}
		if stripped != pd.Name[pd.PostPrefixIdx:] {
			t.Errorf("stripped name mismatch: want %q, got %q", pd.Name[pd.PostPrefixIdx:], stripped)
		}
	})
}
