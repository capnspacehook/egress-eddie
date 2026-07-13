package egresseddie

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type serPkt struct {
	payload []byte
	hwProto uint16
}

func createPackets(tb testing.TB, responses bool) []serPkt {
	tb.Helper()

	ipv4Layer := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    netip.MustParseAddr("10.1.0.1").AsSlice(),
		DstIP:    netip.MustParseAddr("1.1.1.1").AsSlice(),
	}
	ipv6Layer := layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      netip.MustParseAddr("fd00:1::1").AsSlice(),
		DstIP:      netip.MustParseAddr("2606:4700:4700::1111").AsSlice(),
	}
	udpLayer := layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}

	matchingDNSMsg := dns.NewMsg("domain.com.", dns.TypeA)
	if responses {
		matchingDNSMsg.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: "domain.com.", Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
		}}
	}
	matchingDNSMsg.ID = 0
	if err := matchingDNSMsg.Pack(); err != nil {
		tb.Fatalf("packing DNS message: %v", err)
	}

	var nonMatchingDNSMsg *dns.Msg
	if responses {
		nonMatchingDNSMsg = dns.NewMsg("sub.domain.com.", dns.TypeAAAA)
		nonMatchingDNSMsg.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.Header{Name: "sub.domain-mine.com.", Class: dns.ClassINET, TTL: 60},
			AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:4700:4700::1234")},
		}}
	} else {
		nonMatchingDNSMsg = dns.NewMsg("sub.domain-mine.com.", dns.TypeAAAA)
	}
	nonMatchingDNSMsg.ID = 0
	if err := nonMatchingDNSMsg.Pack(); err != nil {
		tb.Fatalf("packing DNS message: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	packets := make([]serPkt, 4)

	// ipv4 matching DNS request
	err := gopacket.SerializeLayers(buf, opts, &ipv4Layer, &udpLayer, gopacket.Payload(matchingDNSMsg.Data))
	if err != nil {
		tb.Fatalf("serializing packet: %v", err)
	}
	packets[0] = serPkt{
		payload: bytes.Clone(buf.Bytes()),
		hwProto: unix.ETH_P_IP,
	}

	// ipv4 non-matching DNS request
	err = gopacket.SerializeLayers(buf, opts, &ipv4Layer, &udpLayer, gopacket.Payload(nonMatchingDNSMsg.Data))
	if err != nil {
		tb.Fatalf("serializing packet: %v", err)
	}
	packets[1] = serPkt{
		payload: bytes.Clone(buf.Bytes()),
		hwProto: unix.ETH_P_IP,
	}

	// ipv6 matching DNS request
	err = gopacket.SerializeLayers(buf, opts, &ipv6Layer, &udpLayer, gopacket.Payload(matchingDNSMsg.Data))
	if err != nil {
		tb.Fatalf("serializing packet: %v", err)
	}
	packets[2] = serPkt{
		payload: bytes.Clone(buf.Bytes()),
		hwProto: unix.ETH_P_IPV6,
	}

	// ipv6 non-matching DNS request
	err = gopacket.SerializeLayers(buf, opts, &ipv6Layer, &udpLayer, gopacket.Payload(nonMatchingDNSMsg.Data))
	if err != nil {
		tb.Fatalf("serializing packet: %v", err)
	}
	packets[3] = serPkt{
		payload: bytes.Clone(buf.Bytes()),
		hwProto: unix.ETH_P_IPV6,
	}

	return packets
}

func setupFilters(tb testing.TB) {
	tb.Helper()

	config := Config{
		DNSResponseQueue: 1,
		Filters: []FilterOptions{
			{
				Name:            "test",
				DNSQueue:        1000,
				TrafficQueue:    1001,
				AllowAnswersFor: 5 * time.Second,
				AllowedDomains:  []string{"*.domain.com", "domain.com"},
			},
		},
		enforcerCreator: newMockEnforcer,
	}
	initMockEnforcers()

	if err := checkConfig(&config); err != nil {
		tb.Fatalf("checking config: %v", err)
	}

	ctx, cancel := context.WithCancel(tb.Context())
	tb.Cleanup(cancel)

	f, err := CreateFilters(ctx, zap.NewNop(), &config, false, false)
	if err != nil {
		tb.Fatalf("creating filters: %v", err)
	}
	f.Start()
	tb.Cleanup(f.Stop)
}

func BenchmarkDNSFilters(b *testing.B) {
	b.ReportAllocs()

	requests := createPackets(b, false)
	responses := createPackets(b, true)
	setupFilters(b)

	for b.Loop() {
		for _, packet := range requests {
			mockEnforcers[1000].hook(nfqueue.Attribute{
				PacketID:   new(uint32(420)),
				CtInfo:     new(uint32(stateNew)),
				HwProtocol: new(packet.hwProto),
				Payload:    new(packet.payload),
			})
		}
		for _, packet := range responses {
			mockEnforcers[1].hook(nfqueue.Attribute{
				PacketID:   new(uint32(420)),
				CtInfo:     new(uint32(stateEstablished)),
				HwProtocol: new(packet.hwProto),
				Payload:    new(packet.payload),
			})
		}
	}
}

func BenchmarkGenericFilter(b *testing.B) {
	b.ReportAllocs()

	packets := createPackets(b, false)
	setupFilters(b)

	for b.Loop() {
		for _, packet := range packets {
			mockEnforcers[1001].hook(nfqueue.Attribute{
				PacketID:   new(uint32(420)),
				CtInfo:     new(uint32(stateNew)),
				HwProtocol: new(packet.hwProto),
				Payload:    new(packet.payload),
			})
		}
	}
}
