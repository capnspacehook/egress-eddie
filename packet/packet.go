package packet

import (
	"errors"
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	"github.com/capnspacehook/egress-eddie/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Decoder struct {
	ip4 *layers.IPv4
	ip6 *layers.IPv6
	udp *layers.UDP

	ipv4DNSParser     *gopacket.DecodingLayerParser
	ipv6DNSParser     *gopacket.DecodingLayerParser
	ipv4GenericParser *gopacket.DecodingLayerParser
	ipv6GenericParser *gopacket.DecodingLayerParser

	decoded []gopacket.LayerType
}

func NewDecoder() Decoder {
	d := Decoder{
		ip4:     new(layers.IPv4),
		ip6:     new(layers.IPv6),
		udp:     new(layers.UDP),
		decoded: make([]gopacket.LayerType, 0, 2),
	}

	// create and reuse the parsers to avoid allocating one for each
	// packet; DNS parsers need to have IgnoreUnsupported set because
	// gopacket isn't parsing DNS, generic parsers need it set so they
	// don't error out when trying to parse above layer 3
	d.ipv4DNSParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4)
	d.ipv4DNSParser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	d.ipv4DNSParser.AddDecodingLayer(d.ip4)
	d.ipv4DNSParser.AddDecodingLayer(d.udp)
	d.ipv4DNSParser.IgnoreUnsupported = true

	d.ipv4GenericParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4)
	d.ipv4GenericParser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	d.ipv4GenericParser.AddDecodingLayer(d.ip4)
	d.ipv4GenericParser.IgnoreUnsupported = true

	d.ipv6DNSParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6)
	d.ipv6DNSParser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	d.ipv6DNSParser.AddDecodingLayer(d.ip6)
	d.ipv6DNSParser.AddDecodingLayer(d.udp)
	d.ipv6DNSParser.IgnoreUnsupported = true

	d.ipv6GenericParser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6)
	d.ipv6GenericParser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	d.ipv6GenericParser.AddDecodingLayer(d.ip6)
	d.ipv6GenericParser.IgnoreUnsupported = true

	return d
}

func (d *Decoder) clearIPv4() {
	*d.ip4 = layers.IPv4{}
}

func (d *Decoder) clearIPv6() {
	*d.ip6 = layers.IPv6{}
}

func (d *Decoder) clearUDP() {
	*d.udp = layers.UDP{}
}

func (d *Decoder) DecodeDNSPacket(packet []byte, ipv6, inbound bool) (_ *dns.Msg, connID types.ConnectionID, err error) {
	d.clearUDP()

	var payload []byte
	if ipv6 {
		d.clearIPv6()
		payload, connID, err = d.decodePacket(d.ipv6DNSParser, packet, 2, inbound)
	} else {
		d.clearIPv4()
		payload, connID, err = d.decodePacket(d.ipv4DNSParser, packet, 2, inbound)
	}
	if err != nil {
		return nil, types.ConnectionID{}, err
	}

	dnsMsg := dns.Msg{Data: payload}
	if err := dnsMsg.Unpack(); err != nil {
		return nil, types.ConnectionID{}, fmt.Errorf("decoding DNS message: %w", err)
	}

	return &dnsMsg, connID, nil
}

func (d *Decoder) DecodePacket(packet []byte, ipv6, inbound bool) (types.ConnectionID, error) {
	if ipv6 {
		d.clearIPv6()
		_, connID, err := d.decodePacket(d.ipv6GenericParser, packet, 1, inbound)
		return connID, err
	}

	d.clearIPv4()
	_, connID, err := d.decodePacket(d.ipv4GenericParser, packet, 1, inbound)
	return connID, err
}

func (d *Decoder) decodePacket(parser *gopacket.DecodingLayerParser, packet []byte, expectedLayers int, inbound bool) ([]byte, types.ConnectionID, error) {
	if err := parser.DecodeLayers(packet, &d.decoded); err != nil {
		return nil, types.ConnectionID{}, fmt.Errorf("decoding packet: %w", err)
	}
	if len(d.decoded) != expectedLayers {
		return nil, types.ConnectionID{}, fmt.Errorf("%d layers were parsed, expecting %d", len(d.decoded), expectedLayers)
	}

	// build connection ID so dns requests/responses can be correlated
	var (
		src, dst     netip.Addr
		srcOK, dstOK bool
	)

	switch d.decoded[0] {
	case layers.LayerTypeIPv4:
		src, srcOK = netip.AddrFromSlice(d.ip4.SrcIP)
		dst, dstOK = netip.AddrFromSlice(d.ip4.DstIP)
	case layers.LayerTypeIPv6:
		src, srcOK = netip.AddrFromSlice(d.ip6.SrcIP)
		dst, dstOK = netip.AddrFromSlice(d.ip6.DstIP)
	default:
		return nil, types.ConnectionID{}, fmt.Errorf("unknown IP protocol %s", d.decoded[0])
	}
	if !srcOK || !dstOK {
		return nil, types.ConnectionID{}, errors.New("converting IPs")
	}

	var srcPort, dstPort uint16
	var payload []byte
	if expectedLayers == 2 {
		srcPort = uint16(d.udp.SrcPort)
		dstPort = uint16(d.udp.DstPort)
		payload = d.udp.Payload
	}

	connID := types.ConnectionID{}
	if inbound {
		connID.Src = netip.AddrPortFrom(dst, dstPort)
		connID.Dst = netip.AddrPortFrom(src, srcPort)
	} else {
		connID.Src = netip.AddrPortFrom(src, srcPort)
		connID.Dst = netip.AddrPortFrom(dst, dstPort)
	}

	return payload, connID, nil
}
