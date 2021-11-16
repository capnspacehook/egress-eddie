package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	state_established = 3

	// used when allowing IPs after a reverse lookup and if
	// 'allowAnswersFor' isn't set
	default_ttl = 60
)

type FilterManager struct {
	queueNum uint16
	ipv6     bool

	logger *zap.Logger

	dnsRespNF *nfqueue.Nfqueue

	filters []*filter
}

type filter struct {
	opts *FilterOptions

	logger *zap.Logger

	dnsReqNF  *nfqueue.Nfqueue
	genericNF *nfqueue.Nfqueue

	connections *TimedCache
	// TODO: replace with net/netaddr when it gets released in the
	// standard library (1.18?)
	allowedIPs          *TimedCache
	additionalHostnames *TimedCache
}

func StartFilters(ctx context.Context, logger *zap.Logger, config *Config) (*FilterManager, error) {
	f := FilterManager{
		queueNum: config.InboundDNSQueue,
		ipv6:     config.IPv6,
		logger:   logger,
		filters:  make([]*filter, len(config.Filters)),
	}

	nf, err := startNfQueue(ctx, logger, config.InboundDNSQueue, config.IPv6, newDNSResponseCallback(&f))
	if err != nil {
		return nil, err
	}
	f.dnsRespNF = nf

	for i := range config.Filters {
		filter, err := startFilter(ctx, logger, &config.Filters[i])
		if err != nil {
			return nil, err
		}

		f.filters[i] = filter
	}

	return &f, nil
}

func (f *FilterManager) Stop() {
	for i := range f.filters {
		f.filters[i].close()
	}

	f.dnsRespNF.Close()
}

func startFilter(ctx context.Context, logger *zap.Logger, opts *FilterOptions) (*filter, error) {
	f := filter{
		opts:        opts,
		logger:      logger,
		connections: NewTimedCache(logger, true),
	}

	if opts.TrafficQueue != 0 {
		f.allowedIPs = NewTimedCache(logger, false)
		f.additionalHostnames = NewTimedCache(logger, false)

		genericNF, err := startNfQueue(ctx, logger, opts.TrafficQueue, opts.IPv6, newGenericCallback(&f))
		if err != nil {
			return nil, fmt.Errorf("error opening nfqueue: %v", err)
		}
		f.genericNF = genericNF
	}

	dnsNF, err := startNfQueue(ctx, logger, opts.DNSQueue, opts.IPv6, newDNSRequestCallback(&f))
	if err != nil {
		return nil, fmt.Errorf("error opening nfqueue: %v", err)
	}
	f.dnsReqNF = dnsNF

	return &f, nil
}

func startNfQueue(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, hook nfqueue.HookFunc) (*nfqueue.Nfqueue, error) {
	afFamily := unix.AF_INET
	if ipv6 {
		afFamily = unix.AF_INET6
	}

	nfqConf := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  0xffff,
		AfFamily:     uint8(afFamily),
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	}

	nf, err := nfqueue.Open(&nfqConf)
	if err != nil {
		return nil, fmt.Errorf("error opening nfqueue: %v", err)
	}

	if err := nf.RegisterWithErrorFunc(ctx, hook, newErrorCallback(logger)); err != nil {
		nf.Close()
		return nil, fmt.Errorf("error registering nfqueue: %v", err)
	}
	logger.Info("started nfqueue", zap.Uint16("nfqueue", queueNum))

	return nf, nil
}

func (f *filter) close() {
	f.dnsReqNF.Close()
	if f.genericNF != nil {
		f.genericNF.Close()
	}
}

func newDNSRequestCallback(f *filter) nfqueue.HookFunc {
	logger := f.logger.With(zap.Uint16("queue.num", f.opts.DNSQueue))

	return func(attr nfqueue.Attribute) int {
		if attr.PacketID == nil {
			return 0
		}
		if attr.CtInfo == nil {
			return 0
		}
		if attr.Payload == nil {
			return 0
		}

		dns, connID, err := parseDNSPacket(*attr.Payload, f.opts.IPv6, false)
		if err != nil {
			logger.Error("error parsing DNS packet", zap.NamedError("error", err))
			return 0
		}
		logger := logger.With(zap.String("conn.id", connID))

		// validate DNS request questions are for allowed
		// hostnames, drop them otherwise
		if !f.opts.AllowAllHostnames && !f.validateDNSQuestions(logger, dns) {
			if err := f.dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		logger.Info("allowing DNS request", zap.Strings("questions", questionStrings(dns.Questions)))

		// give DNS connections a minute to finish max
		logger.Debug("adding connection")
		f.connections.AddEntry(connID, time.Minute)

		if err := f.dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
			logger.Debug("removing connection")
			f.connections.RemoveEntry(connID)
			return 0
		}

		return 0
	}
}

func parseDNSPacket(packet []byte, ipv6, inbound bool) (*layers.DNS, string, error) {
	var (
		ip4     layers.IPv4
		ip6     layers.IPv6
		udp     layers.UDP
		tcp     layers.TCP
		dns     layers.DNS
		parser  *gopacket.DecodingLayerParser
		decoded = make([]gopacket.LayerType, 0, 3)
	)

	// parse DNS packet
	if !ipv6 {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &tcp, &dns)
	} else {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &udp, &tcp, &dns)
	}

	if err := parser.DecodeLayers(packet, &decoded); err != nil {
		return nil, "", err
	}
	if len(decoded) != 3 {
		return nil, "", errors.New("not all layers were parsed")
	}

	var (
		connIDBuilder    strings.Builder
		connType         string
		srcIP, dstIP     string
		srcPort, dstPort string
	)

	// build connection ID so dns requests/responses can be correlated
	if decoded[0] == layers.LayerTypeIPv4 {
		srcIP = ip4.SrcIP.String()
		dstIP = ip4.DstIP.String()
	} else {
		srcIP = ip6.SrcIP.String()
		dstIP = ip6.DstIP.String()
	}
	if decoded[1] == layers.LayerTypeUDP {
		connType = "udp"
		srcPort = strconv.Itoa(int(udp.SrcPort))
		dstPort = strconv.Itoa(int(udp.DstPort))
	} else {
		connType = "tcp"
		srcPort = strconv.Itoa(int(tcp.SrcPort))
		dstPort = strconv.Itoa(int(tcp.DstPort))
	}

	connIDBuilder.WriteString(connType)
	connIDBuilder.WriteByte('|')
	if inbound {
		connIDBuilder.WriteString(dstIP)
		connIDBuilder.WriteByte(':')
		connIDBuilder.WriteString(dstPort)
		connIDBuilder.WriteByte('-')
		connIDBuilder.WriteString(srcIP)
		connIDBuilder.WriteByte(':')
		connIDBuilder.WriteString(srcPort)
	} else {
		connIDBuilder.WriteString(srcIP)
		connIDBuilder.WriteByte(':')
		connIDBuilder.WriteString(srcPort)
		connIDBuilder.WriteByte('-')
		connIDBuilder.WriteString(dstIP)
		connIDBuilder.WriteByte(':')
		connIDBuilder.WriteString(dstPort)
	}

	return &dns, connIDBuilder.String(), nil
}

func (f *filter) validateDNSQuestions(logger *zap.Logger, dns *layers.DNS) bool {
	if dns.QDCount == 0 {
		// drop DNS requests with no questions; this probably
		// doesn't happen in practice but doesn't hurt to
		// handle this case
		logger.Info("dropping dns request with no questions")
		return false
	}

	for i := range dns.Questions {
		// bail out if any of the questions don't contain an allowed
		// hostname
		qName := string(dns.Questions[i].Name)
		if !f.hostnameAllowed(qName) {
			logger.Info("dropping DNS request", zap.ByteString("question", dns.Questions[i].Name))
			return false
		}
	}

	return true
}

func (f *filter) hostnameAllowed(hostname string) bool {
	for j := range f.opts.Hostnames {
		if hostname == f.opts.Hostnames[j] || strings.HasSuffix(hostname, "."+f.opts.Hostnames[j]) {
			return true
		}
	}

	return f.additionalHostnames.EntryExists(hostname)
}

func questionStrings(dnsQs []layers.DNSQuestion) []string {
	questions := make([]string, len(dnsQs))
	for i := range dnsQs {
		questions[i] = string(dnsQs[i].Name) + ": " + dnsQs[i].Type.String()
	}

	return questions
}

func newDNSResponseCallback(f *FilterManager) nfqueue.HookFunc {
	logger := f.logger.With(zap.Uint16("queue.num", f.queueNum))

	return func(attr nfqueue.Attribute) int {
		if attr.PacketID == nil {
			return 0
		}
		if attr.CtInfo == nil {
			return 0
		}
		if attr.Payload == nil {
			return 0
		}

		// since DNS requests are filtered above, we only process
		// DNS responses of established packets to make sure a
		// local attacker can't connect to disallowed IPs by
		// sending a DNS response with an attacker specified IP
		// as an answer, thereby allowing that IP
		if *attr.CtInfo != state_established {
			logger.Warn("dropping DNS response with that is not from an established connection")

			if err := f.dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		dns, connID, err := parseDNSPacket(*attr.Payload, f.ipv6, true)
		if err != nil {
			logger.Error("error parsing DNS packet", zap.NamedError("error", err))
			return 0
		}
		logger := logger.With(zap.String("conn.id", connID))

		// TODO: optimize
		var connFilter *filter
		for _, filter := range f.filters {
			if filter.connections.EntryExists(connID) {
				connFilter = filter
			}
		}
		if connFilter == nil {
			logger.Warn("dropping DNS response from unknown connection", zap.Strings("questions", questionStrings(dns.Questions)))

			if err := f.dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}
		logger.Debug("removing connection")
		connFilter.connections.RemoveEntry(connID)

		// validate DNS response questions are for allowed
		// hostnames, drop them otherwise; responses for disallowed
		// hostnames should never happen in theory, because we
		// block requests for disallowed hostnames but it doesn't
		// hurt to check
		if !connFilter.opts.AllowAllHostnames && !connFilter.validateDNSQuestions(logger, dns) {
			if err := f.dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		if !connFilter.opts.AllowAllHostnames && dns.ANCount > 0 {
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					// temporarily add A and AAAA answers to
					// allowed IP list
					ipStr := answer.IP.String()
					ttl := connFilter.getTTL(answer.TTL)
					logger.Info("allowing IP from DNS reply", zap.String("answer.ip", ipStr), zap.Duration("answer.ttl", ttl))

					connFilter.allowedIPs.AddEntry(ipStr, ttl)
				} else if answer.Type == layers.DNSTypeCNAME {
					// temporarily add CNAME answers to allowed
					// hostnames list
					ttl := connFilter.getTTL(answer.TTL)
					logger.Info("allowing hostname from DNS reply", zap.ByteString("answer.name", answer.CNAME), zap.Duration("answer.ttl", ttl))

					connFilter.additionalHostnames.AddEntry(string(answer.CNAME), connFilter.getTTL(answer.TTL))
				} else if answer.Type == layers.DNSTypeSRV {
					// temporarily add SRV answers to allowed
					// hostnames list
					ttl := connFilter.getTTL(answer.TTL)
					logger.Info("allowing hostname from DNS reply", zap.ByteString("answer.name", answer.SRV.Name), zap.Duration("answer.ttl", ttl))

					connFilter.additionalHostnames.AddEntry(string(answer.SRV.Name), connFilter.getTTL(answer.TTL))
				}
			}
		}

		if err := f.dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
			return 0
		}

		return 0
	}
}

func (f *filter) getTTL(ttl uint32) time.Duration {
	if f.opts.AllowAnswersFor != 0 {
		return f.opts.AllowAnswersFor
	}

	return time.Duration(ttl) * time.Second
}

func newGenericCallback(f *filter) nfqueue.HookFunc {
	logger := f.logger.With(zap.Uint16("queue.num", f.opts.TrafficQueue))

	return func(attr nfqueue.Attribute) int {
		if attr.PacketID == nil {
			return 0
		}
		if attr.Payload == nil {
			return 0
		}

		var (
			ip4     layers.IPv4
			ip6     layers.IPv6
			parser  *gopacket.DecodingLayerParser
			decoded = make([]gopacket.LayerType, 1)
		)

		// parse packet
		if !f.opts.IPv6 {
			parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4)
			parser.IgnoreUnsupported = true
			parser.SetDecodingLayerContainer(gopacket.DecodingLayerArray(nil))
			parser.AddDecodingLayer(&ip4)
		} else {
			parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6)
			parser.IgnoreUnsupported = true
			parser.SetDecodingLayerContainer(gopacket.DecodingLayerArray(nil))
			parser.AddDecodingLayer(&ip6)
		}

		if err := parser.DecodeLayers(*attr.Payload, &decoded); err != nil {
			logger.Error("error parsing packet", zap.NamedError("error", err))
			return 0
		}

		// get source and destination IP
		var (
			src, dst     string
			srcIP, dstIP net.IP
		)

		if decoded[0] == layers.LayerTypeIPv4 {
			src = ip4.SrcIP.String()
			srcIP = ip4.SrcIP
			dst = ip4.DstIP.String()
			dstIP = ip4.DstIP
		} else if decoded[0] == layers.LayerTypeIPv6 {
			src = ip6.SrcIP.String()
			srcIP = ip6.SrcIP
			dst = ip6.DstIP.String()
			dstIP = ip6.DstIP
		}

		// validate that either the source or destination IP is allowed
		var verdict int
		allowed, err := f.validateIPs(logger, src, dst, srcIP, dstIP)
		if err != nil {
			logger.Error("error validating IPs", zap.String("conn.src", src), zap.String("conn.dst", dst), zap.NamedError("error", err))
			verdict = nfqueue.NfDrop
		} else {
			if allowed {
				logger.Info("allowing packet", zap.String("conn.src", src), zap.String("conn.dst", dst))
				verdict = nfqueue.NfAccept
			} else {
				logger.Info("dropping packet", zap.String("conn.src", src), zap.String("conn.dst", dst))
				verdict = nfqueue.NfDrop
			}
		}

		if err := f.genericNF.SetVerdict(*attr.PacketID, verdict); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
		}

		return 0
	}
}

func (f *filter) validateIPs(logger *zap.Logger, src, dst string, srcIP, dstIP net.IP) (bool, error) {
	// check if the destination IP is allowed first, as most likely
	// we are validating an outbound connection
	if f.allowedIPs.EntryExists(dst) {
		return true, nil
	}

	// check if source IP is allowed; if reverse IP lookups are
	// disabled or the IP is allowed return early
	allowed := f.allowedIPs.EntryExists(src)
	if !f.opts.LookupUnknownIPs || allowed {
		return allowed, nil
	}

	// preform reverse IP lookups on the destination and then source
	// IPs only if the IPs are not private
	if !dstIP.IsPrivate() {
		allowed, err := f.lookupAndValidateIP(logger, dst)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	if !srcIP.IsPrivate() {
		return f.lookupAndValidateIP(logger, src)
	}

	return false, nil
}

func (f *filter) lookupAndValidateIP(logger *zap.Logger, ip string) (bool, error) {
	logger.Info("preforming reverse IP lookup", zap.String("ip", ip))
	names, err := net.LookupAddr(ip)
	if err != nil {
		// don't return error if IP simply couldn't be found
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}

	for i := range names {
		if names[i][len(names[i])-1] == '.' {
			names[i] = names[i][:len(names[i])-1]
		}

		if f.hostnameAllowed(names[i]) {
			ttl := f.getTTL(default_ttl)
			logger.Info("allowing IP after reverse lookup", zap.String("ip", ip), zap.Duration("ttl", ttl))
			f.allowedIPs.AddEntry(ip, ttl)
			return true, nil
		}
	}

	return false, nil
}

func newErrorCallback(logger *zap.Logger) nfqueue.ErrorFunc {
	return func(err error) int {
		// skip noisy errors that aren't important when exiting
		var nerr *netlink.OpError
		if errors.As(err, &nerr) {
			if strings.Contains(err.Error(), "i/o timeout") ||
				strings.Contains(err.Error(), "use of closed file") {
				return 0
			}
		}

		logger.Error("netlink error", zap.NamedError("error", err))

		return 0
	}
}
