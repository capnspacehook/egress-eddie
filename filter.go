package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	// from github.com/torvalds/linux/tree/master/include/uapi/linux/netfilter/nf_conntrack_common.h
	stateEstablished = iota
	stateRelated
	stateNew
	stateIsReply
	stateEstablishedReply = stateEstablished + stateIsReply
	stateRelatedReply     = stateRelated + stateIsReply
	stateUntracked        = 7

	dnsQueryTimeout = time.Minute
)

type FilterManager struct {
	ready chan struct{}

	logger *zap.Logger

	queueNum4 uint16
	queueNum6 uint16

	dnsRespNF4 enforcer
	dnsRespNF6 enforcer

	filters []*filter
}

type filter struct {
	dnsReqNFReady  chan struct{}
	genericNFReady chan struct{}
	wg             sync.WaitGroup

	opts *FilterOptions

	logger *zap.Logger

	dnsReqNF4  enforcer
	dnsReqNF6  enforcer
	genericNF4 enforcer
	genericNF6 enforcer

	res resolver

	connections         *TimedCache[connectionID]
	allowedIPs          *TimedCache[netip.Addr]
	additionalHostnames *TimedCache[string]

	isSelfFilter bool
}

type connectionID struct {
	isUDP bool
	src   netip.AddrPort
	dst   netip.AddrPort
}

func (c connectionID) String() string {
	var b strings.Builder

	if c.isUDP {
		b.WriteString("udp")
	} else {
		b.WriteString("tcp")
	}
	b.WriteRune('|')
	b.WriteString(c.src.String())
	b.WriteRune('-')
	b.WriteString(c.dst.String())

	return b.String()
}

type enforcer interface {
	SetVerdict(id uint32, verdict int) error
	Close() error
}

type resolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

type enforcerCreator func(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, hook nfqueue.HookFunc) (enforcer, error)

func StartFilters(ctx context.Context, logger *zap.Logger, config *Config) (*FilterManager, error) {
	f := FilterManager{
		ready:     make(chan struct{}),
		logger:    logger,
		queueNum4: config.InboundDNSQueue.IPv4,
		queueNum6: config.InboundDNSQueue.IPv6,
		filters:   make([]*filter, len(config.Filters)),
	}

	newEnforcer := config.enforcerCreator
	if newEnforcer == nil {
		newEnforcer = startNfQueue
	}
	res := config.resolver
	if res == nil {
		res = &net.Resolver{}
	}

	nf4, nf6, err := startNfQueues(ctx, logger, config.InboundDNSQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
		return newDNSResponseCallback(&f, ipv6)
	})
	if err != nil {
		return nil, err
	}
	f.dnsRespNF4 = nf4
	f.dnsRespNF6 = nf6

	for i := range config.Filters {
		isSelfFilter := config.SelfDNSQueue == config.Filters[i].DNSQueue
		filter, err := startFilter(ctx, logger, &config.Filters[i], isSelfFilter, newEnforcer, res)
		if err != nil {
			// TODO: stop other filters here
			return nil, err
		}

		f.filters[i] = filter
	}

	// Let the DNS response callback know everything is setup. The
	// callback will be executing on another goroutine started by
	// nfqueue.RegisterWithErrorFunc, but only after a packet is
	// received on its nfqueue.
	close(f.ready)

	return &f, nil
}

func (f *FilterManager) Stop() {
	if f.dnsRespNF4 != nil {
		f.dnsRespNF4.Close()
	}
	if f.dnsRespNF6 != nil {
		f.dnsRespNF6.Close()
	}

	for i := range f.filters {
		f.filters[i].close()
	}
}

func startFilter(ctx context.Context, logger *zap.Logger, opts *FilterOptions, isSelfFilter bool, newEnforcer enforcerCreator, res resolver) (*filter, error) {
	filterLogger := logger
	if opts.Name != "" {
		filterLogger = filterLogger.With(zap.String("filter.name", opts.Name))
	}

	f := filter{
		dnsReqNFReady:  make(chan struct{}),
		genericNFReady: make(chan struct{}),
		opts:           opts,
		logger:         filterLogger,
		res:            res,
		connections:    NewTimedCache[connectionID](logger, true),
		isSelfFilter:   isSelfFilter,
	}

	if opts.TrafficQueue.eitherSet() {
		f.allowedIPs = NewTimedCache[netip.Addr](f.logger, false)
		f.additionalHostnames = NewTimedCache[string](filterLogger, false)

		nf4, nf6, err := startNfQueues(ctx, filterLogger, opts.TrafficQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
			return newGenericCallback(&f, ipv6)
		})
		if err != nil {
			return nil, fmt.Errorf("error starting traffic nfqueues: %v", err)
		}
		f.genericNF4 = nf4
		f.genericNF6 = nf6
		// let the generic packet callback know everything is setup
		close(f.genericNFReady)

		if len(f.opts.CachedHostnames) > 0 {
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()

				f.cacheHostnames(ctx, filterLogger)
			}()
		}
	}

	if opts.DNSQueue.eitherSet() {
		nf4, nf6, err := startNfQueues(ctx, filterLogger, opts.DNSQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
			return newDNSRequestCallback(&f, ipv6)
		})
		if err != nil {
			return nil, fmt.Errorf("error starting DNS nfqueues: %v", err)
		}
		f.dnsReqNF4 = nf4
		f.dnsReqNF6 = nf6
		// let the DNS request callback know everything is setup
		close(f.dnsReqNFReady)
	}

	return &f, nil
}

func startNfQueues(ctx context.Context, logger *zap.Logger, queues queue, newEnforcer enforcerCreator, hookGen func(ipv6 bool) nfqueue.HookFunc) (nf4 enforcer, nf6 enforcer, err error) {
	if queues.IPv4 != 0 {
		nf4, err = newEnforcer(ctx, logger, queues.IPv4, false, hookGen(false))
		if err != nil {
			return nil, nil, err
		}
	}
	if queues.IPv6 != 0 {
		nf6, err = newEnforcer(ctx, logger, queues.IPv6, true, hookGen(true))
		if err != nil {
			return nil, nil, err
		}
	}

	return nf4, nf6, nil
}

func startNfQueue(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, hook nfqueue.HookFunc) (enforcer, error) {
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

	// close the nfqueue connection in case of an error
	var ok bool
	defer func() {
		if !ok {
			nf.Close()
		}
	}()

	// Set options to the nfqueue's netlink socket if possible to enable
	// better error messages and more strict checking of arguments from
	// the kernel. Ignore ENOPROTOOPT errors, that just means the kernel
	// doesn't support that option.
	err = nf.Con.SetOption(netlink.ExtendedAcknowledge, true)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return nil, fmt.Errorf("error setting ExtendedAcknowledge netlink option: %v", err)
	}
	err = nf.Con.SetOption(netlink.GetStrictCheck, true)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return nil, fmt.Errorf("error setting GetStrictCheck netlink option: %v", err)
	}

	if err := nf.RegisterWithErrorFunc(ctx, hook, newErrorCallback(logger)); err != nil {
		return nil, fmt.Errorf("error registering nfqueue: %v", err)
	}

	ok = true

	return nf, nil
}

func (f *filter) cacheHostnames(ctx context.Context, logger *zap.Logger) {
	logger.Debug("starting cache loop")

	var (
		ttl   = time.Duration(f.opts.ReCacheEvery) + dnsQueryTimeout
		timer = time.NewTimer(time.Duration(f.opts.ReCacheEvery))
	)

	for {
		for i := range f.opts.CachedHostnames {
			logger.Info("caching lookup of hostname", zap.String("hostname", f.opts.CachedHostnames[i]))
			addrs, err := f.res.LookupNetIP(ctx, "ip", f.opts.CachedHostnames[i])
			if err != nil {
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
					logger.Warn("could not resolve hostname", zap.String("hostname", f.opts.CachedHostnames[i]))
					continue
				}
				logger.Error("error resolving hostname", zap.String("hostname", f.opts.CachedHostnames[i]), zap.NamedError("error", err))
				continue
			}

			for i := range addrs {
				logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]), zap.Duration("ttl", ttl))
				f.allowedIPs.AddEntry(addrs[i], ttl)

				// If the IP address is an IPv4-mapped IPv6 address,
				// add the unwrapped IPv4 address too. That is what
				// will most likely be used.
				if addrs[i].Is4In6() {
					addrs[i] = addrs[i].Unmap()
					logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]), zap.Duration("ttl", ttl))
					f.allowedIPs.AddEntry(addrs[i], ttl)
				}
			}
		}

		timer.Reset(time.Duration(f.opts.ReCacheEvery))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			logger.Debug("exiting cache loop")
			return
		case <-timer.C:
		}
	}
}

func (f *filter) close() {
	f.wg.Wait()

	if f.dnsReqNF4 != nil {
		f.dnsReqNF4.Close()
	}
	if f.dnsReqNF6 != nil {
		f.dnsReqNF6.Close()
	}
	if f.genericNF4 != nil {
		f.genericNF4.Close()
	}
	if f.genericNF6 != nil {
		f.genericNF6.Close()
	}

	f.connections.Stop()
	if f.allowedIPs != nil {
		f.allowedIPs.Stop()
	}
	if f.additionalHostnames != nil {
		f.additionalHostnames.Stop()
	}
}

func newDNSRequestCallback(f *filter, ipv6 bool) nfqueue.HookFunc {
	var queueNum uint16
	if !ipv6 {
		queueNum = f.opts.DNSQueue.IPv4
	} else {
		queueNum = f.opts.DNSQueue.IPv6
	}

	logger := f.logger.With(zap.String("filter.type", "dns-req"))
	logger = logger.With(zap.Uint16("queue.num", queueNum))
	logger.Info("started nfqueue")

	return func(attr nfqueue.Attribute) int {
		// wait until the filter is setup to prevent race conditions
		<-f.dnsReqNFReady

		var dnsReqNF enforcer
		if !ipv6 {
			dnsReqNF = f.dnsReqNF4
		} else {
			dnsReqNF = f.dnsReqNF6
		}

		if attr.PacketID == nil {
			return 0
		}
		if attr.CtInfo == nil {
			return 0
		}
		if attr.Payload == nil {
			return 0
		}

		// verify DNS request is from a new or established connection
		if *attr.CtInfo != stateNew && !connIsEstablished(*attr.CtInfo) {
			logger.Warn("dropping DNS request with unknown state", zap.Uint32("conn.state", *attr.CtInfo))

			if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.String("error", err.Error()))
			}
			return 0
		}

		dns, connID, err := parseDNSPacket(*attr.Payload, ipv6, false)
		if err != nil {
			logger.Error("error parsing DNS packet", zap.NamedError("error", err))
			return 0
		}
		logger := logger.With(zap.Stringer("conn.id", connID))

		// drop DNS replies, they shouldn't be going to this filter
		if dns.ANCount > 0 {
			logger.Warn("dropping DNS reply sent to DNS request filter")

			if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.String("error", err.Error()))
			}
			return 0
		}

		// validate DNS request questions are for allowed
		// hostnames, drop them otherwise
		if !f.opts.AllowAllHostnames && !f.validateDNSQuestions(logger, dns) {
			if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		logger.Info("allowing DNS request", zap.Strings("questions", questionStrings(dns.Questions)))

		// give DNS connections a minute to finish max
		logger.Debug("adding connection")
		f.connections.AddEntry(connID, dnsQueryTimeout)

		if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
			logger.Debug("removing connection")
			f.connections.RemoveEntry(connID)
		}

		return 0
	}
}

func connIsEstablished(state uint32) bool {
	return state == stateEstablished || state == stateRelated || state == stateIsReply || state == stateRelatedReply
}

func parseDNSPacket(packet []byte, ipv6, inbound bool) (*layers.DNS, connectionID, error) {
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
		return nil, connectionID{}, err
	}
	if len(decoded) != 3 {
		return nil, connectionID{}, errors.New("not all layers were parsed")
	}

	// build connection ID so dns requests/responses can be correlated
	var (
		isUDP            bool
		src, dst         netip.Addr
		srcPort, dstPort uint16
		srcOK, dstOK     bool
	)

	if decoded[0] == layers.LayerTypeIPv4 {
		src, srcOK = netip.AddrFromSlice(ip4.SrcIP)
		dst, dstOK = netip.AddrFromSlice(ip4.DstIP)
	} else if decoded[0] == layers.LayerTypeIPv6 {
		src, srcOK = netip.AddrFromSlice(ip6.SrcIP)
		dst, dstOK = netip.AddrFromSlice(ip6.DstIP)
	}
	if !srcOK || !dstOK {
		return nil, connectionID{}, errors.New("error converting IPs")
	}

	if decoded[1] == layers.LayerTypeUDP {
		isUDP = true
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	} else {
		isUDP = false
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	}

	connID := connectionID{
		isUDP: isUDP,
	}
	if inbound {
		connID.src = netip.AddrPortFrom(dst, dstPort)
		connID.dst = netip.AddrPortFrom(src, srcPort)
	} else {
		connID.src = netip.AddrPortFrom(src, srcPort)
		connID.dst = netip.AddrPortFrom(dst, dstPort)
	}

	return &dns, connID, nil
}

func (f *filter) validateDNSQuestions(logger *zap.Logger, dns *layers.DNS) bool {
	if dns.QDCount == 0 {
		// drop DNS requests with no questions; this probably
		// doesn't happen in practice but doesn't hurt to
		// handle this case
		logger.Info("dropping DNS request with no questions")
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
	for j := range f.opts.AllowedHostnames {
		if hostname == f.opts.AllowedHostnames[j] || strings.HasSuffix(hostname, "."+f.opts.AllowedHostnames[j]) {
			return true
		}
	}

	// the self-filter doesn't have a nfqueue for generic traffic, and
	// therefore won't have a cache for additional hostnames
	if f.isSelfFilter {
		return false
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

func newDNSResponseCallback(f *FilterManager, ipv6 bool) nfqueue.HookFunc {
	var queueNum uint16
	if !ipv6 {
		queueNum = f.queueNum4
	} else {
		queueNum = f.queueNum6
	}

	logger := f.logger.With(zap.String("filter.type", "dns-resp"))
	logger = logger.With(zap.Uint16("queue.num", queueNum))
	logger.Info("started nfqueue")

	return func(attr nfqueue.Attribute) int {
		// wait until the filter manager is setup to prevent race conditions
		<-f.ready

		var dnsRespNF enforcer
		if !ipv6 {
			dnsRespNF = f.dnsRespNF4
		} else {
			dnsRespNF = f.dnsRespNF6
		}

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
		if !connIsEstablished(*attr.CtInfo) {
			logger.Warn("dropping DNS response with that is not from an established connection", zap.Uint32("conn.state", *attr.CtInfo))

			if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		dns, connID, err := parseDNSPacket(*attr.Payload, ipv6, true)
		if err != nil {
			logger.Error("error parsing DNS packet", zap.NamedError("error", err))
			return 0
		}
		logger := logger.With(zap.Stringer("conn.id", connID))

		var connFilter *filter
		for _, filter := range f.filters {
			if filter.connections.EntryExists(connID) {
				connFilter = filter
				break
			}
		}
		if connFilter == nil {
			logger.Warn("dropping DNS response from unknown connection", zap.Strings("questions", questionStrings(dns.Questions)))

			if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}
		logger.Debug("removing connection")
		connFilter.connections.RemoveEntry(connID)

		logger = logger.With(zap.String("dns-req.filter.name", connFilter.opts.Name))
		// allow and don't process the DNS response if all hostnames
		// are allowed
		if !connFilter.opts.AllowAllHostnames {
			// validate DNS response questions are for allowed
			// hostnames, drop them otherwise; responses for disallowed
			// hostnames should never happen in theory, because we
			// block requests for disallowed hostnames but it doesn't
			// hurt to check
			if !connFilter.validateDNSQuestions(logger, dns) {
				if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
					logger.Error("error setting verdict", zap.NamedError("error", err))
				}
				return 0
			}

			// don't process the DNS response if the filter it came
			// from is the self filter
			if !connFilter.isSelfFilter && dns.ANCount > 0 {
				ttl := time.Duration(connFilter.opts.AllowAnswersFor)
				for _, answer := range dns.Answers {
					aName := string(answer.Name)
					if !connFilter.hostnameAllowed(aName) {
						logger.Info("dropping DNS reply", zap.ByteString("answer", answer.Name))
						if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
							logger.Error("error setting verdict", zap.NamedError("error", err))
						}
						return 0
					}

					if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
						// temporarily add A and AAAA answers to
						// allowed IP list
						ip, ok := netip.AddrFromSlice(answer.IP)
						if !ok {
							logger.Error("error converting IP", zap.Stringer("answer.ip", answer.IP))
							continue
						}

						logger.Info("allowing IP from DNS reply", zap.Stringer("answer.ip", ip), zap.Duration("answer.ttl", ttl))
						connFilter.allowedIPs.AddEntry(ip, ttl)
					} else if answer.Type == layers.DNSTypeCNAME {
						// temporarily add CNAME answers to allowed
						// hostnames list
						logger.Info("allowing hostname from DNS reply", zap.ByteString("answer.name", answer.CNAME), zap.Duration("answer.ttl", ttl))
						connFilter.additionalHostnames.AddEntry(string(answer.CNAME), ttl)
					} else if answer.Type == layers.DNSTypeSRV {
						// temporarily add SRV answers to allowed
						// hostnames list
						logger.Info("allowing hostname from DNS reply", zap.ByteString("answer.name", answer.SRV.Name), zap.Duration("answer.ttl", ttl))
						connFilter.additionalHostnames.AddEntry(string(answer.SRV.Name), ttl)
					}
				}
			}
		}

		if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
		}

		return 0
	}
}

func newGenericCallback(f *filter, ipv6 bool) nfqueue.HookFunc {
	var queueNum uint16
	if !ipv6 {
		queueNum = f.opts.TrafficQueue.IPv4
	} else {
		queueNum = f.opts.TrafficQueue.IPv6
	}

	logger := f.logger.With(zap.String("filter.type", "traffic"))
	logger = logger.With(zap.Uint16("queue.num", queueNum))
	logger.Info("started nfqueue")

	return func(attr nfqueue.Attribute) int {
		// wait until the filter is setup to prevent race conditions
		<-f.genericNFReady

		var genericNF enforcer
		if !ipv6 {
			genericNF = f.genericNF4
		} else {
			genericNF = f.genericNF6
		}

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
		if !ipv6 {
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
			src, dst     netip.Addr
			srcOK, dstOK bool
		)
		if decoded[0] == layers.LayerTypeIPv4 {
			src, srcOK = netip.AddrFromSlice(ip4.SrcIP)
			dst, dstOK = netip.AddrFromSlice(ip4.DstIP)
			if !srcOK || !dstOK {
				logger.Error("error converting IPs", zap.Stringer("conn.src", ip4.SrcIP), zap.Stringer("conn.dst", ip4.DstIP))
				return 0
			}
		} else if decoded[0] == layers.LayerTypeIPv6 {
			src, srcOK = netip.AddrFromSlice(ip6.SrcIP)
			dst, dstOK = netip.AddrFromSlice(ip6.DstIP)
			if !srcOK || !dstOK {
				logger.Error("error converting IPs", zap.Stringer("conn.src", ip6.SrcIP), zap.Stringer("conn.dst", ip6.DstIP))
				return 0
			}
		}

		// validate that either the source or destination IP is allowed
		var verdict int
		allowed, err := f.validateIPs(logger, src, dst)
		if err != nil {
			logger.Error("error validating IPs", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst), zap.NamedError("error", err))
			verdict = nfqueue.NfDrop
		} else {
			if allowed {
				logger.Info("allowing packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
				verdict = nfqueue.NfAccept
			} else {
				logger.Info("dropping packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
				verdict = nfqueue.NfDrop
			}
		}

		if err := genericNF.SetVerdict(*attr.PacketID, verdict); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
		}

		return 0
	}
}

func (f *filter) validateIPs(logger *zap.Logger, src, dst netip.Addr) (bool, error) {
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
	if !dst.IsPrivate() {
		allowed, err := f.lookupAndValidateIP(logger, dst)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	if !src.IsPrivate() {
		return f.lookupAndValidateIP(logger, src)
	}

	return false, nil
}

func (f *filter) lookupAndValidateIP(logger *zap.Logger, ip netip.Addr) (bool, error) {
	// TODO: build from top-level context
	ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
	defer cancel()

	logger.Info("preforming reverse IP lookup", zap.Stringer("ip", ip))
	names, err := f.res.LookupAddr(ctx, ip.String())
	if err != nil {
		// don't return error if IP simply couldn't be found
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}

	ttl := time.Duration(f.opts.AllowAnswersFor)
	for i := range names {
		// remove trailing dot if necessary before searching through
		// allowed hostnames
		if names[i][len(names[i])-1] == '.' {
			names[i] = names[i][:len(names[i])-1]
		}

		if f.hostnameAllowed(names[i]) {
			logger.Info("allowing IP after reverse lookup", zap.Stringer("ip", ip), zap.Duration("ttl", ttl))
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
