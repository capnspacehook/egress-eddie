package egresseddie

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

	"github.com/capnspacehook/egress-eddie/timedcache"
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

	// give DNS connections a minute to finish max
	// TODO: should this be configurable?
	dnsQueryTimeout = time.Minute
)

type FilterManager struct {
	signaler *signaler

	started bool

	fullDNSLogging bool
	logger         *zap.Logger

	queueNum4 uint16
	queueNum6 uint16

	dnsRespNF4 enforcer
	dnsRespNF6 enforcer

	filters []*filter
}

type filter struct {
	dnsReqSignaler  *signaler
	genericSignaler *signaler
	cachingSignaler *signaler

	started bool
	wg      sync.WaitGroup

	opts *FilterOptions

	fullDNSLogging bool
	logger         *zap.Logger

	dnsReqNF4  enforcer
	dnsReqNF6  enforcer
	genericNF4 enforcer
	genericNF6 enforcer

	res resolver

	connections         *timedcache.TimedCache[connectionID]
	allowedIPs          *timedcache.TimedCache[netip.Addr]
	additionalHostnames *timedcache.TimedCache[string]

	isSelfFilter bool
}

type signaler struct {
	readyCh chan struct{}
	abortCh chan struct{}
}

func newSignaler() *signaler {
	return &signaler{
		readyCh: make(chan struct{}),
		abortCh: make(chan struct{}),
	}
}

func (s *signaler) ready() {
	close(s.readyCh)
}

func (s *signaler) isReady() <-chan struct{} {
	return s.readyCh
}

func (s *signaler) abort() {
	close(s.abortCh)
}

func (s *signaler) shouldAbort() <-chan struct{} {
	return s.abortCh
}

// connectionID is used to correlate DNS requests and responses from
// the same connection
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

// CreateFilters creates packet filters. The returned FilterManager can
// be used to start or stop packet filtering.
func CreateFilters(ctx context.Context, logger *zap.Logger, config *Config, fullDNSLogging bool) (*FilterManager, error) {
	f := FilterManager{
		signaler:       newSignaler(),
		fullDNSLogging: fullDNSLogging,
		logger:         logger,
		queueNum4:      config.InboundDNSQueue.IPv4,
		queueNum6:      config.InboundDNSQueue.IPv6,
		filters:        make([]*filter, len(config.Filters)),
	}

	// if mock enforcers and resolver is not set, use real ones
	newEnforcer := config.enforcerCreator
	if newEnforcer == nil {
		newEnforcer = openNfQueue
	}
	res := config.resolver
	if res == nil {
		res = &net.Resolver{}
	}

	nf4, nf6, err := openNfQueues(ctx, logger, config.InboundDNSQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
		return newDNSResponseCallback(&f, ipv6)
	})
	if err != nil {
		return nil, err
	}
	f.dnsRespNF4 = nf4
	f.dnsRespNF6 = nf6

	for i := range config.Filters {
		isSelfFilter := config.SelfDNSQueue == config.Filters[i].DNSQueue
		filter, err := createFilter(ctx, logger, &config.Filters[i], isSelfFilter, f.fullDNSLogging, newEnforcer, res)
		if err != nil {
			// TODO: stop other filters here
			return nil, err
		}

		f.filters[i] = filter
	}

	return &f, nil
}

// Start starts packet filtering.
func (f *FilterManager) Start() {
	// Let the DNS response callback know everything is setup. The
	// callback will be executing on another goroutine started by
	// nfqueue.RegisterWithErrorFunc, but only after a packet is
	// received on its nfqueue.
	f.signaler.ready()

	for i := range f.filters {
		f.filters[i].start()
	}

	f.started = true
}

// Stop stops packet filtering and cleans up owned resources.
func (f *FilterManager) Stop() {
	// if the filters have not been started yet, tell running goroutines
	// to abort and finish
	if !f.started {
		f.signaler.abort()
	}

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

func createFilter(ctx context.Context, logger *zap.Logger, opts *FilterOptions, isSelfFilter, fullDNSLogging bool, newEnforcer enforcerCreator, res resolver) (*filter, error) {
	filterLogger := logger
	if opts.Name != "" {
		filterLogger = filterLogger.With(zap.String("filter.name", opts.Name))
	}

	f := filter{
		dnsReqSignaler:  newSignaler(),
		genericSignaler: newSignaler(),
		cachingSignaler: newSignaler(),
		opts:            opts,
		fullDNSLogging:  fullDNSLogging,
		logger:          filterLogger,
		res:             res,
		connections:     timedcache.New[connectionID](logger, true),
		isSelfFilter:    isSelfFilter,
	}

	if opts.TrafficQueue.eitherSet() {
		f.allowedIPs = timedcache.New[netip.Addr](f.logger, false)
		f.additionalHostnames = timedcache.New[string](filterLogger, false)

		nf4, nf6, err := openNfQueues(ctx, filterLogger, opts.TrafficQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
			return newGenericCallback(ctx, &f, ipv6)
		})
		if err != nil {
			return nil, fmt.Errorf("error starting traffic nfqueues: %w", err)
		}
		f.genericNF4 = nf4
		f.genericNF6 = nf6

		if len(f.opts.CachedHostnames) > 0 {
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()

				f.cacheHostnames(ctx, filterLogger)
			}()
		}
	}

	if opts.DNSQueue.eitherSet() {
		nf4, nf6, err := openNfQueues(ctx, filterLogger, opts.DNSQueue, newEnforcer, func(ipv6 bool) nfqueue.HookFunc {
			return newDNSRequestCallback(&f, ipv6)
		})
		if err != nil {
			return nil, fmt.Errorf("error starting DNS nfqueues: %w", err)
		}
		f.dnsReqNF4 = nf4
		f.dnsReqNF6 = nf6

	}

	return &f, nil
}

func openNfQueues(ctx context.Context, logger *zap.Logger, queues queue, newEnforcer enforcerCreator, hookGen func(ipv6 bool) nfqueue.HookFunc) (nf4 enforcer, nf6 enforcer, err error) {
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

func openNfQueue(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, hook nfqueue.HookFunc) (enforcer, error) {
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
		return nil, fmt.Errorf("error opening nfqueue: %w", err)
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
		return nil, fmt.Errorf("error setting ExtendedAcknowledge netlink option: %w", err)
	}
	err = nf.Con.SetOption(netlink.GetStrictCheck, true)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return nil, fmt.Errorf("error setting GetStrictCheck netlink option: %w", err)
	}

	if err := nf.RegisterWithErrorFunc(ctx, hook, newErrorCallback(logger)); err != nil {
		return nil, fmt.Errorf("error registering nfqueue: %w", err)
	}

	ok = true

	return nf, nil
}

func (f *filter) start() {
	if f.opts.DNSQueue.eitherSet() {
		f.dnsReqSignaler.ready()
	}
	if f.opts.TrafficQueue.eitherSet() {
		f.genericSignaler.ready()
	}
	if len(f.opts.CachedHostnames) > 0 {
		f.cachingSignaler.ready()
	}

	f.started = true
}

func (f *filter) cacheHostnames(ctx context.Context, logger *zap.Logger) {
	// wait until the filter manager is setup to prevent race conditions
	select {
	case <-f.cachingSignaler.isReady():
	case <-f.cachingSignaler.shouldAbort():
		// the filter manager has been stopped before it was started,
		// return so the parent filter can finish cleaning up
		return
	}

	logger.Debug("starting cache loop")

	var (
		// add to the user supplied duration to ensure there isn't a
		// window where hostnames are not allowed
		ttl   = f.opts.ReCacheEvery + dnsQueryTimeout
		timer = time.NewTimer(f.opts.ReCacheEvery)
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
				logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]))
				f.allowedIPs.AddEntry(addrs[i], ttl)

				// If the IP address is an IPv4-mapped IPv6 address,
				// add the unwrapped IPv4 address too. That is what
				// will most likely be used.
				if addrs[i].Is4In6() {
					addrs[i] = addrs[i].Unmap()
					logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]))
					f.allowedIPs.AddEntry(addrs[i], ttl)
				}
			}
		}

		timer.Reset(f.opts.ReCacheEvery)
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
	// if the filter has not been started yet, tell running goroutines
	// to abort and finish
	if !f.started {
		if f.opts.DNSQueue.eitherSet() {
			f.dnsReqSignaler.abort()
		}
		if f.opts.TrafficQueue.eitherSet() {
			f.genericSignaler.abort()
		}
		if len(f.opts.CachedHostnames) > 0 {
			f.cachingSignaler.abort()
		}
	}

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
		// wait until the filter manager is setup to prevent race conditions
		select {
		case <-f.dnsReqSignaler.isReady():
			// the filter manager has been stopped before it was started,
			// return so the parent filter can finish cleaning up
		case <-f.dnsReqSignaler.shouldAbort():
			return 0
		}

		var dnsReqNF enforcer
		if !ipv6 {
			dnsReqNF = f.dnsReqNF4
		} else {
			dnsReqNF = f.dnsReqNF6
		}

		if attr.PacketID == nil {
			logger.Warn("got packet with no packet ID")
			return 0
		}
		if attr.CtInfo == nil {
			logger.Warn("got packet with no connection state")
			return 0
		}
		if attr.Payload == nil {
			logger.Warn("got packet with no payload")
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
		if dns.QR || dns.ANCount > 0 {
			logger.Warn("dropping DNS reply sent to DNS request filter", dnsFields(dns, f.fullDNSLogging)...)
			if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.String("error", err.Error()))
			}
			return 0
		}

		// validate DNS request questions are for allowed
		// hostnames, drop them otherwise
		if !f.opts.AllowAllHostnames && !f.validateDNSQuestions(dns) {
			logger.Warn("dropping DNS request", dnsFields(dns, f.fullDNSLogging)...)
			if err := dnsReqNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
				logger.Error("error setting verdict", zap.NamedError("error", err))
			}
			return 0
		}

		logger.Info("allowing DNS request", dnsFields(dns, f.fullDNSLogging)...)

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
		return nil, connectionID{}, fmt.Errorf("%d layers were parsed, expecting 3", len(decoded))
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

func (f *filter) validateDNSQuestions(dns *layers.DNS) bool {
	if dns.QDCount == 0 {
		// drop DNS requests with no questions; this probably
		// doesn't happen in practice but doesn't hurt to
		// handle this case
		return false
	}

	for i := range dns.Questions {
		// bail out if any of the questions don't contain an allowed
		// hostname
		qName := string(dns.Questions[i].Name)
		if !f.hostnameAllowed(qName) {
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
		select {
		case <-f.signaler.isReady():
		case <-f.signaler.shouldAbort():
			// the filter manager has been stopped before it was started,
			// return so the parent filter can finish cleaning up
			return 0
		}

		var dnsRespNF enforcer
		if !ipv6 {
			dnsRespNF = f.dnsRespNF4
		} else {
			dnsRespNF = f.dnsRespNF6
		}

		if attr.PacketID == nil {
			logger.Warn("got packet with no packet ID")
			return 0
		}
		if attr.CtInfo == nil {
			logger.Warn("got packet with no connection state")
			return 0
		}
		if attr.Payload == nil {
			logger.Warn("got packet with no payload")
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
			logger.Warn("dropping DNS response from unknown connection", dnsFields(dns, f.fullDNSLogging)...)

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
			if !connFilter.validateDNSQuestions(dns) {
				logger.Info("dropping DNS reply", dnsFields(dns, f.fullDNSLogging)...)
				if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
					logger.Error("error setting verdict", zap.NamedError("error", err))
				}
				return 0
			}

			// don't process the DNS response if the filter it came
			// from is the self filter
			if !connFilter.isSelfFilter && dns.ANCount > 0 {
				ttl := connFilter.opts.AllowAnswersFor
				for _, answer := range dns.Answers {
					aName := string(answer.Name)
					if !connFilter.hostnameAllowed(aName) {
						logger.Info("dropping DNS reply", zap.ByteString("answer", answer.Name))
						if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfDrop); err != nil {
							logger.Error("error setting verdict", zap.NamedError("error", err))
						}
						return 0
					}

					switch answer.Type {
					case layers.DNSTypeA, layers.DNSTypeAAAA:
						// temporarily add A and AAAA answers to allowed IP list
						ip, ok := netip.AddrFromSlice(answer.IP)
						if !ok {
							logger.Error("error converting IP", zap.Stringer("answer.ip", answer.IP))
							continue
						}

						connFilter.allowedIPs.AddEntry(ip, ttl)
						// If the IP address is an IPv4-mapped IPv6 address,
						// add the unwrapped IPv4 address too. That is what
						// will most likely be used.
						if ip.Is4In6() {
							connFilter.allowedIPs.AddEntry(ip.Unmap(), ttl)
						}
					case layers.DNSTypeCNAME, layers.DNSTypeSRV, layers.DNSTypeMX, layers.DNSTypeNS:
						// temporarily add CNAME, SRV, MX, and NS answers to allowed
						// hostnames list
						var name []byte
						switch answer.Type {
						case layers.DNSTypeCNAME:
							name = answer.CNAME
						case layers.DNSTypeSRV:
							name = answer.SRV.Name
						case layers.DNSTypeMX:
							name = answer.MX.Name
						case layers.DNSTypeNS:
							name = answer.NS
						}

						connFilter.additionalHostnames.AddEntry(string(name), ttl)
					default:
						// don't need to specifically handle other answer
						// types, the packet will be allowed so whoever
						// made the DNS request will see this answer
					}
				}
			}
		}

		logger.Info("allowing DNS reply", dnsFields(dns, f.fullDNSLogging)...)
		if err := dnsRespNF.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
			logger.Error("error setting verdict", zap.NamedError("error", err))
		}

		return 0
	}
}

func newGenericCallback(ctx context.Context, f *filter, ipv6 bool) nfqueue.HookFunc {
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
		// wait until the filter manager is setup to prevent race conditions
		select {
		case <-f.genericSignaler.isReady():
		case <-f.genericSignaler.shouldAbort():
			// the filter manager has been stopped before it was started,
			// return so the parent filter can finish cleaning up
			return 0
		}

		var genericNF enforcer
		if !ipv6 {
			genericNF = f.genericNF4
		} else {
			genericNF = f.genericNF6
		}

		if attr.PacketID == nil {
			logger.Warn("got packet with no packet ID")
			return 0
		}
		if attr.Payload == nil {
			logger.Warn("got packet with no payload")
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
		allowed, err := f.validateIPs(ctx, logger, src, dst)
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

func (f *filter) validateIPs(ctx context.Context, logger *zap.Logger, src, dst netip.Addr) (bool, error) {
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
		allowed, err := f.lookupAndValidateIP(ctx, logger, dst)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	if !src.IsPrivate() {
		return f.lookupAndValidateIP(ctx, logger, src)
	}

	return false, nil
}

func (f *filter) lookupAndValidateIP(ctx context.Context, logger *zap.Logger, ip netip.Addr) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
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

	ttl := f.opts.AllowAnswersFor
	for i := range names {
		// remove trailing dot if necessary before searching through
		// allowed hostnames
		if names[i][len(names[i])-1] == '.' {
			names[i] = names[i][:len(names[i])-1]
		}

		if f.hostnameAllowed(names[i]) {
			logger.Info("allowing IP after reverse lookup", zap.Stringer("ip", ip))
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
