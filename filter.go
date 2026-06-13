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
	"github.com/miekg/dns"
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

	// TODO: check ID and questions between requests and responses
	connections       *timedcache.TimedCache[connectionID]
	allowedIPs        *timedcache.TimedCache[netip.Addr]
	additionalDomains *timedcache.TimedCache[string]

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
	src netip.AddrPort
	dst netip.AddrPort
}

func (c connectionID) String() string {
	var b strings.Builder

	b.WriteString(c.src.String())
	b.WriteRune('-')
	b.WriteString(c.dst.String())

	return b.String()
}

// enforcer sets verdicts on packets.
type enforcer interface {
	SetVerdict(id uint32, verdict int) error
	Close() error
}

// resolver resolves domains to IP addresses and vice versa.
type resolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

type verdict int

const (
	dropVerdict   verdict = nfqueue.NfDrop
	acceptVerdict verdict = nfqueue.NfAccept
	// ignoreVerdict is not a nfqueue verdict type, it signals that the
	// verdict can't be set and the packet should be ignored
	ignoreVerdict verdict = 10
)

// packetCallback is a function that decides whether to allow or drop packets.
type packetCallback func(attr nfqueue.Attribute) verdict

// hookCreator is a function that creates a hook function for a given queue.
type hookCreator func(queueNum uint16, ipv6 bool, e enforcer) nfqueue.HookFunc

type enforcerCreator func(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, createHook hookCreator) (enforcer, error)

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

	nf4, nf6, err := openNfQueues(ctx, logger, config.InboundDNSQueue, newEnforcer, newDNSResponseCallback(&f))
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
		f.additionalDomains = timedcache.New[string](filterLogger, false)

		nf4, nf6, err := openNfQueues(ctx, filterLogger, opts.TrafficQueue, newEnforcer, newGenericCallback(&f))
		if err != nil {
			return nil, fmt.Errorf("error starting traffic nfqueues: %w", err)
		}
		f.genericNF4 = nf4
		f.genericNF6 = nf6

		if len(f.opts.CachedDomains) > 0 {
			f.wg.Go(func() {
				f.cacheDomains(ctx, filterLogger)
			})
		}
	}

	if opts.DNSQueue.eitherSet() {
		nf4, nf6, err := openNfQueues(ctx, filterLogger, opts.DNSQueue, newEnforcer, newDNSRequestCallback(&f))
		if err != nil {
			return nil, fmt.Errorf("error starting DNS nfqueues: %w", err)
		}
		f.dnsReqNF4 = nf4
		f.dnsReqNF6 = nf6

	}

	return &f, nil
}

func openNfQueues(ctx context.Context, logger *zap.Logger, queues queue, newEnforcer enforcerCreator, createHook hookCreator) (nf4 enforcer, nf6 enforcer, err error) {
	if queues.IPv4 != 0 {
		nf4, err = newEnforcer(ctx, logger, queues.IPv4, false, createHook)
		if err != nil {
			return nil, nil, err
		}
	}
	if queues.IPv6 != 0 {
		nf6, err = newEnforcer(ctx, logger, queues.IPv6, true, createHook)
		if err != nil {
			return nil, nil, err
		}
	}

	return nf4, nf6, nil
}

func openNfQueue(ctx context.Context, logger *zap.Logger, queueNum uint16, ipv6 bool, createHook hookCreator) (enforcer, error) {
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

	hook := createHook(queueNum, ipv6, nf)
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
	if len(f.opts.CachedDomains) > 0 {
		f.cachingSignaler.ready()
	}

	f.started = true
}

func (f *filter) cacheDomains(ctx context.Context, logger *zap.Logger) {
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
		// window where domains are not allowed
		ttl   = f.opts.ReCacheEvery + dnsQueryTimeout
		timer = time.NewTimer(f.opts.ReCacheEvery)
	)

	for {
		for i := range f.opts.CachedDomains {
			logger.Info("caching lookup of domain", zap.String("domain", f.opts.CachedDomains[i]))
			addrs, err := f.res.LookupNetIP(ctx, "ip", f.opts.CachedDomains[i])
			if err != nil {
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
					logger.Warn("could not resolve domain", zap.String("domain", f.opts.CachedDomains[i]))
					continue
				}
				logger.Error("error resolving domain", zap.String("domain", f.opts.CachedDomains[i]), zap.Error(err))
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
			timer.Stop()
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
		if len(f.opts.CachedDomains) > 0 {
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
	if f.additionalDomains != nil {
		f.additionalDomains.Stop()
	}
}

func newDNSRequestCallback(f *filter) hookCreator {
	createCallback := func(logger *zap.Logger, ipv6 bool) packetCallback {
		return func(attr nfqueue.Attribute) verdict {
			// wait until the filter manager is setup to prevent race conditions
			select {
			case <-f.dnsReqSignaler.isReady():
			case <-f.dnsReqSignaler.shouldAbort():
				// the filter manager has been stopped before it was started,
				// return so the parent filter can finish cleaning up
				return ignoreVerdict
			}

			if attr.PacketID == nil {
				logger.Warn("got packet with no packet ID")
				return ignoreVerdict
			}
			if attr.CtInfo == nil {
				logger.Warn("got packet with no connection state")
				return dropVerdict
			}
			if attr.Payload == nil {
				logger.Warn("got packet with no payload")
				return dropVerdict
			}

			// verify DNS request is from a new or established connection
			if *attr.CtInfo != stateNew && !connIsEstablished(*attr.CtInfo) {
				logger.Warn("dropping DNS request with unknown state", zap.Uint32("conn.state", *attr.CtInfo))
				return dropVerdict
			}

			dns, connID, err := parseDNSPacket(*attr.Payload, ipv6, false)
			if err != nil {
				logger.Error("error parsing DNS packet", zap.Error(err))
				if dns != nil {
					logger.Info("offending DNS packet", dnsFields(dns, f.fullDNSLogging)...)
				}
				return dropVerdict
			}
			logger := logger.With(zap.Stringer("conn.id", connID))

			if dns.OpCode != layers.DNSOpCodeQuery {
				logger.Warn("dropping DNS response with non-query opcode", dnsFields(dns, f.fullDNSLogging)...)
				return dropVerdict
			}
			// drop DNS replies, they shouldn't be going to this filter
			if dns.QR || dns.ANCount > 0 || dns.NSCount > 0 || len(dns.Answers) > 0 || len(dns.Authorities) > 0 {
				logger.Warn("dropping DNS reply sent to DNS request filter", dnsFields(dns, f.fullDNSLogging)...)
				return dropVerdict
			}

			// validate DNS request questions are for allowed
			// domains, drop them otherwise
			if !f.opts.AllowAllDomains && !f.validateDNSQuestions(dns) {
				logger.Warn("dropping DNS request", dnsFields(dns, f.fullDNSLogging)...)
				return dropVerdict
			}

			logger.Info("allowing DNS request", dnsFields(dns, f.fullDNSLogging)...)

			logger.Debug("adding connection")
			f.connections.AddEntry(connID, dnsQueryTimeout)

			return acceptVerdict
		}
	}

	return func(queueNum uint16, ipv6 bool, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "dns-req"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger, ipv6))
	}
}

func connIsEstablished(state uint32) bool {
	return state == stateEstablished || state == stateRelated || state == stateEstablishedReply || state == stateRelatedReply
}

func setVerdict(logger *zap.Logger, e enforcer, attr nfqueue.Attribute, v verdict) {
	if v == ignoreVerdict {
		return
	}

	if err := e.SetVerdict(*attr.PacketID, int(v)); err != nil {
		logger.Error("error setting verdict", zap.Error(err))
	}
}

func parseDNSPacket(packet []byte, ipv6, inbound bool) (*layers.DNS, connectionID, error) {
	var (
		ip4       layers.IPv4
		ip6       layers.IPv6
		udp       layers.UDP
		parsedDNS layers.DNS
		parser    *gopacket.DecodingLayerParser
		decoded   = make([]gopacket.LayerType, 0, 3)
	)

	// parse DNS packet
	if !ipv6 {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &parsedDNS)
	} else {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &udp, &parsedDNS)
	}

	if err := parser.DecodeLayers(packet, &decoded); err != nil {
		return nil, connectionID{}, err
	}
	if len(decoded) != 3 {
		return nil, connectionID{}, fmt.Errorf("%d layers were parsed, expecting 3", len(decoded))
	}

	// messages without a question are valid but rare, and we can't
	// filter them like normal so just drop them
	if parsedDNS.QDCount == 0 || int(parsedDNS.QDCount) != len(parsedDNS.Questions) {
		return &parsedDNS, connectionID{}, fmt.Errorf("dropping DNS response with invalid question count; qd_count=%d questions=%d", parsedDNS.QDCount, len(parsedDNS.Questions))
	}
	// check that the record count matches the number of records
	if int(parsedDNS.ANCount) != len(parsedDNS.Answers) {
		return &parsedDNS, connectionID{}, fmt.Errorf("dropping DNS response with invalid answer count; an_count=%d answers=%d", parsedDNS.ANCount, len(parsedDNS.Answers))
	}
	if int(parsedDNS.NSCount) != len(parsedDNS.Authorities) {
		return &parsedDNS, connectionID{}, fmt.Errorf("dropping DNS response with invalid authority count; ns_count=%d authorities=%d", parsedDNS.NSCount, len(parsedDNS.Authorities))
	}
	if int(parsedDNS.ARCount) != len(parsedDNS.Additionals) {
		return &parsedDNS, connectionID{}, fmt.Errorf("dropping DNS response with invalid additional count; ar_count=%d additionals=%d", parsedDNS.ARCount, len(parsedDNS.Additionals))
	}

	// build connection ID so dns requests/responses can be correlated
	var (
		src, dst         netip.Addr
		srcPort, dstPort uint16
		srcOK, dstOK     bool
	)

	switch decoded[0] {
	case layers.LayerTypeIPv4:
		src, srcOK = netip.AddrFromSlice(ip4.SrcIP)
		dst, dstOK = netip.AddrFromSlice(ip4.DstIP)
	case layers.LayerTypeIPv6:
		src, srcOK = netip.AddrFromSlice(ip6.SrcIP)
		dst, dstOK = netip.AddrFromSlice(ip6.DstIP)
	default:
		return nil, connectionID{}, fmt.Errorf("unknown IP protocol %s", decoded[0])
	}
	if !srcOK || !dstOK {
		return nil, connectionID{}, errors.New("error converting IPs")
	}

	if decoded[1] != layers.LayerTypeUDP {
		return nil, connectionID{}, fmt.Errorf("unexpected layer type for second layer: %s", decoded[1])
	}

	srcPort = uint16(udp.SrcPort)
	dstPort = uint16(udp.DstPort)

	connID := connectionID{}
	if inbound {
		connID.src = netip.AddrPortFrom(dst, dstPort)
		connID.dst = netip.AddrPortFrom(src, srcPort)
	} else {
		connID.src = netip.AddrPortFrom(src, srcPort)
		connID.dst = netip.AddrPortFrom(dst, dstPort)
	}

	return &parsedDNS, connID, nil
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
		// domain
		qName := string(dns.Questions[i].Name)
		if !f.domainAllowed(qName) {
			return false
		}
	}

	return true
}

func (f *filter) domainAllowed(domain string) bool {
	for j := range f.opts.AllowedDomains {
		if domain == f.opts.AllowedDomains[j] || dns.IsSubDomain(f.opts.AllowedDomains[j], domain) {
			return true
		}
	}

	// the self-filter doesn't have a nfqueue for generic traffic, and
	// therefore won't have a cache for additional domains
	if f.isSelfFilter {
		return false
	}

	return f.additionalDomains.EntryExists(domain)
}

func newHookFunc(logger *zap.Logger, e enforcer, callback packetCallback) nfqueue.HookFunc {
	return func(attr nfqueue.Attribute) int {
		v := callback(attr)
		setVerdict(logger, e, attr, v)
		return 0
	}
}

func newDNSResponseCallback(f *FilterManager) hookCreator {
	createCallback := func(logger *zap.Logger, ipv6 bool) packetCallback {
		return func(attr nfqueue.Attribute) verdict {
			// wait until the filter manager is setup to prevent race conditions
			select {
			case <-f.signaler.isReady():
			case <-f.signaler.shouldAbort():
				// the filter manager has been stopped before it was started,
				// return so the parent filter can finish cleaning up
				return ignoreVerdict
			}

			if attr.PacketID == nil {
				logger.Warn("got packet with no packet ID")
				return ignoreVerdict
			}
			if attr.CtInfo == nil {
				logger.Warn("got packet with no connection state")
				return dropVerdict
			}
			if attr.Payload == nil {
				logger.Warn("got packet with no payload")
				return dropVerdict
			}

			// since DNS requests are filtered above, we only process
			// DNS responses of established packets to make sure a
			// local attacker can't connect to disallowed IPs by
			// sending a DNS response with an attacker specified IP
			// as an answer, thereby allowing that IP
			if !connIsEstablished(*attr.CtInfo) {
				logger.Warn("dropping DNS response with that is not from an established connection", zap.Uint32("conn.state", *attr.CtInfo))
				return dropVerdict
			}

			dns, connID, err := parseDNSPacket(*attr.Payload, ipv6, true)
			if err != nil {
				logger.Error("error parsing DNS packet", zap.Error(err))
				if dns != nil {
					logger.Info("offending DNS packet", dnsFields(dns, f.fullDNSLogging)...)
				}
				return dropVerdict
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
				return dropVerdict
			}
			logger.Debug("removing connection")
			connFilter.connections.RemoveEntry(connID)

			logger = logger.With(zap.String("dns-req.filter.name", connFilter.opts.Name))
			// allow and don't process the DNS response if all domains
			// are allowed
			if !connFilter.opts.AllowAllDomains {
				// validate DNS response questions are for allowed
				// domains, drop them otherwise; responses for disallowed
				// domains should never happen in theory, because we
				// block requests for disallowed domains but it doesn't
				// hurt to check
				if !connFilter.validateDNSQuestions(dns) {
					logger.Info("dropping DNS reply", dnsFields(dns, f.fullDNSLogging)...)
					return dropVerdict
				}

				// don't process the DNS response if the filter it came
				// from is the self filter
				if !connFilter.isSelfFilter && dns.ANCount > 0 {
					ttl := connFilter.opts.AllowAnswersFor
					for _, answer := range dns.Answers {
						aName := string(answer.Name)
						if !connFilter.domainAllowed(aName) {
							logger.Info("dropping DNS reply", zap.ByteString("answer", answer.Name))
							return dropVerdict
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
							// domains list
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

							connFilter.additionalDomains.AddEntry(string(name), ttl)
						default:
							// don't need to specifically handle other answer
							// types, the packet will be allowed so whoever
							// made the DNS request will see this answer
						}
					}
				}
			}

			logger.Info("allowing DNS reply", dnsFields(dns, f.fullDNSLogging)...)

			return acceptVerdict
		}
	}

	return func(queueNum uint16, ipv6 bool, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "dns-resp"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger, ipv6))
	}
}

func newGenericCallback(f *filter) hookCreator {
	createCallback := func(logger *zap.Logger, ipv6 bool) packetCallback {
		return func(attr nfqueue.Attribute) verdict {
			// wait until the filter manager is setup to prevent race conditions
			select {
			case <-f.genericSignaler.isReady():
			case <-f.genericSignaler.shouldAbort():
				// the filter manager has been stopped before it was started,
				// return so the parent filter can finish cleaning up
				return ignoreVerdict
			}

			if attr.PacketID == nil {
				logger.Warn("got packet with no packet ID")
				return ignoreVerdict
			}
			if attr.Payload == nil {
				logger.Warn("got packet with no payload")
				return dropVerdict
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
				logger.Error("error parsing packet", zap.Error(err))
				return dropVerdict
			}
			if len(decoded) == 0 {
				logger.Warn("got packet with no layers")
				return dropVerdict
			}

			// get source and destination IP
			var (
				src, dst     netip.Addr
				srcOK, dstOK bool
			)
			switch decoded[0] {
			case layers.LayerTypeIPv4:
				src, srcOK = netip.AddrFromSlice(ip4.SrcIP)
				dst, dstOK = netip.AddrFromSlice(ip4.DstIP)
				if !srcOK || !dstOK {
					logger.Error("error converting IPs", zap.Stringer("conn.src", ip4.SrcIP), zap.Stringer("conn.dst", ip4.DstIP))
					return dropVerdict
				}
			case layers.LayerTypeIPv6:
				src, srcOK = netip.AddrFromSlice(ip6.SrcIP)
				dst, dstOK = netip.AddrFromSlice(ip6.DstIP)
				if !srcOK || !dstOK {
					logger.Error("error converting IPs", zap.Stringer("conn.src", ip6.SrcIP), zap.Stringer("conn.dst", ip6.DstIP))
					return dropVerdict
				}
			default:
				logger.Error("unknown IP protocol", zap.Stringer("protocol", decoded[0]))
				return dropVerdict
			}

			// validate that either the source or destination IP is allowed
			if f.validateIPs(src, dst) {
				logger.Info("allowing packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
				return acceptVerdict
			}

			logger.Info("dropping packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
			return dropVerdict
		}
	}

	return func(queueNum uint16, ipv6 bool, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "traffic"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger, ipv6))
	}
}

func (f *filter) validateIPs(src, dst netip.Addr) bool {
	// check if the destination IP is allowed first, as most likely
	// we are validating an outbound connection
	return f.allowedIPs.EntryExists(dst) || f.allowedIPs.EntryExists(src)
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

		logger.Error("netlink error", zap.Error(err))

		return 0
	}
}
