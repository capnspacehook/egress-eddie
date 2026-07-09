package egresseddie

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"code.dny.dev/ssrf"
	"codeberg.org/miekg/dns"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mdlayher/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/egress-eddie/resolve"
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
)

// this must be kept up to date with the type switches in
// validateDNSAnswers and newDNSResponseCallback
var allowedRRTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeSRV,
	dns.TypeHTTPS,
	dns.TypeSVCB,
	dns.TypeMX,
}

type FilterManager struct {
	signaler *signaler

	started bool

	permissiveMode bool
	fullDNSLogging bool
	logger         *zap.Logger

	queueNum uint16

	injector resolve.DNSInjector

	dnsRespNF enforcer

	filters []*filter
}

type filter struct {
	dnsReqSignaler  *signaler
	genericSignaler *signaler
	cachingSignaler *signaler

	started bool
	wg      sync.WaitGroup

	opts *FilterOptions

	permissiveMode bool
	fullDNSLogging bool
	logger         *zap.Logger

	dnsReqNF  enforcer
	genericNF enforcer

	addrChecker *ssrf.Guardian

	sender   resolve.DNSSender
	injector resolve.DNSInjector

	connections    *timedcache.TimedCache[connectionID, requestInfo]
	allowedIPs     *timedcache.TimedCache[netip.Addr, struct{}]
	allowedTargets *timedcache.TimedCache[string, struct{}]

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

type requestInfo struct {
	id     uint16
	qName  string
	qType  uint16
	qClass uint16
}

// enforcer sets verdicts on packets.
type enforcer interface {
	SetVerdict(id uint32, verdict int) error
	Close() error
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
type hookCreator func(queueNum uint16, e enforcer) nfqueue.HookFunc

type enforcerCreator func(ctx context.Context, logger *zap.Logger, queueNum uint16, createHook hookCreator) (enforcer, error)

// CreateFilters creates packet filters. The returned FilterManager can
// be used to start or stop packet filtering.
func CreateFilters(ctx context.Context, logger *zap.Logger, config *Config, permissiveMode bool, fullDNSLogging bool) (*FilterManager, error) {
	f := FilterManager{
		signaler:       newSignaler(),
		permissiveMode: permissiveMode,
		fullDNSLogging: fullDNSLogging,
		logger:         logger,
		queueNum:       config.DNSResponseQueue,
		filters:        make([]*filter, len(config.Filters)),
	}

	// if mock enforcers and senders are not set, use real ones
	newEnforcer := config.enforcerCreator
	if newEnforcer == nil {
		newEnforcer = openNfQueue
	}

	anyCachedDomains := slices.ContainsFunc(config.Filters, func(opt FilterOptions) bool {
		return len(opt.CachedDomains) > 0
	})

	dnsSender := config.sender
	f.injector = config.injector
	if config.ResolveWithDoH {
		if dnsSender == nil {
			dnsSender = resolve.NewDoHSender(config.DoHURL, config.DoHServerName)
		}
		if f.injector == nil {
			var err error
			f.injector, err = resolve.NewDNSInjector()
			if err != nil {
				return nil, err
			}
		}
	} else if dnsSender == nil && anyCachedDomains {
		var err error
		dnsSender, err = resolve.NewUDPSender(config.ResolverIP)
		if err != nil {
			return nil, fmt.Errorf("creating UDP sender: %w", err)
		}
	}

	nf, err := newEnforcer(ctx, logger, config.DNSResponseQueue, newDNSResponseCallback(&f))
	if err != nil {
		return nil, err
	}
	f.dnsRespNF = nf

	// setup the self-filter first if it exists so it can be used to
	// validate DoH responses to cached domain lookups by other filters
	var startIdx int
	var validateResp resolve.ValidateRespCallback
	haveSelfFilter := config.Filters[0].Name == selfFilterName
	if haveSelfFilter {
		filter, err := createFilter(ctx, logger, &config.Filters[0], true, f.permissiveMode, f.fullDNSLogging, newEnforcer, dnsSender, nil, f.injector)
		if err != nil {
			return nil, err
		}
		f.filters[0] = filter

		validateResp = filter.validateDNSResponse
		startIdx = 1
	}

	for i := startIdx; i < len(config.Filters); i++ {
		filter, err := createFilter(ctx, logger, &config.Filters[i], false, f.permissiveMode, f.fullDNSLogging, newEnforcer, dnsSender, validateResp, f.injector)
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

	if f.dnsRespNF != nil {
		f.dnsRespNF.Close()
	}

	for i := range f.filters {
		f.filters[i].close()
	}

	if f.injector != nil {
		if err := f.injector.Close(); err != nil {
			f.logger.Error("closing raw socket", zap.Error(err))
		}
	}
}

func createFilter(ctx context.Context, logger *zap.Logger, opts *FilterOptions, isSelfFilter, permissiveMode, fullDNSLogging bool, newEnforcer enforcerCreator, sender resolve.DNSSender, validateResp resolve.ValidateRespCallback, injector resolve.DNSInjector) (*filter, error) {
	filterLogger := logger
	if opts.Name != "" {
		filterLogger = filterLogger.With(zap.String("filter.name", opts.Name))
	}

	f := filter{
		dnsReqSignaler:  newSignaler(),
		genericSignaler: newSignaler(),
		cachingSignaler: newSignaler(),
		opts:            opts,
		permissiveMode:  permissiveMode,
		fullDNSLogging:  fullDNSLogging,
		logger:          filterLogger,
		sender:          sender,
		injector:        injector,
		connections:     timedcache.New[connectionID, requestInfo](logger, true),
		isSelfFilter:    isSelfFilter,
	}

	if opts.TrafficQueue != 0 {
		f.allowedIPs = timedcache.New[netip.Addr, struct{}](f.logger, false)
		f.allowedTargets = timedcache.New[string, struct{}](filterLogger, false)

		nf, err := newEnforcer(ctx, filterLogger, opts.TrafficQueue, newGenericCallback(&f))
		if err != nil {
			return nil, fmt.Errorf("starting traffic nfqueues: %w", err)
		}
		f.genericNF = nf

		if len(f.opts.CachedDomains) > 0 {
			f.wg.Go(func() {
				f.cacheDomains(ctx, filterLogger, validateResp)
			})
		}

		var allowedIPv4Prefixes []netip.Prefix
		var allowedIPv6Prefixes []netip.Prefix
		for _, prefix := range f.opts.AllowedAnswerCIDRs {
			if prefix.Addr().Is4() {
				allowedIPv4Prefixes = append(allowedIPv4Prefixes, prefix)
			} else {
				allowedIPv6Prefixes = append(allowedIPv6Prefixes, prefix)
			}
		}

		disallowedIPv4Prefixes := slices.Clone(ssrf.IPv4DeniedPrefixes)
		disallowedIPv6Prefixes := slices.Clone(ssrf.IPv6DeniedPrefixes)
		for _, prefix := range f.opts.DisallowedAnswerCIDRs {
			if prefix.Addr().Is4() {
				disallowedIPv4Prefixes = append(disallowedIPv4Prefixes, prefix)
			} else {
				disallowedIPv6Prefixes = append(disallowedIPv6Prefixes, prefix)
			}
		}

		f.addrChecker = ssrf.New(
			ssrf.WithAllowedV4Prefixes(allowedIPv4Prefixes...),
			ssrf.WithAllowedV6Prefixes(allowedIPv6Prefixes...),
			ssrf.WithDeniedV4Prefixes(disallowedIPv4Prefixes...),
			ssrf.WithDeniedV6Prefixes(disallowedIPv6Prefixes...),
		)
	}

	if opts.DNSQueue != 0 {
		nf, err := newEnforcer(ctx, filterLogger, opts.DNSQueue, newDNSRequestCallback(ctx, &f))
		if err != nil {
			return nil, fmt.Errorf("starting DNS nfqueues: %w", err)
		}
		f.dnsReqNF = nf

	}

	return &f, nil
}

func openNfQueue(ctx context.Context, logger *zap.Logger, queueNum uint16, createHook hookCreator) (enforcer, error) {
	nfqConf := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  0xffff,
		AfFamily:     unix.AF_UNSPEC,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	}

	nf, err := nfqueue.Open(&nfqConf)
	if err != nil {
		return nil, fmt.Errorf("opening nfqueue: %w", err)
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
		return nil, fmt.Errorf("setting ExtendedAcknowledge netlink option: %w", err)
	}
	err = nf.Con.SetOption(netlink.GetStrictCheck, true)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return nil, fmt.Errorf("setting GetStrictCheck netlink option: %w", err)
	}

	hook := createHook(queueNum, nf)
	if err := nf.RegisterWithErrorFunc(ctx, hook, newErrorCallback(logger)); err != nil {
		return nil, fmt.Errorf("registering nfqueue: %w", err)
	}

	ok = true

	return nf, nil
}

func (f *filter) start() {
	if f.opts.DNSQueue != 0 {
		f.dnsReqSignaler.ready()
	}
	if f.opts.TrafficQueue != 0 {
		f.genericSignaler.ready()
	}
	if len(f.opts.CachedDomains) > 0 {
		f.cachingSignaler.ready()
	}

	f.started = true
}

func (f *filter) close() {
	// if the filter has not been started yet, tell running goroutines
	// to abort and finish
	if !f.started {
		if f.opts.DNSQueue != 0 {
			f.dnsReqSignaler.abort()
		}
		if f.opts.TrafficQueue != 0 {
			f.genericSignaler.abort()
		}
		if len(f.opts.CachedDomains) > 0 {
			f.cachingSignaler.abort()
		}
	}

	f.wg.Wait()

	if f.dnsReqNF != nil {
		f.dnsReqNF.Close()
	}
	if f.genericNF != nil {
		f.genericNF.Close()
	}

	f.connections.Stop()
	if f.allowedIPs != nil {
		f.allowedIPs.Stop()
	}
	if f.allowedTargets != nil {
		f.allowedTargets.Stop()
	}
}

// validateDNSResponse validates a DNS response against a DNS request.
// This is really only useful for cacheDomains of various filters
// to use the self-filter to check DoH responses.
func (f *filter) validateDNSResponse(reqMsg, respMsg *dns.Msg) error {
	ri, err := newRequestInfo(reqMsg)
	if err != nil {
		return err
	}

	// confirm that the request and response question matches
	if err := f.compareDNSReqResp(ri, respMsg); err != nil {
		return fmt.Errorf("checking response against request: %w", err)
	}

	// allow DNS response if there are no answers
	if len(respMsg.Answer) != 0 {
		// validate all DNS answer owner names before adding any
		// IPs or domains any allowed lists
		if err := f.validateDNSAnswers(respMsg); err != nil {
			return fmt.Errorf("validating DNS response answers: %w", err)
		}
	}

	return nil
}

func (f *filter) cacheDomains(ctx context.Context, logger *zap.Logger, validateResp resolve.ValidateRespCallback) {
	// wait until the filter manager is setup to prevent race conditions
	select {
	case <-f.cachingSignaler.isReady():
	case <-f.cachingSignaler.shouldAbort():
		// the filter manager has been stopped before it was started,
		// return so the parent filter can finish cleaning up
		return
	}

	if validateResp == nil {
		if f.opts.Name != selfFilterName {
			panic("validateResp must be set for non-self filters")
		}
		validateResp = f.validateDNSResponse
	}

	logger.Debug("starting cache loop", zap.String("transport", f.sender.TransportType()))

	var wg sync.WaitGroup
	// add to the user supplied duration to ensure there isn't a
	// window where domains are not allowed
	ttl := f.opts.ReCacheEvery + resolve.DNSQueryTimeout
	timer := time.NewTimer(f.opts.ReCacheEvery)
	defer timer.Stop()

	for {
		// resolve domains concurrently to avoid IPs in the timed cache
		// getting removed before the queries return
		// TODO: expose config option to limit amount of inflight requests?
		for i := range f.opts.CachedDomains {
			wg.Go(func() {
				logger.Info("caching lookup of domain", zap.String("domain", f.opts.CachedDomains[i]))
				addrs, errs := resolve.Domain(ctx, f.opts.CachedDomains[i], f.sender, validateResp)
				if len(errs) > 0 {
					logger.Warn("resolving domain", zap.String("domain", f.opts.CachedDomains[i]), zap.Errors("errors", errs))
				} else if len(addrs) == 0 {
					logger.Warn("no IPs found for domain", zap.String("domain", f.opts.CachedDomains[i]))
					return
				}

				for i := range addrs {
					logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]))
					f.allowedIPs.Add(addrs[i], ttl)

					// If the IP address is an IPv4-mapped IPv6 address,
					// add the unwrapped IPv4 address too. That is what
					// will most likely be used.
					if addrs[i].Is4In6() {
						addrs[i] = addrs[i].Unmap()
						logger.Info("allowing IP from cached lookup", zap.Stringer("ip", addrs[i]))
						f.allowedIPs.Add(addrs[i], ttl)
					}
				}
			})
		}

		wg.Wait()

		timer.Reset(f.opts.ReCacheEvery)
		select {
		case <-ctx.Done():
			logger.Debug("exiting cache loop")
			return
		case <-timer.C:
		}
	}
}

func newDNSRequestCallback(ctx context.Context, f *filter) hookCreator {
	createCallback := func(logger *zap.Logger) packetCallback {
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
				logger.Warn("ignoring packet with no packet ID")
				return ignoreVerdict
			}
			if attr.CtInfo == nil {
				logger.Warn("dropping packet with no connection state")
				return dropVerdict
			}
			if attr.HwProtocol == nil {
				logger.Warn("dropping packet with no hardware protocol")
				return dropVerdict
			}
			if attr.Payload == nil {
				logger.Warn("dropping packet with no payload")
				return dropVerdict
			}

			// verify DNS request is from a new or established connection
			if *attr.CtInfo != stateNew && !connIsEstablished(*attr.CtInfo) {
				logger.Warn("dropping DNS request with unknown state", zap.Uint32("conn.state", *attr.CtInfo))
				return dropVerdict
			}
			if *attr.HwProtocol != unix.ETH_P_IP && *attr.HwProtocol != unix.ETH_P_IPV6 {
				logger.Warn("dropping packet with unknown hardware protocol", zap.Uint16("hw.protocol", *attr.HwProtocol))
				return dropVerdict
			}

			reqMsg, connID, err := parseDNSPacket(*attr.Payload, *attr.HwProtocol == unix.ETH_P_IPV6, false)
			if err != nil {
				fields := []zap.Field{zap.Error(err)}
				if reqMsg != nil {
					fields = append(fields, dnsFields(reqMsg, f.fullDNSLogging)...)
				}
				logger.Error("parsing DNS packet", fields...)
				return dropVerdict
			}
			logger := logger.With(zap.Stringer("conn.src", connID.src), zap.Stringer("conn.dst", connID.dst))

			if reqMsg.Opcode != dns.OpcodeQuery {
				logger.Warn("dropping DNS request with non-query opcode", dnsFields(reqMsg, f.fullDNSLogging)...)
				return dropVerdict
			}
			// drop DNS replies, they shouldn't be going to this filter
			if reqMsg.Response || len(reqMsg.Answer) > 0 || len(reqMsg.Ns) > 0 {
				logger.Warn("dropping DNS response sent to DNS request filter", dnsFields(reqMsg, f.fullDNSLogging)...)
				return dropVerdict
			}

			// validate DNS request questions are for allowed
			// domains, drop them otherwise
			ri, err := f.validateDNSQuestion(reqMsg)
			if err != nil {
				logger.Warn("dropping DNS request", f.dropReasonFields(err, reqMsg)...)
				return dropVerdict
			}

			if f.injector != nil {
				logger.Info("forwarding DNS request over DoH", dnsFields(reqMsg, f.fullDNSLogging)...)
				respMsg, err := f.proxyDoH(ctx, reqMsg, ri)
				if err != nil {
					logger.Error("forwarding DoH request", zap.Error(err))
					return dropVerdict
				}
				f.handleAnswers(respMsg)

				logger.Info("injecting DNS response from DoH", dnsFields(respMsg, f.fullDNSLogging)...)
				if err := f.injector.InjectResponse(respMsg, connID.src, connID.dst, attr); err != nil {
					logger.Error("injecting DNS response", zap.Error(err))
					return dropVerdict
				}

				// If we are proxying the response over DoH, always drop
				// the original request. The sender won't know we dropped
				// it as UDP is stateless, and we already got a response
				// using DoH so this plaintext request doesn't need to
				// reach the resolver.
				return dropVerdict
			}

			logger.Info("allowing DNS request", dnsFields(reqMsg, f.fullDNSLogging)...)
			logger.Debug("adding connection")
			f.connections.AddValue(connID, ri, resolve.DNSQueryTimeout)

			return acceptVerdict
		}
	}

	return func(queueNum uint16, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "dns-req"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		if f.permissiveMode {
			logger = logger.With(zap.Bool("permissive", true))
		}
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger), f.permissiveMode)
	}
}

// proxyDoH forwards a DNS request over DoH, verifies the response and
// returns it if it's allowed.
func (f *filter) proxyDoH(ctx context.Context, reqMsg *dns.Msg, ri requestInfo) (*dns.Msg, error) {
	respMsg, err := f.sender.SendRequest(ctx, reqMsg)
	if err != nil {
		return nil, fmt.Errorf("forwarding DoH request: %w", err)
	}
	// dnshttp.NewRequest sets the message ID to zero, so we need to
	// set it back
	respMsg.ID = ri.id

	// confirm that the request and response question matches
	if err := f.compareDNSReqResp(ri, respMsg); err != nil {
		return nil, fmt.Errorf("checking response against request: %w", err)
	}

	// allow DNS response if there are no answers
	if len(respMsg.Answer) != 0 {
		// validate all DNS answer owner names before adding any
		// IPs or domains any allowed lists
		if err := f.validateDNSAnswers(respMsg); err != nil {
			return nil, fmt.Errorf("validating DNS response answers: %w", err)
		}
	}

	return respMsg, nil
}

func parseDNSPacket(packet []byte, ipv6, inbound bool) (*dns.Msg, connectionID, error) {
	var (
		ip4     layers.IPv4
		ip6     layers.IPv6
		udp     layers.UDP
		dnsMsg  dns.Msg
		parser  *gopacket.DecodingLayerParser
		decoded = make([]gopacket.LayerType, 0, 2)
	)

	// parse DNS packet
	if !ipv6 {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp)
	} else {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &udp)
	}
	parser.IgnoreUnsupported = true

	if err := parser.DecodeLayers(packet, &decoded); err != nil {
		return nil, connectionID{}, fmt.Errorf("decoding packet: %w", err)
	}
	if len(decoded) != 2 {
		return nil, connectionID{}, fmt.Errorf("%d layers were parsed, expecting 2", len(decoded))
	}
	if decoded[1] != layers.LayerTypeUDP {
		return nil, connectionID{}, fmt.Errorf("unexpected layer type for second layer: %s", decoded[1])
	}

	dnsMsg.Data = udp.Payload
	if err := dnsMsg.Unpack(); err != nil {
		return nil, connectionID{}, fmt.Errorf("decoding DNS message: %w", err)
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
		return nil, connectionID{}, errors.New("converting IPs")
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

	return &dnsMsg, connID, nil
}

func (f *filter) validateDNSQuestion(dnsMsg *dns.Msg) (requestInfo, error) {
	if len(dnsMsg.Question) > 1 {
		// drop DNS requests with more than one question; this is
		// disallowed by RFC 9619: https://www.rfc-editor.org/info/rfc9619/#name-security-considerations
		return requestInfo{}, fmt.Errorf("%d questions in DNS request, expected 1", len(dnsMsg.Question))
	}

	ri, err := newRequestInfo(dnsMsg)
	if err != nil {
		return requestInfo{}, err
	}

	if ri.qClass != dns.ClassINET {
		return requestInfo{}, fmt.Errorf("question class %s is not INET", qClassToString(ri.qClass))
	}
	if !slices.Contains(allowedRRTypes, ri.qType) {
		return requestInfo{}, fmt.Errorf("question type %s is not allowed", rrTypeToString(ri.qType))
	}

	ok, err := f.validateDNSName(ri.qType, ri.qName)
	if err != nil {
		return requestInfo{}, fmt.Errorf("validating domain name %q in question: %w", ri.qName, err)
	}
	if !ok {
		return requestInfo{}, fmt.Errorf("domain name %q in question is not allowed", ri.qName)
	}

	return ri, nil
}

func (f *filter) compareDNSReqResp(req requestInfo, resp *dns.Msg) error {
	if req.id != resp.ID {
		return errors.New("request and response IDs do not match")
	}
	if len(resp.Question) == 0 {
		return errors.New("no questions in DNS response")
	}
	if len(resp.Question) > 1 {
		// drop DNS responses with more than one question; this is
		// disallowed by RFC 9619: https://www.rfc-editor.org/info/rfc9619/#name-security-considerations
		return fmt.Errorf("%d questions in DNS response, expected 1", len(resp.Question))
	}

	// the response question should match the request's question
	respQ := resp.Question[0]
	respQHdr := respQ.Header()
	if respQHdr == nil {
		return errors.New("response question header is nil")
	}
	qType := dns.RRToType(respQ)

	if req.qType != qType {
		return errors.New("request and response question types do not match")
	} else if req.qClass != respQHdr.Class {
		return errors.New("request and response question classes do not match")
	} else if !strings.EqualFold(req.qName, respQHdr.Name) {
		return errors.New("request and response question names do not match")
	}

	return nil
}

func (f *filter) validateDNSAnswers(dnsMsg *dns.Msg) error {
	var allowedTargets []string

	for _, a := range dnsMsg.Answer {
		h := a.Header()
		if h == nil {
			return errors.New("answer header is nil")
		}

		if h.Class != dns.ClassINET {
			return fmt.Errorf("answer RR class %s is not INET", qClassToString(h.Class))
		}
		rrType := dns.RRToType(a)

		// if the owner name is a target from a previous allowed RR it's
		// safe to allow it
		if !slices.Contains(allowedTargets, prepareDomainName(h.Name)) {
			ok, err := f.validateDNSName(rrType, h.Name)
			if err != nil {
				return fmt.Errorf("validating owner domain name %q in answer of RR type %s: %w", h.Name, rrTypeToString(rrType), err)
			}
			if !ok {
				return fmt.Errorf("owner domain name %q in answer of RR type %s is not allowed", h.Name, rrTypeToString(rrType))
			}
		}

		// ensure all target answers are allowed
		// types here must match allowedRRTypes slice
		var emptyTarget bool
		var target string
		switch answer := a.(type) {
		case *dns.A:
			emptyTarget = true
			if !answer.Addr.Is4() {
				return fmt.Errorf("IP address %s in A answer is not an IPv4 address", answer.Addr)
			}
			// the self-filter doesn't have addrChecker set, the parent
			// filter will check the IPs in the answers if it's allowed
			if f.isSelfFilter {
				break
			}

			if err := f.addrChecker.SafeAddr(answer.Addr); err != nil {
				return fmt.Errorf("IP address in A answer: %w", err)
			}
		case *dns.AAAA:
			emptyTarget = true
			if !answer.Addr.Is6() {
				return fmt.Errorf("IP address %s in AAAA answer is not an IPv6 address", answer.Addr)
			}
			// the self-filter doesn't have addrChecker set, the parent
			// filter will check the IPs in the answers if it's allowed
			if f.isSelfFilter {
				break
			}

			if err := f.addrChecker.SafeAddr(answer.Addr); err != nil {
				return fmt.Errorf("IP address in AAAA answer: %w", err)
			}
		case *dns.CNAME:
			target = answer.Target
		case *dns.SRV:
			target = answer.Target
		case *dns.HTTPS:
			target = answer.Target
		case *dns.SVCB:
			target = answer.Target
		case *dns.MX:
			target = answer.Mx
		default:
			return fmt.Errorf("disallowed RR type %s for answer", rrTypeToString(rrType))
		}
		if emptyTarget || target == "." {
			continue
		}

		ok, err := f.targetAllowed(target)
		if err != nil {
			return fmt.Errorf("validating target %q in answer of RR type %s: %w", target, rrTypeToString(rrType), err)
		}
		if !ok {
			return fmt.Errorf("target domain name %q in answer is not allowed", target)
		}
		allowedTargets = append(allowedTargets, prepareDomainName(target))
	}

	return nil
}

func (f *filter) validateDNSName(qtype uint16, name string) (bool, error) {
	// strip prefix labels from appropriate question types, ex a domain
	// for a SRV record might begin with '_https._tcp'
	var strippedName string
	switch qtype {
	case dns.TypeSRV:
		s, labelsStripped := stripPrefixLabels(name)
		if labelsStripped < 2 {
			return false, errors.New("not enough prefix labels")
		} else if labelsStripped > 2 {
			return false, errors.New("too many prefix labels")
		}
		strippedName = s
	case dns.TypeHTTPS:
		s, labelsStripped := stripPrefixLabels(name)
		if labelsStripped != 0 && labelsStripped != 2 {
			return false, errors.New("unexpected number of prefix labels")
		}
		strippedName = s
	case dns.TypeSVCB:
		s, labelsStripped := stripPrefixLabels(name)
		if labelsStripped == 0 {
			return false, errors.New("no prefix labels")
		} else if labelsStripped > 2 {
			return false, errors.New("too many prefix labels")
		}
		strippedName = s
	default:
		strippedName = name
	}

	if ok, err := f.domainAllowed(strippedName); !ok || err != nil {
		return false, err
	}

	return true, nil
}

// domainAllowed checks if a domain name from a question or an owner
// name from an answer is allowed by the filter.
func (f *filter) domainAllowed(domain string) (bool, error) {
	return f.domainNameAllowed(domain, false)
}

// targetAllowed checks if a domain name from specific answer RRs that
// specify targets is allowed by the filter.
func (f *filter) targetAllowed(target string) (bool, error) {
	// allow root labels, they're used in HTTPS and other RRs and are
	// harmless to allow
	if target == "." {
		return true, nil
	}

	return f.domainNameAllowed(target, true)
}

func (f *filter) domainNameAllowed(domain string, isTarget bool) (bool, error) {
	err := validDomainName(domain)
	if err != nil {
		return false, err
	}

	// if all domains are allowed we don't need to check anything else
	if f.opts.AllowAllDomains {
		return true, nil
	}

	lowerDomain := prepareDomainName(domain)
	f.logger.Debug("checking if domain is allowed", zap.String("domain", lowerDomain))

	for _, matcher := range f.opts.allowedDomainMatchers {
		if matcher.Match(lowerDomain) {
			return true, nil
		}
	}

	// if the domain name is a target, check if it's allowed by any of
	// the allowed targets matchers or if already exists as an
	// additional allowed domain
	if isTarget {
		for _, matcher := range f.opts.allowedTargetMatchers {
			if matcher.Match(lowerDomain) {
				return true, nil
			}
		}
	}

	// the self-filter doesn't allow any IPs or additionalDomains
	if f.isSelfFilter {
		return false, nil
	}

	return f.allowedTargets.Exists(lowerDomain), nil
}

// handleAnswers allows IPs and domains in answers of a DNS response;
// this should not be called until the DNS response is fully validated.
func (f *filter) handleAnswers(dnsMsg *dns.Msg) {
	ttl := f.opts.AllowAnswersFor
	for _, a := range dnsMsg.Answer {
		var target string
		// types here must match allowedRRTypes slice
		switch answer := a.(type) {
		case *dns.A:
			f.allowedIPs.Add(answer.Addr, ttl)
		case *dns.AAAA:
			addr := answer.Addr
			f.allowedIPs.Add(addr, ttl)

			// If the IP address is an IPv4-mapped IPv6 address,
			// add the unwrapped IPv4 address too. That is what
			// will most likely be used.
			if addr.Is4In6() {
				f.allowedIPs.Add(addr.Unmap(), ttl)
			}
		case *dns.CNAME:
			target = answer.Target
		case *dns.SRV:
			target = answer.Target
		case *dns.HTTPS:
			target = answer.Target
		case *dns.SVCB:
			target = answer.Target
		case *dns.MX:
			target = answer.Mx
		default:
			// other answer types are rejected in (*filter).validateDNSAnswers
		}
		// temporarily allow resolution of the target domain, but skip root domains
		if target != "" && target != "." {
			f.allowedTargets.Add(prepareDomainName(target), ttl)
		}
	}
}

func newHookFunc(logger *zap.Logger, e enforcer, callback packetCallback, permissiveMode bool) nfqueue.HookFunc {
	return func(attr nfqueue.Attribute) int {
		// panics should be very rare, but worth recovering from them as
		// defense in depth
		defer func() {
			if r := recover(); r != nil {
				logger.Error("recovered from panic", zap.Any("panic", r))
				// attempt to set a drop verdict to fail closed; we don't
				// know what caused the panic so this may panic as well, but
				// chances are high that the panic happened in the callback,
				// not when setting a verdict, and we don't want the nfqueue
				// to fill up
				setVerdict(logger, e, attr, dropVerdict, permissiveMode)
			}
		}()

		v := callback(attr)
		setVerdict(logger, e, attr, v, permissiveMode)
		return 0
	}
}

func newDNSResponseCallback(f *FilterManager) hookCreator {
	createCallback := func(logger *zap.Logger) packetCallback {
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
				logger.Warn("dropping packet with no packet ID")
				return ignoreVerdict
			}
			if attr.CtInfo == nil {
				logger.Warn("dropping packet with no connection state")
				return dropVerdict
			}
			if attr.HwProtocol == nil {
				logger.Warn("dropping packet with no hardware protocol")
				return dropVerdict
			}
			if attr.Payload == nil {
				logger.Warn("dropping packet with no payload")
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
			if *attr.HwProtocol != unix.ETH_P_IP && *attr.HwProtocol != unix.ETH_P_IPV6 {
				logger.Warn("dropping packet with unknown hardware protocol", zap.Uint16("hw.protocol", *attr.HwProtocol))
				return dropVerdict
			}

			respMsg, connID, err := parseDNSPacket(*attr.Payload, *attr.HwProtocol == unix.ETH_P_IPV6, true)
			if err != nil {
				fields := []zap.Field{zap.Error(err)}
				if respMsg != nil {
					fields = append(fields, dnsFields(respMsg, f.fullDNSLogging)...)
				}
				logger.Error("parsing DNS packet", fields...)
				return dropVerdict
			}
			logger := logger.With(zap.Stringer("conn.src", connID.src), zap.Stringer("conn.dst", connID.dst))

			var connFilter *filter
			var reqInfo requestInfo
			for _, filter := range f.filters {
				if ri, ok := filter.connections.Lookup(connID); ok {
					connFilter = filter
					reqInfo = ri
					break
				}
			}
			if connFilter == nil {
				logger.Warn("dropping DNS response from unknown connection", dnsFields(respMsg, f.fullDNSLogging)...)
				return dropVerdict
			}
			logger.Debug("removing connection")
			connFilter.connections.Remove(connID)

			logger = logger.With(zap.String("dns-req.filter.name", connFilter.opts.Name))

			// if we are proxying requests over DoH, we should never
			// receive plaintext DNS responses
			if connFilter.injector != nil {
				logger.Warn("dropping unsolicited DNS response", dnsFields(respMsg, f.fullDNSLogging)...)
				return dropVerdict
			}

			// confirm that the request and response ID and question matches
			if err := connFilter.compareDNSReqResp(reqInfo, respMsg); err != nil {
				logger.Info("dropping DNS response", connFilter.dropReasonFields(err, respMsg)...)
				return dropVerdict
			}

			// allow DNS response if the filter it came from is the self
			// filter, all domains are allowed, or if there are no answers
			if len(respMsg.Answer) == 0 {
				logger.Info("allowing DNS response", dnsFields(respMsg, f.fullDNSLogging)...)
				return acceptVerdict
			}

			// validate all DNS answer owner names before adding any
			// IPs or domains any allowed lists
			if err := connFilter.validateDNSAnswers(respMsg); err != nil {
				logger.Info("dropping DNS response", connFilter.dropReasonFields(err, respMsg)...)
				return dropVerdict
			}
			// the self filter should never allow additional IPs or domains
			if !connFilter.isSelfFilter {
				connFilter.handleAnswers(respMsg)
			}

			logger.Info("allowing DNS response", dnsFields(respMsg, f.fullDNSLogging)...)

			return acceptVerdict
		}
	}

	return func(queueNum uint16, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "dns-resp"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		if f.permissiveMode {
			logger = logger.With(zap.Bool("permissive", true))
		}
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger), f.permissiveMode)
	}
}

func newGenericCallback(f *filter) hookCreator {
	createCallback := func(logger *zap.Logger) packetCallback {
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
				logger.Warn("dropping packet with no packet ID")
				return ignoreVerdict
			}
			if attr.HwProtocol == nil {
				logger.Warn("dropping packet with no hardware protocol")
				return dropVerdict
			}
			if attr.Payload == nil {
				logger.Warn("dropping packet with no payload")
				return dropVerdict
			}

			if *attr.HwProtocol != unix.ETH_P_IP && *attr.HwProtocol != unix.ETH_P_IPV6 {
				logger.Warn("dropping packet with unknown hardware protocol", zap.Uint16("hw.protocol", *attr.HwProtocol))
				return dropVerdict
			}

			var (
				ip4     layers.IPv4
				ip6     layers.IPv6
				parser  *gopacket.DecodingLayerParser
				decoded = make([]gopacket.LayerType, 1)
			)

			// parse packet
			if *attr.HwProtocol == unix.ETH_P_IP {
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
				logger.Error("parsing packet", zap.Error(err))
				return dropVerdict
			}
			if len(decoded) == 0 {
				logger.Warn("dropping packet with no layers")
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
					logger.Error("converting IPs", zap.Stringer("conn.src", ip4.SrcIP), zap.Stringer("conn.dst", ip4.DstIP))
					return dropVerdict
				}
			case layers.LayerTypeIPv6:
				src, srcOK = netip.AddrFromSlice(ip6.SrcIP)
				dst, dstOK = netip.AddrFromSlice(ip6.DstIP)
				if !srcOK || !dstOK {
					logger.Error("converting IPs", zap.Stringer("conn.src", ip6.SrcIP), zap.Stringer("conn.dst", ip6.DstIP))
					return dropVerdict
				}
			default:
				logger.Error("unknown IP protocol", zap.Stringer("protocol", decoded[0]))
				return dropVerdict
			}

			// validate that the destination IP is allowed
			if f.allowedIPs.Exists(dst) {
				logger.Info("allowing packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
				return acceptVerdict
			}

			logger.Info("dropping packet", zap.Stringer("conn.src", src), zap.Stringer("conn.dst", dst))
			return dropVerdict
		}
	}

	return func(queueNum uint16, e enforcer) nfqueue.HookFunc {
		logger := f.logger.With(zap.String("filter.type", "traffic"))
		logger = logger.With(zap.Uint16("queue.num", queueNum))
		if f.permissiveMode {
			logger = logger.With(zap.Bool("permissive", true))
		}
		logger.Info("started nfqueue")

		return newHookFunc(logger, e, createCallback(logger), f.permissiveMode)
	}
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
