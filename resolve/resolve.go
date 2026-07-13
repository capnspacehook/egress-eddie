package resolve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnshttp"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/capnspacehook/singleflight-generic"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/egress-eddie/types"
)

const (
	DNSQueryTimeout = 20 * time.Second

	resolvConfPath = "/etc/resolv.conf"
	numRetries     = 2
)

// DNSSender sends DNS requests and returns DNS responses.
type DNSSender interface {
	// SendRequest sends a DNS request and returns the response.
	SendRequest(ctx context.Context, dnsReq *dns.Msg) (dnsResp *dns.Msg, err error)
	// ResponsesValidated reports whether the DNS responses are validated
	// before they're returned.
	ResponsesValidated() bool
	// TransportType returns the network protocol used to send DNS requests.
	TransportType() string
}

type ValidateRespCallback func(req, resp *dns.Msg) error

type lookupResult struct {
	resp *dns.Msg
	err  error
}

// Domain resolve a domain to IP address(es). On success a slice of IP
// addresses and a slice of errors are returned. Note that the slice of errors
// may not be empty even when IP addresses are returned; one or more queries
// may have succeeded while others failed.
func Domain(ctx context.Context, domain string, sender DNSSender, validateResp ValidateRespCallback) ([]netip.Addr, []error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, DNSQueryTimeout)
	defer cancel()

	reqA := dns.NewMsg(domain, dns.TypeA)
	reqAAAA := dns.NewMsg(domain, dns.TypeAAAA)

	results := make(chan lookupResult, 2)
	doLookup := func(req *dns.Msg, rrStr string) {
		resp, err := sender.SendRequest(timeoutCtx, req)
		if err != nil {
			err = fmt.Errorf("lookup %s %s: %w", domain, rrStr, err)
		}
		if !sender.ResponsesValidated() && resp != nil {
			err = validateResp(req, resp)
			if err != nil {
				err = fmt.Errorf("validate response of %s %s: %w", domain, rrStr, err)
				resp = nil
			}
		}

		results <- lookupResult{resp, err}
	}
	// TODO: allow users to specify which types to resolve?
	go doLookup(reqA, "A")
	go doLookup(reqAAAA, "AAAA")

	addrs := make([]netip.Addr, 0, 2)
	lookupErrs := make([]error, 0, 2)
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				lookupErrs = append(lookupErrs, result.err)
				break
			}

			if result.resp != nil {
				if result.resp.Rcode != dns.RcodeSuccess {
					switch result.resp.Rcode {
					case dns.RcodeNameError:
						return nil, []error{errors.New("domain name does not exist")}
					case dns.RcodeServerFailure:
						lookupErrs = append(lookupErrs, errors.New("server failure"))
					case dns.RcodeRefused:
						lookupErrs = append(lookupErrs, errors.New("refused"))
					case dns.RcodeFormatError:
						lookupErrs = append(lookupErrs, errors.New("format error"))
					case dns.RcodeNotImplemented:
						lookupErrs = append(lookupErrs, errors.New("not implemented"))
					default:
						lookupErrs = append(lookupErrs, fmt.Errorf("received response code %s", dnsutil.RcodeToString(result.resp.Rcode)))
					}

					continue
				}

				for _, rr := range result.resp.Answer {
					switch a := rr.(type) {
					case *dns.A:
						addrs = append(addrs, a.Addr)
					case *dns.AAAA:
						addrs = append(addrs, a.Addr)
					}
				}
			}
		case <-timeoutCtx.Done():
			return addrs, []error{timeoutCtx.Err()}
		}
	}

	return addrs, lookupErrs
}

type singleFlightSender struct {
	sf     *singleflight.Group[types.RequestInfo, *dns.Msg]
	sender DNSSender
}

// NewSingleFlightSender returns a [DNSSender] that will ensure that
// multiple calls with semantically equivalent requests only result in
// a single send of the DNS request, given that the requests come in
// while one is already in flight.
func NewSingleFlightSender(sender DNSSender) DNSSender {
	return &singleFlightSender{
		sf:     new(singleflight.Group[types.RequestInfo, *dns.Msg]),
		sender: sender,
	}
}

// TODO: key off of the cookie as well if if needed
func (s *singleFlightSender) SendRequest(ctx context.Context, dnsReq *dns.Msg) (dnsResp *dns.Msg, err error) {
	ri, err := types.NewRequestInfo(dnsReq)
	if err != nil {
		return nil, err
	}
	// clear the ID and lowercase the name so semantically equivalent
	// requests are grouped together
	ri.ID = 0
	ri.Name = strings.ToLower(ri.Name)

	respMsg, err, shared := s.sf.Do(ri, func() (*dns.Msg, error) {
		return s.sender.SendRequest(ctx, dnsReq)
	})
	if err != nil {
		return nil, err
	}

	if !shared {
		return respMsg, nil
	}

	// copy the response message to avoid callers causing races and
	// set the ID to match the request
	respCopy := respMsg.Copy()
	respCopy.ID = dnsReq.ID

	return respCopy, nil
}

func (s *singleFlightSender) ResponsesValidated() bool {
	return s.sender.ResponsesValidated()
}

func (s *singleFlightSender) TransportType() string {
	return s.sender.TransportType()
}

type udpSender struct {
	resolverAddrs []string

	client *dns.Client
}

func NewUDPSender(resolverHost string) (DNSSender, error) {
	ur := udpSender{
		client: dns.NewClient(),
	}

	if resolverHost != "" {
		ur.resolverAddrs = []string{net.JoinHostPort(resolverHost, "53")}
		return &ur, nil
	}

	conf, err := dnsconf.FromFile(resolvConfPath)
	if err != nil {
		return nil, err
	}
	if len(conf.Servers) == 0 {
		return nil, fmt.Errorf(`no DNS servers found in %s; specify a resolver with "resolverIP"`, resolvConfPath)
	}
	for _, server := range conf.Servers {
		_, err := netip.ParseAddr(server)
		if err != nil {
			return nil, err
		}

		ur.resolverAddrs = append(ur.resolverAddrs, net.JoinHostPort(server, conf.Port))
	}

	return &ur, nil
}

func (u *udpSender) SendRequest(ctx context.Context, dnsReq *dns.Msg) (dnsResp *dns.Msg, err error) {
	for _, addr := range u.resolverAddrs {
		for range numRetries {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			dnsResp, _, err = u.client.Exchange(ctx, dnsReq, "udp", addr)
			if err == nil {
				return dnsResp, nil
			}
		}
	}

	return
}

func (u *udpSender) ResponsesValidated() bool {
	// the self-filter should validate all responses before we receive
	// them so this is true
	return true
}

func (u *udpSender) TransportType() string {
	return "udp"
}

type dohSender struct {
	resolverURL string
	client      *http.Client
}

func NewDoHSender(resolverURL, serverName string) (DNSSender, error) {
	u, err := url.Parse(resolverURL)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return nil, err
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		port = int(p)
	}

	c := http.Client{
		Transport: &http.Transport{
			// ensure the IP is dialed directly
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				addr := net.TCPAddr{
					IP:   ip.AsSlice(),
					Port: port,
					Zone: ip.Zone(),
				}
				return net.DialTCP("tcp", nil, &addr)
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: dnshttp.NextProtos,
				ServerName: serverName,
			},
			ForceAttemptHTTP2: true,
		},
		// reject all redirects, DoH servers shouldn't do this
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
		Timeout: DNSQueryTimeout,
	}

	return &dohSender{
		resolverURL: resolverURL,
		client:      &c,
	}, nil
}

func (d *dohSender) SendRequest(ctx context.Context, dnsReq *dns.Msg) (*dns.Msg, error) {
	id := dnsReq.ID

	httpReq, err := dnshttp.NewRequest("GET", d.resolverURL, dnsReq)
	if err != nil {
		return nil, fmt.Errorf("creating DoH request: %w", err)
	}
	httpReq = httpReq.WithContext(ctx)
	httpResp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending DoH request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status code %d", httpResp.StatusCode)
	}

	dnsResp, err := dnshttp.Response(httpResp)
	if err != nil {
		return nil, fmt.Errorf("reading DoH response: %w", err)
	}

	// dnshttp.NewRequest sets the message ID to zero, so we need to
	// set it back and make the response match the original request ID
	dnsReq.ID = id
	dnsResp.ID = id

	return dnsResp, nil
}

func (d *dohSender) ResponsesValidated() bool {
	// the self-filter can't read DoH traffic so responses are not
	// validated
	return false
}

func (d *dohSender) TransportType() string {
	return "https"
}

// DNSInjector injects synthetic DNS responses back to a client, used when
// proxying requests over DoH.
type DNSInjector interface {
	// InjectResponse crafts and sends a UDP packet containing dnsResp to the
	// client identified by srcAddr, appearing to come from dstAddr.
	InjectResponse(dnsResp *dns.Msg, connID types.ConnectionID, attr nfqueue.Attribute) error
	Close() error
}

type rawInjector struct {
	mtx    sync.RWMutex
	closed bool

	loIface *net.Interface
	socket  int
}

func NewDNSInjector() (DNSInjector, error) {
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket: %w", err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("getting network interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, errors.New("no network interfaces found")
	}

	var loIface *net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loIface = &iface
			break
		}
	}

	return &rawInjector{
		loIface: loIface,
		socket:  sock,
	}, nil
}

func (d *rawInjector) Close() error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.closed = true

	return unix.Close(d.socket)
}

type netPacket interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}

func (d *rawInjector) InjectResponse(dnsResp *dns.Msg, connID types.ConnectionID, attr nfqueue.Attribute) error {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	if d.closed {
		return errors.New("socket is closed")
	}

	var srcMAC, dstMAC net.HardwareAddr
	var sa *unix.SockaddrLinklayer
	if attr.HwAddr != nil {
		if attr.PhysInDev == nil && attr.InDev == nil {
			return errors.New("inDev and physInDev are nil")
		}
		var ifaceIDx int
		if attr.PhysInDev != nil {
			ifaceIDx = int(*attr.PhysInDev)
		} else {
			ifaceIDx = int(*attr.InDev)
		}

		iface, err := net.InterfaceByIndex(ifaceIDx)
		if err != nil {
			return fmt.Errorf("looking up interface: %w", err)
		}

		srcMAC = iface.HardwareAddr
		dstMAC = net.HardwareAddr(*attr.HwAddr)
		sa = &unix.SockaddrLinklayer{Ifindex: ifaceIDx}
	} else {
		// gopacket requires the MACs to have a length of 6 but they don't
		// need to be populated, the kernel will ignore them
		srcMAC = make(net.HardwareAddr, 6)
		dstMAC = make(net.HardwareAddr, 6)

		sa = &unix.SockaddrLinklayer{Ifindex: d.loIface.Index}
	}

	ethLayer := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	var ipLayer netPacket
	if connID.Src.Addr().Is6() {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
		ipLayer = &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      connID.Dst.Addr().AsSlice(),
			DstIP:      connID.Src.Addr().AsSlice(),
		}
	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		ipLayer = &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    connID.Dst.Addr().AsSlice(),
			DstIP:    connID.Src.Addr().AsSlice(),
		}
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(connID.Dst.Port()),
		DstPort: layers.UDPPort(connID.Src.Port()),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("setting UDP checksum layer: %w", err)
	}
	if err := dnsResp.Pack(); err != nil {
		return fmt.Errorf("encoding dns response: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, gopacket.Payload(dnsResp.Data))
	if err != nil {
		return fmt.Errorf("encoding packet: %w", err)
	}

	if err := unix.Sendto(d.socket, buf.Bytes(), 0, sa); err != nil {
		return fmt.Errorf("sending packet: %w", err)
	}

	return nil
}
