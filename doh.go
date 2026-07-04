package egresseddie

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
	"github.com/florianl/go-nfqueue"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

type dohProxy struct {
	resolverURL string
	client      *http.Client
}

// TODO: use generic singleflight and timedcache to minimize requests
func newDoHProxy(resolverURL, serverName string) *dohProxy {
	c := http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				NextProtos: dnshttp.NextProtos,
				ServerName: serverName,
			},
		},
		Timeout: dnsQueryTimeout,
	}

	return &dohProxy{
		resolverURL: resolverURL,
		client:      &c,
	}
}

func (d *dohProxy) sendDoHRequest(dnsReq *dns.Msg) (*dns.Msg, error) {
	httpReq, err := dnshttp.NewRequest("GET", d.resolverURL, dnsReq)
	if err != nil {
		return nil, fmt.Errorf("creating DoH request: %w", err)
	}
	httpResp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending DoH request: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status code %d", httpResp.StatusCode)
	}
	defer httpResp.Body.Close()

	dnsResp, err := dnshttp.Response(httpResp)
	if err != nil {
		return nil, fmt.Errorf("reading DoH response: %w", err)
	}

	return dnsResp, nil
}

type dnsInjector struct {
	mtx    sync.RWMutex
	closed bool

	socket int
}

func newDNSInjector() (*dnsInjector, error) {
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket: %w", err)
	}

	return &dnsInjector{
		socket: sock,
	}, nil
}

func (d *dnsInjector) close() error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.closed = true

	return unix.Close(d.socket)
}

type netPacket interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}

func (d *dnsInjector) injectResponse(dnsResp *dns.Msg, connID connectionID, attr nfqueue.Attribute) error {
	// TODO: cache interfaces?
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
			return fmt.Errorf("getting network interface by index: %w", err)
		}

		srcMAC = iface.HardwareAddr
		dstMAC = net.HardwareAddr(*attr.HwAddr)
		sa = &unix.SockaddrLinklayer{Ifindex: ifaceIDx}
	} else {
		// gopacket requires the MACs to have a length of 6 but they don't
		// need to be populated, the kernel will ignore them
		srcMAC = make(net.HardwareAddr, 6)
		dstMAC = make(net.HardwareAddr, 6)

		iface, err := net.InterfaceByName("lo")
		if err != nil {
			return fmt.Errorf("getting network interface by name: %w", err)
		}
		sa = &unix.SockaddrLinklayer{Ifindex: iface.Index}
	}

	ethLayer := &layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}

	var ipLayer netPacket
	if connID.IsIPv6() {
		ethLayer.EthernetType = layers.EthernetTypeIPv6
		ipLayer = &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      connID.dst.Addr().AsSlice(),
			DstIP:      connID.src.Addr().AsSlice(),
		}
	} else {
		ethLayer.EthernetType = layers.EthernetTypeIPv4
		ipLayer = &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    connID.dst.Addr().AsSlice(),
			DstIP:    connID.src.Addr().AsSlice(),
		}
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(connID.dst.Port()),
		DstPort: layers.UDPPort(connID.src.Port()),
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

	d.mtx.RLock()
	defer d.mtx.RUnlock()
	if d.closed {
		return errors.New("socket is closed")
	}

	if err := unix.Sendto(d.socket, buf.Bytes(), 0, sa); err != nil {
		return fmt.Errorf("sending packet: %w", err)
	}

	return nil
}
