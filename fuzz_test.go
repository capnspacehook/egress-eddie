package egresseddie

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

const (
	// enable when debugging failures
	debugLogging = false
	dumpPackets  = false
)

var (
	disallowedIPv4Port = uint16(2001)
	disallowedIPv6Port = uint16(2011)
	ipv4Localhost      = netip.MustParseAddr("127.0.0.1").AsSlice()
	ipv6Localhost      = netip.MustParseAddr("::1").AsSlice()
	ipv4Answer         = netip.MustParseAddr("1.2.3.4").AsSlice()
	ipv6Answer         = netip.MustParseAddr("::1:2:3:4").AsSlice()
	ipv4Disallowed     = netip.MustParseAddr("4.3.2.1").AsSlice()
	ipv6Disallowed     = netip.MustParseAddr("::4:3:2:1").AsSlice()
	allowedCNAME       = "cname.org"
	trafficPayload     = gopacket.Payload([]byte("https://bit.ly/3aeUqbo"))
)

func FuzzFiltering(f *testing.F) {
	for i, tt := range configTests {
		// only add valid configs to the corpus
		if strings.HasPrefix(tt.testName, "valid") {
			f.Add([]byte(tt.configStr), []byte{byte(i)})
		}
	}

	logger := zap.NewNop()
	if debugLogging {
		var err error
		logger, err = zap.NewDevelopment()
		if err != nil {
			f.Fatalf("error creating logger: %v", err)
		}
	}

	f.Fuzz(func(t *testing.T, configBytes []byte, seedBytes []byte) {
		config, err := parseConfigBytes(configBytes)
		if err != nil {
			t.SkipNow()
		}

		initMockEnforcers()
		config.enforcerCreator = newMockEnforcer
		config.resolver = &mockResolver{}

		// test that a config that passes validation won't cause a
		// error/panic when starting filters
		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, logger, config, false)
		if err != nil {
			failAndDumpConfig(t, configBytes, "error starting filters: %v", err)
		}
		f.Start()

		allowIPv4Port := uint16(1000)
		allowIPv6Port := uint16(1010)

		// test that sending DNS requests, DNS responses, and traffic
		// will not cause a panic and behaves as expected
		for _, filter := range config.Filters {
			// TODO: handle cached hostnames and reverse lookups
			if len(filter.AllowedHostnames) == 0 && !filter.AllowAllHostnames {
				continue
			}

			debugLog(logger, "testing DNS on filter %q", filter.Name)

			cctx := checkCtx{
				logger:      logger,
				cfg:         config,
				filter:      filter,
				configBytes: configBytes,
			}

			allowedName := "google.com"
			if len(filter.AllowedHostnames) > 0 {
				allowedName = filter.AllowedHostnames[0]
			}
			// TODO: ensure this won't collide with another allowed hostname
			disallowedName := "no" + allowedName + "no"

			if filter.DNSQueue.eitherSet() {
				checkBlockingDNSRequests(t, cctx, false, disallowedIPv4Port, allowedName, disallowedName)
				checkBlockingDNSRequests(t, cctx, true, disallowedIPv6Port, allowedName, disallowedName)
				checkAllowingDNS(t, cctx, allowIPv4Port, allowIPv6Port, allowedName, disallowedName)

				allowIPv4Port++
				allowIPv6Port++
			}

			checkBlockingUnknownDNSReplies(t, cctx, allowedName)
		}

		for _, filter := range config.Filters {
			if !filter.TrafficQueue.eitherSet() {
				continue
			}

			debugLog(logger, "testing traffic on filter %q", filter.Name)

			cctx := checkCtx{
				logger:      logger,
				cfg:         config,
				filter:      filter,
				configBytes: configBytes,
			}

			checkHandlingTraffic(t, cctx)
		}

		cancel()
		f.Stop()
	})
}

type checkCtx struct {
	logger      *zap.Logger
	cfg         *Config
	filter      FilterOptions
	configBytes []byte
}

func checkBlockingDNSRequests(t *testing.T, c checkCtx, ipv6 bool, port uint16, allowedName, disallowedName string) {
	t.Helper()

	reqn := c.filter.DNSQueue.IPv4
	qType := layers.DNSTypeA
	answerIP := ipv4Answer
	if ipv6 {
		reqn = c.filter.DNSQueue.IPv6
		qType = layers.DNSTypeAAAA
		answerIP = ipv6Answer
	}

	if reqn == 0 {
		return
	}

	debugLog(c.logger, "send DNS request of allowed domain name on disallowed connection state")
	sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
		ipv6:    ipv6,
		srcPort: port,
		dstPort: 53,
		finalLayer: &layers.DNS{
			QDCount: 1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(allowedName),
					Type:  qType,
					Class: layers.DNSClassIN,
				},
			},
		},
		connState:       stateUntracked,
		expectedVerdict: nfqueue.NfDrop,
	})
	debugLog(c.logger, "send DNS reply of allowed domain name on DNS request queue")
	sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
		ipv6:    ipv6,
		srcPort: port,
		dstPort: 53,
		finalLayer: &layers.DNS{
			QDCount: 1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(allowedName),
					Type:  qType,
					Class: layers.DNSClassIN,
				},
			},
			ANCount: 1,
			Answers: []layers.DNSResourceRecord{
				{
					Name:  []byte(allowedName),
					Type:  qType,
					Class: layers.DNSClassIN,
					IP:    answerIP,
				},
			},
		},
		connState:       stateNew,
		expectedVerdict: nfqueue.NfDrop,
	})
	if !c.filter.AllowAllHostnames {
		debugLog(c.logger, "send DNS request of disallowed domain name")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
			ipv6:    ipv6,
			srcPort: port,
			dstPort: 53,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(disallowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
				},
			},
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
		debugLog(c.logger, "send DNS request with no questions")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
			ipv6:            ipv6,
			srcPort:         port,
			dstPort:         53,
			finalLayer:      &layers.DNS{},
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
		debugLog(c.logger, "send DNS request of disallowed and allowed domain names")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
			ipv6:    ipv6,
			srcPort: port,
			dstPort: 53,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(disallowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
				},
			},
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
		debugLog(c.logger, "send DNS request of allowed and disallowed domain names")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
			ipv6:    ipv6,
			srcPort: port,
			dstPort: 53,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
					{
						Name:  []byte(disallowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
				},
			},
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
	}
}

func checkBlockingUnknownDNSReplies(t *testing.T, c checkCtx, allowedName string) {
	t.Helper()

	check := func(ipv6 bool, n uint16) {
		port := uint16(2001)
		qType := layers.DNSTypeA
		answerIP := ipv4Answer
		if ipv6 {
			port = uint16(2011)
			qType = layers.DNSTypeAAAA
			answerIP = ipv6Answer
		}

		debugLog(c.logger, "send DNS reply on a new connection")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:    ipv6,
			srcPort: 53,
			dstPort: port,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
				},
				ANCount: 1,
				Answers: []layers.DNSResourceRecord{
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
						IP:    answerIP,
					},
				},
			},
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
		debugLog(c.logger, "send DNS reply on an unknown connection")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:    ipv6,
			srcPort: 53,
			dstPort: port,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
					},
				},
				ANCount: 1,
				Answers: []layers.DNSResourceRecord{
					{
						Name:  []byte(allowedName),
						Type:  qType,
						Class: layers.DNSClassIN,
						IP:    answerIP,
					},
				},
			},
			connState:       stateEstablished,
			expectedVerdict: nfqueue.NfDrop,
		})
	}

	if n := c.cfg.InboundDNSQueue.IPv4; n != 0 {
		check(false, n)
	}
	if n := c.cfg.InboundDNSQueue.IPv6; n != 0 {
		check(true, n)
	}
}

func checkAllowingDNS(t *testing.T, c checkCtx, ip4Port, ip6Port uint16, allowedName, disallowedName string) {
	t.Helper()

	// If answers are allowed for too short of a time, we don't
	// want to race against the connection getting forgotten.
	// The self filter only processes DNS responses so it won't
	// have an allowed answers duration set.
	attemptReplies := c.filter.DNSQueue == c.cfg.SelfDNSQueue || (c.filter.DNSQueue != c.cfg.SelfDNSQueue && c.filter.AllowAnswersFor >= time.Millisecond)
	allowVerdict := c.filter.AllowAllHostnames || c.filter.DNSQueue.eitherSet()

	check := func(ipv6 bool, reqn, rplyn uint16) {
		port := ip4Port
		rType := layers.DNSTypeA
		answerIP := ipv4Answer
		if ipv6 {
			port = ip6Port
			rType = layers.DNSTypeAAAA
			answerIP = ipv6Answer
		}

		sendAllowReq := func() {
			sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
				ipv6:    ipv6,
				srcPort: port,
				dstPort: 53,
				finalLayer: &layers.DNS{
					QDCount: 1,
					Questions: []layers.DNSQuestion{
						{
							Name:  []byte(allowedName),
							Type:  rType,
							Class: layers.DNSClassIN,
						},
					},
				},
				connState:       stateNew,
				expectedVerdict: nfqueue.NfAccept,
			})
		}

		debugLog(c.logger, "send DNS request of allowed domain name")
		sendAllowReq()
		if rplyn != 0 && attemptReplies {
			debugLog(c.logger, "send DNS reply of allowed domain name")
			sendPacket(t, c.logger, c.configBytes, mockEnforcers[rplyn], sendOpts{
				ipv6:    ipv6,
				srcPort: 53,
				dstPort: port,
				finalLayer: &layers.DNS{
					QDCount: 1,
					Questions: []layers.DNSQuestion{
						{
							Name:  []byte(allowedName),
							Type:  rType,
							Class: layers.DNSClassIN,
						},
					},
					ANCount: 3,
					Answers: []layers.DNSResourceRecord{
						{
							Name:  []byte(allowedName),
							Type:  rType,
							Class: layers.DNSClassIN,
							IP:    answerIP,
						},
						{
							Name:  []byte(allowedName),
							Type:  layers.DNSTypeCNAME,
							Class: layers.DNSClassIN,
							CNAME: []byte(allowedCNAME),
						},
					},
				},
				connState:       stateEstablished,
				expectedVerdict: boolToVerdict(allowVerdict),
			})

			debugLog(c.logger, "send DNS request of allowed domain name (2)")
			sendAllowReq()
			debugLog(c.logger, "testing blocking known DNS replies")
			checkBlockingKnownDNSReplies(t, c, ipv6, port, allowedName, disallowedName)

			if c.filter.DNSQueue != c.cfg.SelfDNSQueue {
				debugLog(c.logger, "send DNS request of allowed domain name from previous CNAME answer")
				sendPacket(t, c.logger, c.configBytes, mockEnforcers[reqn], sendOpts{
					ipv6:    ipv6,
					srcPort: port,
					dstPort: 53,
					finalLayer: &layers.DNS{
						QDCount: 1,
						Questions: []layers.DNSQuestion{
							{
								Name:  []byte(allowedCNAME),
								Type:  rType,
								Class: layers.DNSClassIN,
							},
						},
					},
					connState:       stateNew,
					expectedVerdict: nfqueue.NfAccept,
				})

				checkBlockingDNSRequests(t, c, ipv6, port, allowedCNAME, disallowedName)
			}
		}
	}

	if reqn, rplyn := c.filter.DNSQueue.IPv4, c.cfg.InboundDNSQueue.IPv4; reqn != 0 {
		check(false, reqn, rplyn)
	}
	if reqn, rplyn := c.filter.DNSQueue.IPv6, c.cfg.InboundDNSQueue.IPv6; reqn != 0 {
		check(true, reqn, rplyn)
	}
}

func checkBlockingKnownDNSReplies(t *testing.T, c checkCtx, ipv6 bool, port uint16, allowedName, disallowedName string) {
	t.Helper()

	n := c.cfg.InboundDNSQueue.IPv4
	rType := layers.DNSTypeA
	answerIP := ipv4Answer
	if ipv6 {
		n = c.cfg.InboundDNSQueue.IPv6
		rType = layers.DNSTypeAAAA
		answerIP = ipv6Answer
	}

	debugLog(c.logger, "send DNS reply with disallowed domain name in question")
	sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
		ipv6:    ipv6,
		srcPort: 53,
		dstPort: port,
		finalLayer: &layers.DNS{
			QDCount: 1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(disallowedName),
					Type:  rType,
					Class: layers.DNSClassIN,
				},
			},
			ANCount: 1,
			Answers: []layers.DNSResourceRecord{
				{
					Name:  []byte(allowedName),
					Type:  rType,
					Class: layers.DNSClassIN,
					IP:    answerIP,
				},
			},
		},
		connState:       stateEstablished,
		expectedVerdict: nfqueue.NfDrop,
	})

	if c.filter.DNSQueue != c.cfg.SelfDNSQueue {
		debugLog(c.logger, "send DNS reply with disallowed domain name in answer")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:    ipv6,
			srcPort: 53,
			dstPort: port,
			finalLayer: &layers.DNS{
				QDCount: 1,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(allowedName),
						Type:  rType,
						Class: layers.DNSClassIN,
					},
				},
				ANCount: 1,
				Answers: []layers.DNSResourceRecord{
					{
						Name:  []byte(disallowedName),
						Type:  rType,
						Class: layers.DNSClassIN,
						IP:    answerIP,
					},
				},
			},
			connState:       stateEstablished,
			expectedVerdict: nfqueue.NfDrop,
		})
	}
}

func checkHandlingTraffic(t *testing.T, c checkCtx) {
	t.Helper()

	// If answers are allowed for too short of a time, we don't
	// want to race against the connection getting forgotten.
	// TODO: test reverse lookups
	allowVerdict := c.filter.DNSQueue.eitherSet() && c.filter.AllowAnswersFor >= time.Millisecond

	check := func(ipv6 bool, n uint16) {
		localhostIP := ipv4Localhost
		answerIP := ipv4Answer
		disallowedIP := ipv4Disallowed
		if ipv6 {
			localhostIP = ipv6Localhost
			answerIP = ipv6Answer
			disallowedIP = ipv6Disallowed
		}

		debugLog(c.logger, "send traffic with allowed dst IP")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:            ipv6,
			srcIP:           localhostIP,
			dstIP:           answerIP,
			srcPort:         1337,
			dstPort:         420,
			finalLayer:      trafficPayload,
			connState:       stateNew,
			expectedVerdict: boolToVerdict(allowVerdict),
		})
		debugLog(c.logger, "send traffic with allowed src IP")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:            ipv6,
			srcIP:           answerIP,
			dstIP:           localhostIP,
			srcPort:         1337,
			dstPort:         420,
			finalLayer:      trafficPayload,
			connState:       stateNew,
			expectedVerdict: boolToVerdict(allowVerdict),
		})
		debugLog(c.logger, "send traffic with disallowed dst IP")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:            ipv6,
			srcIP:           localhostIP,
			dstIP:           disallowedIP,
			srcPort:         1337,
			dstPort:         420,
			finalLayer:      trafficPayload,
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
		debugLog(c.logger, "send traffic with disallowed src IP")
		sendPacket(t, c.logger, c.configBytes, mockEnforcers[n], sendOpts{
			ipv6:            ipv6,
			srcIP:           disallowedIP,
			dstIP:           localhostIP,
			srcPort:         1337,
			dstPort:         420,
			finalLayer:      trafficPayload,
			connState:       stateNew,
			expectedVerdict: nfqueue.NfDrop,
		})
	}

	if n := c.filter.TrafficQueue.IPv4; n != 0 {
		check(false, n)
	}
	if n := c.filter.TrafficQueue.IPv6; n != 0 {
		check(true, n)
	}
}

func failAndDumpConfig(t *testing.T, cb []byte, format string, a ...any) {
	t.Helper()

	t.Logf("config:\n---\n%s\n---\n\n", cb)
	panic(fmt.Sprintf(format, a...))
}

func boolToVerdict(b bool) int {
	v := nfqueue.NfDrop
	if b {
		v = nfqueue.NfAccept
	}

	return v
}

type sendOpts struct {
	ipv6            bool
	srcIP           net.IP
	dstIP           net.IP
	srcPort         uint16
	dstPort         uint16
	finalLayer      gopacket.SerializableLayer
	connState       int
	expectedVerdict int
}

var (
	buf           = gopacket.NewSerializeBuffer()
	serializeOpts = gopacket.SerializeOptions{
		FixLengths: true,
	}
	packetID = uint32(1)
)

func sendPacket(t *testing.T, logger *zap.Logger, cb []byte, e *mockEnforcer, opts sendOpts) {
	t.Helper()

	var (
		ipLayer         gopacket.SerializableLayer
		ipLayerType     = layers.IPProtocolIPv4
		verdictExpected bool
	)
	if opts.ipv6 {
		ipLayerType = layers.IPProtocolIPv6
	}

	// if src or dst IPs aren't set, this is a DNS packet
	if opts.srcIP == nil || opts.dstIP == nil {
		// if src or dst IPs aren't set, set them to localhost for DNS packets
		if !opts.ipv6 {
			opts.srcIP = ipv4Localhost
			opts.dstIP = ipv4Localhost
		} else {
			opts.srcIP = ipv6Localhost
			opts.dstIP = ipv6Localhost
		}

		// Serialize and deserialize the DNS layer to ensure it can be
		// decoded without errors. The fuzzer can sometimes create names
		// in questions that can't be parsed by gopacket currently.
		err := gopacket.SerializeLayers(buf, serializeOpts, opts.finalLayer)
		if err != nil {
			failAndDumpConfig(t, cb, "error serializing DNS packet: %v", err)
		}

		var (
			dnsLayer layers.DNS
			decoded  = make([]gopacket.LayerType, 0, 1)
		)

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &dnsLayer)
		err = parser.DecodeLayers(buf.Bytes(), &decoded)
		if err == nil {
			verdictExpected = true
		}
	}

	if !opts.ipv6 {
		ipLayer = &layers.IPv4{
			Protocol: layers.IPProtocolUDP,
			SrcIP:    opts.srcIP,
			DstIP:    opts.dstIP,
		}
	} else {
		ipLayer = &layers.IPv6{
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      opts.srcIP,
			DstIP:      opts.dstIP,
		}
	}

	err := gopacket.SerializeLayers(buf, serializeOpts,
		ipLayer,
		&layers.UDP{
			SrcPort: layers.UDPPort(opts.srcPort),
			DstPort: layers.UDPPort(opts.dstPort),
		},
		opts.finalLayer,
	)
	if err != nil {
		failAndDumpConfig(t, cb, "error serializing packet: %v", err)
	}

	debugLog(logger, "sending packet: ipv6=%t srcPort=%d dstPort=%d connState=%d verdict=%d",
		opts.ipv6,
		opts.srcPort,
		opts.dstPort,
		opts.connState,
		opts.expectedVerdict,
	)
	if dumpPackets {
		packet := gopacket.NewPacket(buf.Bytes(), ipLayerType, gopacket.Default)
		debugLog(logger, packet.Dump())
	}

	e.hook(nfqueue.Attribute{
		PacketID: ref(packetID),
		CtInfo:   ref(uint32(opts.connState)),
		Payload:  ref(buf.Bytes()),
	})
	verdict, ok := e.verdicts[packetID]
	if verdictExpected && !ok {
		failAndDumpConfig(t, cb, "packet did not receive a verdict")
	}
	if verdict != opts.expectedVerdict {
		failAndDumpConfig(t, cb, "expected verdict %d got %d", opts.expectedVerdict, verdict)
	}
	delete(e.verdicts, packetID)

	packetID++
}

func debugLog(logger *zap.Logger, format string, a ...any) {
	if debugLogging {
		logger.Sugar().Infof(format, a...)
	}
}

func ref[T any](t T) *T {
	return &t
}
