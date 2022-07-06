package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

var (
	debugLogging = true
	dumpPackets  = false

	ipv4Localhost  = netip.MustParseAddr("127.0.0.1").AsSlice()
	ipv6Localhost  = netip.MustParseAddr("::1").AsSlice()
	ipv4Answer     = netip.MustParseAddr("1.2.3.4").AsSlice()
	ipv6Answer     = netip.MustParseAddr("::1:2:3:4").AsSlice()
	ipv4Disallowed = netip.MustParseAddr("4.3.2.1").AsSlice()
	ipv6Disallowed = netip.MustParseAddr("::4:3:2:1").AsSlice()
	trafficPayload = gopacket.Payload([]byte("https://bit.ly/3aeUqbo"))
)

func FuzzConfig(f *testing.F) {
	for _, tt := range configTests {
		f.Add([]byte(tt.configStr))
	}

	logger := zap.NewNop()
	if debugLogging {
		var err error
		logger, err = zap.NewDevelopment()
		if err != nil {
			f.Fatalf("error creating logger: %v", err)
		}
	}

	f.Fuzz(func(t *testing.T, cb []byte) {
		config, err := parseConfigBytes(cb)
		if err != nil {
			return
		}

		initMockEnforcers()
		config.enforcerCreator = newMockEnforcer
		config.resolver = &mockResolver{}

		// test that a config that passes validation won't cause a
		// error/panic when starting filters
		ctx, cancel := context.WithCancel(context.Background())
		f, err := StartFilters(ctx, logger, config)
		if err != nil {
			failAndDumpConfig(t, cb, "error starting filters: %v", err)
		}

		// test that sending DNS requests, DNS responses, and traffic
		// will not cause a panic and behaves as expected
		for _, filter := range config.Filters {
			debugLog(logger, "testing filter %q", filter.Name)

			// TODO: handle cached hostnames and reverse lookups
			if len(filter.AllowedHostnames) == 0 && !filter.AllowAllHostnames {
				continue
			}

			allowedName := "google.com"
			if len(filter.AllowedHostnames) > 0 {
				allowedName = filter.AllowedHostnames[0]
			}
			// TODO: ensure this won't collide with another allowed hostname
			disallowedName := "no" + allowedName + "no"

			if filter.DNSQueue.eitherSet() {
				// send DNS request of allowed domain name
				if n := filter.DNSQueue.IPv4; n != 0 {
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    false,
						srcPort: 1000,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
								},
							},
						},
						connState:       stateNew,
						expectedVerdict: nfqueue.NfAccept,
					})
					// send DNS request of allowed domain name on disallowed connection state
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    false,
						srcPort: 1001,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
								},
							},
						},
						connState:       stateUntracked,
						expectedVerdict: nfqueue.NfDrop,
					})
					// send DNS reply of allowed domain name on DNS request queue
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    false,
						srcPort: 1001,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
								},
							},
							ANCount: 1,
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
									IP:    ipv4Answer,
								},
							},
						},
						connState:       stateNew,
						expectedVerdict: nfqueue.NfDrop,
					})
					if !filter.AllowAllHostnames {
						// send DNS request of disallowed domain name
						sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
							ipv6:    false,
							srcPort: 1001,
							dstPort: 53,
							finalLayer: &layers.DNS{
								QDCount: 1,
								Questions: []layers.DNSQuestion{
									{
										Name:  []byte(disallowedName),
										Type:  layers.DNSTypeA,
										Class: layers.DNSClassIN,
									},
								},
							},
							connState:       stateNew,
							expectedVerdict: nfqueue.NfDrop,
						})
						// send DNS request with no questions
						sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
							ipv6:            false,
							srcPort:         1001,
							dstPort:         53,
							finalLayer:      &layers.DNS{},
							connState:       stateNew,
							expectedVerdict: nfqueue.NfDrop,
						})
					}
				}
				if n := filter.DNSQueue.IPv6; n != 0 {
					// send DNS request of allowed domain name
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    true,
						srcPort: 1010,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeAAAA,
									Class: layers.DNSClassIN,
								},
							},
						},
						connState:       stateNew,
						expectedVerdict: nfqueue.NfAccept,
					})
					// send DNS request of allowed domain name on disallowed connection state
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    true,
						srcPort: 1011,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeAAAA,
									Class: layers.DNSClassIN,
								},
							},
						},
						connState:       stateUntracked,
						expectedVerdict: nfqueue.NfDrop,
					})
					// send DNS reply of allowed domain name on DNS request queue
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    true,
						srcPort: 1011,
						dstPort: 53,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeAAAA,
									Class: layers.DNSClassIN,
								},
							},
							ANCount: 1,
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
									IP:    ipv6Answer,
								},
							},
						},
						connState:       stateNew,
						expectedVerdict: nfqueue.NfDrop,
					})
					if !filter.AllowAllHostnames {
						// send DNS request of disallowed domain name
						sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
							ipv6:    true,
							srcPort: 1011,
							dstPort: 53,
							finalLayer: &layers.DNS{
								QDCount: 1,
								Questions: []layers.DNSQuestion{
									{
										Name:  []byte(disallowedName),
										Type:  layers.DNSTypeAAAA,
										Class: layers.DNSClassIN,
									},
								},
							},
							connState:       stateNew,
							expectedVerdict: nfqueue.NfDrop,
						})
						// send DNS request with no questions
						sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
							ipv6:            true,
							srcPort:         1011,
							dstPort:         53,
							finalLayer:      &layers.DNS{},
							connState:       stateNew,
							expectedVerdict: nfqueue.NfDrop,
						})
					}
				}
			}

			allowVerdict := filter.AllowAllHostnames || filter.DNSQueue.eitherSet()

			if n := config.InboundDNSQueue.IPv4; n != 0 {
				// send DNS reply on a new connection
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:    false,
					srcPort: 53,
					dstPort: 1000,
					finalLayer: &layers.DNS{
						QDCount: 1,
						Questions: []layers.DNSQuestion{
							{
								Name:  []byte(allowedName),
								Type:  layers.DNSTypeA,
								Class: layers.DNSClassIN,
							},
						},
						ANCount: 1,
						Answers: []layers.DNSResourceRecord{
							{
								Name:  []byte(allowedName),
								Type:  layers.DNSTypeA,
								Class: layers.DNSClassIN,
								IP:    ipv4Answer,
							},
						},
					},
					connState:       stateNew,
					expectedVerdict: nfqueue.NfDrop,
				})
				// If answers are allowed for too short of a time, we don't
				// want to race against the connection getting forgotten.
				// The self filter only processes DNS responses so it won't
				// have an allowed answers duration set.
				if filter.DNSQueue == config.SelfDNSQueue ||
					(filter.DNSQueue != config.SelfDNSQueue &&
						time.Duration(filter.AllowAnswersFor) >= time.Millisecond) {
					// send DNS reply of allowed domain name
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    false,
						srcPort: 53,
						dstPort: 1000,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
								},
							},
							ANCount: 1,
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeA,
									Class: layers.DNSClassIN,
									IP:    ipv4Answer,
								},
							},
						},
						connState: stateEstablished,
						// if no dns queue is set, the DNS request won't have
						// been set so this should fail
						expectedVerdict: boolToVerdict(allowVerdict),
					})
				}
			}
			if n := config.InboundDNSQueue.IPv6; n != 0 {
				// send DNS reply on a new connection
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:    true,
					srcPort: 53,
					dstPort: 1010,
					finalLayer: &layers.DNS{
						QDCount: 1,
						Questions: []layers.DNSQuestion{
							{
								Name:  []byte(allowedName),
								Type:  layers.DNSTypeAAAA,
								Class: layers.DNSClassIN,
							},
						},
						ANCount: 1,
						Answers: []layers.DNSResourceRecord{
							{
								Name:  []byte(allowedName),
								Type:  layers.DNSTypeAAAA,
								Class: layers.DNSClassIN,
								IP:    ipv6Answer,
							},
						},
					},
					connState: stateNew,
					// if no dns queue is set, the DNS request won't have
					// been set so this should fail
					expectedVerdict: nfqueue.NfDrop,
				})
				// If answers are allowed for too short of a time, we don't
				// want to race against the connection getting forgotten.
				// The self filter only processes DNS responses so it won't
				// have an allowed answers duration set.
				if filter.DNSQueue == config.SelfDNSQueue ||
					(filter.DNSQueue != config.SelfDNSQueue &&
						time.Duration(filter.AllowAnswersFor) >= time.Millisecond) {
					// send DNS reply of allowed domain name
					sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
						ipv6:    true,
						srcPort: 53,
						dstPort: 1010,
						finalLayer: &layers.DNS{
							QDCount: 1,
							Questions: []layers.DNSQuestion{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeAAAA,
									Class: layers.DNSClassIN,
								},
							},
							ANCount: 1,
							Answers: []layers.DNSResourceRecord{
								{
									Name:  []byte(allowedName),
									Type:  layers.DNSTypeAAAA,
									Class: layers.DNSClassIN,
									IP:    ipv6Answer,
								},
							},
						},
						connState: stateEstablished,
						// if no dns queue is set, the DNS request won't have
						// been set so this should fail
						expectedVerdict: boolToVerdict(allowVerdict),
					})
				}
			}
		}

		for _, filter := range config.Filters {
			if !filter.TrafficQueue.eitherSet() {
				continue
			}

			// If answers are allowed for too short of a time, we don't
			// want to race against the connection getting forgotten.
			// TODO: test reverse lookups
			allowVerdict := filter.DNSQueue.eitherSet() && time.Duration(filter.AllowAnswersFor) >= time.Millisecond

			if n := filter.TrafficQueue.IPv4; n != 0 {
				// send traffic with allowed dst IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            false,
					srcIP:           ipv4Localhost,
					dstIP:           ipv4Answer,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: boolToVerdict(allowVerdict),
				})
				// send traffic with allowed src IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            false,
					srcIP:           ipv4Answer,
					dstIP:           ipv4Localhost,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: boolToVerdict(allowVerdict),
				})
				// send traffic with disallowed dst IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            false,
					srcIP:           ipv4Localhost,
					dstIP:           ipv4Disallowed,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: nfqueue.NfDrop,
				})
				// send traffic with disallowed src IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            false,
					srcIP:           ipv4Disallowed,
					dstIP:           ipv4Localhost,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: nfqueue.NfDrop,
				})
			}
			if n := filter.TrafficQueue.IPv6; n != 0 {
				// send traffic with allowed dst IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            true,
					srcIP:           ipv6Localhost,
					dstIP:           ipv6Answer,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: boolToVerdict(allowVerdict),
				})
				// send traffic with allowed src IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            true,
					srcIP:           ipv6Answer,
					dstIP:           ipv6Localhost,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: boolToVerdict(allowVerdict),
				})
				// send traffic with disallowed dst IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            true,
					srcIP:           ipv6Localhost,
					dstIP:           ipv6Disallowed,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: nfqueue.NfDrop,
				})
				// send traffic with disallowed src IP
				sendPacket(t, logger, cb, mockEnforcers[n], sendOpts{
					ipv6:            true,
					srcIP:           ipv6Disallowed,
					dstIP:           ipv6Localhost,
					srcPort:         1337,
					dstPort:         420,
					finalLayer:      trafficPayload,
					connState:       stateNew,
					expectedVerdict: nfqueue.NfDrop,
				})
			}
		}

		cancel()
		f.Stop()
	})
}

func failAndDumpConfig(t *testing.T, cb []byte, format string, a ...any) {
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
	var (
		ipLayer         gopacket.SerializableLayer
		ipLayerType     = layers.IPProtocolIPv4
		verdictExpected bool
	)
	if opts.ipv6 {
		ipLayerType = layers.IPProtocolIPv6
	}

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
