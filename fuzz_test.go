package main

import (
	"context"
	"testing"

	"github.com/florianl/go-nfqueue"
	"go.uber.org/zap"
)

var (
	dnsReq4  = []byte("E\\x00\\x008\\v\\x97@\\x00@\\x110\\xe8\\u007f\\x00\\x00\\x01\\u007f\\x00\\x005\\xa2\\xcf\\x005\\x00$\\xb0\\x16\\x9a\\x9b\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01")
	dnsReq6  = []byte("`\\x00\\xeb>\\x00/\\x11@\\xfe\\x80\\x00\\x00\\x00\\x00\\x00\\x00d>\\xc1\\xc2\\xc1\\x8d\\x02\\xd4\\xfe\\x80\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\fk\\xff\\xfe\\xac\\xfc\\xe0\\xddr\\x005\\x00/\\xccN\\x1d\\xdc\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01\\x00\\x00)\\x05\\xac\\x00\\x00\\x00\\x00\\x00\\x00")
	dnsResp4 = []byte("E\\x00\\x00\\x98M\\b@\\x00\\x01\\x11.\\x17\\u007f\\x00\\x005\\u007f\\x00\\x00\\x01\\x005\\xa2\\xcf\\x00\\x84\\x16+\\x9a\\x9b\\x81\\x80\\x00\\x01\\x00\\x06\\x00\\x00\\x00\\x00\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\t\\x8a\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\td\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\te\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\t\\x8b\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\tf\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\tq")
	dnsResp6 = []byte("`\\x00\\x00\\x00\\x00\\x8f\\x11@\\xfe\\x80\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\fk\\xff\\xfe\\xac\\xfc\\xe0\\xfe\\x80\\x00\\x00\\x00\\x00\\x00\\x00d>\\xc1\\xc2\\xc1\\x8d\\x02\\xd4\\x005\\xddr\\x00\\x8f\\x0ed\\x1d܁\\x80\\x00\\x01\\x00\\x06\\x00\\x00\\x00\\x01\\x06google\\x03com\\x00\\x00\\x01\\x00\\x01\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\t\\x8a\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\td\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\te\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\t\\x8b\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\tf\\xc0\\f\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\xf0\\x00\\x04\\x8e\\xfa\\tq\\x00\\x00)\\x04\\xd0\\x00\\x00\\x00\\x00\\x00\\x00")
	traffic4 = []byte("E\\x00\\x00<5\\x02@\\x00@\\x06\\xab\\x84\\xc0\\xa8\\x01\\t\\x8e\\xfa\\t\\x8a\\xac\\xd6\\x01\\xbb\\xb7\\xda\\xed\\xe2\\x00\\x00\\x00\\x00\\xa0\\x02\\xfa\\xf0F\\x1b\\x00\\x00\\x02\\x04\\x05\\xb4\\x04\\x02\\b\\n?\\xdf\\x18\\x90\\x00\\x00\\x00\\x00\\x01\\x03\\x03\\a")
	traffic6 = []byte("`\\t\\x0e\\xb7\\x00(\\x06@&\\x01\\x01\\x00\\x81\\u007ft\\xf8R\\xe5K\\xa5=F\\x8a\\x05&\\a\\xf8\\xb0@\\x02\\b\\x17\\x00\\x00\\x00\\x00\\x00\\x00 \\x0e\\xeb\\x16\\x01\\xbb\\x9a\\xe1\\xec\\xdd\\x00\\x00\\x00\\x00\\xa0\\x02\\xfd \\xd5\\u007f\\x00\\x00\\x02\\x04\\x05\\xa0\\x04\\x02\\b\\n N\\xd6e\\x00\\x00\\x00\\x00\\x01\\x03\\x03\\a")
)

func FuzzConfig(f *testing.F) {
	for _, tt := range configTests {
		f.Add([]byte(tt.configStr))
	}

	logger := zap.NewNop()

	f.Fuzz(func(t *testing.T, cb []byte) {
		config, err := parseConfigBytes(cb)
		if err != nil {
			return
		}

		initMockEnforcers()
		config.enforcerCreator = newMockEnforcer
		config.resolver = &mockResolver{}

		// test that a config that passes valdiation won't cause a
		// error/panic when starting filters
		ctx, cancel := context.WithCancel(context.Background())
		f, err := StartFilters(ctx, logger, config)
		if err != nil {
			t.Errorf("config:\n---\n%s\n---\n\nerr: %v", cb, err)
		}

		// test that sending DNS requests, DNS responses, and traffic
		// will not cause a panic
		for _, filter := range config.Filters {
			if filter.DNSQueue.eitherSet() {
				if n := filter.DNSQueue.IPv4; n != 0 {
					mockEnforcers[n].hook(nfqueue.Attribute{
						PacketID: ref(uint32(1000)),
						CtInfo:   ref(uint32(stateNew)),
						Payload:  ref(dnsReq4),
					})

				}
				if n := filter.DNSQueue.IPv6; n != 0 {
					mockEnforcers[n].hook(nfqueue.Attribute{
						PacketID: ref(uint32(1010)),
						CtInfo:   ref(uint32(stateNew)),
						Payload:  ref(dnsReq6),
					})
				}
			}

			if n := config.InboundDNSQueue.IPv4; n != 0 {
				mockEnforcers[n].hook(nfqueue.Attribute{
					PacketID: ref(uint32(1)),
					CtInfo:   ref(uint32(stateEstablished)),
					Payload:  ref(dnsResp4),
				})
			}
			if n := config.InboundDNSQueue.IPv6; n != 0 {
				mockEnforcers[n].hook(nfqueue.Attribute{
					PacketID: ref(uint32(10)),
					CtInfo:   ref(uint32(stateEstablished)),
					Payload:  ref(dnsResp6),
				})
			}
		}
		for _, filter := range config.Filters {
			if !filter.TrafficQueue.eitherSet() {
				continue
			}

			if n := filter.TrafficQueue.IPv4; n != 0 {
				mockEnforcers[n].hook(nfqueue.Attribute{
					PacketID: ref(uint32(1001)),
					CtInfo:   ref(uint32(stateNew)),
					Payload:  ref(traffic4),
				})
			}
			if n := filter.TrafficQueue.IPv6; n != 0 {
				mockEnforcers[n].hook(nfqueue.Attribute{
					PacketID: ref(uint32(1011)),
					CtInfo:   ref(uint32(stateNew)),
					Payload:  ref(traffic6),
				})
			}
		}

		cancel()
		f.Stop()
	})
}

func ref[T any](t T) *T {
	return &t
}
