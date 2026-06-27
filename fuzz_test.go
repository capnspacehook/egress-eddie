package egresseddie

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/florianl/go-nfqueue"
	"go.uber.org/zap"
)

const debugLogging = false

func FuzzVerdicts(f *testing.F) {
	packetDir := filepath.Join("testdata", "dnsPackets")
	entries, err := os.ReadDir(packetDir)
	if err != nil {
		f.Fatalf("error reading directory: %v", err)
	}

	for i, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(packetDir, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("error reading file: %v", err)
		}

		f.Add(b, uint8(i%stateRelatedReply))
	}

	logger := zap.NewNop()
	if debugLogging {
		var err error
		logger, err = zap.NewDevelopment()
		if err != nil {
			f.Fatalf("error creating logger: %v", err)
		}
	}

	cb := []byte(`
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10

[[filters]]
name = "fuzz"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011
allowAnswersFor = "1s"
allowedDomains = [
	"foo",
	"bar",
	"baz.barf",
]`)

	config, err := parseConfigBytes(cb)
	if err != nil {
		f.Fatalf("error parsing config: %v", err)
	}

	initMockEnforcers()
	config.enforcerCreator = newMockEnforcer
	config.resolver = &mockResolver{}

	ctx, cancel := context.WithCancel(context.Background())
	f.Cleanup(cancel)

	filters, err := CreateFilters(ctx, logger, config, false)
	if err != nil {
		f.Fatalf("error creating filters: %v", err)
	}
	filters.Start()

	dnsQueues := []uint16{
		config.InboundDNSQueue.IPv4,
		config.InboundDNSQueue.IPv6,
		config.Filters[0].DNSQueue.IPv4,
		config.Filters[0].DNSQueue.IPv6,
	}

	packetID := uint32(1)
	f.Fuzz(func(t *testing.T, packet []byte, connState uint8) {
		for _, queue := range dnsQueues {
			debugLog(logger, "sending packet to queue %d", queue)
			mockEnforcers[queue].hook(nfqueue.Attribute{
				PacketID: ref(packetID),
				CtInfo:   ref(uint32(connState)),
				Payload:  ref(packet),
			})

			verdict, ok := mockEnforcers[queue].verdicts[packetID]
			if !ok {
				t.Fatalf("packet did not receive a verdict")
			}
			if verdict != nfqueue.NfAccept && verdict != nfqueue.NfDrop {
				t.Fatalf("unexpected verdict %d", verdict)
			}

			delete(mockEnforcers[queue].verdicts, packetID)
		}
	})
}

func debugLog(logger *zap.Logger, format string, a ...any) {
	if debugLogging {
		logger.Sugar().Infof(format, a...)
	}
}

func ref[T any](t T) *T {
	return &t
}
