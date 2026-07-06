package egresseddie

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/florianl/go-nfqueue"
	"go.uber.org/zap"
	"pgregory.net/rapid"
)

var debugLogging = flag.Bool("debug-log", false, "enable debug logging in tests")

func createLogger(t rapid.TB) *zap.Logger {
	t.Helper()

	if !*debugLogging {
		return zap.NewNop()
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating logger: %v", err)
	}
	return logger
}

// FuzzVerdicts sends random packet bytes to all filters (DNS request,
// response and traffic) and verifies that the filters never panic and
// always return an accept or drop verdict.
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

	logger := createLogger(f)
	cb := []byte(`
inboundDNSQueue = 1

[[filters]]
name = "fuzz"
dnsQueue = 1000
trafficQueue = 1001
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
	config.sender = &mockSender{}

	ctx, cancel := context.WithCancel(f.Context())
	f.Cleanup(cancel)

	filters, err := CreateFilters(ctx, logger, config, false, true)
	if err != nil {
		f.Fatalf("error creating filters: %v", err)
	}
	filters.Start()

	dnsQueues := []uint16{
		config.InboundDNSQueue,
		config.Filters[0].DNSQueue,
	}

	packetID := uint32(1)
	f.Fuzz(func(t *testing.T, packet []byte, connState uint8) {
		allowedIPsLen := filters.filters[0].allowedIPs.Len()
		additionalDomainsLen := filters.filters[0].additionalDomains.Len()

		for i, queue := range dnsQueues {
			mockEnforcers[queue].hook(nfqueue.Attribute{
				PacketID: new(packetID),
				CtInfo:   new(uint32(connState)),
				Payload:  new(packet),
			})

			// DNS request filters should never add IPs or domains
			if i < 2 {
				if filters.filters[0].allowedIPs.Len() > allowedIPsLen {
					t.Errorf("queue %d added an IP", queue)
				}
				if filters.filters[0].additionalDomains.Len() > additionalDomainsLen {
					t.Errorf("queue %d added a domain", queue)
				}
			}

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
