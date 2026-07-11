package egresseddie

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/florianl/go-nfqueue/v2"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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

		f.Add(b, uint8(i%stateRelatedReply), false)
		f.Add(b, uint8(i%stateRelatedReply), true)
	}

	logger := createLogger(f)
	cb := []byte(`
dnsResponseQueue = 1

[[filters]]
name = "fuzz"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "1s"
allowedDomains = [
	"foo",
	"bar",
	"baz.barf",
	"*.domain.org",
	"num[2-7].bers.lab",
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
		config.Filters[0].DNSQueue,
		config.DNSResponseQueue,
		config.Filters[0].TrafficQueue,
	}

	packetID := uint32(1)
	f.Fuzz(func(t *testing.T, packet []byte, connState uint8, ipv6 bool) {
		allowedIPsLen := filters.filters[0].allowedIPs.Len()
		allowedTargetsLen := filters.filters[0].allowedTargets.Len()

		hwProto := uint16(unix.ETH_P_IP)
		if ipv6 {
			hwProto = uint16(unix.ETH_P_IPV6)
		}

		for i, queue := range dnsQueues {
			mockEnforcers[queue].hook(nfqueue.Attribute{
				PacketID:   new(packetID),
				CtInfo:     new(uint32(connState)),
				HwProtocol: new(hwProto),
				Payload:    new(packet),
			})

			// only DNS response filter should add IPs or domains
			if i != 1 {
				if filters.filters[0].allowedIPs.Len() > allowedIPsLen {
					t.Errorf("queue %d added an IP", queue)
				}
				if filters.filters[0].allowedTargets.Len() > allowedTargetsLen {
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
