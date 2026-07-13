package egresseddie

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/florianl/go-nfqueue/v2"
	"go.uber.org/zap"

	"github.com/capnspacehook/egress-eddie/types"
)

var mockEnforcers map[uint16]*mockEnforcer

type mockEnforcer struct {
	mtx      sync.Mutex
	hook     nfqueue.HookFunc
	verdicts map[uint32]int
}

func initMockEnforcers() {
	mockEnforcers = make(map[uint16]*mockEnforcer)
}

func newMockEnforcer(_ context.Context, _ *zap.Logger, queueNum uint16, createHook hookCreator) (enforcer, error) {
	if _, ok := mockEnforcers[queueNum]; ok {
		return nil, fmt.Errorf("a nfqueue with the queue number %d has already been started", queueNum)
	}
	if createHook == nil {
		return nil, errors.New("a nil hook creator was passed")
	}

	mEnforcer := &mockEnforcer{
		verdicts: make(map[uint32]int),
	}
	mEnforcer.hook = createHook(queueNum, mEnforcer)
	mockEnforcers[queueNum] = mEnforcer

	return mEnforcer, nil
}

func (m *mockEnforcer) SetVerdict(id uint32, verdict int) error {
	if id == 0 {
		return errors.New("id is zero")
	}

	// these are not the only valid verdicts, but they are the only
	// verdicts egress eddie will pass
	if verdict != nfqueue.NfDrop && verdict != nfqueue.NfAccept {
		return fmt.Errorf("invalid verdict %d", verdict)
	}

	m.mtx.Lock()
	m.verdicts[id] = verdict
	m.mtx.Unlock()

	return nil
}

func (m *mockEnforcer) Close() error {
	return nil
}

type mockSender struct {
	// resp is the response returned by the next SendRequest call. Tests set
	// this before delivering a request that is expected to be proxied.
	resp *dns.Msg
	// called records whether SendRequest was invoked; tests reset it before
	// delivering a request to assert whether the resolver was hit.
	called bool

	responsesValidated bool
}

func (m *mockSender) SendRequest(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	m.called = true
	if m.resp == nil {
		return nil, errors.New("mockSender: no response configured")
	}
	return m.resp, nil
}

func (m *mockSender) ResponsesValidated() bool {
	return m.responsesValidated
}

func (m *mockSender) TransportType() string {
	return "mock"
}

// mockInjector is a resolve.DNSInjector that records how many responses were
// injected instead of writing packets to a raw socket.
type mockInjector struct {
	count int
}

func (m *mockInjector) InjectResponse(_ *dns.Msg, _ types.ConnectionID, _ nfqueue.Attribute) error {
	m.count++
	return nil
}

func (m *mockInjector) Close() error {
	return nil
}
