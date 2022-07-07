package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/florianl/go-nfqueue"
	"go.uber.org/zap"
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

func newMockEnforcer(_ context.Context, _ *zap.Logger, queueNum uint16, ipv6 bool, hook nfqueue.HookFunc) (enforcer, error) {
	if _, ok := mockEnforcers[queueNum]; ok {
		return nil, fmt.Errorf("a nfqueue with the queue number %d has already been started", queueNum)
	}

	mEnforcer := &mockEnforcer{
		hook:     hook,
		verdicts: make(map[uint32]int),
	}
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

type mockResolver struct {
	addrs     map[string][]netip.Addr
	hostnames map[string][]string
}

func (m *mockResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if m.addrs == nil {
		return nil, &net.DNSError{IsNotFound: true}
	}

	if addrs, ok := m.addrs[host]; ok {
		return addrs, nil
	}

	return nil, &net.DNSError{IsNotFound: true}
}

func (m *mockResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if m.hostnames == nil {
		return nil, &net.DNSError{IsNotFound: true}
	}

	if addrs, ok := m.hostnames[addr]; ok {
		return addrs, nil
	}

	return nil, &net.DNSError{IsNotFound: true}
}
