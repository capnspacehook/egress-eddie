package resolve

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"codeberg.org/miekg/dns"
)

type blockingSender struct {
	resp *dns.Msg
}

func (b *blockingSender) SendRequest(ctx context.Context, dnsReq *dns.Msg) (*dns.Msg, error) {
	<-ctx.Done()
	return b.resp, nil
}

func (*blockingSender) ResponsesValidated() bool {
	return false
}

func (*blockingSender) TransportType() string {
	return "blocking"
}

func TestSingleFlightSenderRace(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		blockSender := &blockingSender{
			resp: dns.NewMsg("foo", dns.TypeA),
		}
		sender := NewSingleFlightSender(blockSender)

		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		var wg sync.WaitGroup
		for range 100 {
			wg.Go(func() {
				req := dns.NewMsg("foo", dns.TypeA)
				resp, err := sender.SendRequest(ctx, req)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("response is nil")
					return
				}

				err = resp.Pack()
				if err != nil {
					t.Errorf("packing response: %v", err)
				}
			})
		}

		// wait until all goroutines are blocking in SendRequest, unblock
		// them and wait for them to return; this will test that accessing
		// a shared response does not cause a data race
		synctest.Wait()
		cancel()
		wg.Wait()
	})
}
