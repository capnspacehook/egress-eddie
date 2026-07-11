package types

import (
	"errors"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
)

// ConnectionID is used to correlate DNS requests and responses from
// the same connection
type ConnectionID struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

func (c ConnectionID) String() string {
	var b strings.Builder

	b.WriteString(c.Src.String())
	b.WriteRune('-')
	b.WriteString(c.Dst.String())

	return b.String()
}

// RequestInfo is the base information from a DNS question in a request
// that is used to check that a DNS response has a matching question.
type RequestInfo struct {
	ID    uint16
	Name  string
	Type  uint16
	Class uint16
}

func NewRequestInfo(dnsMsg *dns.Msg) (RequestInfo, error) {
	if len(dnsMsg.Question) == 0 {
		// drop DNS requests with no questions; this probably
		// doesn't happen in practice but doesn't hurt to
		// handle this case
		return RequestInfo{}, errors.New("no questions in DNS request")
	}

	q := dnsMsg.Question[0]
	h := q.Header()
	if h == nil {
		return RequestInfo{}, errors.New("question header is nil")
	}

	return RequestInfo{
		ID:    dnsMsg.ID,
		Name:  h.Name,
		Type:  dns.RRToType(q),
		Class: h.Class,
	}, nil
}
