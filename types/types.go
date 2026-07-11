package types

import (
	"net/netip"
	"strings"
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
