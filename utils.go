package egresseddie

import (
	"errors"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/florianl/go-nfqueue/v2"
	"go.uber.org/zap"
)

func connIsEstablished(state uint32) bool {
	return state == stateEstablished || state == stateRelated || state == stateEstablishedReply || state == stateRelatedReply
}

func setVerdict(logger *zap.Logger, e enforcer, attr nfqueue.Attribute, v verdict, permissiveMode bool) {
	if v == ignoreVerdict {
		return
	}
	if permissiveMode {
		v = nfqueue.NfAccept
	}

	if err := e.SetVerdict(*attr.PacketID, int(v)); err != nil {
		logger.Error("setting verdict", zap.Error(err))
	}
}

func stripPrefixLabels(domain string) (string, int) {
	if domain == "" {
		return "", 0
	}

	var numFound int
	if domain[0] != '_' {
		return domain, 0
	}

	idx, end := dnsutil.Next(domain, 0)
	if end {
		return domain, 0
	}
	numFound++

	// max number of prefixed labels for all record types we support
	// is 2, but we want to know if more than 2 prefix labels were
	// found
	for range 2 {
		if domain[idx] != '_' {
			break
		}

		i, end := dnsutil.Next(domain, idx)
		if end {
			break
		}

		idx = i
		numFound++
	}

	return domain[idx:], numFound
}

func newRequestInfo(dnsMsg *dns.Msg) (requestInfo, error) {
	if len(dnsMsg.Question) == 0 {
		// drop DNS requests with no questions; this probably
		// doesn't happen in practice but doesn't hurt to
		// handle this case
		return requestInfo{}, errors.New("no questions in DNS request")
	}

	q := dnsMsg.Question[0]
	h := q.Header()
	if h == nil {
		return requestInfo{}, errors.New("question header is nil")
	}

	return requestInfo{
		id:     dnsMsg.ID,
		qName:  h.Name,
		qType:  dns.RRToType(q),
		qClass: h.Class,
	}, nil
}

// prepareDomainName removes a trailing dot and lowercases the domain
// name so it can be matched case-insensitively.
func prepareDomainName(domain string) string {
	if domain == "" {
		return ""
	}
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	return strings.ToLower(domain)
}

func qClassToString(qClass uint16) string {
	className, ok := dns.ClassToString[qClass]
	if ok {
		return className
	}
	return "unknown-" + strconv.Itoa(int(qClass))
}

func rrTypeToString(rrType uint16) string {
	typeName, ok := dns.TypeToString[rrType]
	if ok {
		return typeName
	}
	return "unknown-" + strconv.Itoa(int(rrType))
}

func (f *filter) dropReasonFields(reason error, dnsMsg *dns.Msg) []zap.Field {
	return append([]zap.Field{zap.String("reason", reason.Error())}, dnsFields(dnsMsg, f.fullDNSLogging)...)
}
