package egresseddie

// NOTE: This file is mostly AI generated and was cleaned up and
// reviewed by a human.

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"code.dny.dev/ssrf"
	"codeberg.org/miekg/dns"
	"pgregory.net/rapid"

	"github.com/capnspacehook/egress-eddie/resolve"
)

// storedReq mirrors what the request callback stores in f.connections
// (a counting cache: repeated requests on the same connID increment count and
// keep the FIRST stored value).
type storedReq struct {
	requestInfo
	count  int       // counting-cache count (0 == one outstanding)
	expiry time.Time // now + dnsQueryTimeout, refreshed on each Add
}

type model struct {
	pending         map[connectionID]*storedReq
	addrChecker     *ssrf.Guardian
	allowedIPs      map[netip.Addr]time.Time // value == expiry deadline
	targetDomains   map[string]time.Time     // value == expiry deadline
	allowAnswersFor time.Duration
}

func newModel(ac *ssrf.Guardian) *model {
	return &model{
		pending:         make(map[connectionID]*storedReq),
		addrChecker:     ac,
		allowedIPs:      make(map[netip.Addr]time.Time),
		targetDomains:   make(map[string]time.Time),
		allowAnswersFor: propAllowAnswersFor,
	}
}

// prune drops modeled entries whose deadline has passed. Call after
// synctest.Wait() so it lines up with the real cache's timer goroutines.
func (m *model) prune() {
	now := time.Now()
	for k, dl := range m.allowedIPs {
		if !dl.After(now) {
			delete(m.allowedIPs, k)
		}
	}
	for k, dl := range m.targetDomains {
		if !dl.After(now) {
			delete(m.targetDomains, k)
		}
	}
	for k, r := range m.pending {
		if !r.expiry.After(now) {
			delete(m.pending, k)
		}
	}
}

func (m *model) assertCaches(t *rapid.T, f *filter) {
	if got := f.allowedIPs.Len(); got != len(m.allowedIPs) {
		t.Fatalf("allowedIPs size: model=%d real=%d", len(m.allowedIPs), got)
	}
	for ip := range m.allowedIPs {
		if !f.allowedIPs.Exists(ip) {
			t.Fatalf("allowedIPs missing modeled IP %s", ip)
		}
	}

	if got := f.allowedTargets.Len(); got != len(m.targetDomains) {
		t.Fatalf("additionalDomains size: model=%d real=%d", len(m.targetDomains), got)
	}
	for dom := range m.targetDomains {
		if !f.allowedTargets.Exists(dom) {
			t.Fatalf("additionalDomains missing modeled domain %q", dom)
		}
	}

	if got := f.connections.Len(); got != len(m.pending) {
		t.Fatalf("connections size: model=%d real=%d", len(m.pending), got)
	}
	for connID := range m.pending {
		if !f.connections.Exists(connID) {
			t.Fatalf("connections missing modeled connID %s", connID)
		}
	}
}

// addPending models f.connections.AddValue (counting cache: first value wins,
// count increments, deadline refreshes).
func (m *model) addPending(ep endpoint, msg *dns.Msg) {
	connID := ep.connID()
	q := msg.Question[0]
	qHdr := q.Header()

	dl := time.Now().Add(resolve.DNSQueryTimeout)
	if r, ok := m.pending[connID]; ok {
		r.count++
		r.expiry = dl
		return
	}

	m.pending[connID] = &storedReq{
		requestInfo: requestInfo{
			id:     msg.ID,
			qName:  qHdr.Name,
			qType:  dns.RRToType(q),
			qClass: qHdr.Class,
		},
		count:  0,
		expiry: dl,
	}
}

// removePending models f.connections.Remove (counting cache).
func (m *model) removePending(connID connectionID) {
	r, ok := m.pending[connID]
	if !ok {
		return
	}

	if r.count != 0 {
		r.count--
		return
	}
	delete(m.pending, connID)
}

func norm(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func inAllowedDomains(name string) bool {
	return norm(name) == allowedDomain
}

func inAllowedTargets(name string) bool {
	return norm(name) == allowedTarget
}

// domainAllowed mirrors (*filter).domainAllowed for a question/owner name.
func (m *model) domainAllowed(name string) bool {
	n := norm(name)
	if !wellFormedName(n) {
		return false
	}
	if inAllowedDomains(n) {
		return true
	}
	_, ok := m.targetDomains[n]
	return ok
}

// validateName mirrors (*filter).validateDNSName: it applies the qtype-driven
// _prefix-label rules, then falls back to the membership check. It reuses the
// production stripPrefixLabels (format logic, safe to share) but NOT the glob
// matcher (which domainAllowed reimplements as a pool lookup).
func (m *model) validateName(qtype uint16, name string) bool {
	var stripped string
	switch qtype {
	case dns.TypeSRV:
		s, n := stripPrefixLabels(name)
		if n != 2 {
			return false
		}
		stripped = s
	case dns.TypeHTTPS:
		s, n := stripPrefixLabels(name)
		if n != 0 && n != 2 {
			return false
		}
		stripped = s
	case dns.TypeSVCB:
		s, n := stripPrefixLabels(name)
		if n == 0 || n > 2 {
			return false
		}
		stripped = s
	default:
		stripped = name
	}
	return m.domainAllowed(stripped)
}

// targetAllowed mirrors (*filter).targetAllowed.
func (m *model) targetAllowed(target string) bool {
	if target == "." {
		return true
	}
	n := norm(target)
	if !wellFormedName(n) {
		return false
	}
	if inAllowedTargets(n) || inAllowedDomains(n) {
		return true
	}
	_, ok := m.targetDomains[n]
	return ok
}

// wellFormedName reports whether validDomainName accepts the (normalized) name,
// by consulting the validity tags recorded when the name pools were built — it
// never re-derives validDomainName's logic, so a bug there can't be mirrored
// into the oracle. Every name the generators produce is registered in
// nameValidity; an unregistered name means a generator/oracle gap, so it's
// treated as malformed to surface the mismatch loudly rather than silently.
func wellFormedName(n string) bool {
	return nameValidity[n]
}

// --- Conditional model checks ----------------------------------------------
//
// These decide the verdict for structurally-valid messages, and DO depend on
// accumulated model state (allowlist, additionalDomains, the answer chain), so
// they stay in the model.

// requestNameAllowed assumes a structurally valid request (gate passed): is the
// single question name allowed?
func (m *model) requestNameAllowed(msg *dns.Msg) bool {
	q := msg.Question[0]

	return m.validateName(dns.RRToType(q), q.Header().Name)
}

// responseConditionalAccept assumes an established connection with a correlated
// outstanding request (gate passed): is the response allowed? Question
// allowlist plus the in-order answer-chain validation.
func (m *model) responseConditionalAccept(msg *dns.Msg) bool {
	q := msg.Question[0]
	if len(msg.Question) != 1 || !m.validateName(dns.RRToType(q), q.Header().Name) {
		return false
	}
	if len(msg.Answer) == 0 {
		return true
	}
	return m.answersValid(msg)
}

// answersValid mirrors validateDNSAnswers, INCLUDING the in-order
// allowedTargets accumulation. This is the heart of the chaining property.
func (m *model) answersValid(msg *dns.Msg) bool {
	var accumulated []string // normalized targets allowed by earlier RRs

	for _, a := range msg.Answer {
		owner := norm(a.Header().Name)

		// owner allowed if it's a target accumulated from an earlier RR,
		// otherwise it must be allowed as a question/owner name (with the
		// same qtype-driven prefix rules the question uses).
		if !slices.Contains(accumulated, owner) {
			if !m.validateName(dns.RRToType(a), a.Header().Name) {
				return false
			}
		}

		target, targetBearing, supported := rrTarget(a)
		if !supported {
			return false // disallowed RR type (TXT, unknown, ...) -> drop reply
		}
		if !targetBearing {
			switch ans := a.(type) {
			case *dns.A:
				if err := m.addrChecker.SafeAddr(ans.Addr); err != nil {
					return false
				}
			case *dns.AAAA:
				if err := m.addrChecker.SafeAddr(ans.Addr); err != nil {
					return false
				}
			}
			continue // A/AAAA: no target to validate
		}
		if target == "" {
			return false // malformed zero-rdlength target -> drop reply
		}
		if target == "." {
			continue // legal "no endpoint" -> skip, no accumulation
		}
		if !m.targetAllowed(target) {
			return false
		}
		accumulated = append(accumulated, norm(target))
	}

	return true
}

// answerSideEffects mirrors the side-effect loop of the response callback.
// Only valid to call on a fully-accepted reply.
func (m *model) answerSideEffects(msg *dns.Msg) {
	dl := time.Now().Add(m.allowAnswersFor)

	for _, a := range msg.Answer {
		switch ans := a.(type) {
		case *dns.A:
			m.allowedIPs[ans.Addr] = dl
		case *dns.AAAA:
			m.allowedIPs[ans.Addr] = dl
			if ans.Addr.Is4In6() {
				m.allowedIPs[ans.Addr.Unmap()] = dl
			}
		default:
			if t, tb, _ := rrTarget(a); tb && t != "" && t != "." {
				m.targetDomains[norm(t)] = dl
			}
		}
	}
}

// rrTarget mirrors the type switch in validateDNSAnswers exactly.
//   - targetBearing distinguishes A/AAAA (no target) from CNAME/SRV/... (target).
//   - supported is false for RR types egress-eddie rejects (TXT, NS, unknown).
func rrTarget(a dns.RR) (target string, targetBearing, supported bool) {
	switch ans := a.(type) {
	case *dns.A, *dns.AAAA:
		return "", false, true // supported, but no target
	case *dns.CNAME:
		return ans.Target, true, true
	case *dns.SRV:
		return ans.Target, true, true
	case *dns.HTTPS:
		return ans.Target, true, true
	case *dns.SVCB:
		return ans.Target, true, true
	case *dns.MX:
		return ans.Mx, true, true
	default:
		return "", false, false // TXT, NS, unknown numeric types, ...
	}
}
