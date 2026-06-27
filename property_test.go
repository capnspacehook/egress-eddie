package egresseddie

// This file is the skeleton for the main property-based test of egress-eddie.
//
// Goal: assert the core security properties hold under a randomized sequence
// of DNS requests, DNS responses, and L7 traffic packets driven through the
// real filter via the mock enforcers:
//
//  P1. A DNS request is accepted iff its single question name is allowed by
//      the config (or is currently in additionalDomains via a prior chain).
//  P2. A DNS response is accepted iff it correlates to a stored request
//      (matching connID, header ID, and question) AND every answer RR is
//      allowed (owner names + targets), walking the answer section in order.
//  P3. IPs / additional domains are added to the allow-caches ONLY from a
//      response that was fully accepted (never from a dropped one).
//  P4. L7 traffic is accepted iff its src or dst IP is currently in allowedIPs.
//
// Design notes (see discussion):
//   - Time is made deterministic with rapid.SyncTest (synctest bubble + fake
//     clock), mirroring timedcache's own tests. An explicit "advance time"
//     action exercises TTL expiry as a modeled transition.
//   - The oracle is an INDEPENDENT reimplementation. Domain-name matching is
//     reduced to membership lookups against a tiny fixed pool of concrete
//     names so a bug in the glob matcher cannot be mirrored into the oracle.
//   - DNS packets are built with miekg (msg.Pack) and wrapped in gopacket
//     IP/UDP so malformed RDATA (empty target, "." target, 0x20 case, etc.)
//     is reachable exactly as it is from the wire — that's where the known
//     bugs lived.
//
// TODOs are marked inline; the spine (model, oracle, assertions, action map)
// is filled in, the value generators are stubs to expand.

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Fixed config + concrete name pool. The oracle is a lookup against these.
// ---------------------------------------------------------------------------

const (
	// In allowedDomains: a question / owner with this name is allowed.
	allowedDomain = "allowed.test"
	// In allowedTargets: legal only as an RR target, never as a question.
	allowedTarget = "target.test"
	// Not in any list: only ever reachable if added to additionalDomains
	// by a prior accepted chain answer.
	chainDomainA = "chain-a.test"
	chainDomainB = "chain-b.test"
	// Never allowed by anything.
	disallowedDomain = "blocked.test"
)

// The names above are drawn via the tagged pools (wellFormedNames /
// malformedNames) further down, which also record each name's validity.

const (
	propAllowAnswersFor = 10 * time.Second
	propConnTimeout     = time.Minute // dnsQueryTimeout

	// queue numbers for the single test filter
	qInboundV4 = 1
	qInboundV6 = 2
	qDNSReqV4  = 100
	qDNSReqV6  = 101
	qTrafficV4 = 200
	qTrafficV6 = 201
)

const propConfig = `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 2

[[filters]]
name = "prop"
dnsQueue.ipv4 = 100
dnsQueue.ipv6 = 101
trafficQueue.ipv4 = 200
trafficQueue.ipv6 = 201
allowAnswersFor = "10s"
allowedDomains = ["allowed.test"]
allowedTargets = ["target.test"]
`

// ---------------------------------------------------------------------------
// Shadow model
// ---------------------------------------------------------------------------

// storedReq mirrors what the request callback stores in f.connections
// (a counting cache: repeated requests on the same connID increment count and
// keep the FIRST stored value).
type storedReq struct {
	id     uint16
	qname  string // normalized
	qtype  uint16
	qclass uint16
	count  int       // counting-cache count (0 == one outstanding)
	expiry time.Time // now + propConnTimeout, refreshed on each Add
}

type model struct {
	now             func() time.Time
	pending         map[connectionID]*storedReq
	allowedIPs      map[netip.Addr]time.Time // value == expiry deadline
	additionalDoms  map[string]time.Time     // value == expiry deadline
	allowAnswersFor time.Duration
}

func newModel(now func() time.Time) *model {
	return &model{
		now:             now,
		pending:         make(map[connectionID]*storedReq),
		allowedIPs:      make(map[netip.Addr]time.Time),
		additionalDoms:  make(map[string]time.Time),
		allowAnswersFor: propAllowAnswersFor,
	}
}

// prune drops modeled entries whose deadline has passed. Call after
// synctest.Wait() so it lines up with the real cache's timer goroutines.
func (m *model) prune() {
	now := m.now()
	for k, dl := range m.allowedIPs {
		if !dl.After(now) {
			delete(m.allowedIPs, k)
		}
	}
	for k, dl := range m.additionalDoms {
		if !dl.After(now) {
			delete(m.additionalDoms, k)
		}
	}
	for k, r := range m.pending {
		if !r.expiry.After(now) {
			delete(m.pending, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Oracle: pure functions that mirror the filter's allow/deny decisions.
// Domain matching is membership-only over the concrete pool.
// ---------------------------------------------------------------------------

func norm(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func inAllowedDomains(name string) bool { return norm(name) == allowedDomain }
func inAllowedTargets(name string) bool { return norm(name) == allowedTarget }

// domainAllowed mirrors (*filter).domainAllowed for a question/owner name.
func (m *model) domainAllowed(name string) bool {
	n := norm(name)
	if !wellFormedName(n) {
		return false
	}
	if inAllowedDomains(n) {
		return true
	}
	_, ok := m.additionalDoms[n]
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
	_, ok := m.additionalDoms[n]
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

// requestVerdict mirrors the request callback's accept/drop decision and the
// connection it would store. It does NOT mutate the model.
func (m *model) requestVerdict(msg *dns.Msg, connState uint32) (accept bool) {
	// state gate
	if connState != stateNew && !connIsEstablished(connState) {
		return false
	}
	if msg.Opcode != dns.OpcodeQuery {
		return false
	}
	// replies must not arrive on the request queue
	if msg.Response || len(msg.Answer) > 0 || len(msg.Ns) > 0 {
		return false
	}
	// validateDNSQuestion: exactly one question, allowed
	if len(msg.Question) != 1 {
		return false
	}
	q := msg.Question[0]
	return m.validateName(q.Qtype, q.Name)
}

// responseDecision mirrors the response callback. Returns the verdict plus the
// side effects (IPs/domains to add) that a fully-accepted response produces.
//
// IMPORTANT quirk being modeled (REVIEW_TODO #3): the connection entry is
// removed as soon as it is found, BEFORE validation — so even a dropped
// response consumes the pending entry. removeConn reports whether to consume.
func (m *model) responseDecision(msg *dns.Msg, connID connectionID, connState uint32) (accept, removeConn bool, addIPs []netip.Addr, addDoms []string) {
	if !connIsEstablished(connState) {
		return false, false, nil, nil
	}
	req, ok := m.pending[connID]
	if !ok {
		return false, false, nil, nil
	}
	removeConn = true // found -> consumed regardless of outcome

	// compareDNSReqResp + validateDNSQuestion
	if !m.responseCorrelates(req, msg) {
		return false, removeConn, nil, nil
	}
	// question must still be allowed
	if len(msg.Question) != 1 || !m.validateName(msg.Question[0].Qtype, msg.Question[0].Name) {
		return false, removeConn, nil, nil
	}
	// no answers -> accept, no side effects
	if len(msg.Answer) == 0 {
		return true, removeConn, nil, nil
	}
	// validate all answers (in order) BEFORE any side effects
	if !m.answersValid(msg) {
		return false, removeConn, nil, nil
	}

	addIPs, addDoms = answerSideEffects(msg)
	return true, removeConn, addIPs, addDoms
}

// responseCorrelates mirrors compareDNSReqResp: ID, qtype, qclass, qname.
func (m *model) responseCorrelates(req *storedReq, msg *dns.Msg) bool {
	if uint16(msg.Id) != req.id {
		return false
	}
	if len(msg.Question) == 0 {
		return false
	}
	q := msg.Question[0]
	return q.Qtype == req.qtype && q.Qclass == req.qclass && strings.EqualFold(norm(q.Name), req.qname)
}

// answersValid mirrors validateDNSAnswers, INCLUDING the in-order
// allowedTargets accumulation. This is the heart of the chaining property.
func (m *model) answersValid(msg *dns.Msg) bool {
	qtype := msg.Question[0].Qtype // validateDNSAnswers validates owners against the question's qtype
	var accumulated []string       // normalized targets allowed by earlier RRs

	for _, a := range msg.Answer {
		owner := norm(a.Header().Name)

		// owner allowed if it's a target accumulated from an earlier RR,
		// otherwise it must be allowed as a question/owner name (with the
		// same qtype-driven prefix rules the question uses).
		if !slices.Contains(accumulated, owner) {
			if !m.validateName(qtype, a.Header().Name) {
				return false
			}
		}

		target, targetBearing, supported := rrTarget(a)
		if !supported {
			return false // disallowed RR type (TXT, unknown, ...) -> drop reply
		}
		if !targetBearing {
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
func answerSideEffects(msg *dns.Msg) (addIPs []netip.Addr, addDoms []string) {
	for _, a := range msg.Answer {
		switch ans := a.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(ans.A); ok {
				addIPs = append(addIPs, ip)
			}
		case *dns.AAAA:
			if ip, ok := netip.AddrFromSlice(ans.AAAA); ok {
				addIPs = append(addIPs, ip)
				if ip.Is4In6() {
					addIPs = append(addIPs, ip.Unmap())
				}
			}
		default:
			if t, tb, _ := rrTarget(a); tb && t != "" && t != "." {
				addDoms = append(addDoms, norm(t))
			}
		}
	}
	return addIPs, addDoms
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

// ---------------------------------------------------------------------------
// Packet construction (miekg wire DNS wrapped in gopacket IP/UDP)
// ---------------------------------------------------------------------------

var (
	dnsServerV4 = netip.MustParseAddr("9.9.9.9")
	dnsServerV6 = netip.MustParseAddr("2620:fe::fe")
	clientV4    = netip.MustParseAddr("127.0.0.1")
	clientV6    = netip.MustParseAddr("::1")
)

// connIDFor builds the connID exactly as parseDNSPacket would. The connID is
// always {clientAddr:clientPort, serverAddr:53} regardless of direction.
func connIDFor(ipv6 bool, clientPort uint16) connectionID {
	client, server := clientV4, dnsServerV4
	if ipv6 {
		client, server = clientV6, dnsServerV6
	}
	return connectionID{
		src: netip.AddrPortFrom(client, clientPort),
		dst: netip.AddrPortFrom(server, 53),
	}
}

// buildDNSPacket packs msg and wraps it as an IP+UDP packet in the requested
// direction. request: client->server:53. response: server:53->client.
//
// It returns the re-unpacked message so the oracle evaluates EXACTLY what the
// filter sees off the wire. Pack→Unpack is not the identity (e.g. an empty
// target round-trips to "."), so feeding the oracle the pre-pack struct would
// produce spurious mismatches. Packets miekg can't pack/unpack are skipped
// (ok == false) — crafting those is the byte-level fuzzer's job.
func buildDNSPacket(t *rapid.T, msg *dns.Msg, ipv6, response bool, clientPort uint16) (packet []byte, parsed *dns.Msg, ok bool) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, nil, false
	}
	var parsedMsg dns.Msg
	if err := parsedMsg.Unpack(wire); err != nil {
		return nil, nil, false
	}

	client, server := clientV4, dnsServerV4
	if ipv6 {
		client, server = clientV6, dnsServerV6
	}
	srcIP, dstIP := client, server
	srcPort, dstPort := clientPort, uint16(53)
	if response {
		srcIP, dstIP = server, client
		srcPort, dstPort = 53, clientPort
	}

	return wrapUDP(t, ipv6, srcIP, dstIP, srcPort, dstPort, wire), &parsedMsg, true
}

// wrapUDP serializes IP+UDP+payload into wire bytes.
func wrapUDP(t *rapid.T, ipv6 bool, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	var ipLayer gopacket.SerializableLayer
	if !ipv6 {
		ipLayer = &layers.IPv4{Protocol: layers.IPProtocolUDP, SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice()}
	} else {
		ipLayer = &layers.IPv6{NextHeader: layers.IPProtocolUDP, SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice()}
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ipLayer,
		&layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatalf("serializing packet: %v", err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Driver: deliver a packet to a queue and read back the verdict.
// ---------------------------------------------------------------------------

type driver struct {
	t        *rapid.T
	packetID uint32
}

func (d *driver) deliver(queue uint16, connState uint32, packet []byte) (verdict int, gotVerdict bool) {
	d.packetID++
	id := d.packetID
	e := mockEnforcers[queue]
	e.hook(nfqueue.Attribute{
		PacketID: ref(id),
		CtInfo:   ref(connState),
		Payload:  ref(packet),
	})
	v, ok := e.verdicts[id]
	delete(e.verdicts, id)
	return v, ok
}

// ---------------------------------------------------------------------------
// Assertions: compare all four state surfaces after every action.
// ---------------------------------------------------------------------------

func (m *model) assertCaches(t *rapid.T, f *filter) {
	// allowedIPs: bijection between model and real cache.
	if got := f.allowedIPs.Len(); got != len(m.allowedIPs) {
		t.Fatalf("allowedIPs size: model=%d real=%d", len(m.allowedIPs), got)
	}
	for ip := range m.allowedIPs {
		if !f.allowedIPs.Exists(ip) {
			t.Fatalf("allowedIPs missing modeled IP %s", ip)
		}
	}
	// additionalDomains: bijection.
	if got := f.additionalDomains.Len(); got != len(m.additionalDoms) {
		t.Fatalf("additionalDomains size: model=%d real=%d", len(m.additionalDoms), got)
	}
	for dom := range m.additionalDoms {
		if !f.additionalDomains.Exists(dom) {
			t.Fatalf("additionalDomains missing modeled domain %q", dom)
		}
	}
	// connections: bijection.
	if got := f.connections.Len(); got != len(m.pending) {
		t.Fatalf("connections size: model=%d real=%d", len(m.pending), got)
	}
	for connID := range m.pending {
		if !f.connections.Exists(connID) {
			t.Fatalf("connections missing modeled connID %s", connID)
		}
	}
}

// ---------------------------------------------------------------------------
// Generators
//
// Every generated domain name is drawn from a tagged pool that records its
// validity (per validDomainName), so the oracle's wellFormedName never has to
// re-derive that logic from the production code.
// ---------------------------------------------------------------------------

// taggedName is a base domain (no _prefix labels) plus whether validDomainName
// accepts it.
type taggedName struct {
	name       string
	wellFormed bool
}

var (
	// Well-formed names. Config-list membership is by normalized value.
	wellFormedNames = []taggedName{
		{allowedDomain, true},
		{allowedTarget, true},
		{chainDomainA, true},
		{chainDomainB, true},
		{disallowedDomain, true},
	}
	// Malformed names that still survive miekg packing, so they reach the
	// filter and exercise the format-reject path in domainNameAllowed. (Names
	// like "" or "bad..test" can't be packed, so there's no point drawing them
	// for owner/question names — that's the byte-level fuzzer's territory.)
	malformedNames = []taggedName{
		{"-bad.test", false}, // label starts with a dash
		{"bad-.test", false}, // label ends with a dash
	}
	// nameValidity maps a normalized name to its known well-formedness, built
	// from the tagged pools. wellFormedName consults this instead of calling
	// validDomainName, keeping the oracle independent of the code under test.
	nameValidity = map[string]bool{}
)

func init() {
	for _, n := range append(append([]taggedName{}, wellFormedNames...), malformedNames...) {
		nameValidity[norm(n.name)] = n.wellFormed
	}
}

// genBaseName draws a base domain, mostly well-formed but occasionally a
// (packable) malformed one to exercise the validDomainName reject path.
func genBaseName(t *rapid.T) string {
	if rapid.IntRange(0, 9).Draw(t, "malformedName") == 0 {
		return rapid.SampledFrom(malformedNames).Draw(t, "badName").name
	}
	return rapid.SampledFrom(wellFormedNames).Draw(t, "goodName").name
}

// genPrefixLabels returns n leading "_label." prefix labels (e.g. "_sip._tcp.").
func genPrefixLabels(t *rapid.T, n int) string {
	var sb strings.Builder
	for range n {
		sb.WriteString(rapid.SampledFrom([]string{"_http", "_https", "_sip", "_tcp", "_udp"}).Draw(t, "prefixLabel"))
		sb.WriteByte('.')
	}
	return sb.String()
}

// genCase applies a 0x20 (case) transformation. DNS is case-insensitive on the
// wire, so every variant must be handled identically — this is what catches the
// mixed-case chain bug (REVIEW_TODO #2).
func genCase(t *rapid.T, s string) string {
	switch rapid.IntRange(0, 3).Draw(t, "case") {
	case 1:
		return strings.ToUpper(s)
	case 2:
		return strings.ToLower(s)
	case 3:
		return toggleAlternating(s)
	default:
		return s
	}
}

func toggleAlternating(s string) string {
	b := []byte(s)
	flip := false
	for i, c := range b {
		flip = !flip
		if !flip {
			continue
		}
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - 32
		case c >= 'A' && c <= 'Z':
			b[i] = c + 32
		}
	}
	return string(b)
}

// prefixCountsFor biases the number of _prefix labels toward the values that
// make a name valid for the given qtype, while still drawing invalid counts so
// both paths are exercised. Returns 0 for qtypes that don't expect prefixes.
func prefixCountsFor(qtype uint16) []int {
	switch qtype {
	case dns.TypeSRV: // valid: exactly 2
		return []int{2, 2, 2, 0, 1, 3}
	case dns.TypeHTTPS: // valid: 0 or 2
		return []int{0, 0, 2, 2, 1, 3}
	case dns.TypeSVCB: // valid: 1 or 2
		return []int{1, 2, 2, 1, 0, 3}
	default:
		return []int{0}
	}
}

// genName builds a wire name: base domain, optional qtype-appropriate prefix
// labels, and 0x20 casing.
func genName(t *rapid.T, base string, qtype uint16) string {
	n := rapid.SampledFrom(prefixCountsFor(qtype)).Draw(t, "prefixCount")
	return genCase(t, genPrefixLabels(t, n)+base)
}

// genQType draws a qtype: mostly supported, sometimes TXT (unsupported answer
// type) so the deny-by-default path is exercised on the question side too.
func genQType(t *rapid.T) uint16 {
	return rapid.SampledFrom([]uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeSRV,
		dns.TypeHTTPS, dns.TypeSVCB, dns.TypeMX, dns.TypeTXT,
	}).Draw(t, "qtype")
}

// genRequestMsg builds a request *dns.Msg, occasionally malformed (0/2
// questions, reply flags, answers present, non-query opcode) to exercise the
// request drop paths.
func genRequestMsg(t *rapid.T) *dns.Msg {
	msg := new(dns.Msg)
	msg.Id = uint16(rapid.IntRange(0, 0xffff).Draw(t, "id"))
	msg.Opcode = dns.OpcodeQuery

	switch rapid.IntRange(0, 9).Draw(t, "reqShape") {
	case 0:
		// no questions
	case 1:
		// two questions
		msg.Question = []dns.Question{genQuestion(t), genQuestion(t)}
	case 2:
		// reply flag set on the request queue
		msg.Response = true
		msg.Question = []dns.Question{genQuestion(t)}
	case 3:
		// non-query opcode
		msg.Opcode = dns.OpcodeStatus
		msg.Question = []dns.Question{genQuestion(t)}
	case 4:
		// stray answer section
		q := genQuestion(t)
		msg.Question = []dns.Question{q}
		msg.Answer = []dns.RR{genAnswerRR(t, q.Name, q.Qtype)}
	default:
		// well-formed single-question request
		msg.Question = []dns.Question{genQuestion(t)}
	}
	return msg
}

func genQuestion(t *rapid.T) dns.Question {
	qtype := genQType(t)
	return dns.Question{
		Name:   dns.Fqdn(genName(t, genBaseName(t), qtype)),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
}

// genAnswerRR builds one answer RR of a randomly chosen type. Owner is supplied
// by the caller (the chain driver). Targets are drawn from the pool plus the
// edge values "" (malformed) and "." (legal no-endpoint).
func genAnswerRR(t *rapid.T, owner string, qtype uint16) dns.RR {
	hdr := dns.RR_Header{Name: dns.Fqdn(owner), Class: dns.ClassINET, Ttl: 60}

	kind := rapid.SampledFrom([]string{
		"A", "AAAA", "CNAME", "SRV", "HTTPS", "SVCB", "MX", "TXT", "UNKNOWN",
	}).Draw(t, "rrkind")

	switch kind {
	case "A":
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: GenIPv4Addr().Draw(t, "a").AsSlice()}
	case "AAAA":
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: genAAAA(t).AsSlice()}
	case "CNAME":
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: genTarget(t)}
	case "SRV":
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{Hdr: hdr, Priority: 1, Weight: 1, Port: 443, Target: genTarget(t)}
	case "HTTPS":
		hdr.Rrtype = dns.TypeHTTPS
		return &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Target: genTarget(t)}}
	case "SVCB":
		hdr.Rrtype = dns.TypeSVCB
		return &dns.SVCB{Hdr: hdr, Target: genTarget(t)}
	case "MX":
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: 10, Mx: genTarget(t)}
	case "TXT":
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{"v=spf1"}}
	default: // UNKNOWN — an unsupported numeric type via RFC3597
		hdr.Rrtype = 65280 // private-use type, not in egress-eddie's allowlist
		return &dns.RFC3597{Hdr: hdr, Rdata: "00"}
	}
}

// genTarget draws an RR target: pool names (with casing), the legal "." case,
// and the malformed "" case. Note "" and "." are normalized by Pack→Unpack, so
// the oracle (reading the parsed msg) and the filter agree regardless.
func genTarget(t *rapid.T) string {
	switch rapid.IntRange(0, 9).Draw(t, "targetShape") {
	case 0:
		return "." // root / no endpoint — legal, skipped
	case 1:
		return "" // empty — see genTarget note; usually becomes "." on the wire
	default:
		return dns.Fqdn(genCase(t, genBaseName(t)))
	}
}

// genAAAA draws an IPv6 address, occasionally an IPv4-mapped one so the
// Is4In6 → also-add-unmapped side effect is exercised.
func genAAAA(t *rapid.T) netip.Addr {
	if rapid.IntRange(0, 3).Draw(t, "mapped") == 0 {
		return netip.AddrFrom16(GenIPv4Addr().Draw(t, "mapped4").As16())
	}
	return GenIPv6Addr().Draw(t, "aaaa")
}

// genResponseMsg builds a response for an outstanding request. It mostly
// correlates (matching ID/question) but sometimes mismatches each field
// independently to exercise compareDNSReqResp. The answer section is built as a
// chain: each RR's target becomes the next RR's owner, mirroring real CNAME/SRV
// chains so the in-order allowedTargets accumulation is tested.
func genResponseMsg(t *rapid.T, req *storedReq) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true

	msg.Id = req.id
	if rapid.IntRange(0, 4).Draw(t, "mismatchID") == 0 {
		msg.Id = uint16(rapid.IntRange(0, 0xffff).Draw(t, "wrongID"))
	}

	q := dns.Question{Name: dns.Fqdn(genCase(t, req.qname)), Qtype: req.qtype, Qclass: req.qclass}
	if rapid.IntRange(0, 4).Draw(t, "mismatchQName") == 0 {
		q.Name = dns.Fqdn(genName(t, genBaseName(t), req.qtype))
	}
	if rapid.IntRange(0, 6).Draw(t, "mismatchQType") == 0 {
		q.Qtype = genQType(t)
	}
	msg.Question = []dns.Question{q}

	n := rapid.IntRange(0, 3).Draw(t, "nanswers")
	owner := req.qname // first owner is the (correlated) question name
	for range n {
		rr := genAnswerRR(t, genCase(t, owner), q.Qtype)
		msg.Answer = append(msg.Answer, rr)
		// chain: the next owner is this RR's target, if it has one.
		if tgt, tb, _ := rrTarget(rr); tb && tgt != "" && tgt != "." {
			owner = norm(tgt)
		}
	}
	return msg
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

func TestFilterProperties(t *testing.T) {
	rapid.Check(t, testFilterState)
}

func FuzzFilterProperties(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testFilterState))
}

func testFilterState(t *rapid.T) {
	rapid.SyncTest(t, func(t *rapid.T) {
		logger := zap.NewNop()

		// Fresh config + enforcers + filter per run so shrinking replays
		// cleanly (no global state carried across runs).
		config, err := parseConfigBytes([]byte(propConfig))
		if err != nil {
			t.Fatalf("parsing config: %v", err)
		}
		initMockEnforcers()
		config.enforcerCreator = newMockEnforcer
		config.resolver = &mockResolver{}

		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fm, err := CreateFilters(ctx, logger, config, false)
		if err != nil {
			t.Fatalf("creating filters: %v", err)
		}
		fm.Start()
		t.Cleanup(fm.Stop)

		f := fm.filters[0]
		m := newModel(time.Now)
		d := &driver{t: t}

		// clientPort pool gives a small set of distinct connections so the
		// correlation / unknown-connection paths get exercised.
		clientPorts := []uint16{40000, 40001, 40002}

		settleAndCheck := func() {
			synctest.Wait()
			m.prune()
			m.assertCaches(t, f)
		}

		t.Repeat(map[string]func(*rapid.T){
			// --- DNS request ---
			"dns request": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				port := rapid.SampledFrom(clientPorts).Draw(t, "port")
				connState := drawConnState(t)
				msg := genRequestMsg(t)

				packet, parsed, ok := buildDNSPacket(t, msg, ipv6, false, port)
				if !ok {
					return
				}
				queue := uint16(qDNSReqV4)
				if ipv6 {
					queue = qDNSReqV6
				}

				wantAccept := m.requestVerdict(parsed, connState)
				v, gotV := d.deliver(queue, connState, packet)
				assertVerdict(t, gotV, v, wantAccept)

				// model the connection store on accept (counting cache).
				if wantAccept {
					m.addPending(ipv6, port, parsed)
				}
				settleAndCheck()
			},

			// --- DNS response ---
			"dns response": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				port := rapid.SampledFrom(clientPorts).Draw(t, "port")
				connState := drawConnState(t)
				connID := connIDFor(ipv6, port)

				// Build a response; if there's an outstanding request for this
				// connID, correlate to it, else craft a stray reply.
				var msg *dns.Msg
				if req, ok := m.pending[connID]; ok {
					msg = genResponseMsg(t, req)
				} else {
					msg = genResponseMsg(t, &storedReq{
						id:     uint16(rapid.IntRange(0, 0xffff).Draw(t, "strayid")),
						qname:  genBaseName(t),
						qtype:  dns.TypeA,
						qclass: dns.ClassINET,
					})
				}

				packet, parsed, ok := buildDNSPacket(t, msg, ipv6, true, port)
				if !ok {
					return
				}
				queue := uint16(qInboundV4)
				if ipv6 {
					queue = qInboundV6
				}

				accept, removeConn, addIPs, addDoms := m.responseDecision(parsed, connID, connState)
				v, gotV := d.deliver(queue, connState, packet)
				assertVerdict(t, gotV, v, accept)

				if removeConn {
					m.removePending(connID)
				}
				if accept {
					dl := m.now().Add(m.allowAnswersFor)
					for _, ip := range addIPs {
						m.allowedIPs[ip] = dl
					}
					for _, dom := range addDoms {
						m.additionalDoms[dom] = dl
					}
				}
				settleAndCheck()
			},

			// --- L7 traffic ---
			"traffic": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				// TODO: draw src/dst from {allowed IPs in model, random}.
				// accept iff allowedIPs contains src or dst.
				_ = ipv6
				// settleAndCheck() // enable once traffic packets are built
			},

			// --- advance time (exercise TTL expiry as a transition) ---
			"advance time": func(t *rapid.T) {
				secs := rapid.IntRange(1, 70).Draw(t, "secs")
				time.Sleep(time.Duration(secs) * time.Second)
				settleAndCheck()
			},
		})
	})
}

// addPending models f.connections.AddValue (counting cache: first value wins,
// count increments, deadline refreshes).
func (m *model) addPending(ipv6 bool, port uint16, msg *dns.Msg) {
	connID := connIDFor(ipv6, port)
	q := msg.Question[0]
	dl := m.now().Add(propConnTimeout)
	if r, ok := m.pending[connID]; ok {
		r.count++
		r.expiry = dl
		return
	}
	m.pending[connID] = &storedReq{
		id:     msg.Id,
		qname:  norm(q.Name),
		qtype:  q.Qtype,
		qclass: q.Qclass,
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

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func drawConnState(t *rapid.T) uint32 {
	return uint32(rapid.SampledFrom([]int{
		stateNew, stateEstablished, stateRelated,
		stateEstablishedReply, stateRelatedReply, stateUntracked,
	}).Draw(t, "connState"))
}

func assertVerdict(t *rapid.T, gotVerdict bool, verdict int, wantAccept bool) {
	if !gotVerdict {
		t.Fatalf("packet did not receive a verdict")
	}
	want := nfqueue.NfDrop
	if wantAccept {
		want = nfqueue.NfAccept
	}
	if verdict != want {
		t.Fatalf("verdict: got %d want %d (accept=%v)", verdict, want, wantAccept)
	}
}
