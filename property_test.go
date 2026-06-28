package egresseddie

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

	propAllowAnswersFor = 10 * time.Second
	propConnTimeout     = time.Minute // dnsQueryTimeout

	// queue numbers for the single test filter
	qInboundV4 = 1
	qInboundV6 = 2
	qDNSReqV4  = 100
	qDNSReqV6  = 101
	qTrafficV4 = 200
	qTrafficV6 = 201

	propConfig = `
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
)

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

	// clientPort pool gives a small set of distinct connections so the
	// correlation / unknown-connection paths get exercised.
	clientPorts = []uint16{40000, 40001, 40002}
)

func init() {
	for _, n := range append(append([]taggedName{}, wellFormedNames...), malformedNames...) {
		nameValidity[norm(n.name)] = n.wellFormed
	}
}

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
		d := &driver{}

		settleAndCheck := func() {
			synctest.Wait()
			m.prune()
			m.assertCaches(t, f)
		}

		t.Repeat(map[string]func(*rapid.T){
			"dns request": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				ep := drawEndpoint(t, ipv6)
				connState := drawConnState(t)
				msg, malformed := genRequestMsg(t)

				packet, parsed, ok := buildDNSPacket(t, msg, ipv6, false, ep)
				if !ok {
					return
				}
				queue := uint16(qDNSReqV4)
				if ipv6 {
					queue = qDNSReqV6
				}

				accept := !malformed && (connState == stateNew || connIsEstablished(connState)) && m.requestNameAllowed(parsed)
				v, gotV := d.deliver(queue, connState, packet)
				assertVerdict(t, gotV, v, accept)

				// model the connection store on accept (counting cache).
				if accept {
					m.addPending(ep, parsed)
				}
				settleAndCheck()
			},
			"dns response": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				ep := drawResponseEndpoint(t, m, ipv6)
				connState := drawConnState(t)
				connID := ep.connID()

				// Build a response; if there's an outstanding request for this
				// connID, correlate to it (the generator may still inject a
				// mismatch), else craft a stray reply.
				req, havePending := m.pending[connID]

				var msg *dns.Msg
				var malformed bool
				if havePending {
					msg, malformed = genResponseMsg(t, req)
				} else {
					msg, _ = genResponseMsg(t, &storedReq{
						requestInfo: requestInfo{
							id:     uint16(rapid.IntRange(0, 0xffff).Draw(t, "randomID")),
							qName:  dns.Fqdn(genBaseName(t)),
							qType:  dns.TypeA,
							qClass: dns.ClassINET,
						},
					})
					// we don't need to set malformed as if this isn't
					// for a pending request this should always be dropped
				}

				packet, parsed, ok := buildDNSPacket(t, msg, ipv6, true, ep)
				if !ok {
					return
				}
				queue := uint16(qInboundV4)
				if ipv6 {
					queue = qInboundV6
				}

				// The connection entry is consumed as soon as it's found, BEFORE
				// any validation (REVIEW_TODO #3), so the removeConn mutation
				// tracks "found" regardless of the eventual verdict.
				established := connIsEstablished(connState)
				found := havePending && established
				accept := found && !malformed && m.responseConditionalAccept(parsed)

				v, gotV := d.deliver(queue, connState, packet)
				assertVerdict(t, gotV, v, accept)

				if found {
					m.removePending(connID)
				}
				if accept {
					dl := m.now().Add(m.allowAnswersFor)
					addIPs, addDoms := answerSideEffects(parsed)
					for _, ip := range addIPs {
						m.allowedIPs[ip] = dl
					}
					for _, dom := range addDoms {
						m.additionalDoms[dom] = dl
					}
				}
				settleAndCheck()
			},
			"traffic": func(t *rapid.T) {
				ipv6 := rapid.Bool().Draw(t, "ipv6")
				queue := uint16(qTrafficV4)
				if ipv6 {
					queue = qTrafficV6
				}

				src := genTrafficIP(t, m, ipv6, "src")
				dst := genTrafficIP(t, m, ipv6, "dst")
				_, accept := m.allowedIPs[dst]

				packet := buildTrafficPacket(t, ipv6, src, dst)
				v, gotV := d.deliver(queue, drawConnState(t), packet)
				assertVerdict(t, gotV, v, accept)
				settleAndCheck()
			},
			"advance time": func(t *rapid.T) {
				secs := rapid.IntRange(1, 70).Draw(t, "secs")
				time.Sleep(time.Duration(secs) * time.Second)
				settleAndCheck()
			},
		})
	})
}

func drawConnState(t *rapid.T) uint32 {
	return uint32(rapid.SampledFrom([]int{
		stateNew, stateEstablished, stateRelated,
		stateEstablishedReply, stateRelatedReply, stateUntracked,
	}).Draw(t, "connState"))
}

// genRequestMsg builds a request *dns.Msg, occasionally malformed (0/2
// questions, reply flags, answers present, non-query opcode) to exercise the
// request drop paths.
func genRequestMsg(t *rapid.T) (*dns.Msg, bool) {
	msg := new(dns.Msg)
	msg.Id = uint16(rapid.IntRange(0, 0xffff).Draw(t, "id"))
	msg.Opcode = dns.OpcodeQuery

	malformed := true
	switch rapid.IntRange(0, 10).Draw(t, "reqShape") {
	case 0:
		t.Log("no questions")
	case 1:
		t.Log("two questions")
		msg.Question = []dns.Question{genQuestion(t), genQuestion(t)}
	case 2:
		t.Log("reply flag set")
		msg.Response = true
		msg.Question = []dns.Question{genQuestion(t)}
	case 3:
		t.Log("non-query opcode")
		msg.Opcode = dns.OpcodeStatus
		msg.Question = []dns.Question{genQuestion(t)}
	case 4:
		t.Log("answers present")
		q := genQuestion(t)
		msg.Question = []dns.Question{q}
		msg.Answer = []dns.RR{genAnswerRR(t, q.Name)}
	case 5:
		t.Log("authority records present")
		q := genQuestion(t)
		msg.Question = []dns.Question{q}
		msg.Ns = genNoiseRRs(t, "reqNs")
	default:
		// well-formed single-question request
		q, badQ := genQuestionClassified(t)
		if !badQ {
			malformed = false
		}
		msg.Question = []dns.Question{q}
	}

	return msg, malformed
}

// genResponseMsg builds a response for an outstanding request. It mostly
// correlates (matching ID/question) but sometimes mismatches each field
// independently to exercise compareDNSReqResp. The answer section is built as a
// chain: each RR's target becomes the next RR's owner, mirroring real CNAME/SRV
// chains so the in-order allowedTargets accumulation is tested.
func genResponseMsg(t *rapid.T, req *storedReq) (_ *dns.Msg, malformed bool) {
	msg := new(dns.Msg)
	msg.Response = true

	msg.Id = req.id
	if rapid.IntRange(0, 4).Draw(t, "mismatchID") == 0 {
		msg.Id = uint16(rapid.IntRange(0, 0xffff).Draw(t, "wrongID"))
		malformed = msg.Id != req.id
		t.Log("possibly mismatched IDs")
	}

	q := dns.Question{
		Qtype:  req.qType,
		Qclass: req.qClass,
	}

	if rapid.IntRange(0, 6).Draw(t, "mismatchQType") == 0 {
		q.Qtype = genQType(t)
		if q.Qtype == dns.TypeTXT || q.Qtype != req.qType {
			t.Log("mismatched QTypes")
			malformed = true
		}
	}
	if rapid.IntRange(0, 4).Draw(t, "mismatchQName") == 0 {
		baseName, badBaseName := genBaseNameClassified(t)
		name, badName := genNameClassified(t, baseName, q.Qtype)
		q.Name = dns.Fqdn(name)
		if badBaseName || badName || !strings.EqualFold(q.Name, req.qName) {
			t.Log("mismatched QNames")
			malformed = true
		}
	} else {
		q.Name = genCase(t, req.qName)
	}
	if rapid.IntRange(0, 6).Draw(t, "mismatchQClass") == 0 {
		q.Qclass = genClass(t)
		if q.Qclass != req.qClass {
			t.Log("mismatched QClasses")
			malformed = true
		}
	}
	msg.Question = []dns.Question{q}

	n := rapid.IntRange(0, 3).Draw(t, "nAnswers")
	owner := req.qName // first owner is the (correlated) question name
	for range n {
		rr, badRR := genAnswerRRClassified(t, genCase(t, owner))
		if badRR {
			malformed = true
		}
		msg.Answer = append(msg.Answer, rr)
		// chain: the next owner is this RR's target, if it has one.
		if tgt, tb, _ := rrTarget(rr); tb && tgt != "" && tgt != "." {
			owner = norm(tgt)
		}
	}

	// The Authority and Additional sections must be ignored entirely;
	// populate them with poisoned records so a regression that validates or
	// acts on them surfaces as a verdict or cache divergence.
	if rapid.IntRange(0, 2).Draw(t, "addAuthority") == 0 {
		msg.Ns = genNoiseRRs(t, "ns")
	}
	if rapid.IntRange(0, 2).Draw(t, "addAdditional") == 0 {
		msg.Extra = genNoiseRRs(t, "extra")
	}

	return msg, malformed
}

// genNoiseRRs draws records for the Authority (Ns) and Additional (Extra)
// sections. Egress Eddie validates and acts on the Answer section only, so
// these must be completely inert. They're built "poisoned" — a disallowed
// owner plus an arbitrary IP or a disallowed target — so any regression that
// starts validating or acting on these sections shows up as a verdict or
// cache divergence.
func genNoiseRRs(t *rapid.T, label string) []dns.RR {
	n := rapid.IntRange(1, 2).Draw(t, label+"Count")
	rrs := make([]dns.RR, 0, n)
	for range n {
		hdr := dns.RR_Header{Name: dns.Fqdn(disallowedDomain), Class: dns.ClassINET, Ttl: 60}
		switch rapid.IntRange(0, 2).Draw(t, label+"Kind") {
		case 0:
			hdr.Rrtype = dns.TypeA
			rrs = append(rrs, &dns.A{Hdr: hdr, A: GenIPv4Addr().Draw(t, label+"A").AsSlice()})
		case 1:
			hdr.Rrtype = dns.TypeAAAA
			rrs = append(rrs, &dns.AAAA{Hdr: hdr, AAAA: GenIPv6Addr().Draw(t, label+"AAAA").AsSlice()})
		default:
			hdr.Rrtype = dns.TypeCNAME
			rrs = append(rrs, &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(disallowedDomain)})
		}
	}
	return rrs
}

func genQuestion(t *rapid.T) dns.Question {
	q, _ := genQuestionClassified(t)
	return q
}

func genQuestionClassified(t *rapid.T) (q dns.Question, malformed bool) {
	q.Qtype = genQType(t)
	if q.Qtype == dns.TypeTXT {
		t.Log("TXT QType")
		malformed = true
	}

	baseName, badBaseName := genBaseNameClassified(t)
	name, badName := genNameClassified(t, baseName, q.Qtype)
	q.Name = dns.Fqdn(name)
	if badBaseName || badName {
		malformed = true
	}

	q.Qclass = genClass(t)
	if q.Qclass != dns.ClassINET {
		t.Log("non-INET QClass")
		malformed = true
	}

	return
}

// genBaseName draws a base domain, mostly well-formed but occasionally a
// (packable) malformed one to exercise the validDomainName reject path.
func genBaseName(t *rapid.T) string {
	name, _ := genBaseNameClassified(t)
	return name
}

func genBaseNameClassified(t *rapid.T) (name string, malformed bool) {
	if rapid.IntRange(0, 9).Draw(t, "malformedName") == 0 {
		t.Log("malformed base name")
		return rapid.SampledFrom(malformedNames).Draw(t, "badName").name, true
	}
	return rapid.SampledFrom(wellFormedNames).Draw(t, "goodName").name, false
}

// genName builds a wire name: base domain, optional qtype-appropriate prefix
// labels, and 0x20 casing.
func genNameClassified(t *rapid.T, base string, qtype uint16) (string, bool) {
	n, malformed := prefixCountsFor(t, qtype)
	return genCase(t, genPrefixLabels(t, n)+base), malformed
}

// prefixCountsFor biases the number of _prefix labels toward the values that
// make a name valid for the given qtype, while still drawing invalid counts so
// both paths are exercised.
func prefixCountsFor(t *rapid.T, qtype uint16) (int, bool) {
	var counts []int
	switch qtype {
	case dns.TypeSRV: // valid: exactly 2
		counts = []int{2, 2, 2, 2, 0, 1, 3}
	case dns.TypeHTTPS: // valid: 0 or 2
		counts = []int{0, 0, 2, 2, 1, 3}
	case dns.TypeSVCB: // valid: 1 or 2
		counts = []int{1, 1, 2, 2, 0, 3}
	default: // valid: 0
		counts = []int{0, 0, 0, 0, 1, 2, 3}
	}

	n := rapid.SampledFrom(counts).Draw(t, "nPrefixLabels")
	if n > 3 {
		t.Log("invalid prefix label count")
		return n, true
	}
	return n, false
}

// genAnswerRR builds one answer RR of a randomly chosen type. Owner is supplied
// by the caller (the chain driver). Targets are drawn from the pool plus the
// edge values "" (malformed) and "." (legal no-endpoint).
func genAnswerRR(t *rapid.T, owner string) dns.RR {
	rr, _ := genAnswerRRClassified(t, owner)
	return rr
}

func genAnswerRRClassified(t *rapid.T, owner string) (_ dns.RR, malformed bool) {
	hdr := dns.RR_Header{
		Name: dns.Fqdn(owner),
		Ttl:  60,
	}

	hdr.Class = genClass(t)
	if hdr.Class != dns.ClassINET {
		t.Log("non-INET RR class")
		malformed = true
	}

	kind := rapid.SampledFrom([]string{
		"A", "AAAA", "CNAME", "SRV", "HTTPS", "SVCB", "MX", "TXT", "UNKNOWN",
	}).Draw(t, "rrkind")

	switch kind {
	case "A":
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: GenIPv4Addr().Draw(t, "a").AsSlice()}, malformed
	case "AAAA":
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: genAAAA(t).AsSlice()}, malformed
	case "CNAME":
		hdr.Rrtype = dns.TypeCNAME
		target, badTarget := genTarget(t)
		return &dns.CNAME{Hdr: hdr, Target: target}, malformed || badTarget
	case "SRV":
		hdr.Rrtype = dns.TypeSRV
		target, badTarget := genTarget(t)
		return &dns.SRV{Hdr: hdr, Priority: 1, Weight: 1, Port: 443, Target: target}, malformed || badTarget
	case "HTTPS":
		hdr.Rrtype = dns.TypeHTTPS
		target, badTarget := genTarget(t)
		return &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Target: target}}, malformed || badTarget
	case "SVCB":
		hdr.Rrtype = dns.TypeSVCB
		target, badTarget := genTarget(t)
		return &dns.SVCB{Hdr: hdr, Target: target}, malformed || badTarget
	case "MX":
		hdr.Rrtype = dns.TypeMX
		target, badTarget := genTarget(t)
		return &dns.MX{Hdr: hdr, Preference: 10, Mx: target}, malformed || badTarget
	case "TXT":
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{"v=spf1"}}, true
	default: // UNKNOWN — an unsupported numeric type via RFC3597
		hdr.Rrtype = 65280 // private-use type, not in egress-eddie's allowlist
		return &dns.RFC3597{Hdr: hdr, Rdata: "00"}, true
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

// genTarget draws an RR target: pool names (with casing), the legal "." case,
// and the malformed "" case.
func genTarget(t *rapid.T) (string, bool) {
	switch rapid.IntRange(0, 9).Draw(t, "targetShape") {
	case 0:
		return ".", false // root domain is allowed
	case 1:
		t.Log("empty target")
		return "", true
	default:
		baseName, malformed := genBaseNameClassified(t)
		return dns.Fqdn(genCase(t, baseName)), malformed
	}
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
	switch rapid.IntRange(0, 2).Draw(t, "case") {
	case 0:
		return strings.ToUpper(s)
	case 1:
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

// genQType draws a qtype: mostly supported, sometimes TXT (unsupported answer
// type) so the deny-by-default path is exercised on the question side too.
func genQType(t *rapid.T) uint16 {
	return rapid.SampledFrom([]uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeSRV,
		dns.TypeHTTPS, dns.TypeSVCB, dns.TypeMX, dns.TypeTXT,
	}).Draw(t, "qtype")
}

func genClass(t *rapid.T) uint16 {
	if rapid.IntRange(0, 4).Draw(t, "randomQClass") == 0 {
		return rapid.SampledFrom([]uint16{
			dns.ClassCSNET, dns.ClassCHAOS, dns.ClassHESIOD,
			dns.ClassNONE, dns.ClassANY,
		}).Draw(t, "qclass")
	}
	return dns.ClassINET
}

var (
	// Small pools of client and DNS-server addresses. Varying the server
	// (and client) address — not just the port — exercises the full
	// 5-tuple connID correlation: a reply from the wrong server, or to the
	// wrong client, builds a different connID and must not match a pending
	// request.
	clientAddrs4 = []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")}
	clientAddrs6 = []netip.Addr{netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("fd00:1::2")}
	serverAddrs4 = []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("1.1.1.1")}
	serverAddrs6 = []netip.Addr{netip.MustParseAddr("2620:fe::fe"), netip.MustParseAddr("2606:4700:4700::1111")}
)

// endpoint identifies a modeled DNS connection by its client and server
// addresses and the client port.
type endpoint struct {
	client netip.Addr
	server netip.Addr
	port   uint16
}

func drawEndpoint(t *rapid.T, ipv6 bool) endpoint {
	clients, servers := clientAddrs4, serverAddrs4
	if ipv6 {
		clients, servers = clientAddrs6, serverAddrs6
	}
	return endpoint{
		client: rapid.SampledFrom(clients).Draw(t, "client"),
		server: rapid.SampledFrom(servers).Draw(t, "server"),
		port:   rapid.SampledFrom(clientPorts).Draw(t, "port"),
	}
}

func (e endpoint) connID() connectionID {
	return connectionID{
		src: netip.AddrPortFrom(e.client, e.port),
		dst: netip.AddrPortFrom(e.server, 53),
	}
}

// drawResponseEndpoint biases toward an outstanding pending connection (so
// correlated replies, and the answer-chain / side-effect paths behind them,
// stay well exercised across the larger endpoint space), but still draws a
// fresh endpoint often enough to test that a reply on the wrong
// client/server/port does not correlate.
func drawResponseEndpoint(t *rapid.T, m *model, ipv6 bool) endpoint {
	var pending []endpoint
	for connID := range m.pending {
		if connID.src.Addr().Is6() == ipv6 {
			pending = append(pending, endpoint{
				client: connID.src.Addr(),
				server: connID.dst.Addr(),
				port:   connID.src.Port(),
			})
		}
	}
	if len(pending) > 0 && rapid.Bool().Draw(t, "respFromPending") {
		slices.SortFunc(pending, func(a, b endpoint) int {
			if c := a.client.Compare(b.client); c != 0 {
				return c
			}
			if c := a.server.Compare(b.server); c != 0 {
				return c
			}
			return int(a.port) - int(b.port)
		})
		return rapid.SampledFrom(pending).Draw(t, "respEndpoint")
	}
	return drawEndpoint(t, ipv6)
}

// buf is safe to reuse as it's cleared before it's used for
// serialization and avoids extra allocations.
var buf = gopacket.NewSerializeBuffer()

// buildDNSPacket packs msg and wraps it as an IP+UDP packet in the requested
// direction. request: client->server:53. response: server:53->client.
//
// It returns the re-unpacked message so the oracle evaluates EXACTLY what the
// filter sees off the wire. Pack→Unpack is not the identity (e.g. an empty
// target round-trips to "."), so feeding the oracle the pre-pack struct would
// produce spurious mismatches. Packets miekg can't pack/unpack are skipped
// (ok == false) — crafting those is the byte-level fuzzer's job.
func buildDNSPacket(t *rapid.T, msg *dns.Msg, ipv6, response bool, ep endpoint) (packet []byte, parsed *dns.Msg, ok bool) {
	payload, err := msg.Pack()
	if err != nil {
		return nil, nil, false
	}
	var parsedMsg dns.Msg
	if err := parsedMsg.Unpack(payload); err != nil {
		return nil, nil, false
	}

	srcIP, dstIP := ep.client, ep.server
	srcPort, dstPort := ep.port, uint16(53)
	if response {
		srcIP, dstIP = ep.server, ep.client
		srcPort, dstPort = 53, ep.port
	}

	var ipLayer gopacket.SerializableLayer
	if !ipv6 {
		ipLayer = &layers.IPv4{Protocol: layers.IPProtocolUDP, SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice()}
	} else {
		ipLayer = &layers.IPv6{NextHeader: layers.IPProtocolUDP, SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice()}
	}
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ipLayer,
		&layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatalf("serializing packet: %v", err)
	}
	return buf.Bytes(), &parsedMsg, true
}

func genTrafficIP(t *rapid.T, m *model, ipv6 bool, label string) netip.Addr {
	var allowed []netip.Addr
	for ip := range m.allowedIPs {
		if ip.Is4() == !ipv6 {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) > 0 && rapid.Bool().Draw(t, label+"FromAllowed") {
		slices.SortFunc(allowed, func(a, b netip.Addr) int { return a.Compare(b) })
		return rapid.SampledFrom(allowed).Draw(t, label+"IP")
	}
	if ipv6 {
		return GenIPv6Addr().Draw(t, label+"IP")
	}
	return GenIPv4Addr().Draw(t, label+"IP")
}

func buildTrafficPacket(t *rapid.T, ipv6 bool, src, dst netip.Addr) []byte {
	var ipLayer gopacket.SerializableLayer
	if !ipv6 {
		ipLayer = &layers.IPv4{Protocol: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	} else {
		ipLayer = &layers.IPv6{NextHeader: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ipLayer,
		&layers.UDP{SrcPort: 12345, DstPort: 443},
		gopacket.Payload([]byte("traffic")),
	); err != nil {
		t.Fatalf("serializing traffic packet: %v", err)
	}
	return buf.Bytes()
}

type driver struct {
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

func assertVerdict(t *rapid.T, gotVerdict bool, verdict int, wantAccept bool) {
	if !gotVerdict {
		t.Fatalf("packet did not receive a verdict")
	}
	want := nfqueue.NfDrop
	if wantAccept {
		want = nfqueue.NfAccept
	}
	if verdict != want {
		t.Fatalf("verdict: want accept %t got %t", wantAccept, verdict == nfqueue.NfAccept)
	}
}
