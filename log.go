package egresseddie

import (
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// dnsFields returns a list of fields for a zap logger that describes
// a DNS packet.
func dnsFields(dnsMsg *dns.Msg, fullDNSLogging bool) []zap.Field {
	var (
		fields []zap.Field
		flags  []string
	)

	if fullDNSLogging {
		fields = append(fields,
			zap.Uint16("id", dnsMsg.Id),
			zap.Bool("qr", dnsMsg.Response),
			zap.Uint8("opcode", uint8(dnsMsg.Opcode)),
		)
		if dnsMsg.Authoritative {
			flags = append(flags, "aa")
		}
		if dnsMsg.Truncated {
			flags = append(flags, "tc")
		}
		if dnsMsg.RecursionDesired {
			flags = append(flags, "rd")
		}
		if dnsMsg.RecursionAvailable {
			flags = append(flags, "ra")
		}
		fields = append(fields, zap.Strings("flags", flags))

		if dnsMsg.Response {
			fields = append(fields, zap.Uint8("resp-code", uint8(dnsMsg.Rcode)))
		}
	}

	if len(dnsMsg.Question) > 0 {
		fields = append(fields, zap.Array("questions", dnsQuestions(dnsMsg.Question)))
	}

	stringify := func(records []dns.RR, key string) {
		if len(records) == 0 {
			return
		}
		// skip additionals containing empty OPTs
		if len(records) == 1 {
			if opt, ok := records[0].(*dns.OPT); ok && len(opt.Option) == 0 {
				return
			}
		}

		fields = append(fields, zap.Array(key, dnsRecords(records)))
	}

	stringify(dnsMsg.Answer, "answers")
	if fullDNSLogging {
		stringify(dnsMsg.Ns, "authorities")
		stringify(dnsMsg.Extra, "additionals")
	}

	return fields
}

type dnsQuestions []dns.Question

func (q dnsQuestions) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range q {
		if err := enc.AppendObject(dnsQuestion(q[i])); err != nil {
			return err
		}
	}

	return nil
}

type dnsQuestion dns.Question

func (q dnsQuestion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", q.Name)
	enc.AddString("class", strings.ToLower(dns.Class(q.Qclass).String()))
	enc.AddString("type", strings.ToLower(dns.Type(q.Qtype).String()))
	return nil
}

type dnsRecords []dns.RR

func (r dnsRecords) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range r {
		if err := enc.AppendObject(dnsRecord{r[i]}); err != nil {
			return err
		}
	}

	return nil
}

// dnsRecord wraps the dns.RR interface so a log-marshaling method can be
// defined on it.
type dnsRecord struct {
	dns.RR
}

func (r dnsRecord) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	switch rr := r.RR.(type) {
	case *dns.A:
		enc.AddString("ip", rr.A.String())
	case *dns.AAAA:
		enc.AddString("ip", rr.AAAA.String())
	case *dns.CNAME:
		enc.AddString("name", rr.Target)
	case *dns.NS:
		enc.AddString("name", rr.Ns)
	case *dns.MX:
		enc.AddUint16("pref", rr.Preference)
		enc.AddString("name", rr.Mx)
	case *dns.OPT:
		err := enc.AddArray("opts", dnsOpts(rr.Option))
		if err != nil {
			return err
		}
	case *dns.PTR:
		enc.AddString("name", rr.Ptr)
	case *dns.SOA:
		enc.AddString("mname", rr.Ns)
		enc.AddString("rname", rr.Mbox)
		enc.AddUint32("serial", rr.Serial)
		enc.AddUint32("refresh", rr.Refresh)
		enc.AddUint32("retry", rr.Retry)
		enc.AddUint32("expire", rr.Expire)
		enc.AddUint32("min", rr.Minttl)
	case *dns.SRV:
		enc.AddUint16("priority", rr.Priority)
		enc.AddUint16("weight", rr.Weight)
		enc.AddUint16("port", rr.Port)
		enc.AddString("name", rr.Target)
	case *dns.TXT:
		err := enc.AddArray("data", dnsTXTs(rr.Txt))
		if err != nil {
			return err
		}
	case *dns.URI:
		enc.AddUint16("priority", rr.Priority)
		enc.AddUint16("weight", rr.Weight)
		enc.AddString("name", rr.Target)
	}

	enc.AddString("type", strings.ToLower(dns.Type(r.Header().Rrtype).String()))

	return nil
}

type dnsOpts []dns.EDNS0

func (o dnsOpts) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range o {
		if err := enc.AppendObject(dnsOpt{o[i]}); err != nil {
			return err
		}
	}

	return nil
}

// dnsOpt wraps the dns.EDNS0 interface so a log-marshaling method can be
// defined on it. EDNS0 exposes no uniform data accessor, so we log the
// option code and its string representation.
type dnsOpt struct {
	dns.EDNS0
}

func (o dnsOpt) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("code", o.Option())
	enc.AddString("data", o.String())

	return nil
}

type dnsTXTs []string

func (t dnsTXTs) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range t {
		enc.AppendString(t[i])
	}

	return nil
}
