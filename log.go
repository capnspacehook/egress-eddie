package main

import (
	"strings"

	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// dnsFields returns a list of fields for a zap logger that describes
// a DNS packet.
func dnsFields(dns *layers.DNS) []zap.Field {
	fields := []zap.Field{
		zap.Uint8("opcode", uint8(dns.OpCode)),
	}

	var flags []string
	if dns.AA {
		flags = append(flags, "aa")
	}
	if dns.TC {
		flags = append(flags, "tc")
	}
	if dns.RD {
		flags = append(flags, "rd")
	}
	if dns.RA {
		flags = append(flags, "ra")
	}
	fields = append(fields, zap.Strings("flags", flags))

	if dns.QR {
		fields = append(fields, zap.Uint8("resp-code", uint8(dns.ResponseCode)))
	}

	if dns.QDCount > 0 {
		fields = append(fields, zap.Array("questions", dnsQuestions(dns.Questions)))
	}

	stringify := func(records []layers.DNSResourceRecord, key string) {
		if len(records) == 0 {
			return
		}
		// skip additionals containing empty OPTs
		if len(records) == 1 && records[0].Type == layers.DNSTypeOPT && len(records[0].OPT) == 0 {
			return
		}

		fields = append(fields, zap.Array(key, dnsRecords(records)))
	}

	stringify(dns.Answers, "answers")
	stringify(dns.Authorities, "authorities")
	stringify(dns.Additionals, "additionals")

	return fields
}

type dnsQuestions []layers.DNSQuestion

func (q dnsQuestions) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range q {
		enc.AppendObject(dnsQuestion(q[i]))
	}

	return nil
}

type dnsQuestion layers.DNSQuestion

func (q dnsQuestion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddByteString("name", q.Name)
	enc.AddString("type", q.Type.String())
	return nil
}

type dnsRecords []layers.DNSResourceRecord

func (r dnsRecords) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range r {
		enc.AppendObject(dnsRecord(r[i]))
	}

	return nil
}

type dnsRecord layers.DNSResourceRecord

func (r dnsRecord) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	switch r.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		enc.AddString("ip", r.IP.String())
	case layers.DNSTypeCNAME:
		enc.AddByteString("name", r.CNAME)
	case layers.DNSTypeNS:
		enc.AddByteString("name", r.NS)
	case layers.DNSTypeMX:
		enc.AddUint16("pref", r.MX.Preference)
		enc.AddByteString("name", r.MX.Name)
	case layers.DNSTypeOPT:
		enc.AddArray("opts", dnsOpts(r.OPT))
	case layers.DNSTypePTR:
		enc.AddByteString("name", r.PTR)
	case layers.DNSTypeSOA:
		enc.AddByteString("mname", r.SOA.MName)
		enc.AddByteString("rname", r.SOA.RName)
		enc.AddUint32("serial", r.SOA.Serial)
		enc.AddUint32("refresh", r.SOA.Refresh)
		enc.AddUint32("retry", r.SOA.Retry)
		enc.AddUint32("expire", r.SOA.Expire)
		enc.AddUint32("min", r.SOA.Minimum)
	case layers.DNSTypeSRV:
		enc.AddUint16("priority", r.SRV.Priority)
		enc.AddUint16("weight", r.SRV.Weight)
		enc.AddUint16("port", r.SRV.Port)
		enc.AddByteString("name", r.SRV.Name)
	case layers.DNSTypeTXT:
		enc.AddArray("data", dnsTXTs(r.TXTs))
	case layers.DNSTypeURI:
		enc.AddUint16("priority", r.URI.Priority)
		enc.AddUint16("weight", r.URI.Weight)
		enc.AddByteString("name", r.URI.Target)
	}

	enc.AddString("type", strings.ToLower(r.Type.String()))

	return nil
}

type dnsOpts []layers.DNSOPT

func (o dnsOpts) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range o {
		enc.AppendObject(dnsOpt(o[i]))
	}

	return nil
}

type dnsOpt layers.DNSOPT

func (o dnsOpt) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("code", o.Code.String())
	enc.AddBinary("data", o.Data)

	return nil
}

type dnsTXTs [][]byte

func (t dnsTXTs) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range t {
		enc.AppendByteString(t[i])
	}

	return nil
}
