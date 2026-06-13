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
	case *dns.AFSDB:
		enc.AddUint16("subtype", rr.Subtype)
		enc.AddString("hostname", rr.Hostname)
	case *dns.AMTRELAY:
		enc.AddUint8("precedence", rr.Precedence)
		enc.AddUint8("gateway-type", rr.GatewayType)
		enc.AddString("gateway-addr", rr.GatewayAddr.String())
		enc.AddString("gateway-host", rr.GatewayHost)
	case *dns.ANY:
	case *dns.NXNAME:
	case *dns.APL:
		if err := enc.AddArray("prefixes", dnsAPLPrefixes(rr.Prefixes)); err != nil {
			return err
		}
	case *dns.AVC:
		if err := enc.AddArray("data", dnsTXTs(rr.Txt)); err != nil {
			return err
		}
	case *dns.CAA:
		enc.AddUint8("flag", rr.Flag)
		enc.AddString("tag", rr.Tag)
		enc.AddString("value", rr.Value)
	case *dns.CDNSKEY:
		enc.AddUint16("flags", rr.Flags)
		enc.AddUint8("protocol", rr.Protocol)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("public-key", rr.PublicKey)
	case *dns.CDS:
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("digest-type", rr.DigestType)
		enc.AddString("digest", rr.Digest)
	case *dns.CERT:
		enc.AddUint16("cert-type", rr.Type)
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("certificate", rr.Certificate)
	case *dns.CNAME:
		enc.AddString("name", rr.Target)
	case *dns.CSYNC:
		enc.AddUint32("serial", rr.Serial)
		enc.AddUint16("flags", rr.Flags)
		if err := enc.AddArray("type-bit-map", dnsTypeBitMap(rr.TypeBitMap)); err != nil {
			return err
		}
	case *dns.DHCID:
		enc.AddString("digest", rr.Digest)
	case *dns.DLV:
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("digest-type", rr.DigestType)
		enc.AddString("digest", rr.Digest)
	case *dns.DNAME:
		enc.AddString("name", rr.Target)
	case *dns.DNSKEY:
		enc.AddUint16("flags", rr.Flags)
		enc.AddUint8("protocol", rr.Protocol)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("public-key", rr.PublicKey)
	case *dns.DS:
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("digest-type", rr.DigestType)
		enc.AddString("digest", rr.Digest)
	case *dns.EID:
		enc.AddString("endpoint", rr.Endpoint)
	case *dns.EUI48:
		enc.AddUint64("address", rr.Address)
	case *dns.EUI64:
		enc.AddUint64("address", rr.Address)
	case *dns.GID:
		enc.AddUint32("gid", rr.Gid)
	case *dns.GPOS:
		enc.AddString("longitude", rr.Longitude)
		enc.AddString("latitude", rr.Latitude)
		enc.AddString("altitude", rr.Altitude)
	case *dns.HINFO:
		enc.AddString("cpu", rr.Cpu)
		enc.AddString("os", rr.Os)
	case *dns.HIP:
		enc.AddUint8("hit-length", rr.HitLength)
		enc.AddUint8("public-key-algorithm", rr.PublicKeyAlgorithm)
		enc.AddUint16("public-key-length", rr.PublicKeyLength)
		enc.AddString("hit", rr.Hit)
		enc.AddString("public-key", rr.PublicKey)
		if err := enc.AddArray("rendezvous-servers", dnsStrings(rr.RendezvousServers)); err != nil {
			return err
		}
	case *dns.HTTPS:
		enc.AddUint16("priority", rr.Priority)
		enc.AddString("target", rr.Target)
		if err := enc.AddArray("values", dnsSVCBValues(rr.Value)); err != nil {
			return err
		}
	case *dns.IPSECKEY:
		enc.AddUint8("precedence", rr.Precedence)
		enc.AddUint8("gateway-type", rr.GatewayType)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("gateway-addr", rr.GatewayAddr.String())
		enc.AddString("gateway-host", rr.GatewayHost)
		enc.AddString("public-key", rr.PublicKey)
	case *dns.ISDN:
		enc.AddString("address", rr.Address)
		enc.AddString("sub-address", rr.SubAddress)
	case *dns.KEY:
		enc.AddUint16("flags", rr.Flags)
		enc.AddUint8("protocol", rr.Protocol)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("public-key", rr.PublicKey)
	case *dns.KX:
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("exchanger", rr.Exchanger)
	case *dns.L32:
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("locator32", rr.Locator32.String())
	case *dns.L64:
		enc.AddUint16("preference", rr.Preference)
		enc.AddUint64("locator64", rr.Locator64)
	case *dns.LOC:
		enc.AddUint8("version", rr.Version)
		enc.AddUint8("size", rr.Size)
		enc.AddUint8("horiz-pre", rr.HorizPre)
		enc.AddUint8("vert-pre", rr.VertPre)
		enc.AddUint32("latitude", rr.Latitude)
		enc.AddUint32("longitude", rr.Longitude)
		enc.AddUint32("altitude", rr.Altitude)
	case *dns.LP:
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("fqdn", rr.Fqdn)
	case *dns.MB:
		enc.AddString("name", rr.Mb)
	case *dns.MD:
		enc.AddString("name", rr.Md)
	case *dns.MF:
		enc.AddString("name", rr.Mf)
	case *dns.MG:
		enc.AddString("name", rr.Mg)
	case *dns.MINFO:
		enc.AddString("rmail", rr.Rmail)
		enc.AddString("email", rr.Email)
	case *dns.MR:
		enc.AddString("name", rr.Mr)
	case *dns.MX:
		enc.AddUint16("pref", rr.Preference)
		enc.AddString("name", rr.Mx)
	case *dns.NAPTR:
		enc.AddUint16("order", rr.Order)
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("flags", rr.Flags)
		enc.AddString("service", rr.Service)
		enc.AddString("regexp", rr.Regexp)
		enc.AddString("replacement", rr.Replacement)
	case *dns.NID:
		enc.AddUint16("preference", rr.Preference)
		enc.AddUint64("node-id", rr.NodeID)
	case *dns.NIMLOC:
		enc.AddString("locator", rr.Locator)
	case *dns.NINFO:
		if err := enc.AddArray("zs-data", dnsTXTs(rr.ZSData)); err != nil {
			return err
		}
	case *dns.NS:
		enc.AddString("name", rr.Ns)
	case *dns.NSAPPTR:
		enc.AddString("name", rr.Ptr)
	case *dns.NSEC:
		enc.AddString("next-domain", rr.NextDomain)
		if err := enc.AddArray("type-bit-map", dnsTypeBitMap(rr.TypeBitMap)); err != nil {
			return err
		}
	case *dns.NSEC3:
		enc.AddUint8("hash", rr.Hash)
		enc.AddUint8("flags", rr.Flags)
		enc.AddUint16("iterations", rr.Iterations)
		enc.AddUint8("salt-length", rr.SaltLength)
		enc.AddString("salt", rr.Salt)
		enc.AddUint8("hash-length", rr.HashLength)
		enc.AddString("next-domain", rr.NextDomain)
		if err := enc.AddArray("type-bit-map", dnsTypeBitMap(rr.TypeBitMap)); err != nil {
			return err
		}
	case *dns.NSEC3PARAM:
		enc.AddUint8("hash", rr.Hash)
		enc.AddUint8("flags", rr.Flags)
		enc.AddUint16("iterations", rr.Iterations)
		enc.AddUint8("salt-length", rr.SaltLength)
		enc.AddString("salt", rr.Salt)
	case *dns.NULL:
		enc.AddString("data", rr.Data)
	case *dns.NXT:
		enc.AddString("next-domain", rr.NextDomain)
		if err := enc.AddArray("type-bit-map", dnsTypeBitMap(rr.TypeBitMap)); err != nil {
			return err
		}
	case *dns.OPENPGPKEY:
		enc.AddString("public-key", rr.PublicKey)
	case *dns.OPT:
		if err := enc.AddArray("opts", dnsOpts(rr.Option)); err != nil {
			return err
		}
	case *dns.PTR:
		enc.AddString("name", rr.Ptr)
	case *dns.PX:
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("map822", rr.Map822)
		enc.AddString("mapx400", rr.Mapx400)
	case *dns.RKEY:
		enc.AddUint16("flags", rr.Flags)
		enc.AddUint8("protocol", rr.Protocol)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddString("public-key", rr.PublicKey)
	case *dns.RP:
		enc.AddString("mbox", rr.Mbox)
		enc.AddString("txt", rr.Txt)
	case *dns.RRSIG:
		enc.AddUint16("type-covered", rr.TypeCovered)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("labels", rr.Labels)
		enc.AddUint32("orig-ttl", rr.OrigTtl)
		enc.AddUint32("expiration", rr.Expiration)
		enc.AddUint32("inception", rr.Inception)
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddString("signer-name", rr.SignerName)
		enc.AddString("signature", rr.Signature)
	case *dns.RT:
		enc.AddUint16("preference", rr.Preference)
		enc.AddString("host", rr.Host)
	case *dns.SIG:
		enc.AddUint16("type-covered", rr.TypeCovered)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("labels", rr.Labels)
		enc.AddUint32("orig-ttl", rr.OrigTtl)
		enc.AddUint32("expiration", rr.Expiration)
		enc.AddUint32("inception", rr.Inception)
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddString("signer-name", rr.SignerName)
		enc.AddString("signature", rr.Signature)
	case *dns.SMIMEA:
		enc.AddUint8("usage", rr.Usage)
		enc.AddUint8("selector", rr.Selector)
		enc.AddUint8("matching-type", rr.MatchingType)
		enc.AddString("certificate", rr.Certificate)
	case *dns.SOA:
		enc.AddString("mname", rr.Ns)
		enc.AddString("rname", rr.Mbox)
		enc.AddUint32("serial", rr.Serial)
		enc.AddUint32("refresh", rr.Refresh)
		enc.AddUint32("retry", rr.Retry)
		enc.AddUint32("expire", rr.Expire)
		enc.AddUint32("min", rr.Minttl)
	case *dns.SPF:
		if err := enc.AddArray("data", dnsTXTs(rr.Txt)); err != nil {
			return err
		}
	case *dns.SRV:
		enc.AddUint16("priority", rr.Priority)
		enc.AddUint16("weight", rr.Weight)
		enc.AddUint16("port", rr.Port)
		enc.AddString("name", rr.Target)
	case *dns.SSHFP:
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("fp-type", rr.Type)
		enc.AddString("fingerprint", rr.FingerPrint)
	case *dns.SVCB:
		enc.AddUint16("priority", rr.Priority)
		enc.AddString("target", rr.Target)
		if err := enc.AddArray("values", dnsSVCBValues(rr.Value)); err != nil {
			return err
		}
	case *dns.TA:
		enc.AddUint16("key-tag", rr.KeyTag)
		enc.AddUint8("algorithm", rr.Algorithm)
		enc.AddUint8("digest-type", rr.DigestType)
		enc.AddString("digest", rr.Digest)
	case *dns.TALINK:
		enc.AddString("previous-name", rr.PreviousName)
		enc.AddString("next-name", rr.NextName)
	case *dns.TKEY:
		enc.AddString("algorithm", rr.Algorithm)
		enc.AddUint32("inception", rr.Inception)
		enc.AddUint32("expiration", rr.Expiration)
		enc.AddUint16("mode", rr.Mode)
		enc.AddUint16("error", rr.Error)
		enc.AddUint16("key-size", rr.KeySize)
		enc.AddString("key", rr.Key)
		enc.AddUint16("other-len", rr.OtherLen)
		enc.AddString("other-data", rr.OtherData)
	case *dns.TLSA:
		enc.AddUint8("usage", rr.Usage)
		enc.AddUint8("selector", rr.Selector)
		enc.AddUint8("matching-type", rr.MatchingType)
		enc.AddString("certificate", rr.Certificate)
	case *dns.TSIG:
		enc.AddString("algorithm", rr.Algorithm)
		enc.AddUint64("time-signed", rr.TimeSigned)
		enc.AddUint16("fudge", rr.Fudge)
		enc.AddUint16("mac-size", rr.MACSize)
		enc.AddString("mac", rr.MAC)
		enc.AddUint16("orig-id", rr.OrigId)
		enc.AddUint16("error", rr.Error)
		enc.AddUint16("other-len", rr.OtherLen)
		enc.AddString("other-data", rr.OtherData)
	case *dns.TXT:
		if err := enc.AddArray("data", dnsTXTs(rr.Txt)); err != nil {
			return err
		}
	case *dns.UID:
		enc.AddUint32("uid", rr.Uid)
	case *dns.UINFO:
		enc.AddString("uinfo", rr.Uinfo)
	case *dns.URI:
		enc.AddUint16("priority", rr.Priority)
		enc.AddUint16("weight", rr.Weight)
		enc.AddString("name", rr.Target)
	case *dns.X25:
		enc.AddString("psdn-address", rr.PSDNAddress)
	case *dns.ZONEMD:
		enc.AddUint32("serial", rr.Serial)
		enc.AddUint8("scheme", rr.Scheme)
		enc.AddUint8("hash", rr.Hash)
		enc.AddString("digest", rr.Digest)
	case *dns.RESINFO:
		if err := enc.AddArray("data", dnsTXTs(rr.Txt)); err != nil {
			return err
		}
	case *dns.RFC3597:
		enc.AddString("rdata", rr.Rdata)
	case *dns.PrivateRR:
		enc.AddString("data", rr.Data.String())
	}

	enc.AddString("type", strings.ToLower(dns.Type(r.Header().Rrtype).String()))

	return nil
}

type dnsAPLPrefixes []dns.APLPrefix

func (p dnsAPLPrefixes) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range p {
		if err := enc.AppendObject(dnsAPLPrefix(p[i])); err != nil {
			return err
		}
	}

	return nil
}

type dnsAPLPrefix dns.APLPrefix

func (p dnsAPLPrefix) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("negation", p.Negation)
	enc.AddString("network", p.Network.String())

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

type dnsOpt struct {
	dns.EDNS0
}

func (o dnsOpt) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("code", o.Option())
	enc.AddString("data", o.String())

	return nil
}

type dnsStrings []string

func (s dnsStrings) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range s {
		enc.AppendString(s[i])
	}

	return nil
}

type dnsSVCBValues []dns.SVCBKeyValue

func (v dnsSVCBValues) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range v {
		if err := enc.AppendObject(dnsSVCBValue{v[i]}); err != nil {
			return err
		}
	}

	return nil
}

type dnsSVCBValue struct {
	dns.SVCBKeyValue
}

func (v dnsSVCBValue) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint16("key", uint16(v.Key()))
	enc.AddString("value", v.String())

	return nil
}

type dnsTXTs []string

func (t dnsTXTs) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range t {
		enc.AppendString(t[i])
	}

	return nil
}

// dnsTypeBitMap logs the record types in an NSEC-style type bit map by
// their string representations.
type dnsTypeBitMap []uint16

func (t dnsTypeBitMap) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for i := range t {
		enc.AppendString(strings.ToLower(dns.Type(t[i]).String()))
	}

	return nil
}
