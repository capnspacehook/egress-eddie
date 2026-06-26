package egresseddie

import (
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket/layers"
	"pgregory.net/rapid"
)

var (
	domainMembers   []rune
	genDomainMember *rapid.Generator[rune]
)

func init() {
	for r := 'a'; r <= 'z'; r++ {
		domainMembers = append(domainMembers, r)
	}
	for r := 'A'; r <= 'Z'; r++ {
		domainMembers = append(domainMembers, r)
	}
	for r := '0'; r <= '9'; r++ {
		domainMembers = append(domainMembers, r)
	}

	genDomainMember = rapid.SampledFrom(domainMembers)
}

type PrefixedDomainName struct {
	Name          string
	PrefixLabels  int
	PostPrefixIdx int
}

func GenPrefixedDomainName() *rapid.Generator[PrefixedDomainName] {
	return rapid.Custom(func(t *rapid.T) PrefixedDomainName {
		var sb strings.Builder

		maxNameLen := rapid.IntRange(16, 253).Draw(t, "maxNameLen")
		numLabels := rapid.IntRange(1, 4).Draw(t, "numLabels")
		numPrefixLabels := rapid.IntRange(0, 3).Draw(t, "numPrefixLabels")
		maxLen := maxNameLen / (2 * (numLabels + numPrefixLabels))

		var idx int
		for range numPrefixLabels {
			sb.WriteByte('_')
			labelLen := rapid.IntRange(0, maxLen-1).Draw(t, "labelLen")
			for range labelLen {
				sb.WriteRune(genDomainMember.Draw(t, "domainMember"))
			}
			sb.WriteByte('.')

			idx += labelLen + 2
		}

		for range numLabels {
			labelLen := rapid.IntRange(1, maxLen).Draw(t, "labelLen")
			for range labelLen {
				sb.WriteRune(genDomainMember.Draw(t, "domainMember"))
			}
			sb.WriteByte('.')
		}

		return PrefixedDomainName{
			Name:          sb.String(),
			PrefixLabels:  numPrefixLabels,
			PostPrefixIdx: idx,
		}
	})
}

func GenDomainName() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		var sb strings.Builder

		maxNameLen := rapid.IntRange(32, 253).Draw(t, "maxNameLen")
		numLabels := rapid.IntRange(1, 16).Draw(t, "numLabels")
		maxLen := min(maxNameLen/(2*numLabels), 62)

		for i := range numLabels {
			labelLen := rapid.IntRange(1, maxLen).Draw(t, "labelLen")
			for range labelLen {
				sb.WriteRune(genDomainMember.Draw(t, "domainMember"))
			}

			if i != numLabels-1 {
				sb.WriteByte('.')
			}
		}

		return sb.String()
	})
}

func GenLabel() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		var sb strings.Builder

		labelLen := rapid.IntRange(1, 62).Draw(t, "labelLen")
		for range labelLen {
			sb.WriteRune(genDomainMember.Draw(t, "domainMember"))
		}

		return sb.String()
	})
}

func GenIPv4Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom(func(t *rapid.T) netip.Addr {
		var buf [4]byte
		for i := range buf {
			buf[i] = rapid.Byte().Draw(t, "")
		}
		return netip.AddrFrom4(buf)
	})
}

func GenIPv6Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom(func(t *rapid.T) netip.Addr {
		var buf [16]byte
		for i := range buf {
			buf[i] = rapid.Byte().Draw(t, "")
		}
		return netip.AddrFrom16(buf)
	})
}

func GenIPv4Layer() *rapid.Generator[layers.IPv4] {
	return rapid.Custom(func(t *rapid.T) layers.IPv4 {
		ipv4 := layers.IPv4{
			Version:    rapid.Uint8().Draw(t, ""),
			IHL:        rapid.Uint8().Draw(t, ""),
			TOS:        rapid.Uint8().Draw(t, ""),
			Length:     rapid.Uint16().Draw(t, ""),
			Id:         rapid.Uint16().Draw(t, ""),
			Flags:      layers.IPv4Flag(rapid.Uint8().Draw(t, "")),
			FragOffset: rapid.Uint16().Draw(t, ""),
			TTL:        rapid.Uint8().Draw(t, ""),
			Protocol:   layers.IPProtocol(rapid.Uint8().Draw(t, "")),
			Checksum:   rapid.Uint16().Draw(t, ""),
			SrcIP:      GenIPv4Addr().Draw(t, "").AsSlice(),
			DstIP:      GenIPv4Addr().Draw(t, "").AsSlice(),
			Options:    rapid.SliceOfN(rapid.Make[layers.IPv4Option](), 0, int(rapid.Uint8().Draw(t, ""))).Draw(t, ""),
			Padding:    rapid.SliceOfN(rapid.Byte(), 0, int(rapid.Uint16().Draw(t, ""))).Draw(t, ""),
		}

		return ipv4
	})
}

func GenIPv6Layer() *rapid.Generator[layers.IPv6] {
	return rapid.Custom(func(t *rapid.T) layers.IPv6 {
		ipv6 := layers.IPv6{
			Version:      rapid.Uint8().Draw(t, ""),
			TrafficClass: rapid.Uint8().Draw(t, ""),
			FlowLabel:    rapid.Uint32().Draw(t, ""),
			Length:       rapid.Uint16().Draw(t, ""),
			NextHeader:   layers.IPProtocol(rapid.Uint8().Draw(t, "")),
			HopLimit:     rapid.Uint8().Draw(t, ""),
			SrcIP:        GenIPv6Addr().Draw(t, "").AsSlice(),
			DstIP:        GenIPv6Addr().Draw(t, "").AsSlice(),
		}
		if rapid.Bool().Draw(t, "") {
			hopByHop := rapid.Make[layers.IPv6HopByHop]().Draw(t, "")
			ipv6.HopByHop = &hopByHop
		}

		return ipv6
	})
}
