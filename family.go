package bgp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// An AFI is an IANA Address Family Identifier.
type AFI uint16

// AFI values named by this package. Any AFI may be negotiated and carried;
// these are the ones whose reachability information this package knows the
// shape of.
const (
	AFIIPv4  AFI = 1
	AFIIPv6  AFI = 2
	AFIL2VPN AFI = 25
)

// String returns the name of an AFI, or its number when unnamed.
func (a AFI) String() string {
	switch a {
	case AFIIPv4:
		return "IPv4"
	case AFIIPv6:
		return "IPv6"
	case AFIL2VPN:
		return "L2VPN"
	default:
		return fmt.Sprintf("AFI %d", uint16(a))
	}
}

// A SAFI is a BGP Subsequent Address Family Identifier, as described in RFC
// 4760.
type SAFI uint8

// SAFI values named by this package, as assigned by IANA. As with AFI
// values, naming is not a precondition for carrying a family.
const (
	SAFIUnicast   SAFI = 1
	SAFIMulticast SAFI = 2
	SAFIVPLS      SAFI = 65
	SAFIEVPN      SAFI = 70
	SAFIMPLSVPN   SAFI = 128
)

// String returns the name of a SAFI, or its number when unnamed.
func (s SAFI) String() string {
	switch s {
	case SAFIUnicast:
		return "unicast"
	case SAFIMulticast:
		return "multicast"
	case SAFIVPLS:
		return "VPLS"
	case SAFIEVPN:
		return "EVPN"
	case SAFIMPLSVPN:
		return "MPLS VPN"
	default:
		return fmt.Sprintf("SAFI %d", uint8(s))
	}
}

// A Family identifies a BGP address family by the combination of an AFI and
// SAFI, as described in RFC 4760.
type Family struct {
	AFI  AFI
	SAFI SAFI
}

// familyEVPN is the L2VPN EVPN family of RFC 7432, whose NLRI is EVPNRoutes.
var familyEVPN = Family{AFI: AFIL2VPN, SAFI: SAFIEVPN}

// String returns the name of a Family.
func (f Family) String() string {
	// Each half is named independently, so an unnamed AFI or SAFI degrades
	// to its number rather than hiding the other.
	return f.AFI.String() + " " + f.SAFI.String()
}

// prefixShaped reports whether a Family's reachability information is a bare
// list of prefixes, and so is carried as Prefixes. The four families here are
// the ones RFC 4760 was written for; every other family either has a shape of
// its own or is unmodeled, and this is the enumeration both directions of the
// NLRI codec agree on.
func (f Family) prefixShaped() bool {
	switch f.AFI {
	case AFIIPv4, AFIIPv6:
		switch f.SAFI {
		case SAFIUnicast, SAFIMulticast:
			return true
		}
	}

	return false
}

// rdNextHop reports whether a Family carries its MP_REACH_NLRI next hop
// with each address preceded by an 8 byte route distinguisher: the VPN
// families of RFC 4364, section 4.3.2 and RFC 4659, section 3.2.1.1, whose
// RD those documents require to be zero (RFC 8950, section 3 keeps it zero
// for its 24 byte form too). A mandatory zero carries no information, so the
// RD is a wire encoding detail this package manages, like the extended
// length attribute flag: stripped when parsing, restored when marshaling,
// symmetrically so the fixed point holds. SAFI 129 (multicast BGP/MPLS VPN,
// RFC 6514) shares the encoding but is unmodeled; see rfc-status.
func (f Family) rdNextHop() bool {
	switch f.AFI {
	case AFIIPv4, AFIIPv6:
		return f.SAFI == SAFIMPLSVPN
	}

	return false
}

// appendPrefixes appends the wire encoding of each prefix in ps to b: a one
// byte length in bits, followed by the minimum number of bytes required to
// hold those bits. Each prefix must belong to the address family identified
// by afi.
func appendPrefixes(b []byte, ps []netip.Prefix, afi AFI) ([]byte, error) {
	for _, p := range ps {
		var err error
		if b, err = appendPrefix(b, p, afi); err != nil {
			return nil, err
		}
	}

	return b, nil
}

// appendPrefix appends the wire encoding of one prefix to b; see
// appendPrefixes.
func appendPrefix(b []byte, p netip.Prefix, afi AFI) ([]byte, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("bgp: invalid prefix: %s", p)
	}

	var ok bool
	switch afi {
	case AFIIPv4:
		ok = p.Addr().Is4()
	case AFIIPv6:
		ok = p.Addr().Is6() && !p.Addr().Is4In6()
	default:
		return nil, fmt.Errorf("bgp: unsupported AFI %d", uint16(afi))
	}

	if !ok {
		return nil, fmt.Errorf("bgp: prefix %s does not belong to AFI %d", p, uint16(afi))
	}

	p = p.Masked()
	n := (p.Bits() + 7) / 8
	b = append(b, byte(p.Bits()))

	if afi == AFIIPv4 {
		a := p.Addr().As4()
		b = append(b, a[:n]...)
	} else {
		a := p.Addr().As16()
		b = append(b, a[:n]...)
	}

	return b, nil
}

// prefixBits returns the maximum prefix length in bits for a prefix shaped
// AFI, and false for any other AFI.
func prefixBits(afi AFI) (int, bool) {
	switch afi {
	case AFIIPv4:
		return 32, true
	case AFIIPv6:
		return 128, true
	default:
		return 0, false
	}
}

// parsePrefixes parses wire-encoded prefixes from b for the address family
// identified by afi, until b is exhausted. A malformed prefix produces an
// UPDATE Message Error with the given subcode: Invalid Network Field at the
// top level of an UPDATE, or Optional Attribute Error within a multiprotocol
// attribute.
func parsePrefixes(b []byte, afi AFI, subcode uint8) ([]netip.Prefix, error) {
	max, ok := prefixBits(afi)
	if !ok {
		return nil, updateError(subcode, nil, "unsupported AFI %d", uint16(afi))
	}

	// One counting pass sizes the slice exactly, so a prefix list costs a
	// single allocation instead of append's doubling. Truncation is left
	// to the parse loop below, which reports it precisely.
	var count int
	for r := b; len(r) > 0; count++ {
		n := 1 + (int(r[0])+7)/8
		if n > len(r) {
			break
		}

		r = r[n:]
	}

	var ps []netip.Prefix
	if count > 0 {
		ps = make([]netip.Prefix, 0, count)
	}

	for len(b) > 0 {
		p, rest, err := parsePrefix(b, max, afi, subcode)
		if err != nil {
			return nil, err
		}

		ps = append(ps, p)
		b = rest
	}

	return ps, nil
}

// parsePrefix parses one wire-encoded prefix from the front of b, returning
// the prefix and the remaining bytes. b must be non-empty, and max is the
// AFI's maximum prefix length from prefixBits.
func parsePrefix(b []byte, max int, afi AFI, subcode uint8) (netip.Prefix, []byte, error) {
	bits := int(b[0])
	b = b[1:]
	if bits > max {
		return netip.Prefix{}, nil, updateError(subcode, nil,
			"prefix length %d exceeds maximum of %d bits", bits, max)
	}

	n := (bits + 7) / 8
	if len(b) < n {
		return netip.Prefix{}, nil, updateError(subcode, nil, "prefix truncated")
	}

	var addr netip.Addr
	if afi == AFIIPv4 {
		var a [4]byte
		copy(a[:], b[:n])
		addr = netip.AddrFrom4(a)
	} else {
		var a [16]byte
		copy(a[:], b[:n])
		addr = netip.AddrFrom16(a)
	}

	// Mask away any trailing bits beyond the prefix length, which RFC
	// 4271, section 4.3 says must be ignored.
	return netip.PrefixFrom(addr, bits).Masked(), b[n:], nil
}

// appendPathPrefixes appends the wire encoding of each path prefix in ps to
// b: a four byte path identifier (RFC 7911), then the prefix as
// appendPrefixes encodes it. Each prefix must belong to the address family
// identified by afi.
func appendPathPrefixes(b []byte, ps PathPrefixes, afi AFI) ([]byte, error) {
	for _, p := range ps {
		b = binary.BigEndian.AppendUint32(b, p.ID)

		var err error
		if b, err = appendPrefix(b, p.Prefix, afi); err != nil {
			return nil, err
		}
	}

	return b, nil
}

// parsePathPrefixes parses wire-encoded path prefixes (RFC 7911) from b for
// the address family identified by afi, until b is exhausted, mirroring
// parsePrefixes with each prefix preceded by its four byte path identifier.
func parsePathPrefixes(b []byte, afi AFI, subcode uint8) (PathPrefixes, error) {
	max, ok := prefixBits(afi)
	if !ok {
		return nil, updateError(subcode, nil, "unsupported AFI %d", uint16(afi))
	}

	// One counting pass sizes the slice exactly, as in parsePrefixes.
	var count int
	for r := b; len(r) >= 5; count++ {
		n := 5 + (int(r[4])+7)/8
		if n > len(r) {
			break
		}

		r = r[n:]
	}

	var ps PathPrefixes
	if count > 0 {
		ps = make(PathPrefixes, 0, count)
	}

	for len(b) > 0 {
		if len(b) < 5 {
			return nil, updateError(subcode, nil, "path identifier truncated")
		}

		id := binary.BigEndian.Uint32(b[0:4])
		p, rest, err := parsePrefix(b[4:], max, afi, subcode)
		if err != nil {
			return nil, err
		}

		ps = append(ps, PathPrefix{ID: id, Prefix: p})
		b = rest
	}

	return ps, nil
}
