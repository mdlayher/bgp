package bgp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// An MPReachNLRI is the MP_REACH_NLRI attribute, advertising routes and a
// next hop for an arbitrary address family, as described in RFC 4760.
type MPReachNLRI struct {
	// Family is the address family of the advertised routes.
	Family Family

	// NextHop is the address of the router to be used as the next hop to
	// NLRI. Its address family need not match Family: per RFC 8950, IPv4
	// routes may be advertised with an IPv6 next hop when negotiated using
	// ExtendedNextHopCapability. The zero netip.Addr is an absent next
	// hop, a real wire shape: a flowspec UPDATE (RFC 8955) carries none.
	// The route distinguishers a VPN family wraps around its next hop on
	// the wire are managed by this package and never appear here.
	NextHop netip.Addr

	// LinkLocal optionally carries an IPv6 link-local next hop alongside
	// NextHop, as described in RFC 2545. It is the zero netip.Addr when
	// not present.
	LinkLocal netip.Addr

	// NLRI is the advertised reachability information, in the shape Family
	// determines: Prefixes for a prefix shaped family, EVPNRoutes for L2VPN
	// EVPN, RawNLRI for a family this package does not model.
	NLRI NLRI
}

func (MPReachNLRI) attrType() AttrType   { return AttrMPReachNLRI }
func (MPReachNLRI) attrFlags() AttrFlags { return AttrFlagOptional }

func (m MPReachNLRI) appendData(b []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, uint16(m.Family.AFI))
	b = append(b, byte(m.Family.SAFI))

	// A VPN family precedes each next hop address with a route
	// distinguisher which must be zero (see Family.rdNextHop); an rd of 0
	// prepends nothing.
	var rd int
	if m.Family.rdNextHop() {
		rd = 8
	}

	var zero [8]byte

	nh, ll := m.NextHop.Unmap(), m.LinkLocal.Unmap()
	switch {
	case !nh.IsValid() && !ll.IsValid():
		// An absent next hop: length zero, whatever the family.
		b = append(b, 0)
	case nh.Is4() && !ll.IsValid():
		a := nh.As4()
		b = append(b, byte(rd+4))
		b = append(b, zero[:rd]...)
		b = append(b, a[:]...)
	case nh.Is6() && !ll.IsValid():
		a := nh.As16()
		b = append(b, byte(rd+16))
		b = append(b, zero[:rd]...)
		b = append(b, a[:]...)
	case nh.Is6() && ll.Is6():
		a, la := nh.As16(), ll.As16()
		b = append(b, byte(2*rd+32))
		b = append(b, zero[:rd]...)
		b = append(b, a[:]...)
		b = append(b, zero[:rd]...)
		b = append(b, la[:]...)
	default:
		return nil, fmt.Errorf("bgp: invalid MP_REACH_NLRI next hops: %s, %s", m.NextHop, m.LinkLocal)
	}

	// One reserved byte precedes the NLRI.
	b = append(b, 0)
	return appendNLRI(b, m.NLRI, m.Family)
}

// parseMPReachNLRI parses the data of an MP_REACH_NLRI attribute. addPath
// reports that the attribute arrived on a session which negotiated the
// add-path extension for its family in the receive direction; see
// RawAttribute.addPath.
func parseMPReachNLRI(b []byte, addPath bool) (MPReachNLRI, error) {
	if len(b) < 5 {
		return MPReachNLRI{}, updateError(SubcodeOptionalAttributeError, nil,
			"invalid MP_REACH_NLRI attribute length %d", len(b))
	}

	m := MPReachNLRI{Family: Family{
		AFI:  AFI(binary.BigEndian.Uint16(b[0:2])),
		SAFI: SAFI(b[2]),
	}}

	n := int(b[3])
	if len(b[4:]) < n+1 {
		return MPReachNLRI{}, updateError(SubcodeOptionalAttributeError, nil,
			"MP_REACH_NLRI next hop truncated")
	}

	// The valid lengths depend on the family: a VPN family's addresses are
	// each preceded by an 8 byte route distinguisher, mandated zero and
	// stripped here (see Family.rdNextHop), so parse accepts exactly the
	// lengths marshal produces and the fixed point holds. A length of zero
	// is an absent next hop for any family (RFC 8955 sends one).
	nh := b[4 : 4+n]
	switch rd := m.Family.rdNextHop(); {
	case n == 0:
	case !rd && n == 4:
		m.NextHop = netip.AddrFrom4([4]byte(nh))
	case !rd && n == 16:
		m.NextHop = netip.AddrFrom16([16]byte(nh))
	case !rd && n == 32:
		m.NextHop = netip.AddrFrom16([16]byte(nh[0:16]))
		m.LinkLocal = netip.AddrFrom16([16]byte(nh[16:32]))
	case rd && n == 12:
		if err := zeroRD(nh[0:8]); err != nil {
			return MPReachNLRI{}, err
		}

		m.NextHop = netip.AddrFrom4([4]byte(nh[8:12]))
	case rd && n == 24:
		if err := zeroRD(nh[0:8]); err != nil {
			return MPReachNLRI{}, err
		}

		m.NextHop = netip.AddrFrom16([16]byte(nh[8:24]))
	case rd && n == 48:
		if err := zeroRD(nh[0:8]); err != nil {
			return MPReachNLRI{}, err
		}

		if err := zeroRD(nh[24:32]); err != nil {
			return MPReachNLRI{}, err
		}

		m.NextHop = netip.AddrFrom16([16]byte(nh[8:24]))
		m.LinkLocal = netip.AddrFrom16([16]byte(nh[32:48]))
	default:
		return MPReachNLRI{}, updateError(SubcodeOptionalAttributeError, nil,
			"unsupported %s next hop length %d", m.Family, n)
	}

	// One reserved byte, then NLRI.
	nlri, err := parseNLRI(b[4+n+1:], m.Family, addPath)
	if err != nil {
		return MPReachNLRI{}, err
	}

	m.NLRI = nlri
	return m, nil
}

// zeroRD checks that the 8 byte route distinguisher preceding a VPN next
// hop address is zero, the only value RFC 4364, section 4.3.2 and RFC 4659,
// section 3.2.1.1 permit. Anything else is information this package has no
// field for precisely because the RFCs promise there is none.
func zeroRD(b []byte) error {
	if [8]byte(b) != [8]byte{} {
		return updateError(SubcodeOptionalAttributeError, nil,
			"MP_REACH_NLRI next hop route distinguisher must be zero")
	}

	return nil
}

// An MPUnreachNLRI is the MP_UNREACH_NLRI attribute, withdrawing routes for
// an arbitrary address family, as described in RFC 4760.
type MPUnreachNLRI struct {
	// Family is the address family of the withdrawn routes.
	Family Family

	// NLRI is the withdrawn reachability information, in the shape Family
	// determines; see [MPReachNLRI.NLRI]. A nil NLRI withdraws nothing, which
	// is the End-of-RIB marker of RFC 4724; see [NewEndOfRIB].
	NLRI NLRI
}

func (MPUnreachNLRI) attrType() AttrType   { return AttrMPUnreachNLRI }
func (MPUnreachNLRI) attrFlags() AttrFlags { return AttrFlagOptional }

func (m MPUnreachNLRI) appendData(b []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, uint16(m.Family.AFI))
	b = append(b, byte(m.Family.SAFI))
	return appendNLRI(b, m.NLRI, m.Family)
}

// parseMPUnreachNLRI parses the data of an MP_UNREACH_NLRI attribute;
// addPath is as in parseMPReachNLRI.
func parseMPUnreachNLRI(b []byte, addPath bool) (MPUnreachNLRI, error) {
	if len(b) < 3 {
		return MPUnreachNLRI{}, updateError(SubcodeOptionalAttributeError, nil,
			"invalid MP_UNREACH_NLRI attribute length %d", len(b))
	}

	m := MPUnreachNLRI{Family: Family{
		AFI:  AFI(binary.BigEndian.Uint16(b[0:2])),
		SAFI: SAFI(b[2]),
	}}

	nlri, err := parseNLRI(b[3:], m.Family, addPath)
	if err != nil {
		return MPUnreachNLRI{}, err
	}

	m.NLRI = nlri
	return m, nil
}
