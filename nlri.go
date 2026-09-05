package bgp

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
)

// An NLRI is the Network Layer Reachability Information of one address family:
// the payload of an MPReachNLRI or MPUnreachNLRI attribute, whose shape the
// family determines. NLRI is implemented by Prefixes, EVPNRoutes, and RawNLRI.
//
// A nil NLRI carries no reachability information: it is what an End-of-RIB
// marker's MPUnreachNLRI holds, and what parse produces for any family whose
// NLRI is empty.
//
// Reachability information is not universally prefix shaped: the families of
// RFC 4271 and RFC 4760 carry prefixes, EVPN carries typed records (RFC 7432),
// and others carry route distinguishers, labels, or flow specifications. A
// family this package does not model decodes to RawNLRI rather than to an
// error, so it survives parse and re-marshal byte for byte, as an unknown
// attribute type does.
type NLRI interface {
	// appendNLRI appends the wire encoded NLRI for family f, which it may
	// require to be a family the NLRI shape belongs to. This also constrains
	// the set of types which may implement NLRI.
	appendNLRI(b []byte, f Family) ([]byte, error)
}

var (
	_ NLRI = Prefixes(nil)
	_ NLRI = PathPrefixes(nil)
	_ NLRI = EVPNRoutes(nil)
	_ NLRI = RawNLRI(nil)
)

// Prefixes is the NLRI of a prefix shaped address family: IPv4 or IPv6,
// unicast or multicast. It is the shape of all reachability information in
// RFC 4271 and of the address families RFC 4760 was written for.
//
// A Prefixes may only belong to one of those four families. Reachability
// information which happens to contain a prefix but is not a bare list of
// them, such as an RFC 4364 labeled VPN route or an RFC 9136 EVPN IP prefix
// route, is not a Prefixes.
type Prefixes []netip.Prefix

func (ps Prefixes) appendNLRI(b []byte, f Family) ([]byte, error) {
	if !f.prefixShaped() {
		return nil, fmt.Errorf("bgp: %s NLRI is not a list of prefixes", f)
	}

	return appendPrefixes(b, ps, f.AFI)
}

// A PathPrefix is one add-path NLRI entry (RFC 7911): a prefix qualified by
// a path identifier, so a session may carry multiple paths for the same
// prefix at once.
type PathPrefix struct {
	// ID is the path identifier. It has meaning only in combination with
	// Prefix, and only relative to the session the entry traveled on.
	// Identifiers are assigned by the sending speaker and are compared
	// for equality and nothing more. Zero is an ordinary identifier.
	ID uint32

	// Prefix is the IP network the entry advertises or withdraws.
	Prefix netip.Prefix
}

// PathPrefixes is the NLRI of a prefix shaped address family on a session
// which negotiated the add-path extension (RFC 7911) for it. Each entry
// is a prefix qualified by a path identifier: Prefixes' add-path
// counterpart. It appears wherever the negotiation requires: in a
// multiprotocol attribute for a [Session.AddPath] family with the
// matching direction, and in the [Update] NLRIPaths and WithdrawnPaths
// fields for IPv4 unicast at the top level.
type PathPrefixes []PathPrefix

func (ps PathPrefixes) appendNLRI(b []byte, f Family) ([]byte, error) {
	if !f.prefixShaped() {
		return nil, fmt.Errorf("bgp: %s NLRI is not a list of prefixes", f)
	}

	return appendPathPrefixes(b, ps, f.AFI)
}

// An EVPNRouteType is the type of one EVPN NLRI record, as assigned by IANA.
type EVPNRouteType uint8

// EVPNRouteType values for the route types of RFC 7432, section 7 and RFC
// 9136, section 3.
const (
	EVPNRouteEthernetAutoDiscovery         EVPNRouteType = 1
	EVPNRouteMACIPAdvertisement            EVPNRouteType = 2
	EVPNRouteInclusiveMulticastEthernetTag EVPNRouteType = 3
	EVPNRouteEthernetSegment               EVPNRouteType = 4
	EVPNRouteIPPrefix                      EVPNRouteType = 5
)

// String returns the name of an EVPNRouteType.
func (t EVPNRouteType) String() string {
	switch t {
	case EVPNRouteEthernetAutoDiscovery:
		return "Ethernet Auto-Discovery"
	case EVPNRouteMACIPAdvertisement:
		return "MAC/IP Advertisement"
	case EVPNRouteInclusiveMulticastEthernetTag:
		return "Inclusive Multicast Ethernet Tag"
	case EVPNRouteEthernetSegment:
		return "Ethernet Segment"
	case EVPNRouteIPPrefix:
		return "IP Prefix"
	default:
		return fmt.Sprintf("EVPN route type %d", uint8(t))
	}
}

// An EVPNRoute is one record of EVPN reachability information, as described
// in RFC 7432, section 7: a route type and the type specific value it
// frames.
//
// Value is deliberately opaque. Its interpretation (route distinguishers,
// Ethernet segment identifiers, MAC addresses, Ethernet tags, VNIs, MPLS
// labels) is the vocabulary of a layer 2 control plane, which is the
// caller's side of this package's boundary. What this package owns is the
// framing: a route type, a length, and a value of exactly that length.
type EVPNRoute struct {
	Type  EVPNRouteType
	Value []byte
}

// EVPNRoutes is the NLRI of the L2VPN EVPN family (AFI 25, SAFI 70), a list
// of typed records rather than of prefixes, as described in RFC 7432,
// section 7.
type EVPNRoutes []EVPNRoute

func (rs EVPNRoutes) appendNLRI(b []byte, f Family) ([]byte, error) {
	if f != familyEVPN {
		return nil, fmt.Errorf("bgp: EVPN NLRI cannot belong to family %s", f)
	}

	for _, r := range rs {
		if len(r.Value) > math.MaxUint8 {
			return nil, fmt.Errorf("bgp: %s EVPN route value of %d bytes exceeds the maximum of %d",
				r.Type, len(r.Value), math.MaxUint8)
		}

		b = append(b, byte(r.Type), byte(len(r.Value)))
		b = append(b, r.Value...)
	}

	return b, nil
}

// parseEVPNRoutes parses EVPN NLRI records from b until b is exhausted.
func parseEVPNRoutes(b []byte) (EVPNRoutes, error) {
	var rs EVPNRoutes
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, updateError(SubcodeOptionalAttributeError, nil,
				"EVPN NLRI record header truncated")
		}

		n := int(b[1])
		if len(b[2:]) < n {
			return nil, updateError(SubcodeOptionalAttributeError, nil,
				"EVPN NLRI record truncated: %d of %d bytes", len(b[2:]), n)
		}

		rs = append(rs, EVPNRoute{
			Type: EVPNRouteType(b[0]),
			// Cloned so a parsed NLRI never references the read buffer,
			// which ParseMessage is free to reuse between calls.
			Value: bytes.Clone(b[2 : 2+n]),
		})
		b = b[2+n:]
	}

	return rs, nil
}

// A RawNLRI is reachability information in raw binary form: the shape of an
// address family this package does not model, and the escape hatch for
// sending one. It is the NLRI counterpart of an unparsed RawAttribute.
//
// Unlike Prefixes and EVPNRoutes, a RawNLRI belongs to no particular
// family, which is what makes it an escape hatch: a caller may use it to
// send a family whose shape this package models differently, at the cost of
// parsing that family's NLRI themselves. Parse never produces a RawNLRI for
// a family this package does model.
type RawNLRI []byte

func (r RawNLRI) appendNLRI(b []byte, _ Family) ([]byte, error) { return append(b, r...), nil }

// parseNLRI parses the NLRI of family f from b, in the shape f's wire format
// uses. An NLRI appears only inside a multiprotocol attribute, so a
// malformation is always an Optional Attribute Error. addPath reports that
// the session negotiated the add-path extension for f in the receive
// direction, so each entry carries a path identifier (RFC 7911); it is
// only ever set for a prefix shaped family, the only shape add-path is
// supported for.
func parseNLRI(b []byte, f Family, addPath bool) (NLRI, error) {
	// No reachability information at all is a nil NLRI whatever the family,
	// so that nil is the one spelling of nothing in both directions: an
	// End-of-RIB marker parses to a nil NLRI and marshals back from one,
	// and a caller may test for it without knowing the family's shape.
	if len(b) == 0 {
		return nil, nil
	}

	switch {
	case f.prefixShaped() && addPath:
		ps, err := parsePathPrefixes(b, f.AFI, SubcodeOptionalAttributeError)
		if err != nil {
			return nil, err
		}

		return ps, nil
	case f.prefixShaped():
		ps, err := parsePrefixes(b, f.AFI, SubcodeOptionalAttributeError)
		if err != nil {
			return nil, err
		}

		return Prefixes(ps), nil
	case f == familyEVPN:
		rs, err := parseEVPNRoutes(b)
		if err != nil {
			return nil, err
		}

		return rs, nil
	default:
		// Cloned for the reason parseEVPNRoutes clones.
		return RawNLRI(bytes.Clone(b)), nil
	}
}

// appendNLRI appends n's wire encoding for family f, treating a nil NLRI as
// empty: an MPUnreachNLRI which withdraws nothing is the End-of-RIB marker
// of RFC 4724, and an attribute carrying only a family header is how it is
// spelled.
func appendNLRI(b []byte, n NLRI, f Family) ([]byte, error) {
	if n == nil {
		return b, nil
	}

	return n.appendNLRI(b, f)
}
