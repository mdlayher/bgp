package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
)

// A Community is a BGP community value, as described in RFC 1997,
// conventionally written as "ASN:value".
type Community uint32

// NewCommunity produces a Community from an ASN and a value.
func NewCommunity(asn, value uint16) Community {
	return Community(uint32(asn)<<16 | uint32(value))
}

// String returns the conventional "ASN:value" form of a Community.
func (c Community) String() string {
	return fmt.Sprintf("%d:%d", uint32(c)>>16, uint32(c)&0xffff)
}

// Communities is the COMMUNITIES attribute: the community values applied to
// a route.
type Communities []Community

func (Communities) attrType() AttrType   { return AttrCommunities }
func (Communities) attrFlags() AttrFlags { return AttrFlagOptional | AttrFlagTransitive }

func (cs Communities) appendData(b []byte) ([]byte, error) {
	for _, c := range cs {
		b = binary.BigEndian.AppendUint32(b, uint32(c))
	}

	return b, nil
}

// An ExtendedCommunity is a BGP extended community value, as described in
// RFC 4360: 8 wire bytes, carried verbatim. The type and subtype registries
// are large, so the value is deliberately opaque; only the common route
// target and route origin forms (NewRouteTarget, NewRouteOrigin) and the
// origin validation state (NewValidationState, ValidationState) are
// interpreted, by their constructors, accessors, and String.
type ExtendedCommunity [8]byte

// Extended community wire values interpreted by this package: the AS and
// IPv4 address specific types (RFC 4360, RFC 5668) and their route target
// and route origin subtypes, and the non-transitive opaque type's origin
// validation state subtype (RFC 8097).
const (
	ecommTypeTwoOctetAS  = 0x00
	ecommTypeIPv4Address = 0x01
	ecommTypeFourOctetAS = 0x02

	ecommSubtypeRouteTarget = 0x02
	ecommSubtypeRouteOrigin = 0x03

	ecommTypeNonTransitiveOpaque = 0x43
	ecommSubtypeValidationState  = 0x00
)

// A ValidationState is the result of route origin validation (RFC 6811)
// for a route, as carried between speakers in an extended community (RFC
// 8097). Validation itself — the prefix-to-origin database and the lookup
// — is the caller's, exactly as route policy is; this package only carries
// the result.
type ValidationState uint8

// The origin validation states of RFC 8097, section 2.
const (
	ValidationStateValid    ValidationState = 0
	ValidationStateNotFound ValidationState = 1
	ValidationStateInvalid  ValidationState = 2
)

// String returns the name of the ValidationState.
func (s ValidationState) String() string {
	switch s {
	case ValidationStateValid:
		return "valid"
	case ValidationStateNotFound:
		return "not-found"
	case ValidationStateInvalid:
		return "invalid"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// NewValidationState produces the origin validation state ExtendedCommunity
// (RFC 8097) carrying s: a non-transitive opaque community, so it does not
// cross an autonomous system boundary.
func NewValidationState(s ValidationState) ExtendedCommunity {
	return ExtendedCommunity{
		0: ecommTypeNonTransitiveOpaque,
		1: ecommSubtypeValidationState,
		7: byte(s),
	}
}

// ValidationState returns the origin validation state the community carries
// (RFC 8097), reporting false when it is a community of some other kind.
// A state outside the three RFC 8097 defines is returned as is, per the
// RFC's instruction to treat unknown values as Not Found being a policy
// decision this package leaves to the caller.
func (c ExtendedCommunity) ValidationState() (ValidationState, bool) {
	if c[0] != ecommTypeNonTransitiveOpaque || c[1] != ecommSubtypeValidationState {
		return 0, false
	}

	return ValidationState(c[7]), true
}

// NewRouteTarget produces a route target ExtendedCommunity from an ASN and a
// value, choosing the two-octet or four-octet AS specific encoding to fit
// the ASN. The four-octet encoding only has room for a 2 byte value.
func NewRouteTarget(asn, value uint32) (ExtendedCommunity, error) {
	return newASSpecific(ecommSubtypeRouteTarget, asn, value)
}

// NewRouteOrigin produces a route origin (site of origin) ExtendedCommunity
// from an ASN and a value, choosing the two-octet or four-octet AS specific
// encoding to fit the ASN. The four-octet encoding only has room for a 2
// byte value.
func NewRouteOrigin(asn, value uint32) (ExtendedCommunity, error) {
	return newASSpecific(ecommSubtypeRouteOrigin, asn, value)
}

// newASSpecific produces an AS specific ExtendedCommunity with the given
// subtype.
func newASSpecific(subtype uint8, asn, value uint32) (ExtendedCommunity, error) {
	c := ExtendedCommunity{1: subtype}
	if asn <= math.MaxUint16 {
		c[0] = ecommTypeTwoOctetAS
		binary.BigEndian.PutUint16(c[2:4], uint16(asn))
		binary.BigEndian.PutUint32(c[4:8], value)
		return c, nil
	}

	if value > math.MaxUint16 {
		return ExtendedCommunity{}, fmt.Errorf(
			"bgp: a four-octet AS specific extended community value must fit in 2 bytes: %d", value,
		)
	}

	c[0] = ecommTypeFourOctetAS
	binary.BigEndian.PutUint32(c[2:6], asn)
	binary.BigEndian.PutUint16(c[6:8], uint16(value))
	return c, nil
}

// String returns the conventional form of common route target ("RT:") and
// route origin ("SoO:") communities, and of the origin validation state
// ("OVS:", RFC 8097). Other values render as "UNK:type:subtype:0xvalue";
// unlike the similar FRR form, the value bytes are preserved.
func (c ExtendedCommunity) String() string {
	if s, ok := c.ValidationState(); ok {
		return "OVS:" + s.String()
	}

	typ, subtype := c[0], c[1]

	var prefix string
	switch subtype {
	case ecommSubtypeRouteTarget:
		prefix = "RT:"
	case ecommSubtypeRouteOrigin:
		prefix = "SoO:"
	}

	if prefix != "" {
		switch typ {
		case ecommTypeTwoOctetAS:
			return fmt.Sprintf("%s%d:%d", prefix,
				binary.BigEndian.Uint16(c[2:4]), binary.BigEndian.Uint32(c[4:8]))
		case ecommTypeIPv4Address:
			return fmt.Sprintf("%s%s:%d", prefix,
				netip.AddrFrom4([4]byte(c[2:6])), binary.BigEndian.Uint16(c[6:8]))
		case ecommTypeFourOctetAS:
			return fmt.Sprintf("%s%d:%d", prefix,
				binary.BigEndian.Uint32(c[2:6]), binary.BigEndian.Uint16(c[6:8]))
		}
	}

	return fmt.Sprintf("UNK:%d:%d:0x%x", typ, subtype, c[2:8])
}

// ExtendedCommunities is the EXTENDED_COMMUNITIES attribute: the extended
// community values applied to a route.
type ExtendedCommunities []ExtendedCommunity

func (ExtendedCommunities) attrType() AttrType   { return AttrExtendedCommunities }
func (ExtendedCommunities) attrFlags() AttrFlags { return AttrFlagOptional | AttrFlagTransitive }

func (cs ExtendedCommunities) appendData(b []byte) ([]byte, error) {
	for _, c := range cs {
		b = append(b, c[:]...)
	}

	return b, nil
}

// A LargeCommunity is a BGP large community value, as described in RFC 8092,
// conventionally written as "global:local1:local2".
type LargeCommunity struct {
	// Global is the global administrator: the ASN of the autonomous system
	// which defined the community's meaning.
	Global uint32

	// Local1 and Local2 carry data whose meaning is defined by the global
	// administrator.
	Local1, Local2 uint32
}

// String returns the conventional "global:local1:local2" form of a
// LargeCommunity.
func (c LargeCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", c.Global, c.Local1, c.Local2)
}

// LargeCommunities is the LARGE_COMMUNITY attribute: the large community
// values applied to a route.
type LargeCommunities []LargeCommunity

func (LargeCommunities) attrType() AttrType   { return AttrLargeCommunities }
func (LargeCommunities) attrFlags() AttrFlags { return AttrFlagOptional | AttrFlagTransitive }

func (ls LargeCommunities) appendData(b []byte) ([]byte, error) {
	for _, l := range ls {
		b = binary.BigEndian.AppendUint32(b, l.Global)
		b = binary.BigEndian.AppendUint32(b, l.Local1)
		b = binary.BigEndian.AppendUint32(b, l.Local2)
	}

	return b, nil
}
