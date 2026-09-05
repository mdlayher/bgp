package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
)

// AttrFlags describe a BGP path attribute, as described in RFC 4271,
// section 4.3.
type AttrFlags uint8

// AttrFlags values, as described in RFC 4271. The extended length flag is a
// wire encoding detail managed by this package: it is cleared when parsing
// and computed as needed when marshaling.
const (
	AttrFlagOptional   AttrFlags = 0x80
	AttrFlagTransitive AttrFlags = 0x40
	AttrFlagPartial    AttrFlags = 0x20

	attrFlagExtendedLength AttrFlags = 0x10
)

// An AttrType is the type of a BGP path attribute.
type AttrType uint8

// AttrType values, as assigned by IANA.
const (
	AttrOrigin              AttrType = 1
	AttrASPath              AttrType = 2
	AttrNextHop             AttrType = 3
	AttrMED                 AttrType = 4
	AttrLocalPref           AttrType = 5
	AttrAtomicAggregate     AttrType = 6
	AttrAggregator          AttrType = 7
	AttrCommunities         AttrType = 8
	AttrOriginatorID        AttrType = 9
	AttrClusterList         AttrType = 10
	AttrMPReachNLRI         AttrType = 14
	AttrMPUnreachNLRI       AttrType = 15
	AttrExtendedCommunities AttrType = 16
	AttrLargeCommunities    AttrType = 32
	AttrOTC                 AttrType = 35
)

// A RawAttribute is a BGP path attribute in raw binary form, as carried in an
// Update. Parse decodes a RawAttribute into one of this package's Attribute
// types, at the cost of additional allocations; callers which do not inspect
// attribute contents may skip parsing entirely.
//
// When produced by ParseMessage, Data references the input buffer rather
// than copying it; see [ParseMessage].
type RawAttribute struct {
	Flags AttrFlags
	Type  AttrType

	// addPath marks a multiprotocol attribute whose NLRI entries each
	// carry a path identifier (RFC 7911): set by parseUpdate when the
	// attribute's family is one the session negotiated add-path receive
	// for, and consumed by Parse, which then produces PathPrefixes. Never
	// set on an attribute a caller constructs: a sender chooses the
	// encoding by the NLRI type it supplies. Declared before Data so it
	// occupies alignment padding which exists regardless: a RIB retains
	// these at full-table scale, and moving it after Data grows the
	// struct by 8 bytes.
	addPath bool

	Data []byte
}

// Parse decodes a RawAttribute into a typed Attribute. Attributes of a type
// unknown to this package cannot be parsed, and remain available in raw form.
// Parsed Attributes never reference Data, and remain valid after the buffer
// Data references is reused.
//
// A malformed attribute of a known type produces a *MessageError which
// carries the erroneous attribute as its diagnostic data, per RFC 4271,
// section 6.3. An attribute of an unknown type produces a plain error: it is
// not a protocol error, and RFC 4271 requires unrecognized optional
// transitive attributes be passed along unmodified.
func (a RawAttribute) Parse() (Attribute, error) {
	attr, err := a.parse()
	if merr, ok := errors.AsType[*MessageError](err); ok && merr.Data == nil {
		// RFC 4271, section 6.3 requires that attribute errors echo the
		// erroneous attribute itself: flags, type, length, and data. An
		// attribute framed in a real message always fits; the echo is
		// omitted only when a caller constructed an attribute so large that
		// the resulting NOTIFICATION could not be marshaled.
		data, aerr := appendRawAttribute(nil, a)
		if aerr == nil && headerLen+2+len(data) <= MaxMessageSize {
			merr.Data = data
		}
	}

	return attr, err
}

// parse implements Parse, minus the diagnostic data handling.
func (a RawAttribute) parse() (Attribute, error) {
	switch a.Type {
	case AttrOrigin:
		if len(a.Data) != 1 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid ORIGIN attribute length %d", len(a.Data))
		}

		if a.Data[0] > uint8(OriginIncomplete) {
			return nil, updateError(SubcodeInvalidOriginAttribute, nil,
				"invalid ORIGIN value %d", a.Data[0])
		}

		return Origin(a.Data[0]), nil
	case AttrASPath:
		return parseASPath(a.Data)
	case AttrNextHop:
		if len(a.Data) != 4 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid NEXT_HOP attribute length %d", len(a.Data))
		}

		return NextHop(netip.AddrFrom4([4]byte(a.Data))), nil
	case AttrMED:
		if len(a.Data) != 4 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid MULTI_EXIT_DISC attribute length %d", len(a.Data))
		}

		return MED(binary.BigEndian.Uint32(a.Data)), nil
	case AttrLocalPref:
		if len(a.Data) != 4 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid LOCAL_PREF attribute length %d", len(a.Data))
		}

		return LocalPref(binary.BigEndian.Uint32(a.Data)), nil
	case AttrAtomicAggregate:
		if len(a.Data) != 0 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid ATOMIC_AGGREGATE attribute length %d", len(a.Data))
		}

		return AtomicAggregate{}, nil
	case AttrAggregator:
		if len(a.Data) != 8 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid AGGREGATOR attribute length %d", len(a.Data))
		}

		return Aggregator{
			ASN: binary.BigEndian.Uint32(a.Data[0:4]),
			ID:  Identifier(binary.BigEndian.Uint32(a.Data[4:8])),
		}, nil
	case AttrCommunities:
		if len(a.Data)%4 != 0 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid COMMUNITIES attribute length %d", len(a.Data))
		}

		cs := make(Communities, 0, len(a.Data)/4)
		for i := 0; i < len(a.Data); i += 4 {
			cs = append(cs, Community(binary.BigEndian.Uint32(a.Data[i:])))
		}

		return cs, nil
	case AttrOriginatorID:
		if len(a.Data) != 4 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid ORIGINATOR_ID attribute length %d", len(a.Data))
		}

		return OriginatorID(binary.BigEndian.Uint32(a.Data)), nil
	case AttrClusterList:
		if len(a.Data)%4 != 0 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid CLUSTER_LIST attribute length %d", len(a.Data))
		}

		cl := make(ClusterList, 0, len(a.Data)/4)
		for i := 0; i < len(a.Data); i += 4 {
			cl = append(cl, Identifier(binary.BigEndian.Uint32(a.Data[i:])))
		}

		return cl, nil
	case AttrExtendedCommunities:
		if len(a.Data)%8 != 0 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid EXTENDED_COMMUNITIES attribute length %d", len(a.Data))
		}

		ecs := make(ExtendedCommunities, 0, len(a.Data)/8)
		for i := 0; i < len(a.Data); i += 8 {
			ecs = append(ecs, ExtendedCommunity([8]byte(a.Data[i:i+8])))
		}

		return ecs, nil
	case AttrMPReachNLRI:
		m, err := parseMPReachNLRI(a.Data, a.addPath)
		if err != nil {
			return nil, err
		}

		return m, nil
	case AttrMPUnreachNLRI:
		m, err := parseMPUnreachNLRI(a.Data, a.addPath)
		if err != nil {
			return nil, err
		}

		return m, nil
	case AttrLargeCommunities:
		if len(a.Data)%12 != 0 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid LARGE_COMMUNITY attribute length %d", len(a.Data))
		}

		ls := make(LargeCommunities, 0, len(a.Data)/12)
		for i := 0; i < len(a.Data); i += 12 {
			ls = append(ls, LargeCommunity{
				Global: binary.BigEndian.Uint32(a.Data[i:]),
				Local1: binary.BigEndian.Uint32(a.Data[i+4:]),
				Local2: binary.BigEndian.Uint32(a.Data[i+8:]),
			})
		}

		return ls, nil
	case AttrOTC:
		if len(a.Data) != 4 {
			return nil, updateError(SubcodeAttributeLengthError, nil,
				"invalid OTC attribute length %d", len(a.Data))
		}

		return OTC(binary.BigEndian.Uint32(a.Data)), nil
	default:
		return nil, fmt.Errorf("%w %d", errUnknownAttribute, uint8(a.Type))
	}
}

// errUnknownAttribute is the error RawAttribute.Parse wraps for an attribute
// of a type this package does not interpret. It is a plain error, not a
// *MessageError: an unrecognized attribute is not a protocol error.
var errUnknownAttribute = errors.New("bgp: cannot parse attribute of unknown type")

// mpFamily returns the address family a multiprotocol attribute names in
// its first three data bytes. It returns false for an attribute of any
// other type, or one too short to name a family.
func (a RawAttribute) mpFamily() (Family, bool) {
	if (a.Type != AttrMPReachNLRI && a.Type != AttrMPUnreachNLRI) || len(a.Data) < 3 {
		return Family{}, false
	}

	return Family{
		AFI:  AFI(binary.BigEndian.Uint16(a.Data[0:2])),
		SAFI: SAFI(a.Data[2]),
	}, true
}

// RawAttribute implements Attribute so that an attribute this package does
// not interpret travels through MarshalAttributes unmodified, as RFC 4271,
// section 5 requires of unrecognized optional transitive attributes, and so
// that RawAttributes.Parse can return one in place of a typed value. Its
// flags are carried exactly as given.
func (a RawAttribute) attrType() AttrType   { return a.Type }
func (a RawAttribute) attrFlags() AttrFlags { return a.Flags }
func (a RawAttribute) appendData(b []byte) ([]byte, error) {
	return append(b, a.Data...), nil
}

// RawAttributes is the path attribute list of an Update, in raw binary form.
//
// Its Clone method is the retention primitive for callers which store
// attributes past the lifetime of the buffer they reference, most typically
// a RIB keeping a route's attributes, without cloning the whole Update.
type RawAttributes []RawAttribute

// Clone returns a deep copy of the attribute list which shares no memory
// with the original: each attribute's Data survives reuse of the buffer a
// parsed message references. A nil list clones to nil.
func (as RawAttributes) Clone() RawAttributes {
	if as == nil {
		return nil
	}

	cs := make(RawAttributes, len(as))
	for i := range as {
		cs[i] = *as[i].Clone()
	}

	return cs
}

// Find returns the first attribute of type t in as, in raw form: the lookup
// for a caller which only needs to test presence, or which needs an
// attribute this package does not interpret. Lookup is the typed form.
func (as RawAttributes) Find(t AttrType) (RawAttribute, bool) {
	for _, a := range as {
		if a.Type == t {
			return a, true
		}
	}

	return RawAttribute{}, false
}

// Parse decodes every attribute in as into typed form, in list order. An
// attribute of a type this package does not interpret is returned as the
// RawAttribute itself, which implements Attribute: nothing is dropped, and
// MarshalAttributes passes such an attribute along unmodified, as RFC 4271,
// section 5 requires of unrecognized optional transitive attributes.
//
// A malformed attribute of a known type fails the whole parse with its
// *MessageError; see [RawAttribute.Parse]. Typed values never reference the
// raw list's Data, but a RawAttribute returned as-is does, so a caller
// retaining the result past the lifetime of the buffer the list references
// clones the list first.
func (as RawAttributes) Parse() ([]Attribute, error) {
	if as == nil {
		return nil, nil
	}

	attrs := make([]Attribute, 0, len(as))
	for _, a := range as {
		attr, err := a.Parse()
		switch {
		case errors.Is(err, errUnknownAttribute):
			attr = a
		case err != nil:
			return nil, err
		}

		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// markAddPath marks the multiprotocol attributes of the add-path receive
// families fs, so a later typed parse decodes their path identifiers
// without the caller re-supplying the negotiation; see RawAttribute.addPath.
// A short attribute is left unmarked for its parse to reject.
func (as RawAttributes) markAddPath(fs []Family) {
	if len(fs) == 0 {
		return
	}

	for i, a := range as {
		if f, ok := a.mpFamily(); ok && slices.Contains(fs, f) {
			as[i].addPath = true
		}
	}
}

// Lookup finds the first attribute of as whose type is T's and parses it,
// reporting false when as carries none: the typed accessor for one attribute
// of an Update, as in Lookup[ASPath](u.Attributes). A malformed attribute
// produces the *MessageError of RawAttribute.Parse.
//
// T must be one of the typed Attribute implementations, which each know
// their own wire type. The Attribute interface itself is rejected with an
// error, and a RawAttribute has no type of its own to look up, so
// Lookup[RawAttribute] finds nothing; RawAttributes.Find serves both.
func Lookup[T Attribute](as RawAttributes) (T, bool, error) {
	var zero T
	if any(zero) == nil {
		return zero, false, errors.New("bgp: Lookup requires a concrete attribute type, not the Attribute interface")
	}

	raw, ok := as.Find(zero.attrType())
	if !ok {
		return zero, false, nil
	}

	attr, err := raw.Parse()
	if err != nil {
		return zero, false, err
	}

	return attr.(T), true, nil
}

// appendRawAttribute appends the wire encoding of a to b: flags, type,
// length, and data.
func appendRawAttribute(b []byte, a RawAttribute) ([]byte, error) {
	if len(a.Data) > math.MaxUint16 {
		return nil, fmt.Errorf("bgp: attribute %d data too large: %d bytes", uint8(a.Type), len(a.Data))
	}

	flags := a.Flags &^ attrFlagExtendedLength
	if len(a.Data) > math.MaxUint8 {
		flags |= attrFlagExtendedLength
	}

	b = append(b, byte(flags), byte(a.Type))
	if flags&attrFlagExtendedLength != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.Data)))
	} else {
		b = append(b, byte(len(a.Data)))
	}

	return append(b, a.Data...), nil
}

// parseRawAttributes parses raw path attributes from b, until b is
// exhausted. The parsed attributes reference b rather than copying it; see
// ParseMessage.
func parseRawAttributes(b []byte) (RawAttributes, error) {
	// One counting pass sizes the slice exactly, so an attribute list
	// costs a single allocation instead of append's doubling. Truncation
	// is left to the parse loop below, which reports it precisely.
	var count int
	for r := b; len(r) >= 3; count++ {
		var n int
		if AttrFlags(r[0])&attrFlagExtendedLength != 0 {
			if len(r) < 4 {
				break
			}

			n = 4 + int(binary.BigEndian.Uint16(r[2:4]))
		} else {
			n = 3 + int(r[2])
		}
		if n > len(r) {
			break
		}

		r = r[n:]
	}

	var attrs RawAttributes
	if count > 0 {
		attrs = make(RawAttributes, 0, count)
	}

	for len(b) > 0 {
		if len(b) < 3 {
			return nil, updateError(SubcodeMalformedAttributeList, nil,
				"path attribute truncated")
		}

		flags, typ := AttrFlags(b[0]), AttrType(b[1])

		var n int
		if flags&attrFlagExtendedLength != 0 {
			if len(b) < 4 {
				return nil, updateError(SubcodeMalformedAttributeList, nil,
					"path attribute truncated")
			}

			n = int(binary.BigEndian.Uint16(b[2:4]))
			b = b[4:]
		} else {
			n = int(b[2])
			b = b[3:]
		}

		if len(b) < n {
			return nil, updateError(SubcodeMalformedAttributeList, nil,
				"path attribute truncated")
		}

		attrs = append(attrs, RawAttribute{
			Flags: flags &^ attrFlagExtendedLength,
			Type:  typ,
			Data:  b[:n:n],
		})
		b = b[n:]
	}

	return attrs, nil
}

// An Attribute is a BGP path attribute in parsed form. Attribute is
// implemented by Origin, ASPath, NextHop, MED, LocalPref,
// AtomicAggregate, Aggregator, Communities, OriginatorID, ClusterList,
// ExtendedCommunities, MPReachNLRI, MPUnreachNLRI, LargeCommunities, and
// OTC, and by RawAttribute itself, so that an attribute this
// package does not interpret can ride alongside typed ones.
type Attribute interface {
	// attrType and attrFlags are the wire type and canonical flags of the
	// Attribute. appendData appends the Attribute's wire encoded data.
	// These also constrain the set of types which may implement Attribute.
	attrType() AttrType
	attrFlags() AttrFlags
	appendData(b []byte) ([]byte, error)
}

var (
	_ Attribute = Origin(0)
	_ Attribute = ASPath(nil)
	_ Attribute = NextHop{}
	_ Attribute = MED(0)
	_ Attribute = LocalPref(0)
	_ Attribute = AtomicAggregate{}
	_ Attribute = Aggregator{}
	_ Attribute = Communities(nil)
	_ Attribute = OriginatorID(0)
	_ Attribute = ClusterList(nil)
	_ Attribute = ExtendedCommunities(nil)
	_ Attribute = MPReachNLRI{}
	_ Attribute = MPUnreachNLRI{}
	_ Attribute = LargeCommunities(nil)
	_ Attribute = OTC(0)
	_ Attribute = RawAttribute{}
)

// MarshalAttributes converts typed Attributes into raw form, for use in an
// Update message.
func MarshalAttributes(attrs ...Attribute) (RawAttributes, error) {
	ras := make(RawAttributes, 0, len(attrs))
	for _, a := range attrs {
		data, err := a.appendData(nil)
		if err != nil {
			return nil, err
		}

		ras = append(ras, RawAttribute{
			Flags: a.attrFlags(),
			Type:  a.attrType(),
			Data:  data,
		})
	}

	return ras, nil
}

// An Origin is the ORIGIN attribute, describing how the routes in an Update
// were originally learned.
type Origin uint8

// Origin values, as described in RFC 4271.
const (
	OriginIGP        Origin = 0
	OriginEGP        Origin = 1
	OriginIncomplete Origin = 2
)

// String returns the name of an Origin.
func (o Origin) String() string {
	switch o {
	case OriginIGP:
		return "IGP"
	case OriginEGP:
		return "EGP"
	case OriginIncomplete:
		return "incomplete"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(o))
	}
}

func (Origin) attrType() AttrType   { return AttrOrigin }
func (Origin) attrFlags() AttrFlags { return AttrFlagTransitive }

func (o Origin) appendData(b []byte) ([]byte, error) {
	if o > OriginIncomplete {
		return nil, fmt.Errorf("bgp: invalid origin %d", uint8(o))
	}

	return append(b, byte(o)), nil
}

// An ASPath is the AS_PATH attribute: the autonomous systems through which
// routing information in an Update has passed.
//
// ASNs are always encoded in four-octet form, per RFC 6793. Sessions with
// speakers which do not support the Four-Octet AS Number capability are not
// supported by this package.
type ASPath []ASSegment

// An ASSegment is a single segment of an ASPath. Set and Confed select
// among the four wire segment types: the zero value is an ordered
// AS_SEQUENCE.
type ASSegment struct {
	// Set indicates that the segment is unordered: an AS_SET, or an
	// AS_CONFED_SET when Confed is also true.
	Set bool

	// Confed indicates that the segment is a confederation segment per RFC
	// 5065: an AS_CONFED_SEQUENCE, or an AS_CONFED_SET when Set is also
	// true. Confederation segments are exchanged only within a
	// confederation, and this package only carries them. Their section 5.3
	// semantics are the caller's RIB's: a best-path AS_PATH length excludes
	// confederation segments, the MED neighbor AS skips them, and
	// confederation loop detection examines them.
	Confed bool

	// ASNs lists the autonomous systems within the segment.
	ASNs []uint32
}

// An OriginAS is the origin of a route as its AS_PATH names it, derived
// per RFC 6811, section 2, for route origin validation. Exactly one of the
// three readings applies: ASN names the origin; Set reports that the path
// ends in an AS_SET, whose origin is RFC 6811's "NONE" and matches no
// authorization; Empty reports a path which names no origin at all, one
// with no autonomous system outside confederation segments, whose origin
// is the receiving speaker's own AS or confederation, which the path
// cannot know.
type OriginAS struct {
	// ASN is the rightmost autonomous system of the path's final
	// AS_SEQUENCE, or zero when Set or Empty.
	ASN uint32

	// Set reports that the path's final non-confederation segment is an
	// AS_SET.
	Set bool

	// Empty reports a path with no autonomous system outside
	// confederation segments.
	Empty bool
}

// Origin returns the origin autonomous system the path names, per RFC 6811,
// section 2. Confederation segments never name an origin: they are the
// path's intra-confederation record, so they are skipped, and a path of
// only confederation segments reads Empty, since it originated within the
// local confederation. Validation of the origin against RPKI data is the
// caller's; see [ValidationState] for carrying its result.
func (p ASPath) Origin() OriginAS {
	for _, last := range slices.Backward(p) {
		switch {
		case last.Confed:
			continue
		case last.Set:
			return OriginAS{Set: true}
		case len(last.ASNs) == 0:
			// Not encodable, but representable: nothing names an origin.
			return OriginAS{Empty: true}
		default:
			return OriginAS{ASN: last.ASNs[len(last.ASNs)-1]}
		}
	}

	return OriginAS{Empty: true}
}

// Wire values for AS path segment types. The confederation types are RFC
// 5065, section 3.
const (
	asSet            = 1
	asSequence       = 2
	asConfedSequence = 3
	asConfedSet      = 4
)

func (ASPath) attrType() AttrType   { return AttrASPath }
func (ASPath) attrFlags() AttrFlags { return AttrFlagTransitive }

func (p ASPath) appendData(b []byte) ([]byte, error) {
	for _, s := range p {
		if len(s.ASNs) == 0 {
			return nil, errors.New("bgp: AS path segment must contain at least 1 ASN")
		}

		// An AS_SET or AS_CONFED_SET is unordered and cannot be split
		// without changing its meaning.
		if s.Set && len(s.ASNs) > math.MaxUint8 {
			return nil, fmt.Errorf("bgp: AS set segment must contain between 1 and 255 ASNs: %d", len(s.ASNs))
		}

		typ := byte(asSequence)
		switch {
		case s.Set && s.Confed:
			typ = asConfedSet
		case s.Set:
			typ = asSet
		case s.Confed:
			typ = asConfedSequence
		}

		// A wire segment holds at most 255 ASNs; a longer sequence is
		// encoded as multiple segments, per RFC 4271, section 4.3.
		for asns := s.ASNs; len(asns) > 0; {
			n := min(len(asns), math.MaxUint8)
			b = append(b, typ, byte(n))
			for _, asn := range asns[:n] {
				b = binary.BigEndian.AppendUint32(b, asn)
			}

			asns = asns[n:]
		}
	}

	return b, nil
}

// parseASPath parses the data of an AS_PATH attribute.
func parseASPath(b []byte) (ASPath, error) {
	var p ASPath
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, updateError(SubcodeMalformedASPath, nil,
				"AS_PATH segment truncated")
		}

		typ, n := b[0], int(b[1])

		var set, confed bool
		switch typ {
		case asSet:
			set = true
		case asSequence:
		case asConfedSequence:
			confed = true
		case asConfedSet:
			set, confed = true, true
		default:
			return nil, updateError(SubcodeMalformedASPath, nil,
				"unsupported AS_PATH segment type %d", typ)
		}

		if n == 0 {
			return nil, updateError(SubcodeMalformedASPath, nil,
				"empty AS_PATH segment")
		}

		b = b[2:]
		if len(b) < 4*n {
			return nil, updateError(SubcodeMalformedASPath, nil,
				"AS_PATH segment truncated")
		}

		asns := make([]uint32, 0, n)
		for i := range n {
			asns = append(asns, binary.BigEndian.Uint32(b[4*i:]))
		}

		p = append(p, ASSegment{Set: set, Confed: confed, ASNs: asns})
		b = b[4*n:]
	}

	return p, nil
}

// A NextHop is the NEXT_HOP attribute: the IPv4 address of the router to be
// used as the next hop to the routes advertised in an Update. Next hops for
// other address families are carried by MPReachNLRI.
type NextHop netip.Addr

// String returns the string form of a NextHop's address.
func (n NextHop) String() string { return netip.Addr(n).String() }

func (NextHop) attrType() AttrType   { return AttrNextHop }
func (NextHop) attrFlags() AttrFlags { return AttrFlagTransitive }

func (n NextHop) appendData(b []byte) ([]byte, error) {
	addr := netip.Addr(n).Unmap()
	if !addr.Is4() {
		return nil, fmt.Errorf("bgp: next hop must be an IPv4 address: %s", addr)
	}

	a := addr.As4()
	return append(b, a[:]...), nil
}

// A MED is the MULTI_EXIT_DISC (Multi-Exit Discriminator) attribute, used to
// discriminate among multiple entry points to a neighboring autonomous
// system.
type MED uint32

func (MED) attrType() AttrType   { return AttrMED }
func (MED) attrFlags() AttrFlags { return AttrFlagOptional }

func (m MED) appendData(b []byte) ([]byte, error) {
	return binary.BigEndian.AppendUint32(b, uint32(m)), nil
}

// A LocalPref is the LOCAL_PREF attribute: a speaker's degree of preference
// for a route, exchanged between peers within an autonomous system.
type LocalPref uint32

func (LocalPref) attrType() AttrType   { return AttrLocalPref }
func (LocalPref) attrFlags() AttrFlags { return AttrFlagTransitive }

func (l LocalPref) appendData(b []byte) ([]byte, error) {
	return binary.BigEndian.AppendUint32(b, uint32(l)), nil
}

// An AtomicAggregate is the ATOMIC_AGGREGATE attribute, indicating that a
// route was selected over a more specific route which it covers.
type AtomicAggregate struct{}

func (AtomicAggregate) attrType() AttrType   { return AttrAtomicAggregate }
func (AtomicAggregate) attrFlags() AttrFlags { return AttrFlagTransitive }

func (AtomicAggregate) appendData(b []byte) ([]byte, error) { return b, nil }

// An Aggregator is the AGGREGATOR attribute, identifying the autonomous
// system and router which aggregated a route. The ASN is always encoded in
// four-octet form, per RFC 6793.
type Aggregator struct {
	// ASN is the autonomous system number of the aggregating speaker.
	ASN uint32

	// ID is the BGP identifier of the aggregating speaker.
	ID Identifier
}

func (Aggregator) attrType() AttrType   { return AttrAggregator }
func (Aggregator) attrFlags() AttrFlags { return AttrFlagOptional | AttrFlagTransitive }

func (a Aggregator) appendData(b []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint32(b, a.ASN)
	return binary.BigEndian.AppendUint32(b, uint32(a.ID)), nil
}

// An OriginatorID is the ORIGINATOR_ID attribute: the BGP identifier of the
// route's originator in the local autonomous system, added by a route
// reflector, as described in RFC 4456.
type OriginatorID Identifier

// String returns the conventional dotted quad form of an OriginatorID.
func (o OriginatorID) String() string { return Identifier(o).String() }

func (OriginatorID) attrType() AttrType   { return AttrOriginatorID }
func (OriginatorID) attrFlags() AttrFlags { return AttrFlagOptional }

func (o OriginatorID) appendData(b []byte) ([]byte, error) {
	return binary.BigEndian.AppendUint32(b, uint32(o)), nil
}

// A ClusterList is the CLUSTER_LIST attribute: the sequence of route
// reflection clusters a route has passed through, as described in RFC 4456.
// A cluster's identifier is by default its reflector's BGP identifier.
type ClusterList []Identifier

func (ClusterList) attrType() AttrType   { return AttrClusterList }
func (ClusterList) attrFlags() AttrFlags { return AttrFlagOptional }

func (cl ClusterList) appendData(b []byte) ([]byte, error) {
	for _, id := range cl {
		b = binary.BigEndian.AppendUint32(b, uint32(id))
	}

	return b, nil
}

// An OTC is the OTC (Only to Customer) attribute: the autonomous system
// beyond which a route must only propagate toward customers, used to detect
// and prevent route leaks, as described in RFC 9234. The role negotiation
// half of RFC 9234 (an OPEN capability) is out of scope for this package;
// the attribute is meaningful standalone.
type OTC uint32

func (OTC) attrType() AttrType   { return AttrOTC }
func (OTC) attrFlags() AttrFlags { return AttrFlagOptional | AttrFlagTransitive }

func (o OTC) appendData(b []byte) ([]byte, error) {
	return binary.BigEndian.AppendUint32(b, uint32(o)), nil
}
