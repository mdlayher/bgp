package bgp

import (
	"encoding/binary"
	"net/netip"
)

// An Update is a BGP UPDATE message, used to advertise and withdraw routes,
// as described in RFC 4271, section 4.3.
//
// Withdrawn and NLRI are the original RFC 4271 fields, limited by wire
// format to IPv4 unicast prefixes. The MPReachNLRI and MPUnreachNLRI
// attributes (RFC 4760) carry routes for any address family, including IPv4;
// multiprotocol sessions typically leave Withdrawn and NLRI empty.
type Update struct {
	// Withdrawn lists IPv4 unicast prefixes to be removed from service.
	Withdrawn []netip.Prefix

	// Attributes lists the path attributes for NLRI, in raw binary form.
	// Lookup fetches one attribute in typed form, RawAttributes.Parse decodes
	// them all, and MarshalAttributes converts typed attributes back for
	// sending. RFC 4271, section 5 recommends ascending type order; this
	// package marshals them in the order provided.
	Attributes RawAttributes

	// NLRI lists IPv4 unicast prefixes to be advertised: RFC 4271's
	// Network Layer Reachability Information field.
	NLRI []netip.Prefix
}

func (*Update) messageType() MessageType { return MessageTypeUpdate }

// EndOfRIB reports whether the Update is an End-of-RIB marker (RFC 4724,
// section 2) and, if so, for which address family. The marker signals that a
// speaker has sent its complete initial routing table for a family, and is
// meaningful without graceful restart: callers may use it to detect
// convergence.
//
// An empty UPDATE marks the end of the IPv4 unicast table. For any other
// family, the marker is an UPDATE whose only content is an MP_UNREACH_NLRI
// attribute which withdraws nothing.
func (u *Update) EndOfRIB() (Family, bool) {
	if len(u.Withdrawn) != 0 || len(u.NLRI) != 0 {
		return Family{}, false
	}

	switch len(u.Attributes) {
	case 0:
		return Family{AFI: AFIIPv4, SAFI: SAFIUnicast}, true
	case 1:
		// The MP form carries only the family header: an AFI, a SAFI, and
		// zero withdrawn prefixes.
		a := u.Attributes[0]
		if a.Type != AttrMPUnreachNLRI || len(a.Data) != 3 {
			return Family{}, false
		}

		return Family{
			AFI:  AFI(binary.BigEndian.Uint16(a.Data[0:2])),
			SAFI: SAFI(a.Data[2]),
		}, true
	default:
		return Family{}, false
	}
}

// NewEndOfRIB produces the End-of-RIB marker for a family, as described in
// RFC 4724, section 2. A speaker sends the marker after it has advertised
// its complete table for the family. It is [Update.EndOfRIB]'s encoding
// counterpart.
//
// The marker is meaningful without graceful restart: a speaker may send it
// after any initial table transfer as a convergence signal.
func NewEndOfRIB(f Family) *Update {
	if (f == Family{AFI: AFIIPv4, SAFI: SAFIUnicast}) {
		return &Update{}
	}

	data := binary.BigEndian.AppendUint16(make([]byte, 0, 3), uint16(f.AFI))
	return &Update{Attributes: RawAttributes{{
		Flags: AttrFlagOptional,
		Type:  AttrMPUnreachNLRI,
		Data:  append(data, byte(f.SAFI)),
	}}}
}

// AppendBinary implements encoding.BinaryAppender.
func (u *Update) AppendBinary(b []byte) ([]byte, error) {
	b, off := appendHeader(b, MessageTypeUpdate)

	// Withdrawn routes, prefixed by their 2 byte length.
	wOff := len(b)
	b = append(b, 0, 0)
	b, err := appendPrefixes(b, u.Withdrawn, AFIIPv4)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(b[wOff:], uint16(len(b)-wOff-2))

	// Path attributes, prefixed by their 2 byte length.
	aOff := len(b)
	b = append(b, 0, 0)
	for _, a := range u.Attributes {
		b, err = appendRawAttribute(b, a)
		if err != nil {
			return nil, err
		}
	}

	binary.BigEndian.PutUint16(b[aOff:], uint16(len(b)-aOff-2))

	// NLRI occupies the remainder of the message.
	b, err = appendPrefixes(b, u.NLRI, AFIIPv4)
	if err != nil {
		return nil, err
	}

	return finishMessage(b, off)
}

// parseUpdate parses the body of an UPDATE message.
func parseUpdate(b []byte) (*Update, error) {
	if len(b) < 4 {
		return nil, badLength(len(b), "UPDATE message too short: %d byte body", len(b))
	}

	wLen := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b[2:]) < wLen+2 {
		return nil, updateError(SubcodeMalformedAttributeList, nil,
			"UPDATE withdrawn routes truncated")
	}

	var (
		u   Update
		err error
	)

	if wLen > 0 {
		u.Withdrawn, err = parsePrefixes(b[2:2+wLen], AFIIPv4, SubcodeInvalidNetworkField)
		if err != nil {
			return nil, err
		}
	}

	b = b[2+wLen:]

	aLen := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b[2:]) < aLen {
		return nil, updateError(SubcodeMalformedAttributeList, nil,
			"UPDATE path attributes truncated")
	}

	u.Attributes, err = parseRawAttributes(b[2 : 2+aLen])
	if err != nil {
		return nil, err
	}

	if nlri := b[2+aLen:]; len(nlri) > 0 {
		u.NLRI, err = parsePrefixes(nlri, AFIIPv4, SubcodeInvalidNetworkField)
		if err != nil {
			return nil, err
		}
	}

	return &u, nil
}
