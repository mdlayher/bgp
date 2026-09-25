package bgp

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseUpdateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		b       []byte
		code    NotificationCode
		subcode uint8
		data    []byte
	}{
		{
			name:    "short body",
			b:       []byte{0x00, 0x00, 0x00},
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 3},
		},
		{
			name: "withdrawn routes truncated",
			// Withdrawn length 5, but only two bytes follow it.
			b:       []byte{0x00, 0x05, 0x00, 0x00},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			name: "withdrawn routes consume attribute length",
			// Withdrawn length 1 leaves only 1 byte, not the 2 required for
			// the total path attribute length field.
			b:       []byte{0x00, 0x01, 0x18, 0x00},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			name: "withdrawn prefix length invalid",
			// A /33 IPv4 prefix in the withdrawn routes.
			b:       []byte{0x00, 0x06, 33, 192, 0, 2, 0, 1, 0x00, 0x00},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name:    "withdrawn prefix truncated",
			b:       []byte{0x00, 0x02, 24, 203, 0x00, 0x00},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name:    "path attributes truncated",
			b:       []byte{0x00, 0x00, 0x00, 0x04, 0x00},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			name: "path attribute region malformed",
			// One byte of attribute data cannot hold an attribute header.
			b:       []byte{0x00, 0x00, 0x00, 0x01, 0x40},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			name:    "NLRI prefix length invalid",
			b:       []byte{0x00, 0x00, 0x00, 0x00, 33, 203, 0, 113, 0, 1},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name:    "NLRI prefix truncated",
			b:       []byte{0x00, 0x00, 0x00, 0x00, 24, 203},
			code:    NotificationUpdateMessageError,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			// RFC 7606, section 3(g): a repeated multiprotocol attribute
			// leaves the routes the UPDATE carries ambiguous.
			name:    "duplicate MP_REACH_NLRI",
			b:       updateBody(concat(originAttr(), asPathAttr(), mpReachAttr(), mpReachAttr()), nil),
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			name:    "duplicate MP_UNREACH_NLRI",
			b:       updateBody(concat(mpUnreachAttr(), mpUnreachAttr()), nil),
			code:    NotificationUpdateMessageError,
			subcode: SubcodeMalformedAttributeList,
		},
		{
			// RFC 7606, section 5.3: too short to name a family, so the
			// withdrawn routes cannot be located at all.
			name:    "MP_UNREACH_NLRI too short",
			b:       updateBody(attrBytes(AttrFlagOptional, AttrMPUnreachNLRI, 0x00, 0x02), nil),
			code:    NotificationUpdateMessageError,
			subcode: SubcodeOptionalAttributeError,
			data:    attrBytes(AttrFlagOptional, AttrMPUnreachNLRI, 0x00, 0x02),
		},
		{
			// An attribute whose Optional bit is clear is well known by
			// definition, and RFC 7606 does not revise RFC 4271, section
			// 6.3 for one the receiver does not recognize.
			name:    "unrecognized well-known attribute",
			b:       updateBody(concat(originAttr(), asPathAttr(), nextHopAttr(), unknownWellKnownAttr()), v4NLRI()),
			code:    NotificationUpdateMessageError,
			subcode: SubcodeUnrecognizedWellKnownAttribute,
			data:    unknownWellKnownAttr(),
		},
		{
			// RFC 7606, section 5.2: path attributes beyond
			// MP_UNREACH_NLRI but nothing reachable, so the NLRI cannot be
			// trusted to have been located and treat-as-withdraw falls back
			// to a session reset.
			name:    "malformed attribute with nothing reachable",
			b:       updateBody(concat(originAttr(), asPathAttr(), shortMEDAttr()), nil),
			code:    NotificationUpdateMessageError,
			subcode: SubcodeAttributeLengthError,
			data:    shortMEDAttr(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := ParseMessage(testMessage(MessageTypeUpdate, tt.b))
			if r.Message != nil {
				t.Fatalf("expected nil Message, but got: %v", r.Message)
			}

			wantMessageError(t, err, tt.code, tt.subcode, tt.data)
		})
	}
}

func TestUpdateAppendBinaryErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		u    *Update
	}{
		{
			name: "withdrawn family mismatch",
			u: &Update{
				Withdrawn: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			},
		},
		{
			name: "prefixes family mismatch",
			u: &Update{
				NLRI: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			},
		},
		{
			name: "invalid prefix",
			u: &Update{
				NLRI: []netip.Prefix{{}},
			},
		},
		{
			name: "attribute data too large",
			u: &Update{
				Attributes: []RawAttribute{{
					Type: AttrCommunities,
					Data: make([]byte, 65536),
				}},
			},
		},
		{
			// The plain and add-path forms are two encodings of the same
			// wire field, so carrying both is ambiguous.
			name: "withdrawn both forms",
			u: &Update{
				Withdrawn:      []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				WithdrawnPaths: PathPrefixes{{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24")}},
			},
		},
		{
			name: "NLRI both forms",
			u: &Update{
				NLRI:      []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				NLRIPaths: PathPrefixes{{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24")}},
			},
		},
		{
			// One negotiation governs both top level fields, so a plain
			// field and a path field cannot mix: no receiver parses both.
			name: "mixed forms across fields",
			u: &Update{
				Withdrawn: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				NLRIPaths: PathPrefixes{{ID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24")}},
			},
		},
		{
			name: "message too large",
			u: &Update{
				// 1200 /32 prefixes at 5 bytes each overflow MaxMessageSize.
				NLRI: func() []netip.Prefix {
					ps := make([]netip.Prefix, 0, 1200)
					for i := range 1200 {
						a := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
						ps = append(ps, netip.PrefixFrom(a, 32))
					}

					return ps
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.u.AppendBinary(nil); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

// TestUpdateAddPathRoundTrip pins the two wire forms of RFC 7911 NLRI
// through a full message round trip: the top level IPv4 unicast fields
// parse into the path fields, and a marked multiprotocol attribute's typed
// parse produces PathPrefixes, with no session context re-supplied by the
// caller.
func TestUpdateAddPathRoundTrip(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
	v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

	// Two paths for the same prefix in each form is the extension's whole
	// point.
	nlri := PathPrefixes{
		{ID: 1, Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
		{ID: 2, Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
	}

	// The well-known mandatory attributes ride along, so the UPDATE is one
	// a receiver applying RFC 7606, section 3(d) would not treat as a
	// withdrawal: that is not this test's subject.
	mp, err := MarshalAttributes(
		OriginIGP,
		ASPath{{ASNs: []uint32{64512}}},
		NextHop(netip.MustParseAddr("192.0.2.1")),
		MPReachNLRI{
			Family:  v6u,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    nlri,
		},
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	// The parsed MP_REACH_NLRI is marked add-path, since v6u is in the
	// receive set, so the want asserts the mark rather than ignoring it.
	mp[3].addPath = true

	u := &Update{
		WithdrawnPaths: PathPrefixes{{ID: 7, Prefix: netip.MustParsePrefix("192.0.2.0/24")}},
		Attributes:     mp,
		NLRIPaths: PathPrefixes{
			{ID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{ID: 2, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
		},
	}

	b, err := u.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal UPDATE: %v", err)
	}

	r, err := ParseMessageAddPath(b, []Family{v4u, v6u})
	if err != nil {
		t.Fatalf("failed to parse UPDATE: %v", err)
	}

	got := r.Message.(*Update)
	if d := diff(t, u, got); d != "" {
		t.Fatalf("unexpected UPDATE (-want +got):\n%s", d)
	}

	// The mark carried by the parsed attribute decodes the identifiers
	// without the caller re-supplying the negotiation.
	mpr, ok, err := Lookup[MPReachNLRI](got.Attributes)
	if err != nil || !ok {
		t.Fatalf("failed to look up MP_REACH_NLRI: ok=%v, err=%v", ok, err)
	}

	if d := diff[NLRI](t, nlri, mpr.NLRI); d != "" {
		t.Fatalf("unexpected MP_REACH_NLRI reachability (-want +got):\n%s", d)
	}
}

// TestParseUpdateAddPathErrors covers a peer which negotiated add-path and
// then sends malformed entries: the identifier and its prefix must both be
// whole, and a malformation in the top level fields is an Invalid Network
// Field like any other.
func TestParseUpdateAddPathErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
	}{
		{
			// Two bytes of withdrawn field cannot hold a four byte path
			// identifier.
			name: "withdrawn path identifier truncated",
			body: []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "NLRI prefix truncated",
			body: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 24, 192},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseMessageAddPath(
				testMessage(MessageTypeUpdate, tt.body),
				[]Family{{AFI: AFIIPv4, SAFI: SAFIUnicast}},
			)
			wantMessageError(t, err, NotificationUpdateMessageError, SubcodeInvalidNetworkField, nil)
		})
	}
}

// TestParseUpdateMalformed drives the two outcomes of RFC 7606 which still
// deliver the UPDATE: treat-as-withdraw, which marks it, and attribute
// discard, which moves the attribute aside. Each case is one wire body and
// the exact Malformed and Discarded values it must produce.
func TestParseUpdateMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// attrs and nlri are the UPDATE's path attribute and NLRI bytes.
		attrs, nlri []byte

		// subcode and data are the expected Malformed error, or subcode
		// zero for an UPDATE which is not treated as a withdrawal.
		subcode uint8
		data    []byte

		// discarded is the expected Discarded list, and kept the number of
		// attributes left in Attributes.
		discarded RawAttributes
		kept      int
	}{
		{
			// The fault injection case: ORIGIN carrying the Optional bit
			// is RFC 7606, section 3(c)'s flags conflict.
			name:    "ORIGIN optional bit set",
			attrs:   concat(optionalOriginAttr(), asPathAttr(), nextHopAttr()),
			nlri:    v4NLRI(),
			subcode: SubcodeAttributeFlagsError,
			data:    optionalOriginAttr(),
			kept:    3,
		},
		{
			// RFC 4271, section 4.3 allows the Partial bit only on an
			// optional transitive attribute; NEXT_HOP is well known.
			name:    "NEXT_HOP partial bit set",
			attrs:   concat(originAttr(), asPathAttr(), partialNextHopAttr()),
			nlri:    v4NLRI(),
			subcode: SubcodeAttributeFlagsError,
			data:    partialNextHopAttr(),
			kept:    3,
		},
		{
			name:    "ORIGIN undefined value",
			attrs:   concat(attrBytes(AttrFlagTransitive, AttrOrigin, 0x03), asPathAttr(), nextHopAttr()),
			nlri:    v4NLRI(),
			subcode: SubcodeInvalidOriginAttribute,
			data:    attrBytes(AttrFlagTransitive, AttrOrigin, 0x03),
			kept:    3,
		},
		{
			// RFC 7606, section 7.4: a fixed length attribute of the wrong
			// length withdraws the UPDATE's routes.
			name:    "MULTI_EXIT_DISC wrong length",
			attrs:   concat(originAttr(), asPathAttr(), nextHopAttr(), shortMEDAttr()),
			nlri:    v4NLRI(),
			subcode: SubcodeAttributeLengthError,
			data:    shortMEDAttr(),
			kept:    4,
		},
		{
			// RFC 7606, section 7.2: a segment which claims no autonomous
			// systems at all.
			name:    "AS_PATH empty segment",
			attrs:   concat(originAttr(), attrBytes(AttrFlagTransitive, AttrASPath, 0x02, 0x00), nextHopAttr()),
			nlri:    v4NLRI(),
			subcode: SubcodeMalformedASPath,
			data:    attrBytes(AttrFlagTransitive, AttrASPath, 0x02, 0x00),
			kept:    3,
		},
		{
			// RFC 4271, section 4.3: the Partial bit is allowed on an
			// optional transitive attribute.
			name:  "AGGREGATOR partial bit set",
			attrs: concat(originAttr(), asPathAttr(), nextHopAttr(), partialAggregatorAttr()),
			nlri:  v4NLRI(),
			kept:  4,
		},
		{
			// RFC 4271, section 5: an unrecognized optional attribute
			// passes through untouched.
			name:  "unrecognized optional attribute",
			attrs: concat(originAttr(), asPathAttr(), nextHopAttr(), unknownOptionalAttr()),
			nlri:  v4NLRI(),
			kept:  4,
		},
		{
			// RFC 7606, section 3(g): the first occurrence stands and the
			// rest are discarded, unexamined.
			name:      "duplicate ORIGIN",
			attrs:     concat(originAttr(), asPathAttr(), nextHopAttr(), attrBytes(AttrFlagTransitive, AttrOrigin, 0x01)),
			nlri:      v4NLRI(),
			discarded: RawAttributes{{Flags: AttrFlagTransitive, Type: AttrOrigin, Data: []byte{0x01}}},
			kept:      3,
		},
		{
			// RFC 7606, section 7.6: ATOMIC_AGGREGATE bears on no route
			// selection, so its malformation costs only itself.
			name:      "ATOMIC_AGGREGATE non-empty",
			attrs:     concat(originAttr(), asPathAttr(), nextHopAttr(), attrBytes(AttrFlagTransitive, AttrAtomicAggregate, 0x00)),
			nlri:      v4NLRI(),
			discarded: RawAttributes{{Flags: AttrFlagTransitive, Type: AttrAtomicAggregate, Data: []byte{0x00}}},
			kept:      3,
		},
		{
			// RFC 7606, section 7.7: the two-octet AGGREGATOR of a speaker
			// without four-octet ASNs, which this package does not accept.
			name:      "AGGREGATOR two-octet form",
			attrs:     concat(originAttr(), asPathAttr(), nextHopAttr(), shortAggregatorAttr()),
			nlri:      v4NLRI(),
			discarded: RawAttributes{{Flags: AttrFlagOptional | AttrFlagTransitive, Type: AttrAggregator, Data: shortAggregatorAttr()[3:]}},
			kept:      3,
		},
		{
			// Every attribute discarded leaves the list empty, which is
			// nil: the same shape an UPDATE which carried none has.
			name:      "every attribute discarded",
			attrs:     wellKnownAggregatorAttr(),
			discarded: RawAttributes{{Flags: AttrFlagTransitive, Type: AttrAggregator, Data: wellKnownAggregatorAttr()[3:]}},
		},
		{
			// RFC 7606, section 3(h): a discard and a withdraw at once are
			// the withdraw, and the attribute is still recorded.
			name:      "attribute discard beside treat-as-withdraw",
			attrs:     concat(originAttr(), asPathAttr(), nextHopAttr(), attrBytes(AttrFlagTransitive, AttrAtomicAggregate, 0x00), shortMEDAttr()),
			nlri:      v4NLRI(),
			subcode:   SubcodeAttributeLengthError,
			data:      shortMEDAttr(),
			discarded: RawAttributes{{Flags: AttrFlagTransitive, Type: AttrAtomicAggregate, Data: []byte{0x00}}},
			kept:      4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := ParseMessage(testMessage(MessageTypeUpdate, updateBody(tt.attrs, tt.nlri)))
			if err != nil {
				t.Fatalf("failed to parse UPDATE: %v", err)
			}

			u := r.Message.(*Update)

			if tt.subcode == 0 {
				if r.Diagnostics != nil && r.Diagnostics.Malformed != nil {
					t.Fatalf("unexpected treat-as-withdraw mark: %v", r.Diagnostics.Malformed)
				}
			} else {
				if r.Diagnostics == nil {
					t.Fatal("no diagnostics for a treat-as-withdraw UPDATE")
				}

				wantMessageError(t, r.Diagnostics.Malformed, NotificationUpdateMessageError, tt.subcode, tt.data)
			}

			var discarded RawAttributes
			if r.Diagnostics != nil {
				discarded = r.Diagnostics.Discarded
			}

			if d := diff(t, tt.discarded, discarded); d != "" {
				t.Fatalf("unexpected discarded attributes (-want +got):\n%s", d)
			}

			// A discarded attribute is gone from Attributes, and every
			// other one is left exactly as parsed.
			if n := len(u.Attributes); n != tt.kept {
				t.Fatalf("unexpected attributes kept: got %d, want %d", n, tt.kept)
			}

			if tt.kept == 0 && u.Attributes != nil {
				t.Fatal("an emptied attribute list must be nil, not an empty slice")
			}
		})
	}
}

// TestNewEndOfRIB proves the constructor's markers survive the wire and are
// recognized by their reader counterpart, Update.EndOfRIB.
func TestNewEndOfRIB(t *testing.T) {
	t.Parallel()

	families := []Family{
		{AFI: AFIIPv4, SAFI: SAFIUnicast},
		{AFI: AFIIPv6, SAFI: SAFIUnicast},
		{AFI: AFIIPv6, SAFI: SAFIMulticast},
	}

	for _, f := range families {
		b, err := NewEndOfRIB(f).AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to marshal End-of-RIB for %v: %v", f, err)
		}

		r, err := ParseMessage(b)
		if err != nil {
			t.Fatalf("failed to parse End-of-RIB for %v: %v", f, err)
		}

		family, ok := r.Message.(*Update).EndOfRIB()
		if !ok {
			t.Fatalf("marker for %v did not round trip as End-of-RIB", f)
		}

		if family != f {
			t.Fatalf("unexpected End-of-RIB family: got %v, want %v", family, f)
		}
	}
}

func TestUpdateEndOfRIB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		u      *Update
		family Family
		ok     bool
	}{
		{
			name:   "IPv4 unicast",
			u:      &Update{},
			family: Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
			ok:     true,
		},
		{
			name: "IPv6 unicast",
			u: &Update{Attributes: []RawAttribute{{
				Flags: AttrFlagOptional,
				Type:  AttrMPUnreachNLRI,
				Data:  []byte{0x00, 0x02, 0x01},
			}}},
			family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			ok:     true,
		},
		{
			// An add-path session's empty-looking UPDATE is only a marker
			// when the path fields are empty too.
			name: "path fields carry content",
			u: &Update{NLRIPaths: PathPrefixes{
				{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24")},
			}},
		},
		{
			name: "MP unreach with withdrawn prefixes",
			u: &Update{Attributes: []RawAttribute{{
				Flags: AttrFlagOptional,
				Type:  AttrMPUnreachNLRI,
				Data:  []byte{0x00, 0x02, 0x01, 32, 0x20, 0x01, 0x0d, 0xb8},
			}}},
		},
		{
			name: "MP unreach with another attribute",
			u: &Update{Attributes: []RawAttribute{
				{
					Flags: AttrFlagOptional,
					Type:  AttrMPUnreachNLRI,
					Data:  []byte{0x00, 0x02, 0x01},
				},
				{
					Flags: AttrFlagTransitive,
					Type:  AttrLocalPref,
					Data:  []byte{0x00, 0x00, 0x00, 0xc8},
				},
			}},
		},
		{
			name: "attribute is not MP unreach",
			u: &Update{Attributes: []RawAttribute{{
				Flags: AttrFlagTransitive,
				Type:  AttrLocalPref,
				Data:  []byte{0x00, 0x00, 0x00, 0xc8},
			}}},
		},
		{
			name: "withdrawn routes present",
			u:    &Update{Withdrawn: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		},
		{
			name: "prefixes present",
			u:    &Update{NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			family, ok := tt.u.EndOfRIB()
			if ok != tt.ok {
				t.Fatalf("unexpected End-of-RIB: got %v, want %v", ok, tt.ok)
			}

			if d := diff(t, tt.family, family); d != "" {
				t.Fatalf("unexpected family (-want +got):\n%s", d)
			}
		})
	}
}

// updateBody frames an UPDATE message body around hand-built path attribute
// and NLRI bytes, with no withdrawn routes. The Total Attribute Length
// covers attrs exactly, so a truncated attribute inside it is RFC 7606,
// section 4's error rather than a framing error of the message.
func updateBody(attrs, nlri []byte) []byte {
	b := binary.BigEndian.AppendUint16([]byte{0x00, 0x00}, uint16(len(attrs)))
	b = append(b, attrs...)
	return append(b, nlri...)
}

// attrBytes encodes one path attribute in compact length form: the wire
// scaffolding of a hand-built UPDATE body.
func attrBytes(flags AttrFlags, typ AttrType, data ...byte) []byte {
	return append([]byte{byte(flags), byte(typ), byte(len(data))}, data...)
}

// concat joins wire fragments into one attribute field.
func concat(bs ...[]byte) []byte {
	var b []byte
	for _, x := range bs {
		b = append(b, x...)
	}

	return b
}

// The canonical wire form of each attribute a hand-built UPDATE body needs,
// well formed unless the name says otherwise. Each returns a fresh slice, so
// a case may hand the same bytes to both the body and the expected
// diagnostic data.
func originAttr() []byte { return attrBytes(AttrFlagTransitive, AttrOrigin, 0x00) }

func optionalOriginAttr() []byte {
	return attrBytes(AttrFlagOptional|AttrFlagTransitive, AttrOrigin, 0x00)
}

// asPathAttr is one AS_SEQUENCE naming the private ASN 64512.
func asPathAttr() []byte {
	return attrBytes(AttrFlagTransitive, AttrASPath, 0x02, 0x01, 0x00, 0x00, 0xfc, 0x00)
}

func nextHopAttr() []byte { return attrBytes(AttrFlagTransitive, AttrNextHop, 192, 0, 2, 1) }

func partialNextHopAttr() []byte {
	return attrBytes(AttrFlagTransitive|AttrFlagPartial, AttrNextHop, 192, 0, 2, 1)
}

// shortMEDAttr is a MULTI_EXIT_DISC one byte short of its fixed length.
func shortMEDAttr() []byte { return attrBytes(AttrFlagOptional, AttrMED, 0x00, 0x00, 0x00) }

// wellKnownAggregatorAttr is an AGGREGATOR whose Optional bit is clear,
// which its specification requires be set.
func wellKnownAggregatorAttr() []byte {
	return attrBytes(AttrFlagTransitive, AttrAggregator, 0x00, 0x00, 0xfc, 0x00, 192, 0, 2, 1)
}

// shortAggregatorAttr is the two-octet ASN form of AGGREGATOR, which a
// session this package speaks never negotiates.
func shortAggregatorAttr() []byte {
	return attrBytes(AttrFlagOptional|AttrFlagTransitive, AttrAggregator, 0xfc, 0x00, 192, 0, 2, 1)
}

// unknownWellKnownAttr is an attribute of a type this package does not
// interpret whose Optional bit is clear, which makes it well known.
func unknownWellKnownAttr() []byte { return attrBytes(AttrFlagTransitive, AttrType(200), 0x00) }

// unknownOptionalAttr is an optional transitive attribute of a type this
// package does not interpret.
func unknownOptionalAttr() []byte {
	return attrBytes(AttrFlagOptional|AttrFlagTransitive, AttrType(200), 0x00)
}

// partialAggregatorAttr is a well-formed AGGREGATOR with the Partial bit
// set, which its optional transitive flags allow.
func partialAggregatorAttr() []byte {
	return attrBytes(AttrFlagOptional|AttrFlagTransitive|AttrFlagPartial, AttrAggregator, 0x00, 0x00, 0xfc, 0x00, 192, 0, 2, 1)
}

func mpReachAttr() []byte {
	data, err := MPReachNLRI{
		Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
		NextHop: netip.MustParseAddr("2001:db8::1"),
		NLRI:    Prefixes{netip.MustParsePrefix("2001:db8:1::/48")},
	}.appendData(nil)
	if err != nil {
		panic("bgp: failed to encode MP_REACH_NLRI: " + err.Error())
	}

	return attrBytes(AttrFlagOptional, AttrMPReachNLRI, data...)
}

func mpUnreachAttr() []byte {
	return attrBytes(AttrFlagOptional, AttrMPUnreachNLRI, 0x00, 0x02, 0x01)
}

// v4NLRI is one IPv4 unicast prefix for the legacy NLRI field, 203.0.113.0/24.
func v4NLRI() []byte { return []byte{24, 203, 0, 113} }
