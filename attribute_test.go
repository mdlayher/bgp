package bgp

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"testing"
)

func TestRawAttributeParseRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		attr Attribute
		raw  RawAttribute
	}{
		{
			name: "origin",
			attr: OriginEGP,
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrOrigin,
				Data:  []byte{0x01},
			},
		},
		{
			name: "AS path",
			attr: ASPath{
				{ASNs: []uint32{64496, 65536}},
				{Set: true, ASNs: []uint32{64497}},
			},
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrASPath,
				Data: []byte{
					0x02, 0x02, // AS_SEQUENCE, 2 ASNs
					0x00, 0x00, 0xfb, 0xf0,
					0x00, 0x01, 0x00, 0x00,
					0x01, 0x01, // AS_SET, 1 ASN
					0x00, 0x00, 0xfb, 0xf1,
				},
			},
		},
		{
			name: "empty AS path",
			attr: ASPath(nil),
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrASPath,
			},
		},
		{
			name: "next hop",
			attr: NextHop(netip.MustParseAddr("192.0.2.1")),
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrNextHop,
				Data:  []byte{192, 0, 2, 1},
			},
		},
		{
			name: "multi exit disc",
			attr: MED(100),
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMED,
				Data:  []byte{0x00, 0x00, 0x00, 0x64},
			},
		},
		{
			name: "local pref",
			attr: LocalPref(200),
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrLocalPref,
				Data:  []byte{0x00, 0x00, 0x00, 0xc8},
			},
		},
		{
			name: "atomic aggregate",
			attr: AtomicAggregate{},
			raw: RawAttribute{
				Flags: AttrFlagTransitive,
				Type:  AttrAtomicAggregate,
			},
		},
		{
			name: "aggregator",
			attr: Aggregator{ASN: 65536, ID: MustParseIdentifier("192.0.2.1")},
			raw: RawAttribute{
				Flags: AttrFlagOptional | AttrFlagTransitive,
				Type:  AttrAggregator,
				Data:  []byte{0x00, 0x01, 0x00, 0x00, 192, 0, 2, 1},
			},
		},
		{
			name: "communities",
			attr: Communities{NewCommunity(64496, 100)},
			raw: RawAttribute{
				Flags: AttrFlagOptional | AttrFlagTransitive,
				Type:  AttrCommunities,
				Data:  []byte{0xfb, 0xf0, 0x00, 0x64},
			},
		},
		{
			name: "originator ID",
			attr: OriginatorID(MustParseIdentifier("192.0.2.1")),
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrOriginatorID,
				Data:  []byte{192, 0, 2, 1},
			},
		},
		{
			name: "cluster list",
			attr: ClusterList{
				MustParseIdentifier("192.0.2.2"),
				MustParseIdentifier("192.0.2.3"),
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrClusterList,
				Data:  []byte{192, 0, 2, 2, 192, 0, 2, 3},
			},
		},
		{
			name: "extended communities",
			attr: ExtendedCommunities{
				// RT:64496:100, two-octet AS specific.
				{0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64},
				// SoO:192.0.2.1:100, IPv4 address specific.
				{0x01, 0x03, 192, 0, 2, 1, 0x00, 0x64},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional | AttrFlagTransitive,
				Type:  AttrExtendedCommunities,
				Data: []byte{
					0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64,
					0x01, 0x03, 192, 0, 2, 1, 0x00, 0x64,
				},
			},
		},
		{
			name: "large communities",
			attr: LargeCommunities{{Global: 65536, Local1: 1, Local2: 2}},
			raw: RawAttribute{
				Flags: AttrFlagOptional | AttrFlagTransitive,
				Type:  AttrLargeCommunities,
				Data: []byte{
					0x00, 0x01, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x02,
				},
			},
		},
		{
			name: "only to customer",
			attr: OTC(64496),
			raw: RawAttribute{
				Flags: AttrFlagOptional | AttrFlagTransitive,
				Type:  AttrOTC,
				Data:  []byte{0x00, 0x00, 0xfb, 0xf0},
			},
		},
		{
			name: "MP reach IPv6",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    Prefixes{netip.MustParsePrefix("2001:db8::/32")},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x01, // IPv6 unicast
					16, // next hop length
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,                       // reserved
					32, 0x20, 0x01, 0x0d, 0xb8, // 2001:db8::/32
				},
			},
		},
		{
			name: "MP reach IPv6 link local",
			attr: MPReachNLRI{
				Family:    Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop:   netip.MustParseAddr("2001:db8::1"),
				LinkLocal: netip.MustParseAddr("fe80::1"),
				NLRI:      Prefixes{netip.MustParsePrefix("::/0")},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x01,
					32,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,
					0, // ::/0
				},
			},
		},
		{
			name: "MP reach RFC 8950 IPv4 via IPv6",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    Prefixes{netip.MustParsePrefix("203.0.113.0/24")},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x01, 0x01, // IPv4 unicast
					16,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,
					24, 203, 0, 113,
				},
			},
		},
		{
			name: "MP unreach IPv6 end-of-RIB",
			attr: MPUnreachNLRI{
				Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPUnreachNLRI,
				Data:  []byte{0x00, 0x02, 0x01},
			},
		},
		{
			// One RFC 7432, section 7.3 Inclusive Multicast Ethernet Tag
			// route: a route distinguisher, an Ethernet tag, and the
			// originating router's IP. The value is opaque to this package;
			// it is spelled out here so the framing around it is pinned to
			// real EVPN bytes rather than to filler.
			name: "MP reach L2VPN EVPN",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
				NextHop: netip.MustParseAddr("192.0.2.1"),
				NLRI: EVPNRoutes{{
					Type: EVPNRouteInclusiveMulticastEthernetTag,
					Value: []byte{
						0x00, 0x02, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x01,
						0x00, 0x00, 0x00, 0x64,
						32,
						192, 0, 2, 1,
					},
				}},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x19, 0x46,
					4, 192, 0, 2, 1,
					0x00,
					3, 17,
					0x00, 0x02, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x64,
					32,
					192, 0, 2, 1,
				},
			},
		},
		{
			// A VPN-IPv4 route (RFC 4364): the next hop rides behind a zero
			// route distinguisher this package strips and restores, and the
			// label-and-RD-prefixed NLRI is unmodeled, carried verbatim.
			name: "MP reach VPN-IPv4",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv4, SAFI: SAFIMPLSVPN},
				NextHop: netip.MustParseAddr("192.0.2.1"),
				NLRI: RawNLRI{
					112,
					0x00, 0x01, 0x31,
					0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01,
					192, 0, 2,
				},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x01, 0x80,
					12,
					0, 0, 0, 0, 0, 0, 0, 0,
					192, 0, 2, 1,
					0x00,
					112,
					0x00, 0x01, 0x31,
					0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01,
					192, 0, 2,
				},
			},
		},
		{
			// RFC 4659, section 3.2.1.1: a single VPN-IPv6 next hop is the
			// 24 byte form, an 8 byte zero route distinguisher this package
			// strips and restores ahead of the 16 byte address.
			name: "MP reach VPN-IPv6",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIMPLSVPN},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    RawNLRI{120, 0x00, 0x01, 0x31, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x80, // VPN-IPv6
					24, // next hop length: RD + IPv6
					0, 0, 0, 0, 0, 0, 0, 0,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00, // reserved
					120, 0x00, 0x01, 0x31, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
				},
			},
		},
		{
			// A VPN-IPv6 next hop with a link-local alongside is the 48
			// byte form of RFC 4659, section 3.2.1.1: each address behind
			// its own zero route distinguisher.
			name: "MP reach VPN-IPv6 link local",
			attr: MPReachNLRI{
				Family:    Family{AFI: AFIIPv6, SAFI: SAFIMPLSVPN},
				NextHop:   netip.MustParseAddr("2001:db8::1"),
				LinkLocal: netip.MustParseAddr("fe80::1"),
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x80,
					48,
					0, 0, 0, 0, 0, 0, 0, 0,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0, 0, 0, 0, 0, 0, 0, 0,
					0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,
				},
			},
		},
		{
			// A flowspec UPDATE (RFC 8955) carries no next hop at all:
			// length zero, an absent next hop, a zero netip.Addr. The rule
			// itself is unmodeled NLRI, carried verbatim.
			name: "MP reach absent next hop",
			attr: MPReachNLRI{
				Family: Family{AFI: AFIIPv4, SAFI: 133},
				NLRI:   RawNLRI{0x05, 0x01, 0x18, 192, 0, 2},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x01, 0x85,
					0,
					0x00,
					0x05, 0x01, 0x18, 192, 0, 2,
				},
			},
		},
		{
			// L2VPN VPLS is deliberately unmodeled (RFC 4761), so its NLRI
			// is carried verbatim: an unmodeled family survives parse and
			// re-marshal byte for byte rather than failing.
			name: "MP unreach unmodeled family",
			attr: MPUnreachNLRI{
				Family: Family{AFI: AFIL2VPN, SAFI: SAFIVPLS},
				NLRI: RawNLRI{
					0x00, 0x11,
					0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01,
					0x00, 0x01,
					0x00, 0x01,
					0x00, 0x08,
					0x00, 0x06, 0x41,
				},
			},
			raw: RawAttribute{
				Flags: AttrFlagOptional,
				Type:  AttrMPUnreachNLRI,
				Data: []byte{
					0x00, 0x19, 0x41,
					0x00, 0x11,
					0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01,
					0x00, 0x01,
					0x00, 0x01,
					0x00, 0x08,
					0x00, 0x06, 0x41,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ras, err := MarshalAttributes(tt.attr)
			if err != nil {
				t.Fatalf("failed to marshal attribute: %v", err)
			}

			if d := diff(t, []RawAttribute{tt.raw}, ras); d != "" {
				t.Fatalf("unexpected raw attribute (-want +got):\n%s", d)
			}

			got, err := ras[0].Parse()
			if err != nil {
				t.Fatalf("failed to parse attribute: %v", err)
			}

			if d := diff(t, tt.attr, got); d != "" {
				t.Fatalf("unexpected attribute (-want +got):\n%s", d)
			}
		})
	}
}

func TestASPathLongSequenceSplits(t *testing.T) {
	t.Parallel()

	// A single AS_SEQUENCE longer than 255 ASNs is encoded as multiple
	// wire segments, which is how it parses back.
	asns := make([]uint32, 300)
	for i := range asns {
		asns[i] = uint32(i + 1)
	}

	ras, err := MarshalAttributes(ASPath{{ASNs: asns}})
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	attr, err := ras[0].Parse()
	if err != nil {
		t.Fatalf("failed to parse attribute: %v", err)
	}

	want := ASPath{{ASNs: asns[:255]}, {ASNs: asns[255:]}}
	if d := diff[Attribute](t, want, attr); d != "" {
		t.Fatalf("unexpected AS path (-want +got):\n%s", d)
	}
}

func TestASPathSegmentErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path ASPath
	}{
		{
			// An AS_SET is unordered and must not be split.
			name: "long set",
			path: ASPath{{Set: true, ASNs: make([]uint32, 256)}},
		},
		{
			name: "empty segment",
			path: ASPath{{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := MarshalAttributes(tt.path); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestRawAttributeParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		a       RawAttribute
		subcode uint8
	}{
		{
			name:    "origin length",
			a:       RawAttribute{Type: AttrOrigin, Data: []byte{0x00, 0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "origin value",
			a:       RawAttribute{Type: AttrOrigin, Data: []byte{0x03}},
			subcode: SubcodeInvalidOriginAttribute,
		},
		{
			name:    "AS path segment header truncated",
			a:       RawAttribute{Type: AttrASPath, Data: []byte{0x02}},
			subcode: SubcodeMalformedASPath,
		},
		{
			name:    "AS path segment type",
			a:       RawAttribute{Type: AttrASPath, Data: []byte{0x03, 0x01, 0, 0, 0xfb, 0xf0}},
			subcode: SubcodeMalformedASPath,
		},
		{
			name:    "AS path segment empty",
			a:       RawAttribute{Type: AttrASPath, Data: []byte{0x02, 0x00}},
			subcode: SubcodeMalformedASPath,
		},
		{
			name:    "AS path segment ASNs truncated",
			a:       RawAttribute{Type: AttrASPath, Data: []byte{0x02, 0x02, 0, 0, 0xfb, 0xf0}},
			subcode: SubcodeMalformedASPath,
		},
		{
			name:    "next hop length",
			a:       RawAttribute{Type: AttrNextHop, Data: []byte{192, 0, 2}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "multi exit disc length",
			a:       RawAttribute{Type: AttrMED, Data: []byte{0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "local pref length",
			a:       RawAttribute{Type: AttrLocalPref, Data: []byte{0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "atomic aggregate length",
			a:       RawAttribute{Type: AttrAtomicAggregate, Data: []byte{0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "aggregator length",
			a:       RawAttribute{Type: AttrAggregator, Data: []byte{0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "communities length",
			a:       RawAttribute{Type: AttrCommunities, Data: []byte{0x00, 0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "originator ID length",
			a:       RawAttribute{Type: AttrOriginatorID, Data: []byte{192, 0, 2}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "cluster list length",
			a:       RawAttribute{Type: AttrClusterList, Data: []byte{192, 0}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "extended communities length",
			a:       RawAttribute{Type: AttrExtendedCommunities, Data: []byte{0x00, 0x02}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "large communities length",
			a:       RawAttribute{Type: AttrLargeCommunities, Data: []byte{0x00, 0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "only to customer length",
			a:       RawAttribute{Type: AttrOTC, Data: []byte{0x00}},
			subcode: SubcodeAttributeLengthError,
		},
		{
			name:    "MP reach short",
			a:       RawAttribute{Type: AttrMPReachNLRI, Data: []byte{0x00, 0x02}},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach next hop truncated",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{0x00, 0x02, 0x01, 16, 0x20},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach next hop length",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{0x00, 0x02, 0x01, 5, 1, 2, 3, 4, 5, 0x00},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			// A VPN family's route distinguisher must be zero (RFC 4364,
			// 4.3.2): a nonzero one is information this package has no
			// field for precisely because the RFCs promise there is none.
			name: "MP reach VPN nonzero RD",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x01, 0x80,
					12,
					0, 0, 0, 0, 0, 0, 0, 1,
					192, 0, 2, 1,
					0x00,
				},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach VPN-IPv6 nonzero RD",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x80,
					24,
					0, 0, 0, 0, 0, 0, 0, 1,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,
				},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			// A VPN family's next hop is never a bare address: 16 bytes is
			// the unicast form, not the 24 byte RD-prefixed one.
			name: "MP reach VPN-IPv6 next hop without RD",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x02, 0x80,
					16,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0x00,
				},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach VPN nonzero link local RD",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: append(append([]byte{
					0x00, 0x02, 0x80,
					48,
					0, 0, 0, 0, 0, 0, 0, 0,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0, 0, 0, 0, 0, 0, 0, 1,
				}, bytes.Repeat([]byte{0}, 16)...), 0x00),
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			// A bare 4 byte next hop in a VPN family: parse accepts exactly
			// the lengths marshal produces for the family, or the fixed
			// point would not hold.
			name: "MP reach VPN bare next hop",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{0x00, 0x01, 0x80, 4, 192, 0, 2, 1, 0x00},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach unicast RD next hop",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{
					0x00, 0x01, 0x01,
					12,
					0, 0, 0, 0, 0, 0, 0, 0,
					192, 0, 2, 1,
					0x00,
				},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			// An EVPN record whose length overruns the attribute: the
			// framing this package does own, failing at the attribute layer
			// so the erroneous attribute is echoed per RFC 4271, 6.3.
			name: "MP reach EVPN record truncated",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{0x00, 0x19, 0x46, 4, 192, 0, 2, 1, 0x00, 2, 8, 0xde, 0xad},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP reach prefix truncated",
			a: RawAttribute{
				Type: AttrMPReachNLRI,
				Data: []byte{0x00, 0x01, 0x01, 4, 192, 0, 2, 1, 0x00, 24, 203},
			},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name:    "MP unreach short",
			a:       RawAttribute{Type: AttrMPUnreachNLRI, Data: []byte{0x00, 0x02}},
			subcode: SubcodeOptionalAttributeError,
		},
		{
			name: "MP unreach prefix length",
			a: RawAttribute{
				Type: AttrMPUnreachNLRI,
				Data: []byte{0x00, 0x02, 0x01, 129},
			},
			subcode: SubcodeOptionalAttributeError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.a.Parse()

			// Attribute errors carry the erroneous attribute itself as
			// diagnostic data, per RFC 4271, section 6.3.
			data, aerr := appendRawAttribute(nil, tt.a)
			if aerr != nil {
				t.Fatalf("failed to reconstruct attribute: %v", aerr)
			}

			wantMessageError(t, err, NotificationUpdateMessageError, tt.subcode, data)
		})
	}
}

func TestRawAttributeParseUnknownType(t *testing.T) {
	t.Parallel()

	// An unknown attribute type is not a protocol error: no NOTIFICATION
	// must be sent in response, so the error is not a MessageError.
	_, err := (RawAttribute{Type: AttrType(255)}).Parse()
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	if merr, ok := errors.AsType[*MessageError](err); ok {
		t.Fatalf("expected a plain error, but got: %v", merr)
	}
}

func TestParseRawAttributesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "header truncated",
			b:    []byte{0x40, 0x01},
		},
		{
			name: "extended length truncated",
			b:    []byte{byte(attrFlagExtendedLength), 0x01, 0x00},
		},
		{
			name: "data truncated",
			b:    []byte{0x40, 0x01, 0x02, 0x00},
		},
		{
			name: "extended length data truncated",
			b:    []byte{byte(attrFlagExtendedLength), 0x01, 0x01, 0x00, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseRawAttributes(tt.b)
			wantMessageError(t, err, NotificationUpdateMessageError, SubcodeMalformedAttributeList, nil)
		})
	}
}

func TestParseRawAttributesExtendedLengthNormalized(t *testing.T) {
	t.Parallel()

	// A wire attribute may carry the extended length flag even when its
	// data would fit a 1 byte length. The flag is a wire detail: parsing
	// clears it, and marshaling re-encodes in compact form.
	attrs, err := parseRawAttributes([]byte{
		byte(AttrFlagTransitive | attrFlagExtendedLength), byte(AttrOrigin),
		0x00, 0x01, // extended length 1
		0x00,
	})
	if err != nil {
		t.Fatalf("failed to parse attributes: %v", err)
	}

	want := []RawAttribute{{
		Flags: AttrFlagTransitive,
		Type:  AttrOrigin,
		Data:  []byte{0x00},
	}}
	if d := diff(t, want, attrs); d != "" {
		t.Fatalf("unexpected attributes (-want +got):\n%s", d)
	}

	b, err := appendRawAttribute(nil, attrs[0])
	if err != nil {
		t.Fatalf("failed to marshal attribute: %v", err)
	}

	wantB := []byte{byte(AttrFlagTransitive), byte(AttrOrigin), 0x01, 0x00}
	if d := diff(t, wantB, b); d != "" {
		t.Fatalf("unexpected attribute bytes (-want +got):\n%s", d)
	}
}

func TestRawAttributeExtendedLengthRoundTrip(t *testing.T) {
	t.Parallel()

	// Data longer than 255 bytes requires the extended length encoding.
	a := RawAttribute{
		Flags: AttrFlagOptional | AttrFlagTransitive,
		Type:  AttrType(200),
		Data:  bytes.Repeat([]byte{0xaa}, 300),
	}

	b, err := appendRawAttribute(nil, a)
	if err != nil {
		t.Fatalf("failed to marshal attribute: %v", err)
	}

	if n := len(b); n != 4+300 {
		t.Fatalf("unexpected extended length encoding size: %d", n)
	}

	attrs, err := parseRawAttributes(b)
	if err != nil {
		t.Fatalf("failed to parse attributes: %v", err)
	}

	if d := diff(t, []RawAttribute{a}, attrs); d != "" {
		t.Fatalf("unexpected attributes (-want +got):\n%s", d)
	}
}

func TestRawAttributeDataTooLarge(t *testing.T) {
	t.Parallel()

	a := RawAttribute{Data: make([]byte, math.MaxUint16+1)}
	if _, err := appendRawAttribute(nil, a); err == nil {
		t.Fatal("expected an error, but none occurred")
	}
}

func TestMarshalAttributesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		attr Attribute
	}{
		{
			name: "origin invalid",
			attr: Origin(3),
		},
		{
			name: "next hop not IPv4",
			attr: NextHop(netip.MustParseAddr("2001:db8::1")),
		},
		{
			name: "next hop zero",
			attr: NextHop{},
		},
		{
			name: "MP reach next hops invalid",
			attr: MPReachNLRI{
				Family:    Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop:   netip.MustParseAddr("192.0.2.1"),
				LinkLocal: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			name: "MP reach prefix family mismatch",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    Prefixes{netip.MustParsePrefix("192.0.2.0/24")},
			},
		},
		{
			name: "MP unreach prefixes in a non-prefix family",
			attr: MPUnreachNLRI{
				Family: Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
				NLRI:   Prefixes{netip.MustParsePrefix("192.0.2.0/24")},
			},
		},
		{
			name: "MP reach EVPN routes in a prefix family",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    EVPNRoutes{{Type: EVPNRouteIPPrefix}},
			},
		},
		{
			name: "MP reach EVPN route value too long",
			attr: MPReachNLRI{
				Family:  Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
				NextHop: netip.MustParseAddr("192.0.2.1"),
				NLRI: EVPNRoutes{{
					Type:  EVPNRouteMACIPAdvertisement,
					Value: make([]byte, 256),
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := MarshalAttributes(tt.attr); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestNewExtendedCommunities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		c    ExtendedCommunity
		err  error
		want ExtendedCommunity
		s    string
	}{
		{
			name: "RT two-octet AS",
			c:    must(NewRouteTarget(64496, 100)),
			want: ExtendedCommunity{0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64},
			s:    "RT:64496:100",
		},
		{
			name: "RT four-octet AS",
			c:    must(NewRouteTarget(65536, 100)),
			want: ExtendedCommunity{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64},
			s:    "RT:65536:100",
		},
		{
			name: "SoO two-octet AS",
			c:    must(NewRouteOrigin(64496, 100)),
			want: ExtendedCommunity{0x00, 0x03, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64},
			s:    "SoO:64496:100",
		},
		{
			name: "validation state valid",
			c:    NewValidationState(ValidationStateValid),
			want: ExtendedCommunity{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			s:    "OVS:valid",
		},
		{
			name: "validation state not found",
			c:    NewValidationState(ValidationStateNotFound),
			want: ExtendedCommunity{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			s:    "OVS:not-found",
		},
		{
			name: "validation state invalid",
			c:    NewValidationState(ValidationStateInvalid),
			want: ExtendedCommunity{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			s:    "OVS:invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.want, tt.c); d != "" {
				t.Fatalf("unexpected community bytes (-want +got):\n%s", d)
			}

			if got := tt.c.String(); got != tt.s {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.s)
			}
		})
	}
}

func TestASPathOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    ASPath
		want OriginAS
	}{
		{name: "empty", want: OriginAS{Empty: true}},
		{
			name: "single sequence",
			p:    ASPath{{ASNs: []uint32{64496, 65536}}},
			want: OriginAS{ASN: 65536},
		},
		{
			name: "set then sequence",
			p:    ASPath{{Set: true, ASNs: []uint32{64496, 64497}}, {ASNs: []uint32{65536}}},
			want: OriginAS{ASN: 65536},
		},
		{
			name: "sequence then set",
			p:    ASPath{{ASNs: []uint32{64496}}, {Set: true, ASNs: []uint32{65536, 65537}}},
			want: OriginAS{Set: true},
		},
		{
			name: "empty final segment",
			p:    ASPath{{ASNs: []uint32{64496}}, {}},
			want: OriginAS{Empty: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.want, tt.p.Origin()); d != "" {
				t.Fatalf("unexpected origin (-want +got):\n%s", d)
			}
		})
	}
}

func TestExtendedCommunityValidationState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		c    ExtendedCommunity
		want ValidationState
		ok   bool
	}{
		{name: "valid", c: NewValidationState(ValidationStateValid), want: ValidationStateValid, ok: true},
		{name: "invalid", c: NewValidationState(ValidationStateInvalid), want: ValidationStateInvalid, ok: true},
		{
			// RFC 8097 reserves the leading value bytes; a state outside the
			// registry is carried, not judged.
			name: "unknown state",
			c:    ExtendedCommunity{0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
			want: 7,
			ok:   true,
		},
		{name: "route target", c: must(NewRouteTarget(64496, 100))},
		{
			// The transitive opaque type is a different community.
			name: "transitive opaque",
			c:    ExtendedCommunity{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tt.c.ValidationState()
			if ok != tt.ok || got != tt.want {
				t.Fatalf("unexpected state: got (%s, %v), want (%s, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}

	if s := ValidationState(7).String(); s != "unknown(7)" {
		t.Fatalf("unexpected unknown state string: %q", s)
	}
}

func TestNewRouteTargetValueOverflow(t *testing.T) {
	t.Parallel()

	// A four-octet AS specific community only has 2 bytes for its value.
	if _, err := NewRouteTarget(65536, 65536); err == nil {
		t.Fatal("expected an error, but none occurred")
	}
}

func TestAttributeStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "origin IGP", s: OriginIGP.String(), want: "IGP"},
		{name: "origin EGP", s: OriginEGP.String(), want: "EGP"},
		{name: "origin incomplete", s: OriginIncomplete.String(), want: "incomplete"},
		{name: "origin unknown", s: Origin(5).String(), want: "unknown(5)"},
		{name: "community", s: NewCommunity(64496, 100).String(), want: "64496:100"},
		{
			name: "large community",
			s:    LargeCommunity{Global: 65536, Local1: 1, Local2: 2}.String(),
			want: "65536:1:2",
		},
		{
			name: "next hop",
			s:    NextHop(netip.MustParseAddr("192.0.2.1")).String(),
			want: "192.0.2.1",
		},
		{
			name: "originator ID",
			s:    OriginatorID(MustParseIdentifier("192.0.2.1")).String(),
			want: "192.0.2.1",
		},
		{
			name: "extended community RT two-octet AS",
			s:    ExtendedCommunity{0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64}.String(),
			want: "RT:64496:100",
		},
		{
			name: "extended community RT IPv4 address",
			s:    ExtendedCommunity{0x01, 0x02, 192, 0, 2, 1, 0x00, 0x64}.String(),
			want: "RT:192.0.2.1:100",
		},
		{
			name: "extended community RT four-octet AS",
			s:    ExtendedCommunity{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64}.String(),
			want: "RT:65536:100",
		},
		{
			name: "extended community SoO two-octet AS",
			s:    ExtendedCommunity{0x00, 0x03, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64}.String(),
			want: "SoO:64496:100",
		},
		{
			name: "extended community unknown",
			s:    ExtendedCommunity{0x05, 0x0a, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x64}.String(),
			want: "UNK:5:10:0x0000fbf00064",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.s != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", tt.s, tt.want)
			}
		})
	}
}

func FuzzRawAttributeParse(f *testing.F) {
	// Seed with the canonical encoding of every known attribute type, plus
	// real attributes from the route collector corpus.
	seeds := []Attribute{
		OriginIGP,
		ASPath{{ASNs: []uint32{64496, 65536}}, {Set: true, ASNs: []uint32{64497}}},
		NextHop(netip.MustParseAddr("192.0.2.1")),
		MED(100),
		LocalPref(200),
		AtomicAggregate{},
		Aggregator{ASN: 64496, ID: MustParseIdentifier("192.0.2.1")},
		Communities{NewCommunity(64496, 100)},
		OriginatorID(MustParseIdentifier("192.0.2.1")),
		ClusterList{MustParseIdentifier("192.0.2.2")},
		ExtendedCommunities{{0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64}},
		LargeCommunities{{Global: 65536, Local1: 1, Local2: 2}},
		OTC(64496),
		MPReachNLRI{
			Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    Prefixes{netip.MustParsePrefix("2001:db8::/32")},
		},
		MPUnreachNLRI{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
		MPReachNLRI{
			Family:  Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
			NextHop: netip.MustParseAddr("192.0.2.1"),
			NLRI: EVPNRoutes{{
				Type:  EVPNRouteEthernetSegment,
				Value: []byte{0x00, 0x02, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x01},
			}},
		},
		MPUnreachNLRI{
			Family: Family{AFI: AFIL2VPN, SAFI: SAFIVPLS},
			NLRI:   RawNLRI{0x00, 0x03, 0xde, 0xad, 0xbe},
		},
		MPReachNLRI{
			Family:  Family{AFI: AFIIPv4, SAFI: SAFIMPLSVPN},
			NextHop: netip.MustParseAddr("192.0.2.1"),
			NLRI:    RawNLRI{112, 0x00, 0x01, 0x31, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01, 192, 0, 2},
		},
	}

	ras, err := MarshalAttributes(seeds...)
	if err != nil {
		f.Fatalf("failed to marshal seeds: %v", err)
	}

	for _, a := range ras {
		f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
	}

	for _, b := range corpusSeeds(f) {
		m, err := ParseMessage(b)
		if err != nil {
			f.Fatalf("failed to parse corpus message: %v", err)
		}

		if u, ok := m.(*Update); ok {
			for _, a := range u.Attributes {
				f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
			}
		}
	}

	// Full-table RIB dump samples carry the rare and deprecated attribute
	// types the updates corpus lacks, plus RFC 6396's truncated
	// MP_REACH_NLRI form.
	for _, a := range ribSeeds(f) {
		f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
	}

	f.Fuzz(func(t *testing.T, flags, typ uint8, data []byte) {
		a := RawAttribute{Flags: AttrFlags(flags), Type: AttrType(typ), Data: data}

		attr, err := a.Parse()
		if err != nil {
			// Any MessageError must be an UPDATE Message Error whose
			// NOTIFICATION marshals, so a session can always answer the peer.
			if merr, ok := errors.AsType[*MessageError](err); ok {
				if merr.Code != NotificationUpdateMessageError {
					t.Fatalf("unexpected NOTIFICATION code: %s", merr.Code)
				}

				if _, err := merr.Notification().AppendBinary(nil); err != nil {
					t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
				}
			}

			return
		}

		// A parsed Attribute must never reference the input: scrambling the
		// input must not change how the attribute compares against a copy
		// parsed before the scramble.
		want, err := RawAttribute{
			Flags: a.Flags,
			Type:  a.Type,
			Data:  bytes.Clone(data),
		}.Parse()
		if err != nil {
			t.Fatalf("failed to parse cloned attribute: %v", err)
		}

		for i := range data {
			data[i] = ^data[i]
		}

		if d := diff(t, want, attr); d != "" {
			t.Fatalf("parsed attribute references its input (-want +got):\n%s", d)
		}

		// Parse must be a fixed point of marshaling, and a parsed Attribute
		// must always re-marshal.
		ras, err := MarshalAttributes(attr)
		if err != nil {
			t.Fatalf("failed to marshal parsed attribute: %v", err)
		}

		attr2, err := ras[0].Parse()
		if err != nil {
			t.Fatalf("failed to re-parse marshaled attribute: %v", err)
		}

		if d := diff(t, attr, attr2); d != "" {
			t.Fatalf("unexpected re-parsed attribute (-want +got):\n%s", d)
		}
	})
}

func TestRawAttributesParse(t *testing.T) {
	t.Parallel()

	// An attribute of a type this package does not interpret, carried as
	// RFC 4271 requires of unrecognized optional transitive attributes.
	unknown := RawAttribute{
		Flags: AttrFlagOptional | AttrFlagTransitive | AttrFlagPartial,
		Type:  AttrType(255),
		Data:  []byte{0xde, 0xad},
	}

	typed := []Attribute{
		OriginIGP,
		ASPath{{ASNs: []uint32{64496}}},
		NextHop(netip.MustParseAddr("192.0.2.1")),
	}

	raw, err := MarshalAttributes(typed...)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	raw = append(raw, unknown)

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		got, err := raw.Parse()
		if err != nil {
			t.Fatalf("failed to parse attributes: %v", err)
		}

		// The unknown attribute survives in raw form, in its place.
		want := append(append([]Attribute{}, typed...), unknown)
		if d := diff(t, want, got); d != "" {
			t.Fatalf("unexpected attributes (-want +got):\n%s", d)
		}

		// And marshals back unmodified alongside the typed attributes.
		back, err := MarshalAttributes(got...)
		if err != nil {
			t.Fatalf("failed to marshal parsed attributes: %v", err)
		}

		if d := diff(t, raw, back); d != "" {
			t.Fatalf("unexpected raw attributes (-want +got):\n%s", d)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		t.Parallel()

		bad := append(raw.Clone(), RawAttribute{
			Flags: AttrFlagTransitive,
			Type:  AttrOrigin,
			Data:  []byte{0x01, 0x02},
		})
		_, err := bad.Parse()
		if _, ok := errors.AsType[*MessageError](err); !ok {
			t.Fatalf("expected a MessageError, but got: %v", err)
		}
	})

	t.Run("nil", func(t *testing.T) {
		t.Parallel()

		got, err := RawAttributes(nil).Parse()
		if err != nil || got != nil {
			t.Fatalf("expected nil, nil, but got: %v, %v", got, err)
		}
	})
}

func TestRawAttributesFind(t *testing.T) {
	t.Parallel()

	raw, err := MarshalAttributes(OriginIGP, LocalPref(100), LocalPref(200))
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	// The first of a duplicated type wins, like RFC 7606's treatment.
	got, ok := raw.Find(AttrLocalPref)
	if !ok {
		t.Fatal("expected to find LOCAL_PREF")
	}

	if d := diff(t, raw[1], got); d != "" {
		t.Fatalf("unexpected attribute (-want +got):\n%s", d)
	}

	if _, ok := raw.Find(AttrASPath); ok {
		t.Fatal("expected not to find AS_PATH")
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()

	raw, err := MarshalAttributes(
		OriginIGP,
		ASPath{{ASNs: []uint32{64496, 64497}}},
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		t.Parallel()

		got, ok, err := Lookup[ASPath](raw)
		if err != nil {
			t.Fatalf("failed to look up AS_PATH: %v", err)
		}

		if !ok {
			t.Fatal("expected to find AS_PATH")
		}

		if d := diff(t, ASPath{{ASNs: []uint32{64496, 64497}}}, got); d != "" {
			t.Fatalf("unexpected AS_PATH (-want +got):\n%s", d)
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		got, ok, err := Lookup[LocalPref](raw)
		if err != nil || ok || got != 0 {
			t.Fatalf("expected the zero value and not found, but got: %v, %v, %v", got, ok, err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		t.Parallel()

		bad := RawAttributes{{Flags: AttrFlagTransitive, Type: AttrOrigin, Data: []byte{0xff}}}
		_, _, err := Lookup[Origin](bad)
		if _, ok := errors.AsType[*MessageError](err); !ok {
			t.Fatalf("expected a MessageError, but got: %v", err)
		}
	})

	t.Run("interface", func(t *testing.T) {
		t.Parallel()

		// The interface has no wire type of its own to look up.
		if _, _, err := Lookup[Attribute](raw); err == nil {
			t.Fatal("expected an error, but none occurred")
		}
	})

	t.Run("raw", func(t *testing.T) {
		t.Parallel()

		// Nor does a RawAttribute: type 0 is reserved and never present.
		if _, ok, err := Lookup[RawAttribute](raw); ok || err != nil {
			t.Fatalf("expected not found, but got: %v, %v", ok, err)
		}
	})
}

// must unwraps a value/error pair in test fixtures, panicking on error.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

// mustAttributes marshals attrs into raw form, failing the test on error.
func mustAttributes(tb testing.TB, attrs ...Attribute) []RawAttribute {
	tb.Helper()

	ras, err := MarshalAttributes(attrs...)
	if err != nil {
		tb.Fatalf("failed to marshal attributes: %v", err)
	}

	return ras
}
