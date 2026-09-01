package bgp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestParseNLRIShape(t *testing.T) {
	t.Parallel()

	// One prefix's worth of bytes, which four of the families below decode
	// four different ways: the wire gives no hint of the shape, only the
	// family does, which is the whole point of the NLRI interface.
	pfx := []byte{24, 192, 0, 2}

	tests := []struct {
		name string
		f    Family
		b    []byte
		want NLRI
	}{
		{
			name: "IPv4 unicast",
			f:    Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
			want: Prefixes{netip.MustParsePrefix("192.0.2.0/24")},
		},
		{
			name: "IPv4 multicast",
			f:    Family{AFI: AFIIPv4, SAFI: SAFIMulticast},
			want: Prefixes{netip.MustParsePrefix("192.0.2.0/24")},
		},
		{
			// A labeled unicast route (RFC 8277) begins with a label, not a
			// prefix length, so decoding it as a prefix would silently
			// produce a wrong answer rather than no answer.
			name: "IPv4 unmodeled SAFI",
			f:    Family{AFI: AFIIPv4, SAFI: 4},
			want: RawNLRI(pfx),
		},
		{
			// EVPN gets its own bytes: a record's length byte falls where a
			// prefix's leading address byte does, so no short buffer is
			// valid as both a prefix list and a record list.
			name: "L2VPN EVPN",
			f:    Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
			b:    []byte{4, 2, 192, 0},
			want: EVPNRoutes{{Type: EVPNRouteEthernetSegment, Value: []byte{192, 0}}},
		},
		{
			name: "L2VPN VPLS",
			f:    Family{AFI: AFIL2VPN, SAFI: SAFIVPLS},
			want: RawNLRI(pfx),
		},
		{
			name: "unmodeled AFI",
			f:    Family{AFI: 16388, SAFI: 71},
			want: RawNLRI(pfx),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := tt.b
			if b == nil {
				b = pfx
			}

			got, err := parseNLRI(bytes.Clone(b), tt.f)
			if err != nil {
				t.Fatalf("failed to parse NLRI: %v", err)
			}

			if d := diff(t, tt.want, got); d != "" {
				t.Fatalf("unexpected NLRI (-want +got):\n%s", d)
			}
		})
	}
}

func TestParseNLRIEmptyIsNil(t *testing.T) {
	t.Parallel()

	// Nothing is spelled nil for every family, modeled or not, so a caller
	// may recognize an End-of-RIB marker without knowing the family's shape.
	for _, f := range []Family{
		{AFI: AFIIPv4, SAFI: SAFIUnicast},
		{AFI: AFIIPv6, SAFI: SAFIUnicast},
		{AFI: AFIL2VPN, SAFI: SAFIEVPN},
		{AFI: AFIL2VPN, SAFI: SAFIVPLS},
		{AFI: 16388, SAFI: 71},
	} {
		t.Run(f.String(), func(t *testing.T) {
			t.Parallel()

			got, err := parseNLRI(nil, f)
			if err != nil {
				t.Fatalf("failed to parse NLRI: %v", err)
			}

			if got != nil {
				t.Fatalf("expected a nil NLRI, but got: %#v", got)
			}
		})
	}
}

func TestParseEVPNRoutes(t *testing.T) {
	t.Parallel()

	// Two records back to back, the second empty: the framing is a type, a
	// length, and a value of exactly that length, and this package validates
	// nothing beyond it.
	b := []byte{
		2, 4, 0xde, 0xad, 0xbe, 0xef,
		5, 0,
	}

	got, err := parseEVPNRoutes(b)
	if err != nil {
		t.Fatalf("failed to parse EVPN routes: %v", err)
	}

	want := EVPNRoutes{
		{Type: EVPNRouteMACIPAdvertisement, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Type: EVPNRouteIPPrefix},
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected EVPN routes (-want +got):\n%s", d)
	}
}

func TestParseEVPNRoutesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "record header truncated",
			b:    []byte{2},
		},
		{
			name: "trailing record header truncated",
			b:    []byte{2, 1, 0xff, 5},
		},
		{
			name: "value truncated",
			b:    []byte{2, 4, 0xde, 0xad},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A malformed NLRI is only ever reachable inside a
			// multiprotocol attribute, so it is an Optional Attribute
			// Error; the attribute echo is attached by RawAttribute.Parse.
			_, err := parseEVPNRoutes(tt.b)
			wantMessageError(t, err, NotificationUpdateMessageError, SubcodeOptionalAttributeError, nil)
		})
	}
}

func TestNLRINeverAliasesBuffer(t *testing.T) {
	t.Parallel()

	// ParseMessage may alias its read buffer, and pays for it with
	// the rule that a parsed Attribute never does. The prefix shapes satisfy
	// it by decoding into netip values; the two byte-carrying shapes have to
	// clone, so pin that they do.
	tests := []struct {
		name string
		f    Family
		b    []byte
	}{
		{
			name: "EVPN routes",
			f:    Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
			b:    []byte{2, 4, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name: "raw NLRI",
			f:    Family{AFI: AFIL2VPN, SAFI: SAFIVPLS},
			b:    []byte{0x00, 0x11, 0xde, 0xad},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := bytes.Clone(tt.b)
			got, err := parseNLRI(buf, tt.f)
			if err != nil {
				t.Fatalf("failed to parse NLRI: %v", err)
			}

			// Reuse the buffer, exactly as Conn.ReadMessage would.
			want, err := parseNLRI(bytes.Clone(tt.b), tt.f)
			if err != nil {
				t.Fatalf("failed to reparse NLRI: %v", err)
			}

			for i := range buf {
				buf[i] = 0xff
			}

			if d := diff(t, want, got); d != "" {
				t.Fatalf("parsed NLRI changed with the buffer (-want +got):\n%s", d)
			}
		})
	}
}

func TestRawNLRIBelongsToAnyFamily(t *testing.T) {
	t.Parallel()

	// RawNLRI is the escape hatch, so it must not be fenced to the families
	// this package declines to model: a caller may use it to send a shape
	// this package models differently, such as the path-ID NLRI of RFC 7911
	// (unsupported; see rfc-status).
	raw := RawNLRI{0x00, 0x00, 0x00, 0x01, 24, 192, 0, 2}

	b, err := raw.appendNLRI(nil, Family{AFI: AFIIPv4, SAFI: SAFIUnicast})
	if err != nil {
		t.Fatalf("failed to append raw NLRI: %v", err)
	}

	if d := diff(t, []byte(raw), b); d != "" {
		t.Fatalf("unexpected raw NLRI bytes (-want +got):\n%s", d)
	}
}

func TestFamilyString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		f Family
		s string
	}{
		{f: Family{AFI: AFIIPv4, SAFI: SAFIUnicast}, s: "IPv4 unicast"},
		{f: Family{AFI: AFIIPv6, SAFI: SAFIMulticast}, s: "IPv6 multicast"},
		{f: Family{AFI: AFIL2VPN, SAFI: SAFIEVPN}, s: "L2VPN EVPN"},
		{f: Family{AFI: AFIL2VPN, SAFI: SAFIVPLS}, s: "L2VPN VPLS"},
		// Each half degrades on its own, so one unnamed number never hides
		// the other half's name.
		{f: Family{AFI: 16388, SAFI: 71}, s: "AFI 16388 SAFI 71"},
		{f: Family{AFI: AFIL2VPN, SAFI: SAFIMPLSVPN}, s: "L2VPN MPLS VPN"},
		{f: Family{AFI: AFIIPv4, SAFI: 133}, s: "IPv4 SAFI 133"},
		{f: Family{AFI: 16388, SAFI: SAFIUnicast}, s: "AFI 16388 unicast"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.s, tt.f.String()); d != "" {
				t.Fatalf("unexpected family string (-want +got):\n%s", d)
			}
		})
	}
}

func TestEVPNRouteTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		t EVPNRouteType
		s string
	}{
		{t: EVPNRouteEthernetAutoDiscovery, s: "Ethernet Auto-Discovery"},
		{t: EVPNRouteMACIPAdvertisement, s: "MAC/IP Advertisement"},
		{t: EVPNRouteInclusiveMulticastEthernetTag, s: "Inclusive Multicast Ethernet Tag"},
		{t: EVPNRouteEthernetSegment, s: "Ethernet Segment"},
		{t: EVPNRouteIPPrefix, s: "IP Prefix"},
		{t: 6, s: "EVPN route type 6"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.s, tt.t.String()); d != "" {
				t.Fatalf("unexpected EVPN route type string (-want +got):\n%s", d)
			}
		})
	}
}
