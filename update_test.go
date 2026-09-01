package bgp

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := ParseMessage(testMessage(MessageTypeUpdate, tt.b))
			if m != nil {
				t.Fatalf("expected nil Message, but got: %v", m)
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

		m, err := ParseMessage(b)
		if err != nil {
			t.Fatalf("failed to parse End-of-RIB for %v: %v", f, err)
		}

		family, ok := m.(*Update).EndOfRIB()
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
