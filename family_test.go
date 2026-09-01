package bgp

import (
	"net/netip"
	"testing"
)

func TestPrefixesRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		afi  AFI
		ps   []netip.Prefix
		b    []byte
	}{
		{
			name: "IPv4",
			afi:  AFIIPv4,
			// Short prefix lengths use RFC 1918 private space: the RFC 5737
			// documentation blocks are /24s, which no shorter prefix can
			// stay within.
			ps: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("203.0.113.0/24"),
				netip.MustParsePrefix("192.0.2.128/25"),
				netip.MustParsePrefix("192.0.2.1/32"),
			},
			b: []byte{
				0,
				8, 10,
				12, 172, 16,
				24, 203, 0, 113,
				25, 192, 0, 2, 128,
				32, 192, 0, 2, 1,
			},
		},
		{
			name: "IPv6",
			afi:  AFIIPv6,
			ps: []netip.Prefix{
				netip.MustParsePrefix("::/0"),
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("2001:db8:0:1::/64"),
				netip.MustParsePrefix("2001:db8::1/128"),
			},
			b: []byte{
				0,
				32, 0x20, 0x01, 0x0d, 0xb8,
				64, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01,
				128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := appendPrefixes(nil, tt.ps, tt.afi)
			if err != nil {
				t.Fatalf("failed to marshal prefixes: %v", err)
			}

			if d := diff(t, tt.b, b); d != "" {
				t.Fatalf("unexpected prefix bytes (-want +got):\n%s", d)
			}

			ps, err := parsePrefixes(b, tt.afi, SubcodeInvalidNetworkField)
			if err != nil {
				t.Fatalf("failed to parse prefixes: %v", err)
			}

			if d := diff(t, tt.ps, ps); d != "" {
				t.Fatalf("unexpected prefixes (-want +got):\n%s", d)
			}
		})
	}
}

func TestParsePrefixesMasksTrailingBits(t *testing.T) {
	t.Parallel()

	// RFC 4271, section 4.3: trailing bits beyond the prefix length must be
	// ignored, so they are masked away on parse and never re-marshaled.
	ps, err := parsePrefixes([]byte{25, 192, 0, 2, 0xff}, AFIIPv4, SubcodeInvalidNetworkField)
	if err != nil {
		t.Fatalf("failed to parse prefixes: %v", err)
	}

	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")}
	if d := diff(t, want, ps); d != "" {
		t.Fatalf("unexpected prefixes (-want +got):\n%s", d)
	}

	b, err := appendPrefixes(nil, ps, AFIIPv4)
	if err != nil {
		t.Fatalf("failed to marshal prefixes: %v", err)
	}

	if d := diff(t, []byte{25, 192, 0, 2, 0x80}, b); d != "" {
		t.Fatalf("unexpected prefix bytes (-want +got):\n%s", d)
	}
}

func TestParsePrefixesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		b       []byte
		afi     AFI
		subcode uint8
	}{
		{
			name:    "IPv4 prefix length invalid",
			b:       []byte{33, 192, 0, 2, 0, 1},
			afi:     AFIIPv4,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name:    "IPv6 prefix length invalid",
			b:       []byte{129},
			afi:     AFIIPv6,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name:    "prefix truncated",
			b:       []byte{24, 203, 0},
			afi:     AFIIPv4,
			subcode: SubcodeInvalidNetworkField,
		},
		{
			name: "unsupported AFI",
			b:    []byte{24, 203, 0, 113},
			afi:  AFI(25),
			// The error must carry the caller's subcode, which differs
			// between top level NLRI and multiprotocol attributes.
			subcode: SubcodeOptionalAttributeError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePrefixes(tt.b, tt.afi, tt.subcode)
			wantMessageError(t, err, NotificationUpdateMessageError, tt.subcode, nil)
		})
	}
}

func TestAppendPrefixesErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ps   []netip.Prefix
		afi  AFI
	}{
		{
			name: "invalid prefix",
			ps:   []netip.Prefix{{}},
			afi:  AFIIPv4,
		},
		{
			name: "IPv6 prefix in IPv4 AFI",
			ps:   []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			afi:  AFIIPv4,
		},
		{
			name: "IPv4 prefix in IPv6 AFI",
			ps:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			afi:  AFIIPv6,
		},
		{
			name: "IPv4-mapped IPv6 prefix in IPv6 AFI",
			ps:   []netip.Prefix{netip.MustParsePrefix("::ffff:192.0.2.0/120")},
			afi:  AFIIPv6,
		},
		{
			name: "unsupported AFI",
			ps:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			afi:  AFI(25),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := appendPrefixes(nil, tt.ps, tt.afi); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}
