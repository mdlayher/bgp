package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestMessageRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    Message
	}{
		{
			name: "keepalive",
			m:    &Keepalive{},
		},
		{
			name: "open minimal",
			m: &Open{
				ASN:      64496,
				HoldTime: 90 * time.Second,
				ID:       MustParseIdentifier("192.0.2.1"),
			},
		},
		{
			name: "open zero hold time",
			m: &Open{
				ASN: 64496,
				ID:  MustParseIdentifier("192.0.2.1"),
			},
		},
		{
			name: "open four octet ASN",
			m: &Open{
				ASN:      65536,
				HoldTime: 3 * time.Second,
				ID:       MustParseIdentifier("203.0.113.255"),
			},
		},
		{
			name: "open capabilities",
			m: &Open{
				ASN:      64496,
				HoldTime: 180 * time.Second,
				ID:       MustParseIdentifier("192.0.2.1"),
				Capabilities: []Capability{
					MultiprotocolCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
					MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
					ExtendedNextHopCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
					{Code: CapabilityRouteRefresh},
				},
			},
		},
		{
			name: "update empty",
			m:    &Update{},
		},
		{
			name: "update withdraw only",
			m: &Update{
				Withdrawn: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.0/24"),
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
		},
		{
			name: "update IPv4",
			m: &Update{
				Attributes: mustAttributes(
					t,
					OriginIGP,
					ASPath{
						{ASNs: []uint32{64496, 65536}},
						{Set: true, ASNs: []uint32{64497, 64498}},
					},
					NextHop(netip.MustParseAddr("192.0.2.1")),
					MED(100),
					LocalPref(200),
					AtomicAggregate{},
					Aggregator{ASN: 64496, ID: MustParseIdentifier("192.0.2.1")},
					Communities{NewCommunity(64496, 100)},
					LargeCommunities{{Global: 65536, Local1: 1, Local2: 2}},
				),
				NLRI: []netip.Prefix{
					netip.MustParsePrefix("203.0.113.0/24"),
					netip.MustParsePrefix("192.0.2.128/25"),
					netip.MustParsePrefix("198.51.100.1/32"),
				},
			},
		},
		{
			name: "update multiprotocol IPv6",
			m: &Update{
				Attributes: mustAttributes(
					t,
					OriginIncomplete,
					ASPath{{ASNs: []uint32{64496}}},
					MPReachNLRI{
						Family:    Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
						NextHop:   netip.MustParseAddr("2001:db8::1"),
						LinkLocal: netip.MustParseAddr("fe80::1"),
						NLRI: Prefixes{
							netip.MustParsePrefix("2001:db8:1::/48"),
							netip.MustParsePrefix("::/0"),
						},
					},
					MPUnreachNLRI{
						Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
						NLRI: Prefixes{
							netip.MustParsePrefix("2001:db8:2::/48"),
						},
					},
				),
			},
		},
		{
			name: "update RFC 8950 IPv4 via IPv6 next hop",
			m: &Update{
				Attributes: mustAttributes(
					t,
					MPReachNLRI{
						Family:  Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
						NextHop: netip.MustParseAddr("2001:db8::1"),
						NLRI: Prefixes{
							netip.MustParsePrefix("203.0.113.0/24"),
						},
					},
				),
			},
		},
		{
			name: "update IPv6 end-of-RIB",
			m: &Update{
				Attributes: mustAttributes(
					t,
					MPUnreachNLRI{
						Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
					},
				),
			},
		},
		{
			name: "notification",
			m: &Notification{
				Code:    NotificationMessageHeaderError,
				Subcode: SubcodeBadMessageLength,
				Data:    []byte{0xff, 0xff},
			},
		},
		{
			name: "notification no data",
			m:    &Notification{Code: NotificationCease, Subcode: 2},
		},
		{
			name: "route refresh",
			m:    &RouteRefresh{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b, err := tt.m.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal message: %v", err)
			}

			got, err := ParseMessage(b)
			if err != nil {
				t.Fatalf("failed to parse message: %v", err)
			}

			if d := diff(t, tt.m, got); d != "" {
				t.Fatalf("unexpected message (-want +got):\n%s", d)
			}

			// The parsed message must reproduce the marshaled bytes exactly.
			got2, err := got.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal parsed message: %v", err)
			}

			if d := diff(t, b, got2); d != "" {
				t.Fatalf("unexpected message bytes (-want +got):\n%s", d)
			}
		})
	}
}

func TestParseMessageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		b       []byte
		code    NotificationCode
		subcode uint8
		data    []byte
	}{
		{
			name:    "empty",
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
		},
		{
			name:    "short header",
			b:       testMessage(MessageTypeKeepalive, nil)[:headerLen-1],
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
		},
		{
			name: "bad marker",
			b: func() []byte {
				b := testMessage(MessageTypeKeepalive, nil)
				b[0] = 0x00
				return b
			}(),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeConnectionNotSynchronized,
		},
		{
			name: "length mismatch",
			b: func() []byte {
				b := testMessage(MessageTypeKeepalive, nil)
				binary.BigEndian.PutUint16(b[markerLen:], headerLen+1)
				return b
			}(),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 1},
		},
		{
			name:    "length too long",
			b:       testMessage(MessageTypeKeepalive, make([]byte, MaxMessageSize+1-headerLen)),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x10, 0x01},
		},
		{
			name:    "unknown message type",
			b:       testMessage(MessageType(0xff), nil),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageType,
			data:    []byte{0xff},
		},
		{
			name:    "keepalive non-empty body",
			b:       testMessage(MessageTypeKeepalive, []byte{0x00}),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 1},
		},
		{
			name:    "notification short body",
			b:       testMessage(MessageTypeNotification, []byte{0x06}),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 1},
		},
		{
			name:    "route refresh bad body",
			b:       testMessage(MessageTypeRouteRefresh, []byte{0x00, 0x01, 0x00}),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := ParseMessage(tt.b)
			if m != nil {
				t.Fatalf("expected nil Message, but got: %v", m)
			}

			wantMessageError(t, err, tt.code, tt.subcode, tt.data)
		})
	}
}

func TestMessageTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ  MessageType
		want string
	}{
		{typ: MessageTypeOpen, want: "OPEN"},
		{typ: MessageTypeUpdate, want: "UPDATE"},
		{typ: MessageTypeNotification, want: "NOTIFICATION"},
		{typ: MessageTypeKeepalive, want: "KEEPALIVE"},
		{typ: MessageTypeRouteRefresh, want: "ROUTE-REFRESH"},
		{typ: MessageType(0xff), want: "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzParseMessage(f *testing.F) {
	// Seed with a valid encoding of every message type, plus real UPDATE
	// messages captured from a route collector.
	seeds := []Message{
		&Keepalive{},
		&Open{
			ASN:      65536,
			HoldTime: 90 * time.Second,
			ID:       MustParseIdentifier("192.0.2.1"),
			Capabilities: []Capability{
				MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
			},
		},
		&Update{
			Withdrawn:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Attributes: mustAttributes(f, OriginIGP, ASPath{{ASNs: []uint32{64496}}}),
			NLRI:       []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
		&Notification{Code: NotificationCease, Subcode: 2, Data: []byte{0x01}},
		&RouteRefresh{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
	}

	for _, m := range seeds {
		b, err := m.AppendBinary(nil)
		if err != nil {
			f.Fatalf("failed to marshal seed: %v", err)
		}

		f.Add(b)
	}

	for _, b := range corpusSeeds(f) {
		f.Add(b)
	}

	// Each RIB dump attribute sample rides in a minimal synthetic UPDATE,
	// so message level fuzzing also starts from the rare attribute types a
	// full internet table carries.
	for _, a := range ribSeeds(f) {
		ab, err := appendRawAttribute(nil, a)
		if err != nil {
			f.Fatalf("failed to marshal RIB seed attribute: %v", err)
		}

		b := bytes.Repeat([]byte{0xff}, markerLen)
		b = append(b, 0, 0, byte(MessageTypeUpdate))
		b = binary.BigEndian.AppendUint16(b, 0) // withdrawn routes length
		b = binary.BigEndian.AppendUint16(b, uint16(len(ab)))
		b = append(b, ab...)
		binary.BigEndian.PutUint16(b[markerLen:markerLen+2], uint16(len(b)))
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMessage(b)
		if err != nil {
			if m != nil {
				t.Fatal("non-nil Message with non-nil error")
			}

			// Any MessageError must describe a NOTIFICATION which itself
			// marshals, so a session can always answer the peer.
			if merr, ok := errors.AsType[*MessageError](err); ok {
				if _, err := merr.Notification().AppendBinary(nil); err != nil {
					t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
				}
			}

			return
		}

		// Parse must be a fixed point of marshaling: parsing the marshaled
		// form of a parsed message reproduces both the message and the bytes.
		b1, err := m.AppendBinary(nil)
		if err != nil {
			// A parsed message need not re-marshal: for example, an OPEN may
			// spread more capabilities across multiple optional parameters
			// than fit in the single parameter this package generates.
			t.Skip("parsed message does not re-marshal")
		}

		m2, err := ParseMessage(b1)
		if err != nil {
			t.Fatalf("failed to re-parse marshaled message: %v", err)
		}

		if d := diff(t, m, m2); d != "" {
			t.Fatalf("unexpected re-parsed message (-want +got):\n%s", d)
		}

		b2, err := m2.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-marshal message: %v", err)
		}

		if !bytes.Equal(b1, b2) {
			t.Fatalf("marshaling is not idempotent:\n b1: %x\n b2: %x", b1, b2)
		}
	})
}

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not
// equal. Comparisons handle the netip types, and treat nil and empty byte
// slices as equivalent, since the wire format cannot distinguish them.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()
	return cmp.Diff(
		want, got,
		// Open.fourOctet is a parse-side signal for the FSM, pinned by
		// TestParseOpenFourOctet rather than compared structurally.
		cmpopts.IgnoreUnexported(Open{}),
		cmp.Comparer(func(x, y netip.Addr) bool { return x == y }),
		cmp.Comparer(func(x, y netip.Prefix) bool { return x == y }),
		cmp.Comparer(func(x, y NextHop) bool { return netip.Addr(x) == netip.Addr(y) }),
		cmp.FilterValues(
			func(x, y []byte) bool { return len(x) == 0 && len(y) == 0 },
			cmp.Comparer(func(_, _ []byte) bool { return true }),
		),
	)
}

// testMessage produces a wire message with a valid marker and length, the
// given type, and body.
func testMessage(typ MessageType, body []byte) []byte {
	b := bytes.Repeat([]byte{0xff}, markerLen)
	b = binary.BigEndian.AppendUint16(b, uint16(headerLen+len(body)))
	b = append(b, byte(typ))
	return append(b, body...)
}

// wantMessageError asserts that err is a *MessageError carrying the given
// NOTIFICATION code, subcode, and data, and returns it.
func wantMessageError(tb testing.TB, err error, code NotificationCode, subcode uint8, data []byte) *MessageError {
	tb.Helper()

	merr, ok := errors.AsType[*MessageError](err)
	if !ok {
		tb.Fatalf("expected *MessageError, but got: %v", err)
	}

	if d := diff(tb, code, merr.Code); d != "" {
		tb.Fatalf("unexpected NOTIFICATION code (-want +got):\n%s", d)
	}

	if d := diff(tb, subcode, merr.Subcode); d != "" {
		tb.Fatalf("unexpected NOTIFICATION subcode (-want +got):\n%s", d)
	}

	if d := diff(tb, data, merr.Data); d != "" {
		tb.Fatalf("unexpected NOTIFICATION data (-want +got):\n%s", d)
	}

	return merr
}
