package bgp

import (
	"bytes"
	"testing"
)

// TestRouteRefreshSubtypeRoundTrip pins the wire form of the Message
// Subtype: each assigned value, and an unassigned one, marshals to the byte
// between AFI and SAFI and parses back unchanged. The codec is stateless, so
// it never judges a subtype: that is the session's business.
func TestRouteRefreshSubtypeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subtype RouteRefreshSubtype
	}{
		{name: "request", subtype: RouteRefreshRequest},
		{name: "BoRR", subtype: RouteRefreshBegin},
		{name: "EoRR", subtype: RouteRefreshEnd},
		{name: "unassigned", subtype: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := &RouteRefresh{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				Subtype: tt.subtype,
			}

			b, err := want.AppendBinary(nil)
			if err != nil {
				t.Fatalf("failed to marshal ROUTE-REFRESH: %v", err)
			}

			wantB := testMessage(MessageTypeRouteRefresh, []byte{0x00, 0x02, byte(tt.subtype), 0x01})
			if !bytes.Equal(wantB, b) {
				t.Fatalf("unexpected ROUTE-REFRESH bytes:\nwant: %x\n got: %x", wantB, b)
			}

			got, err := ParseMessage(b)
			if err != nil {
				t.Fatalf("failed to parse ROUTE-REFRESH: %v", err)
			}

			if d := diff[Message](t, want, got); d != "" {
				t.Fatalf("unexpected ROUTE-REFRESH (-want +got):\n%s", d)
			}
		})
	}
}

// TestRouteRefreshReservedByte pins the RFC 7313 contract for the byte RFC
// 2918 reserved: a ROUTE-REFRESH with a nonzero value there round-trips byte
// for byte through ParseMessage and AppendBinary, since the byte is now the
// Message Subtype and an unnegotiated or unassigned value must survive
// for whoever consumes it next.
func TestRouteRefreshReservedByte(t *testing.T) {
	t.Parallel()

	wire := testMessage(MessageTypeRouteRefresh, []byte{
		0x00, 0x02, // AFI IPv6
		0x07, // the reserved byte, nonzero on the wire
		0x01, // SAFI unicast
	})

	m, err := ParseMessage(wire)
	if err != nil {
		t.Fatalf("failed to parse ROUTE-REFRESH: %v", err)
	}

	want := &RouteRefresh{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}, Subtype: 7}
	if d := diff[Message](t, want, m); d != "" {
		t.Fatalf("unexpected ROUTE-REFRESH (-want +got):\n%s", d)
	}

	b, err := m.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal ROUTE-REFRESH: %v", err)
	}

	if !bytes.Equal(wire, b) {
		t.Fatalf("ROUTE-REFRESH did not round-trip:\nwant: %x\n got: %x", wire, b)
	}
}

// TestRouteRefreshLengthErrors pins RFC 7313, section 5: a BoRR or EoRR
// whose body is not 4 bytes draws ROUTE-REFRESH Message Error / Invalid
// Message Length carrying the complete message, while a request of the
// wrong length, or a body too short to name its subtype, stays the Bad
// Message Length of every fixed-size message.
func TestRouteRefreshLengthErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    []byte
		code    NotificationCode
		subcode uint8
		whole   bool
	}{
		{
			name:    "BoRR long",
			body:    []byte{0x00, 0x01, 0x01, 0x01, 0x00},
			code:    NotificationRouteRefreshMessageError,
			subcode: SubcodeInvalidMessageLength,
			whole:   true,
		},
		{
			name:    "EoRR short",
			body:    []byte{0x00, 0x01, 0x02},
			code:    NotificationRouteRefreshMessageError,
			subcode: SubcodeInvalidMessageLength,
			whole:   true,
		},
		{
			name:    "request long",
			body:    []byte{0x00, 0x01, 0x00, 0x01, 0x00},
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
		},
		{
			name:    "no subtype",
			body:    []byte{0x00, 0x01},
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wire := testMessage(MessageTypeRouteRefresh, tt.body)
			_, err := ParseMessage(wire)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			// Section 5's data is the complete message; RFC 4271's is the
			// erroneous length field.
			data := wire[markerLen : markerLen+2]
			if tt.whole {
				data = wire
			}

			wantMessageError(t, err, tt.code, tt.subcode, data)
		})
	}
}
