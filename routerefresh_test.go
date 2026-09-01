package bgp

import (
	"bytes"
	"testing"
)

// TestRouteRefreshReservedByte pins the documented normalization: the
// reserved byte between AFI and SAFI is discarded on parse and written as
// zero on marshal.
func TestRouteRefreshReservedByte(t *testing.T) {
	t.Parallel()

	m, err := ParseMessage(testMessage(MessageTypeRouteRefresh, []byte{
		0x00, 0x02, // AFI IPv6
		0x07, // reserved, nonzero on the wire
		0x01, // SAFI unicast
	}))
	if err != nil {
		t.Fatalf("failed to parse ROUTE-REFRESH: %v", err)
	}

	want := &RouteRefresh{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}}
	if d := diff[Message](t, want, m); d != "" {
		t.Fatalf("unexpected ROUTE-REFRESH (-want +got):\n%s", d)
	}

	b, err := m.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal ROUTE-REFRESH: %v", err)
	}

	wantB := testMessage(MessageTypeRouteRefresh, []byte{0x00, 0x02, 0x00, 0x01})
	if !bytes.Equal(wantB, b) {
		t.Fatalf("unexpected ROUTE-REFRESH bytes:\nwant: %x\n got: %x", wantB, b)
	}
}
