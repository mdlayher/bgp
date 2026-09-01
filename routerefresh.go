package bgp

import "encoding/binary"

// A RouteRefresh is a BGP ROUTE-REFRESH message: a request that a peer
// re-advertise its routes for a given address family, as described in RFC
// 2918. Support is negotiated using CapabilityRouteRefresh.
type RouteRefresh struct {
	// Family is the address family of the routes to be refreshed.
	Family Family
}

func (*RouteRefresh) messageType() MessageType { return MessageTypeRouteRefresh }

// AppendBinary implements encoding.BinaryAppender.
func (r *RouteRefresh) AppendBinary(b []byte) ([]byte, error) {
	b, off := appendHeader(b, MessageTypeRouteRefresh)
	b = binary.BigEndian.AppendUint16(b, uint16(r.Family.AFI))
	b = append(b, 0, byte(r.Family.SAFI))
	return finishMessage(b, off)
}

// parseRouteRefresh parses the body of a ROUTE-REFRESH message.
func parseRouteRefresh(b []byte) (*RouteRefresh, error) {
	if len(b) != 4 {
		return nil, badLength(len(b), "ROUTE-REFRESH message must have a 4 byte body: %d bytes", len(b))
	}

	return &RouteRefresh{Family: Family{
		AFI:  AFI(binary.BigEndian.Uint16(b[0:2])),
		SAFI: SAFI(b[3]),
	}}, nil
}
