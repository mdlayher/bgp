package bgp

import (
	"encoding/binary"
	"fmt"
)

// A RouteRefreshSubtype is the Message Subtype of a ROUTE-REFRESH message:
// the byte between its AFI and SAFI, which RFC 2918 reserved and RFC 7313
// redefined. A normal request carries RouteRefreshRequest. A BoRR or EoRR
// demarcation brackets a peer's re-advertisement of its Adj-RIB-Out, and
// is meaningful only on a session which negotiated the enhanced route
// refresh capability; see Session.EnhancedRouteRefresh.
type RouteRefreshSubtype uint8

// RouteRefreshSubtype values, as assigned by IANA in RFC 7313, section 6.
const (
	// RouteRefreshRequest is a normal route refresh request (RFC 2918):
	// the peer is asked to re-advertise its routes for the family.
	RouteRefreshRequest RouteRefreshSubtype = 0

	// RouteRefreshBegin is the BoRR demarcation of RFC 7313: the
	// beginning of a route refresh, after which a receiver marks the
	// family's routes from the peer as stale.
	RouteRefreshBegin RouteRefreshSubtype = 1

	// RouteRefreshEnd is the EoRR demarcation of RFC 7313: the ending of
	// a route refresh, at which a receiver removes the family's routes
	// from the peer which are still marked stale.
	RouteRefreshEnd RouteRefreshSubtype = 2
)

// String returns the RFC 7313 name of the RouteRefreshSubtype.
func (s RouteRefreshSubtype) String() string {
	switch s {
	case RouteRefreshRequest:
		return "Route-Refresh"
	case RouteRefreshBegin:
		return "BoRR"
	case RouteRefreshEnd:
		return "EoRR"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// demarcation reports whether s is one of the RFC 7313 demarcations, BoRR
// or EoRR.
func (s RouteRefreshSubtype) demarcation() bool {
	return s == RouteRefreshBegin || s == RouteRefreshEnd
}

// A RouteRefresh is a BGP ROUTE-REFRESH message, as described in RFC 2918
// and RFC 7313. With the zero Subtype it is a request that a peer
// re-advertise its routes for a given address family, whose support is
// negotiated using CapabilityRouteRefresh. With a demarcation Subtype it
// brackets such a re-advertisement, whose support is negotiated using
// CapabilityEnhancedRouteRefresh.
type RouteRefresh struct {
	// Family is the address family of the routes to be refreshed.
	Family Family

	// Subtype is the Message Subtype: a normal request, or a BoRR or EoRR
	// demarcation (RFC 7313). It is carried byte for byte, so an
	// unassigned value survives ParseMessage and AppendBinary unchanged;
	// whether a value is acted on is the session's decision, not the
	// codec's. See FSMConfig.OnRouteRefresh.
	Subtype RouteRefreshSubtype
}

func (*RouteRefresh) messageType() MessageType { return MessageTypeRouteRefresh }

// AppendBinary implements encoding.BinaryAppender.
func (r *RouteRefresh) AppendBinary(b []byte) ([]byte, error) {
	b, off := appendHeader(b, MessageTypeRouteRefresh)
	b = binary.BigEndian.AppendUint16(b, uint16(r.Family.AFI))
	b = append(b, byte(r.Subtype), byte(r.Family.SAFI))
	return finishMessage(b, off)
}

// routeRefreshBodyLen is the fixed length of a ROUTE-REFRESH message body:
// an AFI, a subtype, and a SAFI.
const routeRefreshBodyLen = 4

// parseRouteRefresh parses a complete ROUTE-REFRESH message, header
// included, since the diagnostic data of a malformed demarcation is the
// whole message.
func parseRouteRefresh(b []byte) (*RouteRefresh, error) {
	body := b[headerLen:]
	if len(body) != routeRefreshBodyLen {
		// RFC 7313, section 5: a BoRR or EoRR of the wrong length draws
		// ROUTE-REFRESH Message Error / Invalid Message Length, with the
		// complete message as data. The subtype is only known once the
		// body reaches it; any shorter body, and any other subtype, is a
		// Bad Message Length as for every fixed-size message.
		if len(body) > 2 && RouteRefreshSubtype(body[2]).demarcation() {
			return nil, routeRefreshError(SubcodeInvalidMessageLength, b,
				"ROUTE-REFRESH %s message must have a %d byte body: %d bytes",
				RouteRefreshSubtype(body[2]), routeRefreshBodyLen, len(body))
		}

		return nil, badLength(len(body),
			"ROUTE-REFRESH message must have a %d byte body: %d bytes",
			routeRefreshBodyLen, len(body))
	}

	return &RouteRefresh{
		Family: Family{
			AFI:  AFI(binary.BigEndian.Uint16(body[0:2])),
			SAFI: SAFI(body[3]),
		},
		Subtype: RouteRefreshSubtype(body[2]),
	}, nil
}
