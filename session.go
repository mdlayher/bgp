package bgp

import (
	"fmt"
	"net"
	"time"
)

// A State is an RFC 4271, section 8 state of the finite state machine. The
// FSM reports its transitions through OnStateChange. There is deliberately
// no accessor to poll, because polled state is stale by the time it is
// acted on; [ErrNotEstablished] remains the only queryable session fact.
//
// During a connection collision (RFC 4271, section 6.8, which models the
// second connection as a second FSM) the reported state is the attempt's
// aggregate: the furthest-progressed of everything live. It may therefore
// regress, from OpenConfirm back to OpenSent, when the further connection
// loses the collision or dies while the other survives.
type State int

// The RFC 4271, section 8 session states, numbered as in section 8.2.2 and
// as MRT (RFC 6396) and BMP (RFC 7854) carry them: Idle is 1 and
// Established is 6. The zero value is not a state.
const (
	StateIdle State = iota + 1
	StateConnect
	StateActive
	StateOpenSent
	StateOpenConfirm
	StateEstablished
)

// String returns the RFC 4271 name of the State.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateConnect:
		return "Connect"
	case StateActive:
		return "Active"
	case StateOpenSent:
		return "OpenSent"
	case StateOpenConfirm:
		return "OpenConfirm"
	case StateEstablished:
		return "Established"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// fsmSubcode is the RFC 6608 subcode reporting an unexpected message in this
// state, for the two OPEN-exchange states a connection can hold.
func (s State) fsmSubcode() uint8 {
	if s == StateOpenSent {
		return SubcodeUnexpectedMessageOpenSent
	}

	return SubcodeUnexpectedMessageOpenConfirm
}

// A Session reports the negotiated parameters of an established session,
// passed to OnEstablished at both layers.
//
// A Session is fully owned: every field, the Families and ExtendedNextHop
// slices included, remains valid after the handler returns and after the
// session ends, unlike the borrowed values an FSM's other handlers receive.
// Anything this package does not model stays raw and reachable through Peer.
type Session struct {
	// Peer is the remote speaker's OPEN message, so uninterpreted
	// capabilities stay reachable. Unlike a Message from ParseMessage, it is
	// fully owned and remains valid for the life of the session and beyond.
	Peer *Open

	// Local is the OPEN this speaker sent on the session's connection, so
	// both-sides questions, such as RFC 8538's N bit conjunction or this
	// attempt's graceful restart Restart State bit, can be answered
	// without duplicating configuration. It is shared across sessions and
	// must not be modified.
	Local *Open

	// Families is the negotiated multiprotocol intersection, in the local
	// configuration's order. A peer which advertises no multiprotocol
	// capability at all is the implicit IPv4 unicast speaker of RFC 4760,
	// so a classic session reports IPv4 unicast here even though neither
	// speaker advertised it explicitly.
	Families []Family

	// RouteRefresh reports whether the peer advertised the route refresh
	// capability (RFC 2918).
	RouteRefresh bool

	// ExtendedNextHop lists the families the peer accepts IPv6 next hops
	// for (RFC 8950). Nothing in this package reads it: it is the caller's
	// input for deciding whether to advertise a family's routes with an
	// IPv6 next hop, an MPReachNLRI.NextHop the caller builds.
	ExtendedNextHop []Family

	// AddPath lists the families for which the add-path extension (RFC
	// 7911) was negotiated, with the directions that apply to this
	// speaker. Send means this speaker may advertise multiple paths for
	// the family, each NLRI entry carrying a path identifier. Those
	// entries are PathPrefixes in a multiprotocol attribute, or the
	// Update NLRIPaths and WithdrawnPaths fields for IPv4 unicast at the
	// top level. Receive means the peer will do the same, so this
	// session's inbound NLRI for the family arrives in those forms.
	// Assigning identifiers and selecting the paths to send remain the
	// caller's RIB's.
	AddPath []AddPathFamily

	// GracefulRestart is the peer's decoded graceful restart capability
	// (RFC 4724), or nil when the peer advertised none, or only a
	// malformed one. Like Peer, it is fully owned and remains valid after
	// the session ends: a helper decides retention after the close. All
	// graceful restart behavior is the caller's.
	GracefulRestart *GracefulRestart

	// HoldTime is the negotiated hold time: the minimum of the two
	// speakers' proposals, and the budget for a single handler invocation.
	HoldTime time.Duration

	// LocalAddr is the session connection's local address, carried
	// verbatim from its Conn: a *net.TCPAddr for a TCP transport, and
	// whatever the connection reports for a custom one.
	LocalAddr net.Addr

	// RemoteAddr is the peer's address on the session connection, in
	// LocalAddr's form. The pair serves logging, metrics, and liveness
	// bootstrap: a BFD session (RFC 5880) protecting the peering runs
	// between these endpoints.
	RemoteAddr net.Addr
}

// A Close reports why a session or session attempt ended, passed to OnClose
// at both layers. Every field is fully owned.
type Close struct {
	// Notification is the NOTIFICATION which ended the session, fully
	// owned, or nil if the transport died without one.
	Notification *Notification

	// Local reports which speaker ended the session or attempt. True when
	// this speaker did: it sent Notification, or gave up on a transport
	// whose write failed — including the hold-time write deadline. False
	// when the peer did: it sent Notification, or its connection ended,
	// which is any read error that is not a parse error. Notification is
	// nil exactly when the transport failed, so a nil Notification with
	// Local set is RFC 4271's TcpConnectionFails event on this side of
	// the connection.
	Local bool

	// Err is the transport, parse, or handler error which caused the
	// close, if any.
	Err error

	// Established reports whether this close ends an established session,
	// one whose OnEstablished has fired, rather than a failed session
	// attempt. The distinction is load-bearing for graceful restart
	// helpers: a failed reconnect attempt while stale routes are retained
	// must not be mistaken for the session ending again.
	Established bool
}
