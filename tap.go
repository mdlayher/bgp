package bgp

import (
	"net"
	"slices"
)

// A Direction is the direction a message traveled on a connection, as seen
// by this speaker.
type Direction int

const (
	// DirectionReceived: the peer sent the message and this speaker read it.
	DirectionReceived Direction = iota

	// DirectionSent: this speaker wrote the message to the peer.
	DirectionSent
)

// String returns the name of the Direction.
func (d Direction) String() string {
	switch d {
	case DirectionReceived:
		return "received"
	case DirectionSent:
		return "sent"
	default:
		return "unknown"
	}
}

// A MessageEvent is one message crossing one connection, as reported to the
// OnMessage tap of an FSM or Peer. A tap observes every message a peering
// exchanges, in both directions and on every connection the state machine
// owns. That includes the OPEN exchange, a collision's losing connection,
// keepalives, and NOTIFICATIONs.
//
// An event fires only when a frame was delimited, a complete header at
// minimum. A connection which dies mid-read fires nothing, and a message
// which failed to marshal never fires: no byte reached the connection.
type MessageEvent struct {
	// Direction is the direction the message traveled.
	Direction Direction

	// Raw is the message exactly as framed on the wire, header included.
	// When a received header's length field is invalid, Raw holds only the
	// header: framing is lost beyond it. When a write failed, some of Raw
	// may have crossed the wire.
	Raw []byte

	// Message is the parsed (received) or written (sent) message, or nil
	// when a received frame could not be parsed.
	Message Message

	// Err is nil for a message which parsed or wrote cleanly. On a
	// received event it is otherwise the *MessageError describing the
	// parse failure; on a sent event, the transport's write error.
	Err error

	// LocalAddr and RemoteAddr are the connection's endpoints, which
	// distinguish a collision's two connections. Their concrete types are
	// the transport's; a TCP connection reports *net.TCPAddr.
	LocalAddr, RemoteAddr net.Addr
}

// clone returns a fully owned copy of the event: Raw is copied and Message
// deep-copied, so a Peer's tap may retain what the FSM only lends.
func (e MessageEvent) clone() MessageEvent {
	e.Raw = slices.Clone(e.Raw)
	e.Message = cloneMessage(e.Message)
	return e
}

// cloneMessage deep-copies a Message of any type, or returns nil for nil.
func cloneMessage(m Message) Message {
	switch m := m.(type) {
	case *Open:
		return m.Clone()
	case *Update:
		return m.Clone()
	case *Notification:
		return m.Clone()
	case *Keepalive:
		return &Keepalive{}
	case *RouteRefresh:
		return m.Clone()
	default:
		return nil
	}
}
