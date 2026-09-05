// Package bgp implements the Border Gateway Protocol version 4 (BGP-4), as
// described in RFC 4271 and related RFCs.
//
// The package is built in layers. Each layer is usable without the ones
// above it:
//
//   - The [Message] types, such as [Open], [Update], and [Notification],
//     with their binary encoding.
//   - [Conn] frames messages over a connection.
//   - [FSM] runs the RFC 4271 finite state machine over a Conn: one session
//     attempt for each Connect call, delivering zero-copy borrowed values
//     to its handlers.
//   - [Peer] wraps an FSM with a retry loop and handlers whose values are
//     fully owned.
//   - [Server] coordinates many Peers, accepting connections on shared
//     listeners.
//
// Most callers want [Peer] or [Server]. [FSM] is the expert layer for
// callers who need zero-copy delivery or their own retry policy. There is
// no routing table and no policy: an established session hands received
// UPDATE messages to the caller, who owns any routing decisions.
//
// Multiprotocol BGP (RFC 4760) is a first-class concern: the [MPReachNLRI]
// and [MPUnreachNLRI] attributes carry routes for any address family,
// including IPv4, and IPv4 routes may use an IPv6 next hop (RFC 8950). The
// IPv4-only fields of an [Update] exist for compatibility with the original
// RFC 4271 wire format.
package bgp

import (
	"encoding"
	"encoding/binary"
	"fmt"
)

const (
	// MaxMessageSize is the maximum size in bytes of an encoded BGP message,
	// as described in RFC 4271, section 4.1.
	MaxMessageSize = 4096

	// headerLen is the size in bytes of a BGP message header: a marker,
	// followed by a 2 byte length and 1 byte type.
	headerLen = markerLen + 3

	// markerLen is the size in bytes of the all-ones marker field which
	// begins a BGP message header.
	markerLen = 16
)

// A MessageType is the type of a BGP Message.
type MessageType uint8

// MessageType values, as assigned by IANA.
const (
	MessageTypeOpen         MessageType = 1
	MessageTypeUpdate       MessageType = 2
	MessageTypeNotification MessageType = 3
	MessageTypeKeepalive    MessageType = 4
	MessageTypeRouteRefresh MessageType = 5
)

// String returns the name of a MessageType.
func (t MessageType) String() string {
	switch t {
	case MessageTypeOpen:
		return "OPEN"
	case MessageTypeUpdate:
		return "UPDATE"
	case MessageTypeNotification:
		return "NOTIFICATION"
	case MessageTypeKeepalive:
		return "KEEPALIVE"
	case MessageTypeRouteRefresh:
		return "ROUTE-REFRESH"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}

// A Message is a BGP message which can append its binary form to a buffer.
// *Open, *Update, *Notification, *Keepalive, and *RouteRefresh implement
// Message. Call AppendBinary with a nil buffer for a standalone encoding.
type Message interface {
	encoding.BinaryAppender

	// messageType is the type of the Message on the wire. It also constrains
	// the set of types which may implement Message.
	messageType() MessageType
}

var (
	_ Message = (*Open)(nil)
	_ Message = (*Update)(nil)
	_ Message = (*Notification)(nil)
	_ Message = (*Keepalive)(nil)
	_ Message = (*RouteRefresh)(nil)
)

// ParseMessage parses a [Message] from b, which must contain exactly one
// BGP message.
//
// To avoid copies, a parsed Message references b: do not modify or reuse b
// while the Message or data taken from it remains in use. To retain a
// Message longer, copy the referenced data ([RawAttribute.Data],
// [Capability.Data], and [Notification.Data]): the Clone methods on
// [Update], [Open], and [Notification] detach a whole message at once,
// [RawAttributes.Clone] detaches an attribute list alone, and
// [RawAttribute.Parse] returns [Attribute] values which never reference b.
//
// A malformed message produces a [*MessageError] describing the
// Notification RFC 4271 requires in response.
//
// ParseMessage knows no session, so it never decodes RFC 7911 path
// identifiers. Whether an NLRI entry carries one is negotiated per session
// and per family, and is not recognizable from the bytes. Messages read on
// a [Conn] are parsed with their session's negotiation instead. A caller
// which knows the negotiation itself uses [ParseMessageAddPath]; see
// [Session.AddPath].
func ParseMessage(b []byte) (Message, error) {
	return parseMessage(b, nil)
}

// ParseMessageAddPath parses a [Message] from b like [ParseMessage], but
// decodes RFC 7911 path identifiers in any UPDATE for the given families.
// The families are the add-path receive set of the session the message
// traveled on, from the receiver's perspective.
//
// It serves consumers which see a session's messages without holding its
// [Conn], such as a BMP station. A station learns the negotiation from
// the OPENs a Peer Up message embeds, decoding each side's capability via
// [Capability.AddPath].
//
// Only prefix shaped families support add-path; any other family in the
// set is ignored. The aliasing contract is [ParseMessage]'s.
func ParseMessageAddPath(b []byte, addPath []Family) (Message, error) {
	return parseMessage(b, addPath)
}

// parseMessage implements ParseMessage. addPath is the add-path receive
// set of the session the message arrived on: the families whose inbound
// NLRI entries carry path identifiers (RFC 7911), which a session-free
// parse cannot know. Only UPDATE parsing consumes it.
func parseMessage(b []byte, addPath []Family) (Message, error) {
	if len(b) < headerLen {
		return nil, headerError(SubcodeBadMessageLength, nil,
			"message too short: %d bytes", len(b))
	}

	for _, c := range b[:markerLen] {
		if c != 0xff {
			return nil, headerError(SubcodeConnectionNotSynchronized, nil,
				"invalid message header marker")
		}
	}

	// The wire length field is echoed back to the peer as the diagnostic
	// data of a Bad Message Length error.
	lb := b[markerLen : markerLen+2]
	length := int(binary.BigEndian.Uint16(lb))
	if length != len(b) {
		return nil, headerError(SubcodeBadMessageLength, lb,
			"message length %d does not match input length %d", length, len(b))
	}

	if length > MaxMessageSize {
		return nil, headerError(SubcodeBadMessageLength, lb,
			"message length %d exceeds maximum of %d bytes", length, MaxMessageSize)
	}

	// Each parser is assigned to Message via a concrete pointer type, so a
	// failed parse must return an untyped nil rather than the parser's typed
	// nil boxed in a non-nil interface.
	var (
		m   Message
		err error
	)

	body := b[headerLen:]
	switch typ := MessageType(b[headerLen-1]); typ {
	case MessageTypeOpen:
		m, err = parseOpen(body)
	case MessageTypeUpdate:
		m, err = parseUpdate(body, addPath)
	case MessageTypeNotification:
		m, err = parseNotification(body)
	case MessageTypeKeepalive:
		if len(body) != 0 {
			return nil, badLength(len(body),
				"KEEPALIVE message must have an empty body: %d bytes", len(body))
		}

		m = &Keepalive{}
	case MessageTypeRouteRefresh:
		m, err = parseRouteRefresh(body)
	default:
		return nil, headerError(SubcodeBadMessageType, b[headerLen-1:headerLen],
			"unknown message type %d", uint8(typ))
	}

	if err != nil {
		return nil, err
	}

	return m, nil
}

// appendHeader begins a message by appending a BGP message header with type
// typ to b, returning the offset of the start of the message within b. The
// message length is populated later by finishMessage.
func appendHeader(b []byte, typ MessageType) ([]byte, int) {
	off := len(b)
	for range markerLen {
		b = append(b, 0xff)
	}

	b = append(b, 0, 0, byte(typ))
	return b, off
}

// finishMessage completes a message started by appendHeader at offset off
// within b, validating the message's length and storing it in the message
// header.
func finishMessage(b []byte, off int) ([]byte, error) {
	n := len(b) - off
	if n > MaxMessageSize {
		return nil, fmt.Errorf("bgp: message length %d exceeds maximum of %d bytes", n, MaxMessageSize)
	}

	binary.BigEndian.PutUint16(b[off+markerLen:off+markerLen+2], uint16(n))
	return b, nil
}
