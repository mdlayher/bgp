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
//
// An address family's NLRI is decoded only as far as the wire format goes.
// A prefix shaped family decodes to [netip.Prefix] values. Any other family
// this package names decodes to records, each a type and an opaque value,
// such as [EVPNRoutes] and [LinkStateRoutes]. What a record means belongs
// in a package of its own, which reads and writes the record's value. A
// family this package does not name is a [RawNLRI].
package bgp
