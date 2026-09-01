# bgp

A Go library for the BGP-4 wire format and, eventually, sessions: message
encode/decode plus a boring RFC 4271 state machine. Never a RIB, never a
policy engine.

## Language

**Adj-RIB-In**:
The routes learned from one specific peer, before policy and selection.
Per-peer; owned by the caller's RIB.

**Adj-RIB-Out**:
The routes advertised to one specific peer. Per-peer; owned by the
caller's RIB and drained through the Peer's send path.

**Attribute**:
A BGP path attribute. Raw form (uninterpreted flags/type/data) is the
default representation; parsed (typed) form is opt-in.

**Backpressure**:
Throttling a producer by the consumer's real rate rather than by a
queue. Inbound, a blocking handler pauses the receive path so the
transport's flow control throttles the remote speaker; outbound, the
queueless send path throttles a pusher at the peer's receive rate.

**BFD**:
Bidirectional Forwarding Detection (RFC 5880): a fast liveness protocol
for the forwarding path between two speakers, independent of BGP's own
hold timer. Out of scope to implement here; a BFD-driven caller feeds
its down signal into a session reset carrying BFD Down (RFC 9384).

**Bounce**:
Deliberately ending an established session so that it re-establishes
fresh; "clear" in router CLIs.
_Avoid_: clear (collides with Go's builtin); bare reset (a CLI "soft
reset" is a route refresh, not a bounce; qualify as session reset, or
name the wire subcode, Administrative Reset)

**Capability**:
An optional feature advertised in an OPEN message (RFC 5492), negotiated
per session.

**Cluster ID**:
The identifier of a route reflection cluster (RFC 4456), carried in the
CLUSTER_LIST attribute; by default its reflector's identifier.

**Coalescing**:
Collapsing multiple changes to the same prefix into one advertisement
of current state: a slow peer receives fewer, newer messages, never a
backlog of history. The reason an Adj-RIB-Out is state with a dirty
set, not a change queue.

**Connection**:
A single reliable byte stream carrying BGP messages, normally TCP. A
peering may briefly hold two (collision), and a session uses exactly one.

**Direction**:
Which way a message traveled on a connection as seen by this speaker:
received from the peer, or sent to it. Not the connection's initiator,
which is its origin (dialed or accepted).

**End-of-RIB**:
An UPDATE-shaped marker (RFC 4724) which signals that a speaker has
sent its complete initial routing table for one family. A wire-level
marker meaningful without graceful restart, not a RIB feature.

**EVPN**:
Ethernet VPN (RFC 7432): the L2VPN EVPN family, whose reachability
information is typed records describing MAC/IP bindings and Ethernet
segments rather than IP prefixes. This package frames the records and
interprets nothing inside them.

**Extended community**:
An 8 byte community value (RFC 4360), treated as an opaque type plus
value. Only the common route target and route origin forms are
interpreted, for display and construction.

**Family**:
An address family identified by an AFI/SAFI pair (e.g. IPv6 unicast).
_Avoid_: AFI alone when the SAFI matters

**FSM**:
The finite state machine of one peering (RFC 4271, section 8):
connection establishment, collision resolution, OPEN negotiation, and
session liveness. The zero-copy expert layer: its hooks lend callers
the wire's own memory under a borrow contract. A Peer wraps one.

**Graceful restart**:
The mechanism (RFC 4724) by which a session may die and return without
the surviving speaker withdrawing the routes learned from it: the
routes go stale instead, and are swept when the returning speaker's
End-of-RIB arrives or the restart time expires.

**Hard Reset**:
A Cease NOTIFICATION (RFC 8538, subcode 9) instructing the peer to
flush immediately, graceful restart notwithstanding.

**Helper**:
The speaker whose peer restarts: it retains that peer's routes as
stale, still forwarding on them, while the peer is away.
_Avoid_: receiving speaker

**Identifier**:
A BGP identifier (RFC 6286): a 4 byte nonzero number unique within an
autonomous system, conventionally derived from an IPv4 address and
rendered dotted quad. A number, not an address.
_Avoid_: router ID

**Loc-RIB**:
The speaker's selected routes after best-path selection across all
peers. Per-speaker; owned by the caller's RIB.

**Message**:
One complete BGP protocol unit on the wire: OPEN, UPDATE, NOTIFICATION,
KEEPALIVE, or ROUTE-REFRESH.
_Avoid_: packet, frame

**NLRI**:
The reachability information of one address family (Network Layer
Reachability Information), in the shape that family determines: a list
of prefixes for the classic families, typed records for EVPN, raw bytes
for a family this package does not model.
_Avoid_: assuming NLRI means prefixes

**Origin AS**:
The autonomous system a route originated from, as its AS path names it
(RFC 6811): the rightmost AS of a final AS_SEQUENCE; none when the
path ends in an AS_SET; the receiving speaker's own when the path is
empty. The subject of origin validation.
_Avoid_: origin alone (the ORIGIN attribute is a different thing: how
the route entered BGP)

**Origin validation state**:
The result of route origin validation (RFC 6811) for one route, either
valid, not found, or invalid, as carried between speakers in an extended
community (RFC 8097). Validation itself is policy, and the caller's;
this package carries the result.
_Avoid_: RPKI state (RPKI is the infrastructure, not the verdict)

**OTC**:
The "Only to Customer" attribute (RFC 9234): the autonomous system
beyond which a route must only propagate toward customers. Used to
detect route leaks. Role negotiation is out of scope.

**Peer**:
The remote speaker of a specific session; also the local object that
manages the relationship with it across session attempts, handing its
callers owned copies of everything the wire delivered. The mainstream
layer: a RIB plugs in here.
_Avoid_: neighbor

**Prefix**:
A single IP network (address plus length) carried as one NLRI entry.
_Avoid_: route (when no attributes are attached), network

**Pusher**:
The caller's per-session goroutine which drains the Adj-RIB-Out through
the Peer's send path: started on establishment, bound to the session
ctx, and the only goroutine sending UPDATEs on its session. One
sender per session is what turns per-call FIFO into whole-session
order.
_Avoid_: writer (the transport-level goroutine inside the bgp package),
sender

**Restart time**:
The retention deadline a restarting speaker advertises in its graceful
restart capability: how long a helper should keep its stale routes. At
most 4095 seconds on the wire.

**Restarting speaker**:
The speaker whose BGP process restarts while its forwarding plane keeps
working; on return it re-advertises its table and marks the end of each
family with End-of-RIB.

**RIB**:
Route storage plus best-path selection (Routing Information Base).
Permanently out of scope for this package; plugged in by the caller at
the Peer boundary.
_Avoid_: routing table (when the BGP-specific structure is meant)

**Route**:
A prefix together with the path attributes that apply to it. Routes exist
at the session/caller layer; the wire layer deals only in prefixes and
attributes.

**Server**:
The local speaker's coordinator of many peerings: listening TCP sockets,
connection demultiplexing by remote address, and peer lifecycle. TCP
only, because it demultiplexes by address; a Peer alone runs on any
transport. Like a Peer, never a RIB and never a policy engine.

**Session**:
The Established BGP relationship between two speakers over one connection,
with negotiated capabilities, families, and hold time.

**Session attempt**:
One pass of the FSM out of Idle and back: connecting, the OPEN
exchange, and collision resolution. Once a connection is confirmed,
the attempt continues as the session itself until the session ends.
Any transition back to Idle concludes the attempt, with exactly one
Close whenever anything observable began.
_Avoid_: attempt alone where a single dial could be meant; an attempt
may span many dials

**Session reset**:
Ending an established session with a NOTIFICATION while the peering
continues: the RFC term (RFC 4486, RFC 9384) for the act behind a
bounce, and the ResetSession verb. Distinct from a CLI "soft reset",
which is a route refresh.

**Shutdown communication**:
A human-readable UTF-8 message of at most 255 bytes (RFC 9003) carried
by an Administrative Shutdown or Administrative Reset Cease, telling
the remote operator why the session ended.

**Speaker**:
Any BGP endpoint, local or remote.

**Stale route**:
A route a helper retains after its session died, pending refresh by the
returning peer or expiry of the restart time.

**Tap**:
An observation-only hook on a peering's message stream: it sees every
message that crossed the wire, in both directions, and steers nothing.
Distinct from a handler, which receives the messages a session
delivers and may end the session by returning an error.
_Avoid_: handler (for the tap), capture (a tap's consumer, not the tap)

**Unconfigured peer**:
A remote speaker connecting from an address with no configured Peer.
Its connection is observed at most and always rejected.
_Avoid_: stranger, unknown peer; "dynamic neighbors" and "promiscuous
peering" name the feature of welcoming them, not the entity

**Withdraw**:
Removing a previously advertised prefix from service.
_Avoid_: revoke, retract
